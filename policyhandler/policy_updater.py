# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
# ================================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.

"""policy-updater thread"""

import copy
import json
import logging
from Queue import Queue
from threading import Lock, Thread

from .config import Config
from .deploy_handler import DeployHandler
from .onap.audit import Audit, AuditHttpCode, AuditResponseCode
from .policy_consts import (AUTO_CATCH_UP, CATCH_UP, LATEST_POLICIES,
                            REMOVED_POLICIES)
from .policy_rest import PolicyRest
from .policy_utils import Utils
from .step_timer import StepTimer


class PolicyUpdater(Thread):
    """queue and handle the policy-updates in a separate thread"""
    _logger = logging.getLogger("policy_handler.policy_updater")

    def __init__(self):
        """init static config of PolicyUpdater."""
        Thread.__init__(self, name="policy_updater")
        self.daemon = True

        self._catch_up_timer = None
        self._aud_shutdown = None
        self._aud_catch_up = None

        catch_up_config = Config.config.get(CATCH_UP, {})
        self._catch_up_interval = catch_up_config.get("interval") or 15*60
        self._catch_up_max_skips = catch_up_config.get("max_skips") or 3
        self._catch_up_skips = 0
        self._catch_up_prev_message = None

        self._lock = Lock()
        self._queue = Queue()


    def enqueue(self, audit=None, policies_updated=None, policies_removed=None):
        """enqueue the policy-updates"""
        policies_updated = policies_updated or []
        policies_removed = policies_removed or []

        PolicyUpdater._logger.info(
            "enqueue request_id %s policies_updated %s policies_removed %s",
            ((audit and audit.request_id) or "none"),
            json.dumps(policies_updated), json.dumps(policies_removed))

        with self._lock:
            self._queue.put((audit, policies_updated, policies_removed))


    def catch_up(self, audit=None):
        """need to bring the latest policies to DCAE-Controller"""
        with self._lock:
            if not self._aud_catch_up:
                self._aud_catch_up = audit or Audit(req_message=AUTO_CATCH_UP)
                PolicyUpdater._logger.info(
                    "catch_up %s request_id %s",
                    self._aud_catch_up.req_message, self._aud_catch_up.request_id
                )

        self.enqueue()


    def run(self):
        """wait and run the policy-update in thread"""
        while True:
            PolicyUpdater._logger.info("waiting for policy-updates...")
            queued_audit, policies_updated, policies_removed = self._queue.get()
            PolicyUpdater._logger.info(
                "got request_id %s policies_updated %s policies_removed %s",
                ((queued_audit and queued_audit.request_id) or "none"),
                json.dumps(policies_updated), json.dumps(policies_removed))

            if not self._keep_running():
                break

            if self._on_catch_up():
                self._reset_queue()
                continue
            elif not queued_audit:
                continue

            self._on_policies_update(queued_audit, policies_updated, policies_removed)

        PolicyUpdater._logger.info("exit policy-updater")

    def _keep_running(self):
        """thread-safe check whether to continue running"""
        with self._lock:
            keep_running = not self._aud_shutdown

        if self._aud_shutdown:
            self._aud_shutdown.audit_done()
        return keep_running

    def _run_catch_up_timer(self):
        """create and start the catch_up timer"""
        if not self._catch_up_interval:
            return

        if self._catch_up_timer:
            self._logger.info("next step catch_up_timer in %s", self._catch_up_interval)
            self._catch_up_timer.next()
            return

        self._catch_up_timer = StepTimer(
            "catch_up_timer",
            self._catch_up_interval,
            PolicyUpdater.catch_up,
            PolicyUpdater._logger,
            self
        )
        self._logger.info("started catch_up_timer in %s", self._catch_up_interval)
        self._catch_up_timer.start()

    def _pause_catch_up_timer(self):
        """pause catch_up_timer"""
        if self._catch_up_timer:
            self._logger.info("pause catch_up_timer")
            self._catch_up_timer.pause()

    def _stop_catch_up_timer(self):
        """stop and destroy the catch_up_timer"""
        if self._catch_up_timer:
            self._logger.info("stopping catch_up_timer")
            self._catch_up_timer.stop()
            self._catch_up_timer.join()
            self._catch_up_timer = None
            self._logger.info("stopped catch_up_timer")

    def _need_to_send_catch_up(self, aud_catch_up, catch_up_message):
        """try not to send the duplicate messages on auto catchup unless hitting the max count"""
        if aud_catch_up.req_message != AUTO_CATCH_UP \
        or self._catch_up_skips >= self._catch_up_max_skips \
        or not Utils.are_the_same(catch_up_message, self._catch_up_prev_message):
            self._catch_up_skips = 0
            self._catch_up_prev_message = copy.deepcopy(catch_up_message)
            log_line = "going to send the catch_up {0}: {1}".format(
                aud_catch_up.req_message,
                json.dumps(self._catch_up_prev_message)
            )
            self._logger.info(log_line)
            aud_catch_up.info(log_line)
            return True

        self._catch_up_skips += 1
        self._catch_up_prev_message = copy.deepcopy(catch_up_message)
        log_line = "skip {0}/{1} sending the same catch_up {2}: {3}".format(
            self._catch_up_skips, self._catch_up_max_skips,
            aud_catch_up.req_message, json.dumps(self._catch_up_prev_message)
        )
        self._logger.info(log_line)
        aud_catch_up.info(log_line)
        return False

    def _reset_queue(self):
        """clear up the queue"""
        with self._lock:
            if not self._aud_catch_up and not self._aud_shutdown:
                with self._queue.mutex:
                    self._queue.queue.clear()

    def _on_catch_up(self):
        """bring all the latest policies to DCAE-Controller"""
        with self._lock:
            aud_catch_up = self._aud_catch_up
            if self._aud_catch_up:
                self._aud_catch_up = None

        if not aud_catch_up:
            return False

        log_line = "catch_up {0} request_id {1}".format(
            aud_catch_up.req_message, aud_catch_up.request_id
        )
        try:
            PolicyUpdater._logger.info(log_line)
            self._pause_catch_up_timer()

            catch_up_message = PolicyRest.get_latest_policies(aud_catch_up)
            catch_up_message[CATCH_UP] = True

            catch_up_result = ""
            if not aud_catch_up.is_success():
                catch_up_result = "- not sending catch-up to deployment-handler due to errors"
                PolicyUpdater._logger.warn(catch_up_result)
            elif not self._need_to_send_catch_up(aud_catch_up, catch_up_message):
                catch_up_result = "- skipped sending the same policies"
            else:
                DeployHandler.policy_update(aud_catch_up, catch_up_message, rediscover=True)
                if not aud_catch_up.is_success():
                    catch_up_result = "- failed to send catch-up to deployment-handler"
                    PolicyUpdater._logger.warn(catch_up_result)
                else:
                    catch_up_result = "- sent catch-up to deployment-handler"
            success, _, _ = aud_catch_up.audit_done(result=catch_up_result)
            PolicyUpdater._logger.info(log_line + " " + catch_up_result)

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(aud_catch_up.request_id, type(ex).__name__, str(ex),
                                 "on_catch_up", log_line + " " + catch_up_result))

            PolicyUpdater._logger.exception(error_msg)
            aud_catch_up.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            aud_catch_up.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            success = False

        if not success:
            self._catch_up_prev_message = None

        self._run_catch_up_timer()

        PolicyUpdater._logger.info("policy_handler health: %s",
                                   json.dumps(aud_catch_up.health(full=True)))
        return success


    def _on_policies_update(self, queued_audit, policies_updated, policies_removed):
        """handle the event of policy-updates from the queue"""
        deployment_handler_changed = None
        result = ""

        log_line = "request_id: {} policies_updated: {} policies_removed: {}".format(
            ((queued_audit and queued_audit.request_id) or "none"),
            json.dumps(policies_updated), json.dumps(policies_removed))

        try:
            updated_policies, removed_policies = PolicyRest.get_latest_updated_policies(
                (queued_audit, policies_updated, policies_removed))

            if not queued_audit.is_success():
                result = "- not sending policy-updates to deployment-handler due to errors"
                PolicyUpdater._logger.warn(result)
            else:
                message = {LATEST_POLICIES: updated_policies, REMOVED_POLICIES: removed_policies}
                deployment_handler_changed = DeployHandler.policy_update(queued_audit, message)
                if not queued_audit.is_success():
                    result = "- failed to send policy-updates to deployment-handler"
                    PolicyUpdater._logger.warn(result)
                else:
                    result = "- sent policy-updates to deployment-handler"

            success, _, _ = queued_audit.audit_done(result=result)

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(queued_audit.request_id, type(ex).__name__, str(ex),
                                 "on_policies_update", log_line + " " + result))

            PolicyUpdater._logger.exception(error_msg)
            queued_audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            queued_audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            success = False

        if deployment_handler_changed:
            self._catch_up_prev_message = None
            self._pause_catch_up_timer()
            self.catch_up()
        elif not success:
            self._catch_up_prev_message = None


    def shutdown(self, audit):
        """Shutdown the policy-updater"""
        PolicyUpdater._logger.info("shutdown policy-updater")
        with self._lock:
            self._aud_shutdown = audit
        self.enqueue()

        self._stop_catch_up_timer()

        if self.is_alive():
            self.join()
