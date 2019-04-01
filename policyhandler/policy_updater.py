# ================================================================================
# Copyright (c) 2017-2019 AT&T Intellectual Property. All rights reserved.
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

"""policy-updater thread"""

import json
from threading import Event, Lock, Thread

from . import pdp_client
from .config import Config, Settings
from .deploy_handler import DeployHandler, PolicyUpdateMessage
from .onap.audit import Audit, AuditHttpCode, AuditResponseCode
from .policy_consts import AUTO_CATCH_UP, AUTO_RECONFIGURE, CATCH_UP
from .service_activator import ServiceActivator
from .step_timer import StepTimer
from .utils import Utils


_LOGGER = Utils.get_logger(__file__)

class PolicyUpdater(Thread):
    """sequentially handle the policy-updates and catch-ups in its own policy_updater thread"""
    def __init__(self, on_reconfigure_receiver):
        """init static config of PolicyUpdater."""
        Thread.__init__(self, name="policy_updater", daemon=True)
        self._reconfigure_receiver = on_reconfigure_receiver

        self._lock = Lock()
        self._run = Event()
        self._settings = Settings(CATCH_UP, Config.RECONFIGURE)

        self._catch_up_timer = None
        self._reconfigure_timer = None

        self._aud_shutdown = None
        self._aud_catch_up = None
        self._aud_reconfigure = None
        self._policy_updates = pdp_client.PolicyUpdates()

        self._catch_up_interval = None
        self._reconfigure_interval = None
        self._set_timer_intervals()

    def _set_timer_intervals(self):
        """set intervals on timers"""
        self._settings.set_config(Config.discovered_config)
        if not self._settings.is_changed():
            self._settings.commit_change()
            return False

        _, catch_up = self._settings.get_by_key(CATCH_UP, {})
        self._catch_up_interval = catch_up.get(Config.TIMER_INTERVAL) or 15*60

        _, reconfigure = self._settings.get_by_key(Config.RECONFIGURE, {})
        self._reconfigure_interval = reconfigure.get(Config.TIMER_INTERVAL) or 10*60

        _LOGGER.info(
            "intervals: catch_up(%s) reconfigure(%s): %s",
            self._catch_up_interval, self._reconfigure_interval, self._settings)
        self._settings.commit_change()
        return True

    def policy_update(self, policies_updated, policies_removed):
        """enqueue the policy-updates"""
        with self._lock:
            self._policy_updates.push_policy_updates(policies_updated, policies_removed)
            self._run.set()

    def catch_up(self, audit=None):
        """need to bring the latest policies to DCAE-Controller"""
        with self._lock:
            if not self._aud_catch_up:
                self._aud_catch_up = audit or Audit(req_message=AUTO_CATCH_UP)
                _LOGGER.info(
                    "catch_up %s request_id %s",
                    self._aud_catch_up.req_message, self._aud_catch_up.request_id
                )
            self._run.set()

    def reconfigure(self, audit=None):
        """job to check for and bring in the updated config for policy-handler"""
        with self._lock:
            if not self._aud_reconfigure:
                self._aud_reconfigure = audit or Audit(req_message=AUTO_RECONFIGURE)
                _LOGGER.info(
                    "%s request_id %s",
                    self._aud_reconfigure.req_message, self._aud_reconfigure.request_id
                )
            self._run.set()

    def run(self):
        """wait and run the policy-update in thread"""
        _LOGGER.info("starting policy_updater...")
        self._run_reconfigure_timer()
        while True:
            _LOGGER.info("waiting for policy-updates...")
            self._run.wait()

            with self._lock:
                self._run.clear()

            if not self._keep_running():
                break

            self._on_reconfigure()

            if not self._keep_running():
                break

            if self._on_catch_up():
                continue

            self._on_policy_update()

        _LOGGER.info("exit policy-updater")

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
            _LOGGER.info("next step catch_up_timer in %s", self._catch_up_interval)
            self._catch_up_timer.next(self._catch_up_interval)
            return

        self._catch_up_timer = StepTimer(
            "catch_up_timer", self._catch_up_interval,
            PolicyUpdater.catch_up, self
        )
        _LOGGER.info("started catch_up_timer in %s", self._catch_up_interval)
        self._catch_up_timer.start()

    def _run_reconfigure_timer(self):
        """create and start the reconfigure timer"""
        if not self._reconfigure_interval:
            return

        if self._reconfigure_timer:
            _LOGGER.info("next step reconfigure_timer in %s", self._reconfigure_interval)
            self._reconfigure_timer.next(self._reconfigure_interval)
            return

        self._reconfigure_timer = StepTimer(
            "reconfigure_timer", self._reconfigure_interval,
            PolicyUpdater.reconfigure, self
        )
        _LOGGER.info("started reconfigure_timer in %s", self._reconfigure_interval)
        self._reconfigure_timer.start()

    def _pause_catch_up_timer(self):
        """pause catch_up_timer"""
        if self._catch_up_timer:
            _LOGGER.info("pause catch_up_timer")
            self._catch_up_timer.pause()

    def _stop_timers(self):
        """stop and destroy the catch_up and reconfigure timers"""
        if self._catch_up_timer:
            _LOGGER.info("stopping catch_up_timer")
            self._catch_up_timer.stop()
            self._catch_up_timer.join()
            self._catch_up_timer = None
            _LOGGER.info("stopped catch_up_timer")

        if self._reconfigure_timer:
            _LOGGER.info("stopping reconfigure_timer")
            self._reconfigure_timer.stop()
            self._reconfigure_timer.join()
            self._reconfigure_timer = None
            _LOGGER.info("stopped reconfigure_timer")

    def _on_reconfigure(self):
        """bring the latest config and reconfigure"""
        with self._lock:
            aud_reconfigure = self._aud_reconfigure
            if self._aud_reconfigure:
                self._aud_reconfigure = None

        if not aud_reconfigure:
            return

        log_line = "{}({})".format(aud_reconfigure.req_message, aud_reconfigure.request_id)
        reconfigure_result = ""
        try:
            need_to_catch_up = False
            _LOGGER.info(log_line)

            active_prev = ServiceActivator.is_active_mode_of_operation(aud_reconfigure)
            Config.discover(aud_reconfigure)

            if not Config.discovered_config.is_changed():
                active = ServiceActivator.determine_mode_of_operation(aud_reconfigure)
                reconfigure_result = " -- config not changed"
            else:
                changed_configs = []

                if ServiceActivator.reconfigure(aud_reconfigure):
                    changed_configs.append(Config.SERVICE_ACTIVATOR)
                active = ServiceActivator.determine_mode_of_operation(aud_reconfigure)

                if self._set_timer_intervals():
                    changed_configs.append("timer_intervals")

                if pdp_client.PolicyRest.reconfigure():
                    need_to_catch_up = True
                    changed_configs.append(Config.FIELD_POLICY_ENGINE)

                if DeployHandler.reconfigure(aud_reconfigure):
                    need_to_catch_up = True
                    changed_configs.append(Config.DEPLOY_HANDLER)

                if self._reconfigure_receiver(aud_reconfigure):
                    need_to_catch_up = True
                    changed_configs.append("web-socket")

                reconfigure_result = " -- config changed on {} changes: {}".format(
                    json.dumps(changed_configs), Config.discovered_config)

            need_to_catch_up = need_to_catch_up or (active and not active_prev)
            if need_to_catch_up:
                reconfigure_result += " -- going to catch_up"

            Config.discovered_config.commit_change()
            aud_reconfigure.audit_done(result=reconfigure_result)
            _LOGGER.info(log_line + reconfigure_result)

            if need_to_catch_up:
                self._pause_catch_up_timer()
                self.catch_up()

        except Exception as ex:
            error_msg = "crash {} {}{}: {}: {}".format(
                "_on_reconfigure", log_line, reconfigure_result, type(ex).__name__, str(ex))

            _LOGGER.exception(error_msg)
            aud_reconfigure.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            aud_reconfigure.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            aud_reconfigure.audit_done(result=error_msg)

        self._run_reconfigure_timer()

        _LOGGER.info("policy_handler health: %s", json.dumps(aud_reconfigure.health(full=True)))
        _LOGGER.info("process_info: %s", json.dumps(aud_reconfigure.process_info()))


    def _on_catch_up(self):
        """bring all the latest policies to DCAE-Controller"""
        with self._lock:
            aud_catch_up = self._aud_catch_up
            if self._aud_catch_up:
                self._aud_catch_up = None
                self._policy_updates.reset()

        if not aud_catch_up:
            return False

        if not ServiceActivator.is_active_mode_of_operation(aud_catch_up):
            catch_up_result = "passive -- skip catch_up {0} request_id {1}".format(
                aud_catch_up.req_message, aud_catch_up.request_id
            )
            self._pause_catch_up_timer()
            aud_catch_up.audit_done(result=catch_up_result)
            _LOGGER.info(catch_up_result)
            self._run_catch_up_timer()

            _LOGGER.info("policy_handler health: %s", json.dumps(aud_catch_up.health(full=True)))
            _LOGGER.info("process_info: %s", json.dumps(aud_catch_up.process_info()))
            return False

        log_line = "catch_up {0} request_id {1}".format(
            aud_catch_up.req_message, aud_catch_up.request_id
        )
        catch_up_result = ""
        try:
            not_found_ok = None
            _LOGGER.info(log_line)
            self._pause_catch_up_timer()

            (_, policies,
             policy_filters) = pdp_client.PolicyMatcher.get_deployed_policies(aud_catch_up)

            catch_up_message = None
            if aud_catch_up.is_not_found():
                not_found_ok = True
            else:
                _, catch_up_message = pdp_client.PolicyMatcher.build_catch_up_message(
                    aud_catch_up, policies, policy_filters)

            if not_found_ok:
                catch_up_result = ("- not sending catch-up "
                                   "- no deployed policies or policy-filters")
                _LOGGER.warning(catch_up_result)
            elif not (catch_up_message and aud_catch_up.is_success()):
                catch_up_result = "- not sending catch-up to deployment-handler due to errors"
                _LOGGER.warning(catch_up_result)
            elif catch_up_message.empty():
                catch_up_result = "- not sending empty catch-up to deployment-handler"
            else:
                aud_catch_up.reset_http_status_not_found()
                DeployHandler.policy_update(aud_catch_up, catch_up_message)
                if not aud_catch_up.is_success():
                    catch_up_result = "- failed to send catch-up to deployment-handler"
                    _LOGGER.warning(catch_up_result)
                else:
                    catch_up_result = "- sent catch-up to deployment-handler"
            success, _, _ = aud_catch_up.audit_done(result=catch_up_result)
            _LOGGER.info(log_line + " " + catch_up_result)

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(aud_catch_up.request_id, type(ex).__name__, str(ex),
                                 "on_catch_up", log_line + " " + catch_up_result))

            _LOGGER.exception(error_msg)
            aud_catch_up.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            aud_catch_up.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            aud_catch_up.audit_done(result=error_msg)
            success = False

        self._run_catch_up_timer()

        _LOGGER.info("policy_handler health: %s", json.dumps(aud_catch_up.health(full=True)))
        _LOGGER.info("process_info: %s", json.dumps(aud_catch_up.process_info()))
        return success


    def _on_policy_update(self):
        """handle the event of policy-updates"""
        result = ""
        with self._lock:
            audit, policies_updated, policies_removed = self._policy_updates.pop_policy_updates()

        if not audit:
            return

        log_line = "request_id: {} policies_updated: {} policies_removed: {}".format(
            audit.request_id, json.dumps(policies_updated), json.dumps(policies_removed))
        _LOGGER.info(log_line)

        try:
            not_found_ok = None
            (updated_policies, removed_policies,
             policy_filter_matches) = pdp_client.PolicyMatcher.match_to_deployed_policies(
                 audit, policies_updated, policies_removed)

            if audit.is_not_found():
                not_found_ok = True
            elif updated_policies or removed_policies:
                (updated_policies,
                 removed_policies) = pdp_client.PolicyRest.get_latest_updated_policies(
                     audit, updated_policies, removed_policies
                 )

            if not_found_ok:
                result = ("- not sending policy-updates to deployment-handler "
                          "- no deployed policies or policy-filters")
                _LOGGER.warning(result)
            elif not audit.is_success():
                result = "- not sending policy-updates to deployment-handler due to errors"
                _LOGGER.warning(result)
            elif not updated_policies and not removed_policies:
                result = "- not sending empty policy-updates to deployment-handler"
                _LOGGER.info(result)
            else:
                message = PolicyUpdateMessage(updated_policies, removed_policies,
                                              policy_filter_matches, False)
                log_updates = ("policies-updated[{}], removed[{}], policy_filter_matches[{}]"
                               .format(len(updated_policies),
                                       len(removed_policies),
                                       len(policy_filter_matches)))

                audit.reset_http_status_not_found()
                DeployHandler.policy_update(audit, message)

                log_line = "request_id[{}]: {}".format(audit.request_id, str(message))
                if not audit.is_success():
                    result = "- failed to send to deployment-handler {}".format(log_updates)
                    _LOGGER.warning(result)
                else:
                    result = "- sent to deployment-handler {}".format(log_updates)

            audit.audit_done(result=result)
            _LOGGER.info(log_line + " " + result)

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "on_policies_update", log_line + " " + result))

            _LOGGER.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        if DeployHandler.server_instance_changed:
            DeployHandler.server_instance_changed = False
            self._pause_catch_up_timer()
            self.catch_up()


    def shutdown(self, audit):
        """Shutdown the policy-updater"""
        _LOGGER.info("shutdown policy-updater")
        with self._lock:
            self._aud_shutdown = audit
            self._run.set()

        self._stop_timers()

        if self.is_alive():
            self.join()
