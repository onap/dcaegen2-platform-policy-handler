"""policy-updater thread"""

# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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

import logging
import json
from Queue import Queue
from threading import Thread, Lock

from .policy_rest import PolicyRest
from .deploy_handler import DeployHandler
from .onap.audit import Audit

class PolicyUpdater(Thread):
    """queue and handle the policy-updates in a separate thread"""
    _logger = logging.getLogger("policy_handler.policy_updater")

    def __init__(self):
        """init static config of PolicyUpdater."""
        Thread.__init__(self, name="policy_updater")
        self.daemon = True

        self._aud_shutdown = None
        self._aud_catch_up = None

        self._lock = Lock()
        self._queue = Queue()

    def enqueue(self, audit=None, policies_updated=None, policies_removed=None):
        """enqueue the policy-updates"""
        policies_updated = policies_updated or []
        policies_removed = policies_removed or []

        PolicyUpdater._logger.info(
            "policies_updated %s policies_removed %s",
            json.dumps(policies_updated), json.dumps(policies_removed))
        self._queue.put((audit, policies_updated, policies_removed))

    def run(self):
        """wait and run the policy-update in thread"""
        while True:
            PolicyUpdater._logger.info("waiting for policy-updates...")
            audit, policies_updated, policies_removed = self._queue.get()
            PolicyUpdater._logger.info(
                "got policies_updated %s policies_removed %s",
                json.dumps(policies_updated), json.dumps(policies_removed))

            if not self._keep_running():
                self._queue.task_done()
                break

            if self._on_catch_up(audit) or not audit:
                continue

            updated_policies, removed_policies = PolicyRest.get_latest_updated_policies(
                (audit, policies_updated, policies_removed))

            DeployHandler.policy_update(audit, updated_policies, removed_policies=removed_policies)
            audit.audit_done()
            self._queue.task_done()

        PolicyUpdater._logger.info("exit policy-updater")

    def _keep_running(self):
        """thread-safe check whether to continue running"""
        with self._lock:
            keep_running = not self._aud_shutdown

        if self._aud_shutdown:
            self._aud_shutdown.audit_done()
        return keep_running

    def catch_up(self, audit):
        """need to bring the latest policies to DCAE-Controller"""
        PolicyUpdater._logger.info("catch_up requested")
        with self._lock:
            self._aud_catch_up = audit

        self.enqueue()

    def _reset_queue(self):
        """clear up the queue"""
        with self._lock:
            self._aud_catch_up = None
            self._queue.task_done()
            self._queue = Queue()

    def _on_catch_up(self, audit):
        """Bring the latest policies to DCAE-Controller"""
        self._lock.acquire()
        aud_catch_up = self._aud_catch_up
        if self._aud_catch_up:
            self._aud_catch_up = None
        self._lock.release()

        if not aud_catch_up:
            return False

        PolicyUpdater._logger.info("catch_up")
        latest_policies, errored_policies = PolicyRest.get_latest_policies(aud_catch_up)

        if not aud_catch_up.is_success():
            PolicyUpdater._logger.warn("not sending catch-up to deployment-handler due to errors")
            if not audit:
                self._queue.task_done()
        else:
            DeployHandler.policy_update(
                aud_catch_up, latest_policies, errored_policies=errored_policies, catch_up=True)
            self._reset_queue()
        success, _, _ = aud_catch_up.audit_done()
        PolicyUpdater._logger.info("policy_handler health: %s", json.dumps(Audit.health()))

        return success

    def shutdown(self, audit):
        """Shutdown the policy-updater"""
        PolicyUpdater._logger.info("shutdown policy-updater")
        with self._lock:
            self._aud_shutdown = audit
        self.enqueue()
        if self.is_alive():
            self.join()
