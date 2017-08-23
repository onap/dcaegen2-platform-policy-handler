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

class PolicyUpdater(Thread):
    """queue and handle the policy-updates in a separate thread"""
    _logger = logging.getLogger("policy_handler.policy_updater")

    def __init__(self):
        """init static config of PolicyUpdater."""
        Thread.__init__(self)
        self.name = "policy_updater"
        self.daemon = True

        self._req_shutdown = None
        self._req_catch_up = None

        self._lock = Lock()
        self._queue = Queue()

    def enqueue(self, audit=None, policy_names=None):
        """enqueue the policy-names"""
        policy_names = policy_names or []
        PolicyUpdater._logger.info("policy_names %s", json.dumps(policy_names))
        self._queue.put((audit, policy_names))

    def run(self):
        """wait and run the policy-update in thread"""
        while True:
            PolicyUpdater._logger.info("waiting for policy-updates...")
            audit, policy_names = self._queue.get()
            PolicyUpdater._logger.info("got policy-updates %s", json.dumps(policy_names))
            if not self._keep_running():
                self._queue.task_done()
                break
            if self._on_catch_up():
                continue

            if not policy_names:
                self._queue.task_done()
                continue

            updated_policies = PolicyRest.get_latest_policies_by_names((audit, policy_names))
            PolicyUpdater.policy_update(audit, updated_policies)
            audit.audit_done()
            self._queue.task_done()

        PolicyUpdater._logger.info("exit policy-updater")

    def _keep_running(self):
        """thread-safe check whether to continue running"""
        self._lock.acquire()
        keep_running = not self._req_shutdown
        self._lock.release()
        if self._req_shutdown:
            self._req_shutdown.audit_done()
        return keep_running

    def catch_up(self, audit):
        """need to bring the latest policies to DCAE-Controller"""
        self._lock.acquire()
        self._req_catch_up = audit
        self._lock.release()
        self.enqueue()

    def _on_catch_up(self):
        """Bring the latest policies to DCAE-Controller"""
        self._lock.acquire()
        req_catch_up = self._req_catch_up
        if self._req_catch_up:
            self._req_catch_up = None
            self._queue.task_done()
            self._queue = Queue()
        self._lock.release()
        if not req_catch_up:
            return False

        PolicyUpdater._logger.info("catch_up")
        latest_policies = PolicyRest.get_latest_policies(req_catch_up)
        PolicyUpdater.policy_update(req_catch_up, latest_policies)
        req_catch_up.audit_done()
        return True

    @staticmethod
    def policy_update(audit, updated_policies):
        """Invoke deploy-handler"""
        if updated_policies:
            PolicyUpdater._logger.info("updated_policies %s", json.dumps(updated_policies))
            DeployHandler.policy_update(audit, updated_policies)

    def shutdown(self, audit):
        """Shutdown the policy-updater"""
        PolicyUpdater._logger.info("shutdown policy-updater")
        self._lock.acquire()
        self._req_shutdown = audit
        self._lock.release()
        self.enqueue()
        if self.is_alive():
            self.join()
