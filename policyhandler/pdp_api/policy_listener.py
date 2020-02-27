# ================================================================================
# Copyright (c) 2019-2020 AT&T Intellectual Property. All rights reserved.
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

"""
policy-listener communicates with policy-engine
to receive push notifications through DMaaP MR
on updates and removal of policies.

on receiving the policy-notifications, the policy-listener
passes the notifications to policy-updater
"""

import json
import os
from threading import Event, Lock, Thread

from ..onap.audit import Audit, AuditResponseCode
from ..utils import Utils
from .dmaap_mr import DmaapMr
from .pdp_consts import (DEPLOYED_POLICIES, PDP_METADATA, PDP_POLICY_ID,
                         PDP_POLICY_VERSION, UNDEPLOYED_POLICIES)

_LOGGER = Utils.get_logger(__file__)

class PolicyListener(Thread):
    """listener to DMaaP MR"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    SLEEP_BEFORE_RESTARTING = 30

    def __init__(self, audit, policy_updater):
        """listener to receive the policy notifications from PolicyEngine"""
        Thread.__init__(self, name="policy_listener", daemon=True)

        self._policy_updater = policy_updater
        self._lock = Lock()
        self._run_event = Event()
        self._keep_running = True
        self._first_loop = True

        self._dmaap_mr = None
        self.reconfigure(audit)

    def reconfigure(self, audit):
        """configure and reconfigure the DMaaP MR"""
        reconfigured = DmaapMr.reconfigure(audit)
        if reconfigured and not self._first_loop:
            with self._lock:
                self._first_loop = True
        return reconfigured

    def run(self):
        """listen on DMaaP MR and pass the policy notifications to policy-updater"""
        _LOGGER.info("starting policy_listener...")
        delayed_restarting = False
        while True:
            if not self._get_keep_running():
                break

            if delayed_restarting:
                _LOGGER.info(
                    "going to sleep for %s secs before restarting policy-notifications",
                    PolicyListener.SLEEP_BEFORE_RESTARTING)

                self._run_event.clear()
                self._run_event.wait(PolicyListener.SLEEP_BEFORE_RESTARTING)
                if not self._get_keep_running():
                    break

            audit = Audit(job_name="policy_update",
                          req_message="waiting for policy-notifications...",
                          retry_get_config=True)

            policy_updates = DmaapMr.get_policy_updates(audit)

            if not self._get_keep_running():
                audit.audit_done(result="exiting policy_listener")
                break

            delayed_restarting = not audit.is_success()
            if self._first_loop:
                policy_updater = None
                with self._lock:
                    if self._first_loop:
                        self._first_loop = False
                        policy_updater = self._policy_updater
                if policy_updater is not None:
                    audit.req_message = "first catch_up"
                    _LOGGER.info(audit.info("first catch_up - ignoring policy-updates: {}"
                                            .format(json.dumps(policy_updates))))
                    policy_updater.catch_up(audit)
            elif not policy_updates:
                _LOGGER.info(audit.info(
                    "no policy-updates: {}".format(json.dumps(policy_updates))))
                audit.audit_done(result="no policy-updates")
            else:
                self._on_policy_update_message(audit, policy_updates)

        _LOGGER.info("exit policy_listener")

    def _get_keep_running(self):
        """thread-safe check whether to continue running"""
        with self._lock:
            keep_running = self._keep_running
        return keep_running

    def _on_policy_update_message(self, audit, policy_updates):
        """received the notification from PDP"""
        try:
            _LOGGER.info("Received notification message: %s", json.dumps(policy_updates))
            if not policy_updates:
                return

            policies_updated = []

            for idx, pdp_update_msg in enumerate(policy_updates):
                pdp_update_msg = Utils.safe_json_parse(pdp_update_msg)

                if not pdp_update_msg or not isinstance(pdp_update_msg, dict):
                    _LOGGER.warning(audit.warn(
                        "unexpected message from PDP: {}".format(json.dumps(pdp_update_msg)),
                        error_code=AuditResponseCode.DATA_ERROR))
                    continue

                _LOGGER.debug("raw policy_update[%s]: %s", idx, json.dumps(pdp_update_msg))

                deployed_policies = [
                    {PDP_METADATA: {PDP_POLICY_ID: p_deployed.get(PDP_POLICY_ID),
                                    PDP_POLICY_VERSION: p_deployed.get(PDP_POLICY_VERSION)}}
                    for p_deployed in pdp_update_msg.get(DEPLOYED_POLICIES, [])
                    if (p_deployed.get(PDP_POLICY_ID) is not None
                        and p_deployed.get(PDP_POLICY_VERSION) is not None)]

                undeployed_policies = [
                    {PDP_METADATA: {PDP_POLICY_ID: p_undeployed.get(PDP_POLICY_ID),
                                    PDP_POLICY_VERSION: p_undeployed.get(PDP_POLICY_VERSION)}}
                    for p_undeployed in pdp_update_msg.get(UNDEPLOYED_POLICIES, [])
                    if (p_undeployed.get(PDP_POLICY_ID) is not None
                        and p_undeployed.get(PDP_POLICY_VERSION) is not None)]

                if not deployed_policies and not undeployed_policies:
                    _LOGGER.warning(audit.warn(
                        "no policy deployed or undeployed: {}".format(json.dumps(pdp_update_msg)),
                        error_code=AuditResponseCode.DATA_ERROR))
                    continue

                policy_update = {DEPLOYED_POLICIES: deployed_policies,
                                 UNDEPLOYED_POLICIES: undeployed_policies}
                _LOGGER.info(audit.info("policy_update[{}]: {}"
                                        .format(idx, json.dumps(policy_update))))

                policies_updated.append(policy_update)

            if not policies_updated:
                _LOGGER.warning(audit.warn(
                    "erroneous notification from PDP: {}".format(json.dumps(policy_updates)),
                    error_code=AuditResponseCode.DATA_ERROR))
                return

            with self._lock:
                policy_updater = self._policy_updater
            if policy_updater is not None:
                policy_updater.policy_update(audit, policies_updated)
        except Exception as ex:
            error_msg = "crash {} {} at {}: {}".format(type(ex).__name__, str(ex),
                                                       "on_policy_update_message",
                                                       json.dumps(policy_updates))
            _LOGGER.exception(audit.fatal(error_msg))

    def shutdown(self, audit):
        """Shutdown the policy_listener"""
        _LOGGER.info(audit.info("shutdown policy_listener - no waiting..."))
        with self._lock:
            self._keep_running = False
            self._policy_updater = None
            self._run_event.set()
