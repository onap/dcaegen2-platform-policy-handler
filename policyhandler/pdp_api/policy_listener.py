# ================================================================================
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
# Copyright (C) 2020 Wipro Limited.
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
to receive push notifications
on updates and removal of policies.

on receiving the policy-notifications, the policy-receiver
passes the notifications to policy-updater
"""
import json
import os
import time
from threading import Lock, Thread

from ..config import Config, Settings
from .dmaap import Subscriber

from ..onap.audit import Audit
from ..utils import Utils
from policyhandler.pdp_api.pdp_consts import PDP_POLICY_ID, PDP_POLICY_VERSION

REMOVED = 'undeployed-policies'
DEPLOYED = 'deployed-policies'

_LOGGER = Utils.get_logger(__file__)


class PolicyListener(Thread):
    """listener to PolicyEngine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    DMAAP_HEALTH = "DMaap_health"

    def __init__(self, audit, policy_updater):
        """listener to receive the policy notifications from PolicyEngine"""
        Thread.__init__(self, name="policy_receiver", daemon=True)
        self._settings = Settings(Config.POLLING_INTERVAL)
        self.polling_interval = 0
        self._policy_updater = policy_updater
        self._lock = Lock()
        self.dmaap_subscriber = Subscriber()
        self._keep_running = True
        self._sleep_before_restarting = 5
        Audit.register_item_health(PolicyListener.DMAAP_HEALTH, self._get_health)
        self.reconfigure(audit)

    def reconfigure(self, audit):
        """configure and reconfigure the listener"""
        with self._lock:
            _LOGGER.info(audit.info("DMaap_HEALTH {}".format(
                json.dumps(self._get_health(), sort_keys=True))))
            self._sleep_before_restarting = 5

            self._settings.set_config(Config.discovered_config)
            _, self.polling_interval = self._settings.get_by_key(Config.POLLING_INTERVAL, 60)
            if self.dmaap_subscriber.reconfigure(audit):
                self._keep_running = False
                return True

    def run(self):
        """listen on dmaap for notifications and pass the policy notifications to policy-updater"""
        _LOGGER.info("starting policy_receiver...")
        self._keep_running = True
        while True:
            if not self._get_keep_running():
                break

            _LOGGER.info("waiting for policy-notifications...")
            if self._get_keep_running():
                messages = self.dmaap_subscriber.get_messages()
                if messages:
                    self._on_pdp_message(messages)

            time.sleep(self.polling_interval)
        Audit.register_item_health(PolicyListener.DMAAP_HEALTH, self._get_health)
        _LOGGER.info("exit policy-receiver")

    def _get_keep_running(self):
        with self._lock:
            keep_running = self._keep_running
        return keep_running

    def _on_pdp_message(self, messages):
        """received the notification from PDP

            deployed-policies:
                -
                    policy-type: onap.policies.monitoring.cdap.tca.hi.lo.app
                    policy-type-version: 1.0.0
                    policy-id: onap.scaleout.tca
                    policy-version: 2.0.0
                    success-count: 3
                    failure-count: 0
                    incomplete-count: 0
            undeployed-policies:
            -
                    policy-type: onap.policies.monitoring.cdap.tca.hi.lo.app
                    policy-type-version: 1.0.0
                    policy-id: onap.scaleout.tca
                    policy-version: 1.0.0
                    success-count: 3
                    failure-count: 0
                    incomplete-count: 0


        """

        try:
            _LOGGER.info("Received notification message: %s", messages)
            _LOGGER.info("dmaap_health %s", json.dumps(self._get_health(), sort_keys=True))
            policies_updated = []
            policies_removed = []
            if not messages:
                return

            for message in messages:
                message = json.loads(message)
                if not message or not isinstance(message, dict):
                    _LOGGER.warning("unexpected message from PDP: %s", json.dumps(message))
                    return

                for policy in message.get(DEPLOYED, []):
                    policies_updated.append({PDP_POLICY_ID: policy.get(PDP_POLICY_ID),
                                             PDP_POLICY_VERSION: policy.get(PDP_POLICY_VERSION)})

                for policy in message.get(REMOVED, []):
                    policies_removed.append({PDP_POLICY_ID: policy.get(PDP_POLICY_ID),
                                             PDP_POLICY_VERSION: policy.get(PDP_POLICY_VERSION)})

                if not policies_updated and not policies_removed:
                    _LOGGER.info("no policy updated or removed")
                    return

            self._policy_updater.policy_update(policies_updated, policies_removed)

        except Exception as ex:
            error_msg = "crash {} {} at {}: {}".format(type(ex).__name__, str(ex),
                                                       "on_pdp_message", json.dumps(messages))
            _LOGGER.exception(error_msg)

    def _get_health(self):
        """returns the healthcheck of the dmaap as json"""
        dmaap_health = self.dmaap_subscriber.get_dmaap_health()
        return dmaap_health

    def shutdown(self, audit):
        """Shutdown the policy-listener"""
        _LOGGER.info(audit.info("shutdown policy-listener"))
        with self._lock:
            self._keep_running = False

        if self.is_alive():
            self.join()
