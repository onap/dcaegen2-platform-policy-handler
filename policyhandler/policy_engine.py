"""policy-engine-client communicates with policy-engine thru PolicyEngine client object"""

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
import re

from .config import Config, PolicyEngineConfig
from .onap.audit import Audit
from .PolicyEngine import PolicyEngine, NotificationHandler, NotificationScheme
from .policy_updater import PolicyUpdater

class PolicyNotificationHandler(NotificationHandler):
    """handler of the policy-engine push notifications"""
    _logger = logging.getLogger("policy_handler.policy_notification")

    def __init__(self, policy_updater):
        scope_prefixes = [scope_prefix.replace(".", "[.]")
                          for scope_prefix in Config.config["scope_prefixes"]]
        self._policy_scopes = re.compile("(" + "|".join(scope_prefixes) + ")")
        PolicyNotificationHandler._logger.info("_policy_scopes %s", self._policy_scopes.pattern)
        self._policy_updater = policy_updater
        self._policy_updater.start()

    def notificationReceived(self, notification):
        if not notification or not notification._loadedPolicies:
            return

        policy_names = [loaded._policyName
                        for loaded in notification._loadedPolicies
                        if self._policy_scopes.match(loaded._policyName)]

        if not policy_names:
            PolicyNotificationHandler._logger.info("no policy updated for scopes %s",
                                                   self._policy_scopes.pattern)
            return

        audit = Audit(req_message="notificationReceived from PDP")
        audit.retry_get_config = True
        self._policy_updater.enqueue(audit, policy_names)

class PolicyEngineClient(object):
    """ policy-engine client"""
    _logger = logging.getLogger("policy_handler.policy_engine")
    _policy_updater = None
    _pdp_notification_handler = None
    _policy_engine = None

    @staticmethod
    def shutdown(audit):
        """Shutdown the notification-handler"""
        PolicyEngineClient._policy_updater.shutdown(audit)

    @staticmethod
    def catch_up(audit):
        """bring the latest policies from policy-engine"""
        PolicyEngineClient._policy_updater.catch_up(audit)

    @staticmethod
    def create_policy_engine_properties():
        """create the policy_engine.properties file from config.json"""
        pass

    @staticmethod
    def run():
        """Using policy-engine client to talk to policy engine"""
        audit = Audit(req_message="start PDP client")
        PolicyEngineClient._policy_updater = PolicyUpdater()
        PolicyEngineClient._pdp_notification_handler = PolicyNotificationHandler(
            PolicyEngineClient._policy_updater)

        sub_aud = Audit(aud_parent=audit)
        sub_aud.metrics_start("create client to PDP")
        basic_client_auth = PolicyEngineConfig.save_to_file()
        PolicyEngineClient._policy_engine = PolicyEngine(
            PolicyEngineConfig.PATH_TO_PROPERTIES,
            scheme=NotificationScheme.AUTO_ALL_NOTIFICATIONS.name,
            handler=PolicyEngineClient._pdp_notification_handler,
            basic_client_auth=basic_client_auth
        )
        sub_aud.metrics("created client to PDP")
        seed_scope = ".*"
        PolicyEngineClient._policy_engine.getConfig(policyName=seed_scope)
        sub_aud.metrics("seeded client by PDP.getConfig for policyName={0}".format(seed_scope))

        PolicyEngineClient.catch_up(audit)
