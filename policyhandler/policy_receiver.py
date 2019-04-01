# ================================================================================
# Copyright (c) 2018-2019 AT&T Intellectual Property. All rights reserved.
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
policy-receiver communicates with policy-engine
thru web-socket to receive push notifications
on updates and removal of policies.

on receiving the policy-notifications, the policy-receiver
passes the notifications to policy-updater
"""

from .service_activator import ServiceActivator

class PolicyReceiver(object):
    """
    policy-receiver - static singleton wrapper around two threads
        policy_updater - master thread for all scheduled actions
        policy_listener - listens to policy-engine through web-socket
    """
    _policy_updater = None
    _policy_listener = None

    @staticmethod
    def is_running():
        """check whether the policy-receiver runs"""
        return (PolicyReceiver._policy_listener
                and PolicyReceiver._policy_listener.is_alive()
                and PolicyReceiver._policy_updater
                and PolicyReceiver._policy_updater.is_alive())

    @staticmethod
    def _close_listener(audit):
        """stop the notification-handler"""
        if PolicyReceiver._policy_listener:
            policy_receiver = PolicyReceiver._policy_listener
            PolicyReceiver._policy_listener = None
            policy_receiver.shutdown(audit)

    @staticmethod
    def shutdown(audit):
        """shutdown the notification-handler and policy-updater"""
        PolicyReceiver._close_listener(audit)
        PolicyReceiver._policy_updater.shutdown(audit)

    @staticmethod
    def catch_up(audit):
        """request to bring the latest policies to DCAE"""
        PolicyReceiver._policy_updater.catch_up(audit)

    @staticmethod
    def reconfigure(audit):
        """request to reconfigure the updated config for policy-handler"""
        PolicyReceiver._policy_updater.reconfigure(audit)

    @staticmethod
    def _on_reconfigure(audit):
        """act on reconfiguration event"""
        active = ServiceActivator.is_active_mode_of_operation(audit)

        if not PolicyReceiver._policy_listener:
            if active:
                from . import pdp_client
                PolicyReceiver._policy_listener = pdp_client.PolicyListener(
                    audit, PolicyReceiver._policy_updater
                )
                PolicyReceiver._policy_listener.start()
            return

        if not active:
            PolicyReceiver._close_listener(audit)
            return

        PolicyReceiver._policy_listener.reconfigure(audit)


    @staticmethod
    def run(audit):
        """run policy_updater and policy_receiver"""
        from .policy_updater import PolicyUpdater
        PolicyReceiver._policy_updater = PolicyUpdater(PolicyReceiver._on_reconfigure)

        PolicyReceiver._on_reconfigure(audit)

        PolicyReceiver._policy_updater.start()

        PolicyReceiver.catch_up(audit)
