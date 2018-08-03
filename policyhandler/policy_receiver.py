# ================================================================================
# Copyright (c) 2018 AT&T Intellectual Property. All rights reserved.
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

"""
policy-receiver communicates with policy-engine
thru web-socket to receive push notifications
on updates and removal of policies.

on receiving the policy-notifications, the policy-receiver
passes the notifications to policy-updater
"""

import json
import logging
import time
from threading import Lock, Thread

import websocket

from .config import Config
from .policy_consts import MATCHING_CONDITIONS, POLICY_NAME, POLICY_VERSION
from .policy_updater import PolicyUpdater

LOADED_POLICIES = 'loadedPolicies'
REMOVED_POLICIES = 'removedPolicies'
POLICY_VER = 'versionNo'
POLICY_MATCHES = 'matches'

class _PolicyReceiver(Thread):
    """web-socket to PolicyEngine"""
    _logger = logging.getLogger("policy_handler.policy_receiver")

    def __init__(self):
        """web-socket inside the thread to receive policy notifications from PolicyEngine"""
        Thread.__init__(self, name="policy_receiver")
        self.daemon = True

        self._lock = Lock()
        self._keep_running = True

        config = Config.settings[Config.FIELD_POLICY_ENGINE]
        self.web_socket_url = resturl = config["url"] + config["path_pdp"]

        if resturl.startswith("https:"):
            self.web_socket_url = resturl.replace("https:", "wss:") + "notifications"
        else:
            self.web_socket_url = resturl.replace("http:", "ws:") + "notifications"

        self._web_socket = None

        self._policy_updater = PolicyUpdater()
        self._policy_updater.start()

    def run(self):
        """listen on web-socket and pass the policy notifications to policy-updater"""
        websocket.enableTrace(True)
        restarting = False
        while True:
            if not self._get_keep_running():
                break

            self._stop_notifications()

            if restarting:
                time.sleep(5)

            _PolicyReceiver._logger.info(
                "connecting to policy-notifications at: %s", self.web_socket_url)
            self._web_socket = websocket.WebSocketApp(
                self.web_socket_url,
                on_message=self._on_pdp_message,
                on_close=self._on_ws_close,
                on_error=self._on_ws_error
            )

            _PolicyReceiver._logger.info("waiting for policy-notifications...")
            self._web_socket.run_forever()
            restarting = True

        _PolicyReceiver._logger.info("exit policy-receiver")

    def _get_keep_running(self):
        """thread-safe check whether to continue running"""
        with self._lock:
            keep_running = self._keep_running
        return keep_running

    def _stop_notifications(self):
        """Shuts down the AutoNotification service if running."""
        with self._lock:
            if self._web_socket and self._web_socket.sock and self._web_socket.sock.connected:
                self._web_socket.close()
                _PolicyReceiver._logger.info("Stopped receiving notifications from PDP")

    def _on_pdp_message(self, _, message):
        """received the notification from PDP"""
        try:
            _PolicyReceiver._logger.info("Received notification message: %s", message)
            if not message:
                return
            message = json.loads(message)

            if not message or not isinstance(message, dict):
                _PolicyReceiver._logger.warning("unexpected message from PDP: %s",
                                                json.dumps(message))
                return

            policies_updated = [
                {POLICY_NAME: policy.get(POLICY_NAME),
                 POLICY_VERSION: policy.get(POLICY_VER),
                 MATCHING_CONDITIONS: policy.get(POLICY_MATCHES, {})}
                for policy in message.get(LOADED_POLICIES, [])
            ]

            policies_removed = [
                {POLICY_NAME: removed_policy.get(POLICY_NAME),
                 POLICY_VERSION: removed_policy.get(POLICY_VER)}
                for removed_policy in message.get(REMOVED_POLICIES, [])
            ]

            if not policies_updated and not policies_removed:
                _PolicyReceiver._logger.info("no policy updated or removed")
                return

            self._policy_updater.policy_update(policies_updated, policies_removed)
        except Exception as ex:
            error_msg = "crash {} {} at {}: {}".format(type(ex).__name__, str(ex),
                                                       "on_pdp_message", json.dumps(message))

            _PolicyReceiver._logger.exception(error_msg)

    def _on_ws_error(self, _, error):
        """report an error"""
        _PolicyReceiver._logger.error("policy-notification error: %s", error)

    def _on_ws_close(self, _):
        """restart web-socket on close"""
        _PolicyReceiver._logger.info("lost connection to PDP - restarting...")

    def shutdown(self, audit):
        """Shutdown the policy-receiver"""
        _PolicyReceiver._logger.info("shutdown policy-receiver")
        with self._lock:
            self._keep_running = False

        self._stop_notifications()

        if self.is_alive():
            self.join()

        self._policy_updater.shutdown(audit)

    def catch_up(self, audit):
        """need to bring the latest policies to DCAE-Controller"""
        self._policy_updater.catch_up(audit)

class PolicyReceiver(object):
    """policy-receiver - static singleton wrapper"""
    _policy_receiver = None

    @staticmethod
    def shutdown(audit):
        """Shutdown the notification-handler"""
        PolicyReceiver._policy_receiver.shutdown(audit)

    @staticmethod
    def catch_up(audit):
        """bring the latest policies from policy-engine"""
        PolicyReceiver._policy_receiver.catch_up(audit)

    @staticmethod
    def run(audit):
        """Using policy-engine client to talk to policy engine"""
        PolicyReceiver._policy_receiver = _PolicyReceiver()
        PolicyReceiver._policy_receiver.start()

        PolicyReceiver.catch_up(audit)
