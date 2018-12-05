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

import copy
import json
import logging
import ssl
import time
import urllib.parse
from datetime import datetime
from threading import Lock, Thread

import websocket

from .config import Config, Settings
from .onap.audit import Audit
from .policy_consts import MATCHING_CONDITIONS, POLICY_NAME, POLICY_VERSION
from .policy_updater import PolicyUpdater
from .policy_utils import Utils

LOADED_POLICIES = 'loadedPolicies'
REMOVED_POLICIES = 'removedPolicies'
POLICY_VER = 'versionNo'
POLICY_MATCHES = 'matches'

class _PolicyReceiver(Thread):
    """web-socket to PolicyEngine"""
    _logger = logging.getLogger("policy_handler.policy_receiver")
    WS_STARTED = "started"
    WS_START_COUNT = "start_count"
    WS_CLOSE_COUNT = "close_count"
    WS_ERROR_COUNT = "error_count"
    WS_PONG_COUNT = "pong_count"
    WS_MESSAGE_COUNT = "message_count"
    WS_MESSAGE_TIMESTAMP = "message_timestamp"
    WS_STATUS = "status"
    WS_PING_INTERVAL_DEFAULT = 180

    def __init__(self, audit):
        """web-socket inside the thread to receive policy notifications from PolicyEngine"""
        Thread.__init__(self, name="policy_receiver", daemon=True)

        self._lock = Lock()
        self._keep_running = True
        self._settings = Settings(Config.FIELD_POLICY_ENGINE)

        self._sleep_before_restarting = 5
        self._web_socket_url = None
        self._web_socket_sslopt = None
        self._tls_wss_ca_mode = None
        self._web_socket = None
        self._ws_ping_interval_in_secs = _PolicyReceiver.WS_PING_INTERVAL_DEFAULT
        self._web_socket_health = {
            _PolicyReceiver.WS_START_COUNT: 0,
            _PolicyReceiver.WS_CLOSE_COUNT: 0,
            _PolicyReceiver.WS_ERROR_COUNT: 0,
            _PolicyReceiver.WS_PONG_COUNT: 0,
            _PolicyReceiver.WS_MESSAGE_COUNT: 0,
            _PolicyReceiver.WS_STATUS: "created"
        }

        Audit.register_item_health("web_socket_health", self._get_health)
        self._reconfigure(audit)

        self._policy_updater = PolicyUpdater(self._reconfigure)

    def _reconfigure(self, audit):
        """configure and reconfigure the web-socket"""
        with self._lock:
            _PolicyReceiver._logger.info(audit.info("web_socket_health {}".format(
                json.dumps(self._get_health(), sort_keys=True))))
            self._sleep_before_restarting = 5
            self._settings.set_config(Config.discovered_config)
            changed, config = self._settings.get_by_key(Config.FIELD_POLICY_ENGINE)

            if not changed:
                self._settings.commit_change()
                return False

            prev_web_socket_url = self._web_socket_url
            prev_web_socket_sslopt = self._web_socket_sslopt
            prev_ws_ping_interval_in_secs = self._ws_ping_interval_in_secs

            self._web_socket_sslopt = None

            resturl = urllib.parse.urljoin(config.get("url", "").lower().rstrip("/") + "/",
                                           config.get("path_notifications", "/pdp/notifications"))

            self._tls_wss_ca_mode = config.get(Config.TLS_WSS_CA_MODE)

            self._ws_ping_interval_in_secs = config.get(Config.WS_PING_INTERVAL_IN_SECS)
            if not self._ws_ping_interval_in_secs or self._ws_ping_interval_in_secs < 60:
                self._ws_ping_interval_in_secs = _PolicyReceiver.WS_PING_INTERVAL_DEFAULT

            if resturl.startswith("https:"):
                self._web_socket_url = resturl.replace("https:", "wss:")

                verify = Config.get_tls_verify(self._tls_wss_ca_mode)
                if verify is False:
                    self._web_socket_sslopt = {'cert_reqs': ssl.CERT_NONE}
                elif verify is True:
                    pass
                else:
                    self._web_socket_sslopt = {'ca_certs': verify}

            else:
                self._web_socket_url = resturl.replace("http:", "ws:")

            log_changed = (
                "changed web_socket_url(%s) or tls_wss_ca_mode(%s)"
                " or ws_ping_interval_in_secs(%s): %s" %
                (self._web_socket_url, self._tls_wss_ca_mode, self._ws_ping_interval_in_secs,
                 self._settings))
            if (self._web_socket_url == prev_web_socket_url
                    and Utils.are_the_same(prev_web_socket_sslopt, self._web_socket_sslopt)
                    and prev_ws_ping_interval_in_secs == self._ws_ping_interval_in_secs):
                _PolicyReceiver._logger.info(audit.info("not {}".format(log_changed)))
                self._settings.commit_change()
                return False

            _PolicyReceiver._logger.info(audit.info(log_changed))
            self._settings.commit_change()

        self._stop_notifications()
        return True

    def run(self):
        """listen on web-socket and pass the policy notifications to policy-updater"""
        self._policy_updater.start()
        _PolicyReceiver._logger.info("starting policy_receiver...")
        websocket.enableTrace(True)
        restarting = False
        while True:
            if not self._get_keep_running():
                break

            self._stop_notifications()

            if restarting:
                with self._lock:
                    sleep_before_restarting = self._sleep_before_restarting
                _PolicyReceiver._logger.info(
                    "going to sleep for %s secs before restarting policy-notifications",
                    sleep_before_restarting)

                time.sleep(sleep_before_restarting)
                if not self._get_keep_running():
                    break

            with self._lock:
                web_socket_url = self._web_socket_url
                sslopt = copy.deepcopy(self._web_socket_sslopt)
                tls_wss_ca_mode = self._tls_wss_ca_mode
                ws_ping_interval_in_secs = self._ws_ping_interval_in_secs

            _PolicyReceiver._logger.info(
                "connecting to policy-notifications at %s with sslopt(%s) tls_wss_ca_mode(%s)",
                web_socket_url, json.dumps(sslopt), tls_wss_ca_mode)

            self._web_socket = websocket.WebSocketApp(
                web_socket_url,
                on_open=self._on_ws_open,
                on_message=self._on_pdp_message,
                on_close=self._on_ws_close,
                on_error=self._on_ws_error,
                on_pong=self._on_ws_pong
            )

            _PolicyReceiver._logger.info("waiting for policy-notifications...")
            self._web_socket.run_forever(sslopt=sslopt, ping_interval=ws_ping_interval_in_secs)
            restarting = True

        _PolicyReceiver._logger.info("exit policy-receiver")

    def _get_keep_running(self):
        """thread-safe check whether to continue running"""
        with self._lock:
            keep_running = self._keep_running
        return keep_running

    def _stop_notifications(self):
        """close the web-socket == stops the notification service if running."""
        with self._lock:
            if self._web_socket and self._web_socket.sock and self._web_socket.sock.connected:
                self._web_socket.close()
                _PolicyReceiver._logger.info("Stopped receiving notifications from PDP")

    def _on_pdp_message(self, *args):
        """received the notification from PDP"""
        self._web_socket_health[_PolicyReceiver.WS_MESSAGE_COUNT] += 1
        self._web_socket_health[_PolicyReceiver.WS_MESSAGE_TIMESTAMP] = str(datetime.utcnow())
        try:
            message = args and args[-1]
            _PolicyReceiver._logger.info("Received notification message: %s", message)
            _PolicyReceiver._logger.info("web_socket_health %s",
                                         json.dumps(self._get_health(), sort_keys=True))
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

    def _on_ws_error(self, error):
        """report an error"""
        _PolicyReceiver._logger.exception("policy-notification error %s", str(error))
        self._sleep_before_restarting = 60 if isinstance(error, ssl.SSLError) else 5

        self._web_socket_health[_PolicyReceiver.WS_STATUS] = "error"
        self._web_socket_health[_PolicyReceiver.WS_ERROR_COUNT] += 1
        self._web_socket_health["last_error"] = {
            "error": str(error), "timestamp": str(datetime.utcnow())
        }
        _PolicyReceiver._logger.info("web_socket_health %s",
                                     json.dumps(self._get_health(), sort_keys=True))

    def _on_ws_close(self, code, reason):
        """restart web-socket on close"""
        self._web_socket_health["last_closed"] = str(datetime.utcnow())
        self._web_socket_health[_PolicyReceiver.WS_STATUS] = "closed"
        self._web_socket_health[_PolicyReceiver.WS_CLOSE_COUNT] += 1
        _PolicyReceiver._logger.info(
            "lost connection(%s, %s) to PDP - restarting... web_socket_health %s",
            code, reason, json.dumps(self._get_health(), sort_keys=True))

    def _on_ws_open(self):
        """started web-socket"""
        self._web_socket_health[_PolicyReceiver.WS_STATUS] = _PolicyReceiver.WS_STARTED
        self._web_socket_health[_PolicyReceiver.WS_START_COUNT] += 1
        self._web_socket_health[_PolicyReceiver.WS_STARTED] = datetime.utcnow()
        _PolicyReceiver._logger.info("opened connection to PDP web_socket_health %s",
                                     json.dumps(self._get_health(), sort_keys=True))

    def _on_ws_pong(self, pong):
        """pong = response to pinging the server of the web-socket"""
        self._web_socket_health[_PolicyReceiver.WS_PONG_COUNT] += 1
        _PolicyReceiver._logger.info(
            "pong(%s) from connection to PDP web_socket_health %s",
            pong, json.dumps(self._get_health(), sort_keys=True))

    def _get_health(self):
        """returns the healthcheck of the web-socket as json"""
        web_socket_health = copy.deepcopy(self._web_socket_health)
        started = web_socket_health.get(_PolicyReceiver.WS_STARTED)
        if started:
            web_socket_health[_PolicyReceiver.WS_STARTED] = str(started)
            web_socket_health["uptime"] = str(datetime.utcnow() - started)
        return web_socket_health


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

    def is_running(self):
        """check whether the policy-receiver and policy-updater are running"""
        return self.is_alive() and self._policy_updater.is_alive()

class PolicyReceiver(object):
    """policy-receiver - static singleton wrapper"""
    _policy_receiver = None

    @staticmethod
    def is_running():
        """check whether the policy-receiver runs"""
        return PolicyReceiver._policy_receiver and PolicyReceiver._policy_receiver.is_running()

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
        PolicyReceiver._policy_receiver = _PolicyReceiver(audit)
        PolicyReceiver._policy_receiver.start()

        PolicyReceiver.catch_up(audit)
