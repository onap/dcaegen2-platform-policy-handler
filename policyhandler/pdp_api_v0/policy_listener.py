# ================================================================================
# Copyright (c) 2018-2020 AT&T Intellectual Property. All rights reserved.
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
policy_listener communicates with policy-engine
thru web-socket to receive push notifications
on updates and removal of policies.

on receiving the policy-notifications, the policy-receiver
passes the notifications to policy-updater
"""

import copy
import json
import os
import ssl
import time
import urllib.parse
from datetime import datetime
from threading import Lock, Thread

import websocket

from ..config import Config, Settings
from ..onap.audit import Audit
from ..utils import Utils
from .pdp_consts import MATCHING_CONDITIONS, POLICY_NAME, POLICY_VERSION

LOADED_POLICIES = 'loadedPolicies'
REMOVED_POLICIES = 'removedPolicies'
POLICY_VER = 'versionNo'
POLICY_MATCHES = 'matches'

_LOGGER = Utils.get_logger(__file__)

class PolicyListener(Thread):
    """web-socket to PolicyEngine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    WS_STARTED = "started"
    WS_START_COUNT = "start_count"
    WS_CLOSE_COUNT = "close_count"
    WS_ERROR_COUNT = "error_count"
    WS_PONG_COUNT = "pong_count"
    WS_MESSAGE_COUNT = "message_count"
    WS_MESSAGE_TIMESTAMP = "message_timestamp"
    WS_STATUS = "status"
    WS_PING_INTERVAL_DEFAULT = 30
    WEB_SOCKET_HEALTH = "web_socket_health"

    def __init__(self, audit, policy_updater):
        """web-socket inside the thread to receive policy notifications from PolicyEngine"""
        Thread.__init__(self, name="policy_receiver", daemon=True)

        self._policy_updater = policy_updater
        self._lock = Lock()
        self._keep_running = True
        self._settings = Settings(Config.FIELD_POLICY_ENGINE)

        self._sleep_before_restarting = 5
        self._web_socket_url = None
        self._web_socket_sslopt = None
        self._tls_wss_ca_mode = None
        self._web_socket = None
        self._ws_ping_interval_in_secs = PolicyListener.WS_PING_INTERVAL_DEFAULT
        self._web_socket_health = {
            PolicyListener.WS_START_COUNT: 0,
            PolicyListener.WS_CLOSE_COUNT: 0,
            PolicyListener.WS_ERROR_COUNT: 0,
            PolicyListener.WS_PONG_COUNT: 0,
            PolicyListener.WS_MESSAGE_COUNT: 0,
            PolicyListener.WS_STATUS: "created"
        }

        Audit.register_item_health(PolicyListener.WEB_SOCKET_HEALTH, self._get_health)
        self.reconfigure(audit)

    def reconfigure(self, audit):
        """configure and reconfigure the web-socket"""
        with self._lock:
            _LOGGER.info(audit.info("web_socket_health {}".format(
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
                self._ws_ping_interval_in_secs = PolicyListener.WS_PING_INTERVAL_DEFAULT

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
                _LOGGER.info(audit.info("not {}".format(log_changed)))
                self._settings.commit_change()
                return False

            _LOGGER.info(audit.info(log_changed))
            self._settings.commit_change()

        self._stop_notifications()
        return True

    def run(self):
        """listen on web-socket and pass the policy notifications to policy-updater"""
        _LOGGER.info("starting policy_receiver...")
        websocket.enableTrace(True)
        restarting = False
        while True:
            if not self._get_keep_running():
                break

            self._stop_notifications()

            if restarting:
                with self._lock:
                    sleep_before_restarting = self._sleep_before_restarting
                _LOGGER.info(
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

            _LOGGER.info(
                "connecting to policy-notifications at %s with sslopt(%s) tls_wss_ca_mode(%s)"
                " ws_ping_interval_in_secs(%s)",
                web_socket_url, json.dumps(sslopt), tls_wss_ca_mode, ws_ping_interval_in_secs)

            self._web_socket = websocket.WebSocketApp(
                web_socket_url,
                on_open=self._on_ws_open,
                on_message=self._on_pdp_message,
                on_close=self._on_ws_close,
                on_error=self._on_ws_error,
                on_pong=self._on_ws_pong
            )

            _LOGGER.info("waiting for policy-notifications...")
            self._web_socket.run_forever(sslopt=sslopt, ping_interval=ws_ping_interval_in_secs)
            restarting = True

        Audit.register_item_health(PolicyListener.WEB_SOCKET_HEALTH)
        _LOGGER.info("exit policy-receiver")

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
                _LOGGER.info("stopped receiving notifications from PDP")

    def _on_pdp_message(self, *args):
        """received the notification from PDP"""
        self._web_socket_health[PolicyListener.WS_MESSAGE_COUNT] += 1
        self._web_socket_health[PolicyListener.WS_MESSAGE_TIMESTAMP] = str(datetime.utcnow())
        try:
            message = args and args[-1]
            _LOGGER.info("Received notification message: %s", message)
            _LOGGER.info("web_socket_health %s", json.dumps(self._get_health(), sort_keys=True))
            if not message:
                return
            message = json.loads(message)

            if not message or not isinstance(message, dict):
                _LOGGER.warning("unexpected message from PDP: %s", json.dumps(message))
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
                _LOGGER.info("no policy updated or removed")
                return

            self._policy_updater.policy_update(policies_updated, policies_removed)
        except Exception as ex:
            error_msg = "crash {} {} at {}: {}".format(type(ex).__name__, str(ex),
                                                       "on_pdp_message", json.dumps(message))

            _LOGGER.exception(error_msg)

    def _on_ws_error(self, error):
        """report an error"""
        _LOGGER.exception("policy-notification error %s", str(error))
        self._sleep_before_restarting = 60 if isinstance(error, ssl.SSLError) else 5

        self._web_socket_health[PolicyListener.WS_STATUS] = "error"
        self._web_socket_health[PolicyListener.WS_ERROR_COUNT] += 1
        self._web_socket_health["last_error"] = {
            "error": str(error), "timestamp": str(datetime.utcnow())
        }
        _LOGGER.info("web_socket_health %s", json.dumps(self._get_health(), sort_keys=True))

    def _on_ws_close(self, code, reason):
        """restart web-socket on close"""
        self._web_socket_health["last_closed"] = str(datetime.utcnow())
        self._web_socket_health[PolicyListener.WS_STATUS] = "closed"
        self._web_socket_health[PolicyListener.WS_CLOSE_COUNT] += 1
        _LOGGER.info(
            "lost connection(%s, %s) to PDP web_socket_health %s",
            code, reason, json.dumps(self._get_health(), sort_keys=True))

    def _on_ws_open(self):
        """started web-socket"""
        self._web_socket_health[PolicyListener.WS_STATUS] = PolicyListener.WS_STARTED
        self._web_socket_health[PolicyListener.WS_START_COUNT] += 1
        self._web_socket_health[PolicyListener.WS_STARTED] = datetime.utcnow()
        _LOGGER.info("opened connection to PDP web_socket_health %s",
                     json.dumps(self._get_health(), sort_keys=True))

    def _on_ws_pong(self, pong):
        """pong = response to pinging the server of the web-socket"""
        self._web_socket_health[PolicyListener.WS_PONG_COUNT] += 1
        _LOGGER.info(
            "pong(%s) from connection to PDP web_socket_health %s",
            pong, json.dumps(self._get_health(), sort_keys=True))

    def _get_health(self):
        """returns the healthcheck of the web-socket as json"""
        web_socket_health = copy.deepcopy(self._web_socket_health)
        web_socket_health[Config.WS_PING_INTERVAL_IN_SECS] = self._ws_ping_interval_in_secs
        started = web_socket_health.get(PolicyListener.WS_STARTED)
        if started:
            web_socket_health[PolicyListener.WS_STARTED] = str(started)
            web_socket_health["uptime"] = str(datetime.utcnow() - started)
        return web_socket_health


    def shutdown(self, audit):
        """Shutdown the policy_listener"""
        _LOGGER.info(audit.info("shutdown policy_listener"))
        with self._lock:
            self._keep_running = False

        self._stop_notifications()

        if self.is_alive():
            self.join()
