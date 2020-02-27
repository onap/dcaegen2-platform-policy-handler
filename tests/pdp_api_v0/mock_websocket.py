# ============LICENSE_START=======================================================
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
"""mocking for the websocket - for testing of policy-engine"""

import json
import time

from policyhandler.pdp_api_v0.pdp_consts import POLICY_NAME
from policyhandler.pdp_api_v0.policy_listener import (LOADED_POLICIES,
                                                      POLICY_VER,
                                                      REMOVED_POLICIES)
from policyhandler.utils import Utils

from .mock_policy_engine import MockPolicyEngine2018

_LOGGER = Utils.get_logger(__file__)

class MockWebSocket(object):
    """Mock websocket"""
    on_message = None

    @staticmethod
    def send_notification(updated_indexes):
        """fake notification through the web-socket"""
        if not MockWebSocket.on_message:
            return
        message = {
            LOADED_POLICIES: [
                {POLICY_NAME: "{0}.{1}.xml".format(
                    MockPolicyEngine2018.get_policy_id(policy_index), policy_index + 1),
                 POLICY_VER: str(policy_index + 1)}
                for policy_index in updated_indexes or []
            ],
            REMOVED_POLICIES : []
        }
        message = json.dumps(message)
        _LOGGER.info("send_notification: %s", message)
        MockWebSocket.on_message(None, message)

    @staticmethod
    def enableTrace(yes_no):
        """ignore"""
        pass

    class MockSocket(object):
        """Mock websocket"""
        def __init__(self):
            self.connected = True

    class WebSocketApp(object):
        """Mocked WebSocketApp"""
        def __init__(self, web_socket_url,
                     on_open=None, on_message=None, on_close=None, on_error=None, on_pong=None):
            self.web_socket_url = web_socket_url
            self.on_open = on_open
            self.on_message = MockWebSocket.on_message = on_message
            self.on_close = on_close
            self.on_error = on_error
            self.on_pong = on_pong
            self.sock = MockWebSocket.MockSocket()
            _LOGGER.info("MockWebSocket for: %s", self.web_socket_url)

        def run_forever(self, sslopt=None, ping_interval=None):
            """forever in the loop"""
            _LOGGER.info("MockWebSocket run_forever with sslopt=%s, ping_interval=%s...",
                         json.dumps(sslopt), ping_interval)
            counter = 0
            while self.sock.connected:
                counter += 1
                _LOGGER.info("MockWebSocket sleep %s...", counter)
                time.sleep(5)
            _LOGGER.info("MockWebSocket exit %s", counter)

        def close(self):
            """close socket"""
            self.sock.connected = False
