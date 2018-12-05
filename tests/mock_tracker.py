# ============LICENSE_START=======================================================
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
"""record all the messages going outside policy-handler during testing"""

import copy
import json

from policyhandler.onap.audit import REQUEST_X_ECOMP_REQUESTID
from policyhandler.policy_utils import Utils

from .mock_expected import HISTORY_EXPECTED
from .mock_settings import Settings

RESPONSE = "res"

class _MockHttpRequestInResponse(object):
    """Mock http request in reponse object"""
    def __init__(self, method, uri, **kwargs):
        self.method = method
        self.uri = uri
        self.params = copy.deepcopy(kwargs.get("params"))
        self.req_json = copy.deepcopy(kwargs.get("json"))
        self.headers = copy.deepcopy(kwargs.get("headers"))

    def to_json(self):
        """create json of the request"""
        return {
            "method": self.method,
            "uri": self.uri,
            "params": self.params,
            "json": self.req_json,
            "headers": self.headers
        }


class MockHttpResponse(object):
    """Mock http response based on request"""
    def __init__(self, method, uri, res_json, **kwargs):
        """create response based on request"""
        self.request = _MockHttpRequestInResponse(method, uri, **kwargs)

        self.status_code = kwargs.get("status_code", 200)
        self.res = copy.deepcopy(res_json)
        self.text = json.dumps(self.res)

        self._track()

    def json(self):
        """returns json of response"""
        return self.res

    def raise_for_status(self):
        """ignoring"""
        pass

    def to_json(self):
        """create json of the message"""
        return {
            "request": self.request.to_json(),
            "status_code": self.status_code,
            RESPONSE: self.res
        }

    def _track(self):
        """append the message to tracker's history"""
        Tracker.track(self.to_json())

    def __str__(self):
        """stringify for logging"""
        return json.dumps(self.to_json(), sort_keys=True)


class Tracker(object):
    """record all the messages going outside policy-handler during testing"""
    test_name = None
    messages = []

    @staticmethod
    def reset(test_name):
        """remove all the messages from history"""
        Tracker.test_name = test_name
        Tracker.messages.clear()

    @staticmethod
    def track(message):
        """append the tracked message to the history"""
        message = copy.deepcopy(message)
        Tracker.messages.append(message)
        if Settings.logger:
            Settings.logger.info("tracked_message: %s", json.dumps(message, sort_keys=True))

    @staticmethod
    def to_string():
        """stringify message history for logging"""
        return json.dumps(Tracker.messages, sort_keys=True)

    @staticmethod
    def _hide_volatiles(obj):
        """hides the volatile field values"""
        if not isinstance(obj, dict):
            return obj

        for key, value in obj.items():
            if key in [REQUEST_X_ECOMP_REQUESTID, RESPONSE]:
                obj[key] = "*"
            elif isinstance(value, dict):
                obj[key] = Tracker._hide_volatiles(value)

        return obj

    @staticmethod
    def validate():
        """validate that the message history is as expected"""
        Settings.logger.info("Tracker.validate(%s)", Tracker.test_name)
        messages = [Tracker._hide_volatiles(copy.deepcopy(message))
                    for message in Tracker.messages]
        expected = HISTORY_EXPECTED.get(Tracker.test_name, [])

        Settings.logger.info("messages: %s", json.dumps(messages, sort_keys=True))
        Settings.logger.info("expected: %s", json.dumps(expected, sort_keys=True))
        assert Utils.are_the_same(messages, expected)

        Settings.logger.info("history valid for Tracker.validate(%s)", Tracker.test_name)
