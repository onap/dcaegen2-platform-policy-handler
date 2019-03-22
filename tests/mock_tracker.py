# ============LICENSE_START=======================================================
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
# ECOMP is a trademark and service mark of AT&T Intellectual Property.
"""record all the messages going outside policy-handler during testing"""

import copy
import json

from policyhandler.config import Config
from policyhandler.onap.audit import REQUEST_X_ECOMP_REQUESTID
from policyhandler.utils import Utils

RESPONSE = "res"
PEP_INSTANCE = "ONAPInstance"
_LOGGER = Utils.get_logger(__file__)

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
    test_names = []
    validated_tests = {}
    valid_tests = {}

    @staticmethod
    def reset(test_name=None):
        """remove all the messages from history"""
        Tracker.test_name = test_name
        Tracker.messages.clear()
        Tracker.test_names.append(test_name)

    @staticmethod
    def track(message):
        """append the tracked message to the history"""
        message = copy.deepcopy(message)
        Tracker.messages.append(message)
        if _LOGGER:
            _LOGGER.info("tracked_message: %s", json.dumps(message, sort_keys=True))

    @staticmethod
    def to_string():
        """stringify message history for logging"""
        return json.dumps(Tracker.messages, sort_keys=True)

    @staticmethod
    def get_status(test_name=None):
        """get the status of validation"""
        if Tracker.valid_tests.get(test_name):
            return "success"
        if Tracker.validated_tests.get(test_name):
            return "failed"
        if test_name in Tracker.test_names:
            return "covered"
        return "unknown"

    @staticmethod
    def log_all_tests():
        """log the covered and not covered test names"""
        _LOGGER.info("-"*75)
        _LOGGER.info("tracked test_names[%s]", len(Tracker.test_names))
        for idx, test_name in enumerate(Tracker.test_names):
            _LOGGER.info("%s[%s]: %s", Tracker.get_status(test_name), (idx + 1), test_name)

        _LOGGER.info("not tracked test_names listed in main.mock_expected")
        from .main.mock_expected import HISTORY_EXPECTED as main_history
        for test_name in main_history:
            if test_name not in Tracker.test_names:
                _LOGGER.info("untracked: %s", test_name)

        _LOGGER.info("not tracked test_names listed in pdp_api_2018.mock_expected")
        from .pdp_api_2018.mock_expected import HISTORY_EXPECTED as pdp_api_2018_history
        for test_name in pdp_api_2018_history:
            if test_name not in Tracker.test_names:
                _LOGGER.info("untracked: %s", test_name)

    @staticmethod
    def _hide_volatiles(obj):
        """hides the volatile field values"""
        if not isinstance(obj, dict):
            return obj

        for key, value in obj.items():
            if key in [REQUEST_X_ECOMP_REQUESTID, RESPONSE, PEP_INSTANCE]:
                obj[key] = "*"
            elif isinstance(value, dict):
                obj[key] = Tracker._hide_volatiles(value)

        return obj

    @staticmethod
    def validate():
        """validate that the message history is as expected"""
        _LOGGER.info("Tracker.validate(%s)", Tracker.test_name)
        messages = [Tracker._hide_volatiles(copy.deepcopy(message))
                    for message in Tracker.messages]
        Tracker.validated_tests[Tracker.test_name] = True

        if Config.is_pdp_api_default():
            from .main.mock_expected import HISTORY_EXPECTED as main_history
            expected = main_history.get(Tracker.test_name, [])
        else:
            from .pdp_api_2018.mock_expected import HISTORY_EXPECTED as pdp_api_2018_history
            expected = pdp_api_2018_history.get(Tracker.test_name, [])

        _LOGGER.info("messages: %s", json.dumps(messages, sort_keys=True))
        _LOGGER.info("expected: %s", json.dumps(expected, sort_keys=True))
        assert Utils.are_the_same(messages, expected)

        _LOGGER.info("history valid for Tracker.validate(%s)", Tracker.test_name)
        Tracker.valid_tests[Tracker.test_name] = True
