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
"""record all the messages going outside policy-handler during testing"""

import copy
import json

from policyhandler.config import Config
from policyhandler.onap.audit import (REQUEST_X_ECOMP_REQUESTID,
                                      REQUEST_X_ONAP_REQUESTID)
from policyhandler.utils import Utils

REQUEST = "request"
STATUS_CODE = "status_code"
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
    def __init__(self, method, uri, res_json=None, **kwargs):
        """create response based on request"""
        self.request = _MockHttpRequestInResponse(method, uri, **kwargs)
        self.headers = {}

        self.status_code, self.res = Tracker.get_response(self.request.to_json())
        if self.status_code is None and res_json:
            self.status_code = kwargs.get(STATUS_CODE, 200)
        if res_json:
            self.res = copy.deepcopy(res_json)
        if self.status_code is None:
            self.status_code = 500
        self.text = json.dumps(self.res)

        _LOGGER.info("MockHttpResponse: %s", self)

    def json(self):
        """returns json of response"""
        return self.res

    def raise_for_status(self):
        """ignoring"""
        pass

    def to_json(self):
        """create json of the message"""
        return {
            REQUEST: self.request.to_json(),
            STATUS_CODE: self.status_code,
            RESPONSE: self.res
        }

    def __str__(self):
        """stringify for logging"""
        return json.dumps(self.to_json(), sort_keys=True)


class Tracker(object):
    """record all the messages going outside policy-handler during testing"""
    test_name = None
    test_names = []

    requests = []
    expected = []

    validated_tests = {}
    valid_tests = {}

    main_history = {}
    pdp_api_v0_history = {}

    @staticmethod
    def _init():
        """load expected data from json files"""
        try:
            with open("tests/main/expectations.json", 'r') as expectations:
                Tracker.main_history = json.load(expectations)
        except Exception:
            Tracker.main_history = {}

        try:
            with open("tests/pdp_api_v0/expectations.json", 'r') as expectations:
                Tracker.pdp_api_v0_history = json.load(expectations)
        except Exception:
            Tracker.pdp_api_v0_history = {}

    @staticmethod
    def reset(test_name=None):
        """remove all the messages from history"""
        if not Tracker.test_names:
            Tracker._init()

        Tracker.test_name = test_name
        Tracker.requests.clear()
        Tracker.test_names.append(test_name)

        if Config.is_pdp_api_default():
            Tracker.expected = Tracker.main_history.get(Tracker.test_name, [])
        else:
            Tracker.expected = Tracker.pdp_api_v0_history.get(Tracker.test_name, [])


    @staticmethod
    def get_response(request):
        """
        track the request to the history of requests
        and return the response with the status_code from the expected history queue
        """
        request_idx = len(Tracker.requests)
        request = copy.deepcopy(request)
        Tracker.requests.append(request)

        if request_idx < len(Tracker.expected):
            expected = Tracker.expected[request_idx] or {}
            masked_request = Tracker._hide_volatiles(copy.deepcopy(request))
            expected_request = Tracker._hide_volatiles(copy.deepcopy(expected.get(REQUEST)))
            if Utils.are_the_same(masked_request, expected_request):
                _LOGGER.info("as expected[%s]: %s", request_idx,
                             json.dumps(expected, sort_keys=True))
                return expected.get(STATUS_CODE), expected.get(RESPONSE)

            unexpected_request = {"unit-test-tracker": {
                "request_idx": request_idx,
                "received_request": copy.deepcopy(request),
                "expected": copy.deepcopy(expected.get(REQUEST))
            }}
            _LOGGER.error("unexpected_request[%s]: %s", request_idx,
                          json.dumps(unexpected_request, sort_keys=True))
            return None, unexpected_request

        unexpected_request = {"unit-test-tracker":{
            "request_idx": request_idx, "out-of-range": len(Tracker.expected),
            "received_request": copy.deepcopy(request)
        }}
        _LOGGER.error("unexpected_request[%s]: %s", request_idx,
                      json.dumps(unexpected_request, sort_keys=True))
        return None, unexpected_request

    @staticmethod
    def to_string():
        """stringify message history for logging"""
        return json.dumps(Tracker.requests, sort_keys=True)

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

        _LOGGER.info("not tracked test_names listed in main.expectations")

        for test_name in Tracker.main_history:
            if test_name not in Tracker.test_names:
                _LOGGER.info("untracked: %s", test_name)

        _LOGGER.info("not tracked test_names listed in pdp_api_v0.expectations")
        for test_name in Tracker.pdp_api_v0_history:
            if test_name not in Tracker.test_names:
                _LOGGER.info("untracked: %s", test_name)

    @staticmethod
    def _hide_volatiles(obj):
        """hides the volatile field values"""
        if not isinstance(obj, dict):
            return obj

        for key, value in obj.items():
            if key in [REQUEST_X_ONAP_REQUESTID, REQUEST_X_ECOMP_REQUESTID, RESPONSE, PEP_INSTANCE]:
                obj[key] = "*"
            elif isinstance(value, dict):
                obj[key] = Tracker._hide_volatiles(value)

        return obj

    @staticmethod
    def validate():
        """validate that the message history is as expected"""
        _LOGGER.info("Tracker.validate(%s)", Tracker.test_name)
        Tracker.validated_tests[Tracker.test_name] = True
        requests = [Tracker._hide_volatiles(copy.deepcopy(request))
                    for request in Tracker.requests]
        expected_reqs = [Tracker._hide_volatiles(copy.deepcopy(expected.get(REQUEST)))
                         for expected in Tracker.expected]

        _LOGGER.info("requests: %s", json.dumps(requests, sort_keys=True))
        _LOGGER.info("expected: %s", json.dumps(expected_reqs, sort_keys=True))
        assert Utils.are_the_same(requests, expected_reqs)

        _LOGGER.info("history valid for Tracker.validate(%s)", Tracker.test_name)
        Tracker.valid_tests[Tracker.test_name] = True
