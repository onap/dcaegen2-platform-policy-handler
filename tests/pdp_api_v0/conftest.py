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
"""
startdard pytest file that contains the shared fixtures
https://docs.pytest.org/en/latest/fixture.html
"""

import pytest

from policyhandler import pdp_client
from policyhandler.pdp_api_v0.pdp_consts import POLICY_NAME
from policyhandler.utils import Utils

from ..mock_settings import MockSettings
from ..mock_tracker import MockHttpResponse
from .mock_policy_engine import MockPolicyEngine2018
from .mock_websocket import MockWebSocket

_LOGGER = Utils.get_logger(__file__)

@pytest.fixture(scope="session", autouse=True)
def _auto_setup_policy_engine_pdp_api_v0():
    """initialize the mock-policy-engine_pdp_api_v0 per the whole test session"""
    _LOGGER.info("create _auto_setup_policy_engine_pdp_api_v0")
    MockPolicyEngine2018.init()
    yield _auto_setup_policy_engine_pdp_api_v0
    _LOGGER.info("teardown _auto_setup_policy_engine_pdp_api_v0")


@pytest.fixture(scope="module")
def fix_pdp_api_v0():
    """test on the old (2018) pdp API"""
    _LOGGER.info("setup fix_pdp_api_v0 %s", MockSettings.OLD_PDP_API_VERSION)
    MockSettings.setup_pdp_api(MockSettings.OLD_PDP_API_VERSION)

    yield fix_pdp_api_v0
    MockSettings.setup_pdp_api()
    _LOGGER.info("teardown fix_pdp_api_v0 %s", MockSettings.OLD_PDP_API_VERSION)

@pytest.fixture()
def fix_pdp_post(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    def monkeyed_policy_rest_post(uri, json=None, **kwargs):
        """monkeypatch for the POST to policy-engine"""
        res_json = MockPolicyEngine2018.get_config(json.get(POLICY_NAME))
        return MockHttpResponse("post", uri, res_json, json=json, **kwargs)

    _LOGGER.info("setup fix_pdp_post")
    pdp_client.PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.pdp_client.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post
    _LOGGER.info("teardown fix_pdp_post")

@pytest.fixture()
def fix_pdp_post_big(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    def monkeyed_policy_rest_post(uri, **kwargs):
        """monkeypatch for the POST to policy-engine"""
        res_json = MockPolicyEngine2018.get_configs_all()
        return MockHttpResponse("post", uri, res_json, **kwargs)

    _LOGGER.info("setup fix_pdp_post_big")
    pdp_client.PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.pdp_client.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post_big
    _LOGGER.info("teardown fix_pdp_post_big")


class MockException(Exception):
    """mock exception"""
    pass

@pytest.fixture()
def fix_pdp_post_boom(monkeypatch):
    """monkeyed request /getConfig to PDP - exception"""
    def monkeyed_policy_rest_post_boom(uri, **_):
        """monkeypatch for the POST to policy-engine"""
        raise MockException("fix_pdp_post_boom {}".format(uri))

    _LOGGER.info("setup fix_pdp_post_boom")
    pdp_client.PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.pdp_client.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post_boom)
    yield fix_pdp_post_boom
    _LOGGER.info("teardown fix_pdp_post_boom")


@pytest.fixture()
def fix_policy_receiver_websocket(monkeypatch):
    """monkeyed websocket for policy_receiver"""
    _LOGGER.info("setup fix_policy_receiver_websocket")
    monkeypatch.setattr('policyhandler.pdp_api_v0.policy_listener.websocket', MockWebSocket)

    yield fix_policy_receiver_websocket
    _LOGGER.info("teardown fix_policy_receiver_websocket")

class MockBoom(Exception):
    """mock exception"""
    pass

@pytest.fixture()
def fix_select_latest_policies_boom(monkeypatch):
    """monkeyed exception"""
    def monkeyed_boom(*_, **__):
        """monkeypatch for the select_latest_policies"""
        raise MockBoom("fix_select_latest_policies_boom")

    policy_utils_path = 'policyhandler.pdp_api_v0.policy_utils.PolicyUtils'

    _LOGGER.info("setup fix_select_latest_policies_boom at %s", policy_utils_path)

    monkeypatch.setattr('{}.select_latest_policies'.format(policy_utils_path), monkeyed_boom)
    monkeypatch.setattr('{}.select_latest_policy'.format(policy_utils_path), monkeyed_boom)
    monkeypatch.setattr('{}.extract_policy_id'.format(policy_utils_path), monkeyed_boom)

    yield fix_select_latest_policies_boom
    _LOGGER.info("teardown fix_select_latest_policies_boom at %s", policy_utils_path)
