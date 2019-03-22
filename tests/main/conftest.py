# ============LICENSE_START=======================================================
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
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
startdard pytest file that contains the shared fixtures
https://docs.pytest.org/en/latest/fixture.html
"""

import pytest

from policyhandler import pdp_client
from policyhandler.pdp_api.pdp_consts import PDP_POLICY_ID, PDP_REQ_RESOURCE
from policyhandler.utils import Utils

from ..mock_tracker import MockHttpResponse
from .mock_policy_engine import MockPolicyEngine

_LOGGER = Utils.get_logger(__file__)

@pytest.fixture(scope="session", autouse=True)
def _auto_setup_policy_engine():
    """initialize the mock-policy-engine per the whole test session"""
    _LOGGER.info("create _auto_setup_policy_engine")
    MockPolicyEngine.init()
    yield _auto_setup_policy_engine
    _LOGGER.info("teardown _auto_setup_policy_engine")

@pytest.fixture()
def fix_pdp_post(monkeypatch):
    """monkeyed request /decision/v1 to PDP"""
    def monkeyed_policy_rest_post(uri, json=None, **kwargs):
        """monkeypatch for the POST to policy-engine"""
        policy_ids = json.get(PDP_REQ_RESOURCE, {}).get(PDP_POLICY_ID)
        policy_id = policy_ids and policy_ids[0]
        res_json = MockPolicyEngine.get_policy(policy_id)
        return MockHttpResponse("post", uri, res_json, json=json, **kwargs)

    _LOGGER.info("setup fix_pdp_post")
    pdp_client.PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.pdp_client.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post
    _LOGGER.info("teardown fix_pdp_post")
