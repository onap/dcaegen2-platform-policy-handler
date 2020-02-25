# ============LICENSE_START=======================================================
# Copyright (c) 2019-2020 AT&T Intellectual Property. All rights reserved.
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
standard pytest file that contains the shared fixtures
https://docs.pytest.org/en/latest/fixture.html
"""

import time

import pytest
from policyhandler import pdp_client
from policyhandler.deploy_handler import DeployHandler
from policyhandler.onap.audit import Audit
from policyhandler.pdp_api.dmaap_mr import DmaapMr
from policyhandler.utils import Utils

from ..mock_tracker import MockHttpResponse

_LOGGER = Utils.get_logger(__file__)

@pytest.fixture()
def fix_pdp_post(monkeypatch):
    """monkeyed request /decision/v1 to PDP"""
    def monkeyed_policy_rest_post(uri, json=None, **kwargs):
        """monkeypatch for the POST to policy-engine"""
        return MockHttpResponse("post", uri, json=json, **kwargs)

    _LOGGER.info("setup fix_pdp_post")
    pdp_client.PolicyRest._lazy_inited = False
    pdp_client.PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.pdp_client.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post
    _LOGGER.info("teardown fix_pdp_post")

@pytest.fixture()
def fix_deploy_handler(monkeypatch):
    """monkeyed requests to deployment-handler"""
    def monkeyed_deploy_handler_put(uri, **kwargs):
        """monkeypatch for policy-update request.put to deploy_handler"""
        return MockHttpResponse("put", uri, **kwargs)

    def monkeyed_deploy_handler_get(uri, **kwargs):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MockHttpResponse("get", uri, **kwargs)

    _LOGGER.info("setup fix_deploy_handler")
    audit = None
    if DeployHandler._lazy_inited is False:
        audit = Audit(req_message="fix_deploy_handler")
        DeployHandler._lazy_init(audit)

    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.put',
                        monkeyed_deploy_handler_put)
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.get',
                        monkeyed_deploy_handler_get)

    yield fix_deploy_handler
    if audit:
        audit.audit_done("teardown")
    _LOGGER.info("teardown fix_deploy_handler")

@pytest.fixture()
def fix_dmaap_mr(monkeypatch):
    """monkeyed requests to dmaap_mr"""
    def monkeyed_dmaap_mr_get(uri, **kwargs):
        """monkeypatch policy-update request.get to dmaap_mr"""
        if kwargs.get("params"):
            _LOGGER.info("--- fix_dmaap_mr --- sleeping 3 secs...")
            time.sleep(3)
        else:
            _LOGGER.info("--- fix_dmaap_mr --- sleeping 0.5 secs...")
            time.sleep(0.5)
        _LOGGER.info("--- fix_dmaap_mr --- send back the response")
        return MockHttpResponse("get", uri, **kwargs)

    _LOGGER.info("setup fix_dmaap_mr")
    audit = Audit(req_message="fix_dmaap_mr")
    DmaapMr._lazy_inited = False
    DmaapMr._lazy_init(audit)

    monkeypatch.setattr('policyhandler.pdp_api.dmaap_mr.DmaapMr._requests_session.get',
                        monkeyed_dmaap_mr_get)

    yield fix_dmaap_mr
    audit.audit_done("teardown")
    _LOGGER.info("teardown fix_dmaap_mr")
