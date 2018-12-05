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
"""
startdard pytest file that contains the shared fixtures
https://docs.pytest.org/en/latest/fixture.html
"""
import base64
import copy
import json

import pytest

from policyhandler.config import Config
from policyhandler.deploy_handler import DeployHandler
from policyhandler.discovery import DiscoveryClient
from policyhandler.onap.audit import Audit
from policyhandler.policy_consts import CATCH_UP, POLICY_NAME, TARGET_ENTITY
from policyhandler.policy_receiver import PolicyReceiver
from policyhandler.policy_rest import PolicyRest

from .mock_deploy_handler import MockDeploymentHandler
from .mock_policy_engine import MockPolicyEngine
from .mock_settings import Settings
from .mock_tracker import MockHttpResponse, Tracker
from .mock_websocket import MockWebSocket


@pytest.fixture(autouse=True)
def _auto_test_cycle(request):
    """log all the test starts and ends"""
    if request.cls:
        test_name = "%s::%s::%s" % (request.module.__name__,
                                    request.cls.__name__,
                                    request.function.__name__)
    else:
        test_name = "%s::%s" % (request.module.__name__, request.function.__name__)

    Tracker.reset(test_name)
    if Settings.logger:
        Settings.logger.info(">>>>>>> start %s", test_name)
    yield _auto_test_cycle
    if Settings.logger:
        Settings.logger.info(">>>>>>> tracked messages: %s", Tracker.to_string())
        Settings.logger.info(">>>>>>> ended %s", test_name)


@pytest.fixture(scope="session", autouse=True)
def _auto_setup_policy_engine():
    """initialize the mock-policy-engine per the whole test session"""
    Settings.init()

    Settings.logger.info("create _auto_setup_policy_engine")
    MockPolicyEngine.init()
    yield _auto_setup_policy_engine
    Settings.logger.info("teardown _auto_setup_policy_engine")


@pytest.fixture()
def fix_pdp_post(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    def monkeyed_policy_rest_post(uri, json=None, **kwargs):
        """monkeypatch for the POST to policy-engine"""
        res_json = MockPolicyEngine.get_config(json.get(POLICY_NAME))
        return MockHttpResponse("post", uri, res_json, json=json, **kwargs)

    Settings.logger.info("setup fix_pdp_post")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post
    Settings.logger.info("teardown fix_pdp_post")

@pytest.fixture()
def fix_deploy_handler(monkeypatch):
    """monkeyed requests to deployment-handler"""
    def monkeyed_deploy_handler_put(uri, **kwargs):
        """monkeypatch for policy-update request.put to deploy_handler"""
        return MockHttpResponse("put", uri, MockDeploymentHandler.default_response(),
                                **kwargs)

    def monkeyed_deploy_handler_get(uri, **kwargs):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MockHttpResponse("get", uri, MockDeploymentHandler.get_deployed_policies(),
                                **kwargs)

    Settings.logger.info("setup fix_deploy_handler")
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
    Settings.logger.info("teardown fix_deploy_handler")


@pytest.fixture()
def fix_cherrypy_engine_exit(monkeypatch):
    """monkeyed cherrypy.engine.exit()"""
    Settings.logger.info("setup fix_cherrypy_engine_exit")

    def monkeyed_cherrypy_engine_exit():
        """monkeypatch for deploy_handler"""
        Settings.logger.info("cherrypy_engine_exit()")

    monkeypatch.setattr('policyhandler.web_server.cherrypy.engine.exit',
                        monkeyed_cherrypy_engine_exit)
    yield fix_cherrypy_engine_exit
    Settings.logger.info("teardown fix_cherrypy_engine_exit")


@pytest.fixture()
def fix_pdp_post_big(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    def monkeyed_policy_rest_post(uri, **kwargs):
        """monkeypatch for the POST to policy-engine"""
        res_json = MockPolicyEngine.get_configs_all()
        return MockHttpResponse("post", uri, res_json, **kwargs)

    Settings.logger.info("setup fix_pdp_post_big")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post_big
    Settings.logger.info("teardown fix_pdp_post_big")


class MockException(Exception):
    """mock exception"""
    pass


@pytest.fixture()
def fix_pdp_post_boom(monkeypatch):
    """monkeyed request /getConfig to PDP - exception"""
    def monkeyed_policy_rest_post_boom(uri, **_):
        """monkeypatch for the POST to policy-engine"""
        raise MockException("fix_pdp_post_boom {}".format(uri))

    Settings.logger.info("setup fix_pdp_post_boom")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post_boom)
    yield fix_pdp_post_boom
    Settings.logger.info("teardown fix_pdp_post_boom")


@pytest.fixture()
def fix_select_latest_policies_boom(monkeypatch):
    """monkeyed exception"""
    def monkeyed_boom(*args, **kwargs):
        """monkeypatch for the select_latest_policies"""
        raise MockException("monkeyed_boom")

    Settings.logger.info("setup fix_select_latest_policies_boom")
    monkeypatch.setattr('policyhandler.policy_utils.PolicyUtils.select_latest_policies',
                        monkeyed_boom)
    monkeypatch.setattr('policyhandler.policy_utils.PolicyUtils.select_latest_policy',
                        monkeyed_boom)
    monkeypatch.setattr('policyhandler.policy_utils.PolicyUtils.extract_policy_id',
                        monkeyed_boom)

    yield fix_select_latest_policies_boom
    Settings.logger.info("teardown fix_select_latest_policies_boom")

@pytest.fixture()
def fix_discovery(monkeypatch):
    """monkeyed discovery request.get"""
    def monkeyed_discovery(uri):
        """monkeypatch for get from consul"""
        res_json = {}
        dh_service = None
        if Config.discovered_config:
            _, dh_config = Config.discovered_config.get_by_key(Config.DEPLOY_HANDLER)
            dh_config = dh_config and dh_config.get(TARGET_ENTITY)
        if dh_service and uri == DiscoveryClient.CONSUL_SERVICE_MASK.format(
                Config.consul_url, dh_service):
            res_json = [{
                "ServiceAddress": "1.1.1.1",
                "ServicePort": "123"
            }]
        elif uri == DiscoveryClient.CONSUL_KV_MASK.format(
                Config.consul_url, Config.system_name):
            res_json = [{"Value": base64.b64encode(
                json.dumps(Settings.mock_config).encode()).decode("utf-8")}]
        return MockHttpResponse("get", uri, res_json)

    Settings.logger.info("setup fix_discovery")
    monkeypatch.setattr('policyhandler.discovery.requests.get', monkeyed_discovery)
    yield fix_discovery
    Settings.logger.info("teardown fix_discovery")


@pytest.fixture(scope="module")
def fix_auto_catch_up():
    """increase the frequency of auto catch_up"""

    Settings.logger.info("setup fix_auto_catch_up %s", json.dumps(Settings.mock_config))
    prev_config = copy.deepcopy(Settings.mock_config)
    Settings.mock_config.get(Config.SERVICE_NAME_POLICY_HANDLER, {}) \
        .get(CATCH_UP, {})[Config.TIMER_INTERVAL] = 5
    Settings.logger.info("fix_auto_catch_up %s", json.dumps(Settings.mock_config))
    Settings.rediscover_config()

    yield fix_auto_catch_up
    Settings.rediscover_config(prev_config)
    Settings.logger.info("teardown fix_auto_catch_up")


@pytest.fixture()
def fix_deploy_handler_413(monkeypatch):
    """monkeyed failed discovery request.get"""
    def monkeyed_deploy_handler_put(uri, **kwargs):
        """monkeypatch for deploy_handler"""
        return MockHttpResponse(
            "put", uri,
            {"server_instance_uuid": Settings.deploy_handler_instance_uuid},
            status_code=413, **kwargs
        )

    def monkeyed_deploy_handler_get(uri, **kwargs):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MockHttpResponse("get", uri, MockDeploymentHandler.get_deployed_policies(),
                                **kwargs)

    Settings.logger.info("setup fix_deploy_handler_413")
    audit = None
    if DeployHandler._lazy_inited is False:
        audit = Audit(req_message="fix_deploy_handler_413")
        DeployHandler._lazy_init(audit)

    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.put',
                        monkeyed_deploy_handler_put)
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.get',
                        monkeyed_deploy_handler_get)

    yield fix_deploy_handler_413
    if audit:
        audit.audit_done("teardown")
    Settings.logger.info("teardown fix_deploy_handler_413")


@pytest.fixture()
def fix_deploy_handler_404(monkeypatch):
    """monkeyed failed discovery request.get"""
    def monkeyed_deploy_handler_put(uri, **kwargs):
        """monkeypatch for deploy_handler"""
        return MockHttpResponse("put", uri, MockDeploymentHandler.default_response(),
                                **kwargs)

    def monkeyed_deploy_handler_get(uri, **kwargs):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MockHttpResponse("get", uri, MockDeploymentHandler.default_response(),
                                **kwargs)

    Settings.logger.info("setup fix_deploy_handler_404")
    audit = None
    if DeployHandler._lazy_inited is False:
        audit = Audit(req_message="fix_deploy_handler_404")
        DeployHandler._lazy_init(audit)

    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.put',
                        monkeyed_deploy_handler_put)
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.get',
                        monkeyed_deploy_handler_get)

    yield fix_deploy_handler_404
    if audit:
        audit.audit_done("teardown")
    Settings.logger.info("teardown fix_deploy_handler_404")

@pytest.fixture()
def fix_policy_receiver_websocket(monkeypatch):
    """monkeyed websocket for policy_receiver"""
    Settings.logger.info("setup fix_policy_receiver_websocket")
    monkeypatch.setattr('policyhandler.policy_receiver.websocket', MockWebSocket)
    yield fix_policy_receiver_websocket
    Settings.logger.info("teardown fix_policy_receiver_websocket")
