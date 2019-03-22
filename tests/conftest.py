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
from policyhandler.policy_consts import CATCH_UP, TARGET_ENTITY
from policyhandler.utils import Utils

from .mock_deploy_handler import MockDeploymentHandler
from .mock_settings import MockSettings
from .mock_tracker import MockHttpResponse, Tracker

_LOGGER = Utils.get_logger(__file__)

_LOGGER.info("init MockSettings")
MockSettings.init()

@pytest.fixture(scope="session", autouse=True)
def _auto_setup__global():
    """initialize the _auto_setup__global per the whole test session"""
    _LOGGER.info("_auto_setup__global")

    yield _auto_setup__global
    Tracker.log_all_tests()
    _LOGGER.info("teardown _auto_setup__global")


@pytest.fixture(autouse=True)
def _auto_test_cycle(request):
    """log all the test starts and ends"""
    module_name = request.module.__name__.replace(".", "/")
    if request.cls:
        test_name = "%s.py::%s::%s" % (module_name, request.cls.__name__,
                                       request.function.__name__)
    else:
        test_name = "%s.py::%s" % (module_name, request.function.__name__)

    Tracker.reset(test_name)
    _LOGGER.info("-"*75)
    _LOGGER.info(">>>>>>> start [%s]: %s", len(Tracker.test_names), test_name)
    yield _auto_test_cycle
    _LOGGER.info(">>>>>>> tracked messages: %s", Tracker.to_string())
    _LOGGER.info(">>>>>>> %s[%s]: %s", Tracker.get_status(test_name),
                 len(Tracker.test_names), test_name)


@pytest.fixture()
def fix_cherrypy_engine_exit(monkeypatch):
    """monkeyed cherrypy.engine.exit()"""
    _LOGGER.info("setup fix_cherrypy_engine_exit")

    def monkeyed_cherrypy_engine_exit():
        """monkeypatch for deploy_handler"""
        _LOGGER.info("cherrypy_engine_exit()")

    monkeypatch.setattr('policyhandler.web_server.cherrypy.engine.exit',
                        monkeyed_cherrypy_engine_exit)
    yield fix_cherrypy_engine_exit
    _LOGGER.info("teardown fix_cherrypy_engine_exit")


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
                json.dumps(MockSettings.mock_config).encode()).decode("utf-8")}]
        return MockHttpResponse("get", uri, res_json)

    _LOGGER.info("setup fix_discovery")
    monkeypatch.setattr('policyhandler.discovery.requests.get', monkeyed_discovery)
    yield fix_discovery
    _LOGGER.info("teardown fix_discovery")

@pytest.fixture(scope="module")
def fix_auto_catch_up():
    """increase the frequency of auto catch_up"""

    _LOGGER.info("setup fix_auto_catch_up %s", json.dumps(MockSettings.mock_config))
    prev_config = copy.deepcopy(MockSettings.mock_config)
    MockSettings.mock_config.get(Config.SERVICE_NAME_POLICY_HANDLER, {}) \
        .get(CATCH_UP, {})[Config.TIMER_INTERVAL] = 5
    _LOGGER.info("fix_auto_catch_up %s", json.dumps(MockSettings.mock_config))
    MockSettings.rediscover_config()

    yield fix_auto_catch_up
    MockSettings.rediscover_config(prev_config)
    _LOGGER.info("teardown fix_auto_catch_up")


@pytest.fixture()
def fix_deploy_handler_413(monkeypatch):
    """monkeyed failed discovery request.get"""
    def monkeyed_deploy_handler_put(uri, **kwargs):
        """monkeypatch for deploy_handler"""
        return MockHttpResponse(
            "put", uri,
            {"server_instance_uuid": MockSettings.deploy_handler_instance_uuid},
            status_code=413, **kwargs
        )

    def monkeyed_deploy_handler_get(uri, **kwargs):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MockHttpResponse("get", uri, MockDeploymentHandler.get_deployed_policies(),
                                **kwargs)

    _LOGGER.info("setup fix_deploy_handler_413")
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
    _LOGGER.info("teardown fix_deploy_handler_413")


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

    _LOGGER.info("setup fix_deploy_handler_404")
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
    _LOGGER.info("teardown fix_deploy_handler_404")
