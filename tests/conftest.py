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
"""
standard pytest file that contains the shared fixtures
https://docs.pytest.org/en/latest/fixture.html
"""
import base64
import copy
import json
import os

import pytest

from policyhandler.config import Config
from policyhandler.discovery import DiscoveryClient
from policyhandler.policy_consts import CATCH_UP, TARGET_ENTITY
from policyhandler.utils import Utils

from .mock_settings import MockSettings
from .mock_tracker import MockHttpResponse, Tracker

_LOGGER = Utils.get_logger(__file__)

MockSettings.init_mock_config()

@pytest.fixture(scope="session", autouse=True)
def _auto_setup__global():
    """initialize the _auto_setup__global per the whole test session"""
    _LOGGER.info("_auto_setup__global")

    yield _auto_setup__global
    Tracker.log_all_tests()
    _LOGGER.info("teardown _auto_setup__global")


@pytest.fixture(autouse=True, scope="module")
def _auto_module_cycle(request):
    """log all the test starts and ends"""
    module_name = request.module.__name__.replace(".", "/")

    _LOGGER.info("start_module: %s %s", module_name, "->"*25)
    yield _auto_module_cycle
    _LOGGER.info("end_module: %s %s", module_name, "<-"*25)

@pytest.fixture(autouse=True)
def _auto_test_cycle(request):
    """log all the test starts and ends"""
    _LOGGER.info("-"*75)
    module_name = request.module.__name__.replace(".", "/")
    if request.cls:
        test_name = "%s.py::%s::%s" % (module_name, request.cls.__name__,
                                       request.function.__name__)
    else:
        test_name = "%s.py::%s" % (module_name, request.function.__name__)

    Tracker.reset(test_name)
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
        return MockHttpResponse("get", uri, res_json=res_json)

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

@pytest.fixture(scope="module")
def fix_pdp_authorization():
    """set env vars that overwrite the headers.Authorization on pdp and dmaap_mr clients"""
    _LOGGER.info("setup fix_pdp_authorization %s", json.dumps(MockSettings.mock_config))
    prev_config = copy.deepcopy(MockSettings.mock_config)

    os.environ.update({
        Config.PDP_USER: "alex-PDP_USER",
        Config.PDP_PWD: "alex-PDP_PWD",
        Config.DMAAP_MR_USER: "alex-DMAAP_MR_USER",
        Config.DMAAP_MR_PWD: "alex-DMAAP_MR_PWD"
    })
    Config._local_config._config = None
    Config._pdp_authorization = None
    Config._dmaap_mr_authorization = None
    MockSettings.reinit_mock_config()
    MockSettings.rediscover_config()

    _LOGGER.info("fix_pdp_authorization %s, %s: %s:%s %s:%s",
                 json.dumps(Config._pdp_authorization), json.dumps(Config._dmaap_mr_authorization),
                 os.environ.get(Config.PDP_USER), os.environ.get(Config.PDP_PWD),
                 os.environ.get(Config.DMAAP_MR_USER), os.environ.get(Config.DMAAP_MR_PWD))

    yield fix_pdp_authorization

    del os.environ[Config.PDP_USER]
    del os.environ[Config.PDP_PWD]
    del os.environ[Config.DMAAP_MR_USER]
    del os.environ[Config.DMAAP_MR_PWD]

    Config._local_config._config = None
    Config._pdp_authorization = None
    Config._dmaap_mr_authorization = None
    MockSettings.reinit_mock_config()
    MockSettings.rediscover_config(prev_config)
    _LOGGER.info("teardown fix_pdp_authorization %s, %s: %s:%s %s:%s",
                 json.dumps(Config._pdp_authorization), json.dumps(Config._dmaap_mr_authorization),
                 os.environ.get(Config.PDP_USER), os.environ.get(Config.PDP_PWD),
                 os.environ.get(Config.DMAAP_MR_USER), os.environ.get(Config.DMAAP_MR_PWD))
