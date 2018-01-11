# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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

"""test of the package for policy-handler of DCAE-Controller"""

import copy
import json
import logging
import re
import sys
import time
import uuid
from datetime import datetime

import pytest

import cherrypy
from cherrypy.test.helper import CPWebCase

from policyhandler.config import Config
from policyhandler.deploy_handler import DeployHandler
from policyhandler.discovery import DiscoveryClient
from policyhandler.onap.audit import (REQUEST_X_ECOMP_REQUESTID, Audit,
                                      AuditHttpCode)
from policyhandler.policy_consts import (POLICY_BODY, POLICY_CONFIG, POLICY_ID,
                                         POLICY_NAME, POLICY_VERSION)
from policyhandler.policy_handler import LogWriter
from policyhandler.policy_receiver import (LOADED_POLICIES, POLICY_VER,
                                           REMOVED_POLICIES, PolicyReceiver)
from policyhandler.policy_rest import PolicyRest
from policyhandler.policy_utils import PolicyUtils
from policyhandler.web_server import _PolicyWeb

POLICY_HANDLER_VERSION = "2.0.0"

class MonkeyHttpResponse(object):
    """Monkey http reposne"""
    def __init__(self, headers):
        self.headers = headers or {}

class MonkeyedResponse(object):
    """Monkey response"""
    def __init__(self, full_path, res_json, json_body=None, headers=None):
        self.full_path = full_path
        self.req_json = json_body or {}
        self.status_code = 200
        self.request = MonkeyHttpResponse(headers)
        self.res = res_json
        self.text = json.dumps(self.res)

    def json(self):
        """returns json of response"""
        return self.res

    def raise_for_status(self):
        """ignoring"""
        pass

def monkeyed_discovery(full_path):
    """monkeypatch for get from consul"""
    res_json = {}
    if full_path == DiscoveryClient.CONSUL_SERVICE_MASK.format(Config.config["deploy_handler"]):
        res_json = [{
            DiscoveryClient.SERVICE_ADDRESS: "1.1.1.1",
            DiscoveryClient.SERVICE_PORT: "123"
        }]
    elif full_path == DiscoveryClient.CONSUL_KV_MASK.format(Config.get_system_name()):
        res_json = copy.deepcopy(Settings.dicovered_config)
    return MonkeyedResponse(full_path, res_json)

@pytest.fixture()
def fix_discovery(monkeypatch):
    """monkeyed discovery request.get"""
    Settings.logger.info("setup fix_discovery")
    monkeypatch.setattr('policyhandler.discovery.requests.get', monkeyed_discovery)
    yield fix_discovery  # provide the fixture value
    Settings.logger.info("teardown fix_discovery")

class Settings(object):
    """init all locals"""
    logger = None
    RUN_TS = datetime.utcnow().isoformat()[:-3] + 'Z'
    dicovered_config = None

    @staticmethod
    def init():
        """init locals"""
        Config.load_from_file()

        with open("etc_upload/config.json", 'r') as config_json:
            Settings.dicovered_config = json.load(config_json)

        Config.load_from_file("etc_upload/config.json")

        Settings.logger = logging.getLogger("policy_handler.unit_test")
        sys.stdout = LogWriter(Settings.logger.info)
        sys.stderr = LogWriter(Settings.logger.error)

        print "print ========== run_policy_handler =========="
        Settings.logger.info("========== run_policy_handler ==========")
        Audit.init(Config.get_system_name(), POLICY_HANDLER_VERSION, Config.LOGGER_CONFIG_FILE_PATH)

        Settings.logger.info("starting policy_handler with config:")
        Settings.logger.info(Audit.log_json_dumps(Config.config))

Settings.init()

class MonkeyPolicyBody(object):
    """policy body that policy-engine returns"""
    @staticmethod
    def create_policy_body(policy_id, policy_version=1):
        """returns a fake policy-body"""
        prev_ver = str(policy_version - 1)
        this_ver = str(policy_version)
        config = {
            "policy_updated_from_ver": prev_ver,
            "policy_updated_to_ver": this_ver,
            "policy_hello": "world!",
            "policy_updated_ts": Settings.RUN_TS,
            "updated_policy_id": policy_id
        }
        return {
            "policyConfigMessage": "Config Retrieved! ",
            "policyConfigStatus": "CONFIG_RETRIEVED",
            "type": "JSON",
            POLICY_NAME: "{0}.{1}.xml".format(policy_id, this_ver),
            POLICY_VERSION: this_ver,
            POLICY_CONFIG: json.dumps(config),
            "matchingConditions": {
                "ONAPName": "DCAE",
                "ConfigName": "alex_config_name"
            },
            "responseAttributes": {},
            "property": None
        }

    @staticmethod
    def is_the_same_dict(policy_body_1, policy_body_2):
        """check whether both policy_body objects are the same"""
        if not isinstance(policy_body_1, dict) or not isinstance(policy_body_2, dict):
            return False
        for key in policy_body_1.keys():
            if key not in policy_body_2:
                return False

            val_1 = policy_body_1[key]
            val_2 = policy_body_2[key]
            if isinstance(val_1, dict) \
            and not MonkeyPolicyBody.is_the_same_dict(val_1, val_2):
                return False
            if (val_1 is None and val_2 is not None) \
            or (val_1 is not None and val_2 is None) \
            or (val_1 != val_2):
                return False
        return True

class MonkeyPolicyEngine(object):
    """pretend this is the policy-engine"""
    _scope_prefix = Config.config["scope_prefixes"][0]
    LOREM_IPSUM = """Lorem ipsum dolor sit amet consectetur ametist""".split()
    _policies = []

    @staticmethod
    def init():
        """init static vars"""
        MonkeyPolicyEngine._policies = [
            MonkeyPolicyBody.create_policy_body(
                MonkeyPolicyEngine._scope_prefix + policy_id, policy_index + 1)
            for policy_id in MonkeyPolicyEngine.LOREM_IPSUM
            for policy_index in range(1 + MonkeyPolicyEngine.LOREM_IPSUM.index(policy_id))]
        Settings.logger.info("MonkeyPolicyEngine._policies: %s",
                             json.dumps(MonkeyPolicyEngine._policies))

    @staticmethod
    def get_config(policy_name):
        """find policy the way the policy-engine finds"""
        if not policy_name:
            return []
        return [copy.deepcopy(policy)
                for policy in MonkeyPolicyEngine._policies
                if re.match(policy_name, policy[POLICY_NAME])]

    @staticmethod
    def get_policy_id(policy_index):
        """get the policy_id by index"""
        return MonkeyPolicyEngine._scope_prefix \
             + MonkeyPolicyEngine.LOREM_IPSUM[policy_index % len(MonkeyPolicyEngine.LOREM_IPSUM)]

    @staticmethod
    def gen_policy_latest(policy_index):
        """generate the policy response by policy_index = version - 1"""
        policy_id = MonkeyPolicyEngine.get_policy_id(policy_index)
        expected_policy = {
            POLICY_ID : policy_id,
            POLICY_BODY : MonkeyPolicyBody.create_policy_body(policy_id, policy_index + 1)
        }
        return policy_id, PolicyUtils.parse_policy_config(expected_policy)

    @staticmethod
    def gen_all_policies_latest():
        """generate all latest policies"""
        return dict(
            MonkeyPolicyEngine.gen_policy_latest(policy_index)
            for policy_index in range(len(MonkeyPolicyEngine.LOREM_IPSUM))
        )

    @staticmethod
    def gen_policies_latest(match_to_policy_name):
        """generate all latest policies"""
        return dict(
            (k, v)
            for k, v in MonkeyPolicyEngine.gen_all_policies_latest().iteritems()
            if re.match(match_to_policy_name, k)
        )

MonkeyPolicyEngine.init()

def monkeyed_policy_rest_post(full_path, json=None, headers=None):
    """monkeypatch for the POST to policy-engine"""
    res_json = MonkeyPolicyEngine.get_config(json.get(POLICY_NAME))
    return MonkeyedResponse(full_path, res_json, json, headers)

@pytest.fixture()
def fix_pdp_post(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    Settings.logger.info("setup fix_pdp_post")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post  # provide the fixture value
    Settings.logger.info("teardown fix_pdp_post")

def monkeyed_deploy_handler(full_path, json=None, headers=None):
    """monkeypatch for deploy_handler"""
    return MonkeyedResponse(full_path, {}, json, headers)

@pytest.fixture()
def fix_deploy_handler(monkeypatch, fix_discovery):
    """monkeyed discovery request.get"""
    Settings.logger.info("setup fix_deploy_handler")
    DeployHandler._lazy_init()
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.post',
                        monkeyed_deploy_handler)
    yield fix_deploy_handler  # provide the fixture value
    Settings.logger.info("teardown fix_deploy_handler")

def monkeyed_cherrypy_engine_exit():
    """monkeypatch for deploy_handler"""
    Settings.logger.info("monkeyed_cherrypy_engine_exit()")

@pytest.fixture()
def fix_cherrypy_engine_exit(monkeypatch):
    """monkeyed cherrypy.engine.exit()"""
    Settings.logger.info("setup fix_cherrypy_engine_exit")
    monkeypatch.setattr('policyhandler.web_server.cherrypy.engine.exit',
                        monkeyed_cherrypy_engine_exit)
    yield fix_cherrypy_engine_exit  # provide the fixture value
    Settings.logger.info("teardown fix_cherrypy_engine_exit")

class MonkeyedWebSocket(object):
    """Monkey websocket"""
    on_message = None

    @staticmethod
    def send_notification(updated_indexes):
        """fake notification through the web-socket"""
        if not MonkeyedWebSocket.on_message:
            return
        message = {
            LOADED_POLICIES : [
                {POLICY_NAME: "{0}.{1}.xml".format(
                    MonkeyPolicyEngine.get_policy_id(policy_index), policy_index + 1),
                 POLICY_VER: str(policy_index + 1)}
                for policy_index in updated_indexes or []
            ],
            REMOVED_POLICIES : []
        }
        message = json.dumps(message)
        Settings.logger.info("send_notification: %s", message)
        MonkeyedWebSocket.on_message(None, message)

    @staticmethod
    def enableTrace(yes_no):
        """ignore"""
        pass

    class MonkeyedSocket(object):
        """Monkey websocket"""
        def __init__(self):
            self.connected = True

    class WebSocketApp(object):
        """Monkeyed WebSocketApp"""
        def __init__(self, web_socket_url, on_message=None, on_close=None, on_error=None):
            self.web_socket_url = web_socket_url
            self.on_message = MonkeyedWebSocket.on_message = on_message
            self.on_close = on_close
            self.on_error = on_error
            self.sock = MonkeyedWebSocket.MonkeyedSocket()
            Settings.logger.info("MonkeyedWebSocket for: %s", self.web_socket_url)

        def run_forever(self):
            """forever in the loop"""
            while self.sock.connected:
                Settings.logger.info("MonkeyedWebSocket sleep...")
                time.sleep(5)
            Settings.logger.info("MonkeyedWebSocket exit")

        def close(self):
            """close socket"""
            self.sock.connected = False

@pytest.fixture()
def fix_policy_receiver_websocket(monkeypatch):
    """monkeyed websocket for policy_receiver"""
    Settings.logger.info("setup fix_policy_receiver_websocket")
    monkeypatch.setattr('policyhandler.policy_receiver.websocket', MonkeyedWebSocket)
    yield fix_policy_receiver_websocket  # provide the fixture value
    Settings.logger.info("teardown fix_policy_receiver_websocket")

def test_get_policy_latest(fix_pdp_post):
    """test /policy_latest/<policy-id>"""
    policy_id, expected_policy = MonkeyPolicyEngine.gen_policy_latest(3)

    audit = Audit(req_message="get /policy_latest/{0}".format(policy_id or ""))
    policy_latest = PolicyRest.get_latest_policy((audit, policy_id, None, None)) or {}
    audit.audit_done(result=json.dumps(policy_latest))

    Settings.logger.info("expected_policy: %s", json.dumps(expected_policy))
    Settings.logger.info("policy_latest: %s", json.dumps(policy_latest))
    assert MonkeyPolicyBody.is_the_same_dict(policy_latest, expected_policy)
    assert MonkeyPolicyBody.is_the_same_dict(expected_policy, policy_latest)

def test_healthcheck():
    """test /healthcheck"""
    audit = Audit(req_message="get /healthcheck")
    audit.metrics_start("test /healthcheck")
    time.sleep(0.1)

    audit.metrics("test /healthcheck")
    health = Audit.health() or {}
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)

def test_healthcheck_with_error():
    """test /healthcheck"""
    audit = Audit(req_message="get /healthcheck")
    audit.metrics_start("test /healthcheck")
    time.sleep(0.2)
    audit.error("error from test_healthcheck_with_error")
    audit.fatal("fatal from test_healthcheck_with_error")
    audit.debug("debug from test_healthcheck_with_error")
    audit.warn("debug from test_healthcheck_with_error")
    audit.info_requested("debug from test_healthcheck_with_error")
    if audit.is_success():
        audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
    audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
    audit.metrics("test /healthcheck")

    health = Audit.health() or {}
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)

@pytest.mark.usefixtures("fix_pdp_post")
class WebServerTest(CPWebCase):
    """testing the web-server - runs tests in alphabetical order of method names"""
    def setup_server():
        """setup the web-server"""
        cherrypy.tree.mount(_PolicyWeb(), '/')

    setup_server = staticmethod(setup_server)

    def test_web_healthcheck(self):
        """test /healthcheck"""
        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)
        Settings.logger.info("got healthcheck: %s", self.body)
        self.assertStatus('200 OK')

    def test_web_policy_latest(self):
        """test /policy_latest/<policy-id>"""
        policy_id, expected_policy = MonkeyPolicyEngine.gen_policy_latest(3)

        self.getPage("/policy_latest/{0}".format(policy_id or ""))
        self.assertStatus('200 OK')

        policy_latest = json.loads(self.body)

        Settings.logger.info("policy_latest: %s", self.body)
        Settings.logger.info("expected_policy: %s", json.dumps(expected_policy))
        assert MonkeyPolicyBody.is_the_same_dict(policy_latest, expected_policy)
        assert MonkeyPolicyBody.is_the_same_dict(expected_policy, policy_latest)

    def test_web_all_policies_latest(self):
        """test GET /policies_latest"""
        expected_policies = MonkeyPolicyEngine.gen_all_policies_latest()

        result = self.getPage("/policies_latest")
        Settings.logger.info("result: %s", result)
        Settings.logger.info("body: %s", self.body)
        self.assertStatus('200 OK')

        policies_latest = json.loads(self.body)
        self.assertIn("valid_policies", policies_latest)
        policies_latest = policies_latest["valid_policies"]

        Settings.logger.info("policies_latest: %s", json.dumps(policies_latest))
        Settings.logger.info("expected_policies: %s", json.dumps(expected_policies))
        assert MonkeyPolicyBody.is_the_same_dict(policies_latest, expected_policies)
        assert MonkeyPolicyBody.is_the_same_dict(expected_policies, policies_latest)

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        match_to_policy_name = Config.config["scope_prefixes"][0] + "amet.*"
        expected_policies = MonkeyPolicyEngine.gen_policies_latest(match_to_policy_name)

        body = json.dumps({POLICY_NAME: match_to_policy_name})
        result = self.getPage("/policies_latest", method='POST',
                              body=body,
                              headers=[
                                  (REQUEST_X_ECOMP_REQUESTID, str(uuid.uuid4())),
                                  ("Content-Type", "application/json"),
                                  ('Content-Length', str(len(body)))
                              ])
        Settings.logger.info("result: %s", result)
        Settings.logger.info("body: %s", self.body)
        self.assertStatus('200 OK')

        policies_latest = json.loads(self.body)

        Settings.logger.info("policies_latest: %s", json.dumps(policies_latest))
        Settings.logger.info("expected_policies: %s", json.dumps(expected_policies))
        assert MonkeyPolicyBody.is_the_same_dict(policies_latest, expected_policies)
        assert MonkeyPolicyBody.is_the_same_dict(expected_policies, policies_latest)

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_policy_receiver_websocket",
        "fix_cherrypy_engine_exit")
    def test_zzz_run_policy_handler(self):
        """test run policy handler"""
        Settings.logger.info("start policy handler")
        audit = Audit(req_message="start policy handler")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep before shutdown...")
        time.sleep(1)
        result = self.getPage("/shutdown")
        Settings.logger.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got shutdown: %s", self.body)
        time.sleep(1)

    # @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    # def test_zzz_web_catch_up(self):
    #     """test /catch_up"""
        # Settings.logger.info("start policy handler")
    #     audit = Audit(req_message="start policy handler")
    #     PolicyReceiver.run(audit)
    #     time.sleep(5)
    #     result = self.getPage("/catch_up")
    #     Settings.logger.info("catch_up result: %s", result)
    #     self.assertStatus('200 OK')
    #     Settings.logger.info("got catch_up: %s", self.body)
