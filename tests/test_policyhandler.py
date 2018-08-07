# ============LICENSE_START=======================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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
import re
import time
import uuid

import pytest
import cherrypy
from cherrypy.test.helper import CPWebCase

from policyhandler.config import Config
from policyhandler.deploy_handler import DeployHandler
from policyhandler.discovery import DiscoveryClient
from policyhandler.onap.audit import (REQUEST_X_ECOMP_REQUESTID, Audit,
                                      AuditHttpCode)
from policyhandler.policy_consts import (LATEST_POLICIES, POLICY_BODY,
                                         POLICY_CONFIG, POLICY_ID, POLICY_NAME,
                                         POLICY_VERSION, POLICY_VERSIONS)
from policyhandler.policy_receiver import (LOADED_POLICIES, POLICY_VER,
                                           REMOVED_POLICIES, PolicyReceiver)
from policyhandler.policy_rest import PolicyRest
from policyhandler.policy_utils import PolicyUtils, Utils
from policyhandler.web_server import _PolicyWeb

from .mock_settings import Settings

Settings.init()

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
    if full_path == DiscoveryClient.CONSUL_SERVICE_MASK.format(Config.settings["deploy_handler"]):
        res_json = [{
            "ServiceAddress": "1.1.1.1",
            "ServicePort": "123"
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


class MockPolicyEngine(object):
    """pretend this is the policy-engine"""
    scope_prefix = "test_scope_prefix.Config_"
    LOREM_IPSUM = """Lorem ipsum dolor sit amet consectetur ametist""".split()
    LONG_TEXT = "0123456789" * 100
    _policies = []

    @staticmethod
    def init():
        """init static vars"""
        MockPolicyEngine._policies = [
            MonkeyPolicyBody.create_policy_body(
                MockPolicyEngine.scope_prefix + policy_id, policy_index + 1)
            for policy_id in MockPolicyEngine.LOREM_IPSUM
            for policy_index in range(1 + MockPolicyEngine.LOREM_IPSUM.index(policy_id))]
        Settings.logger.info("MockPolicyEngine._policies: %s",
                             json.dumps(MockPolicyEngine._policies))

    @staticmethod
    def get_config(policy_name):
        """find policy the way the policy-engine finds"""
        if not policy_name:
            return []
        return [copy.deepcopy(policy)
                for policy in MockPolicyEngine._policies
                if re.match(policy_name, policy[POLICY_NAME])]

    @staticmethod
    def get_configs_all():
        """get all policies the way the policy-engine finds"""
        policies = [copy.deepcopy(policy)
                    for policy in MockPolicyEngine._policies]
        for policy in policies:
            policy["config"] = MockPolicyEngine.LONG_TEXT
        return policies

    @staticmethod
    def get_policy_id(policy_index):
        """get the policy_id by index"""
        return (MockPolicyEngine.scope_prefix
                + MockPolicyEngine.LOREM_IPSUM[
                    policy_index % len(MockPolicyEngine.LOREM_IPSUM)])

    @staticmethod
    def gen_policy_latest(policy_index, version_offset=0):
        """generate the policy response by policy_index = version - 1"""
        policy_id = MockPolicyEngine.get_policy_id(policy_index)
        policy = {
            POLICY_ID: policy_id,
            POLICY_BODY: MonkeyPolicyBody.create_policy_body(
                policy_id, policy_index + 1 - version_offset)
        }
        return policy_id, PolicyUtils.parse_policy_config(policy)

    @staticmethod
    def gen_all_policies_latest(version_offset=0):
        """generate all latest policies"""
        return dict(MockPolicyEngine.gen_policy_latest(policy_index, version_offset=version_offset)
                    for policy_index in range(len(MockPolicyEngine.LOREM_IPSUM)))

    @staticmethod
    def gen_policies_latest(match_to_policy_name):
        """generate all latest policies"""
        return dict((k, v)
                    for k, v in MockPolicyEngine.gen_all_policies_latest().items()
                    if re.match(match_to_policy_name, k))


MockPolicyEngine.init()


class MockDeploymentHandler(object):
    """pretend this is the deployment-handler"""

    @staticmethod
    def default_response():
        """generate the deployed policies message"""
        return {"server_instance_uuid": Settings.deploy_handler_instance_uuid}

    @staticmethod
    def get_deployed_policies():
        """generate the deployed policies message"""
        response = MockDeploymentHandler.default_response()
        policies = dict(
            (policy_id, {
                POLICY_ID: policy_id,
                POLICY_VERSIONS: {policy.get(POLICY_BODY, {}).get(POLICY_VERSION, "999"): True},
                "pending_update": False})
            for policy_id, policy in (MockPolicyEngine.gen_all_policies_latest(version_offset=1)
                                                      .items()))
        response["policies"] = policies

        return response


@pytest.fixture()
def fix_pdp_post(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    def monkeyed_policy_rest_post(full_path, json=None, headers=None):
        """monkeypatch for the POST to policy-engine"""
        res_json = MockPolicyEngine.get_config(json.get(POLICY_NAME))
        return MonkeyedResponse(full_path, res_json, json, headers)

    Settings.logger.info("setup fix_pdp_post")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post  # provide the fixture value
    Settings.logger.info("teardown fix_pdp_post")


@pytest.fixture()
def fix_pdp_post_big(monkeypatch):
    """monkeyed request /getConfig to PDP"""
    def monkeyed_policy_rest_post(full_path, json=None, headers=None):
        """monkeypatch for the POST to policy-engine"""
        res_json = MockPolicyEngine.get_configs_all()
        return MonkeyedResponse(full_path, res_json, json, headers)

    Settings.logger.info("setup fix_pdp_post_big")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post)
    yield fix_pdp_post_big  # provide the fixture value
    Settings.logger.info("teardown fix_pdp_post_big")


class MockException(Exception):
    """mock exception"""
    pass


@pytest.fixture()
def fix_pdp_post_boom(monkeypatch):
    """monkeyed request /getConfig to PDP - exception"""
    def monkeyed_policy_rest_post_boom(full_path, json=None, headers=None):
        """monkeypatch for the POST to policy-engine"""
        raise MockException("fix_pdp_post_boom")

    Settings.logger.info("setup fix_pdp_post_boom")
    PolicyRest._lazy_init()
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post',
                        monkeyed_policy_rest_post_boom)
    yield fix_pdp_post_boom
    Settings.logger.info("teardown fix_pdp_post_boom")

@staticmethod
def monkeyed_boom(*args, **kwargs):
    """monkeypatch for the select_latest_policies"""
    raise MockException("monkeyed_boom")

@pytest.fixture()
def fix_select_latest_policies_boom(monkeypatch):
    """monkeyed exception"""

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
def fix_deploy_handler(monkeypatch, fix_discovery):
    """monkeyed requests to deployment-handler"""
    def monkeyed_deploy_handler_put(full_path, json=None, headers=None):
        """monkeypatch for policy-update request.put to deploy_handler"""
        return MonkeyedResponse(full_path, MockDeploymentHandler.default_response(),
                                json, headers)

    def monkeyed_deploy_handler_get(full_path, headers=None):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MonkeyedResponse(full_path, MockDeploymentHandler.get_deployed_policies(),
                                None, headers)

    Settings.logger.info("setup fix_deploy_handler")
    audit = Audit(req_message="fix_deploy_handler")
    DeployHandler._lazy_init(audit)

    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.put',
                        monkeyed_deploy_handler_put)
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.get',
                        monkeyed_deploy_handler_get)

    yield fix_deploy_handler  # provide the fixture value
    Settings.logger.info("teardown fix_deploy_handler")


@pytest.fixture()
def fix_deploy_handler_fail(monkeypatch, fix_discovery):
    """monkeyed failed discovery request.get"""
    def monkeyed_deploy_handler_put(full_path, json=None, headers=None):
        """monkeypatch for deploy_handler"""
        res = MonkeyedResponse(
            full_path,
            {"server_instance_uuid": Settings.deploy_handler_instance_uuid},
            json, headers
        )
        res.status_code = 413
        return res

    def monkeyed_deploy_handler_get(full_path, headers=None):
        """monkeypatch policy-update request.get to deploy_handler"""
        return MonkeyedResponse(full_path, MockDeploymentHandler.default_response(),
                                None, headers)

    @staticmethod
    def monkeyed_deploy_handler_init(audit_ignore, rediscover=False):
        """monkeypatch for deploy_handler init"""
        DeployHandler._url = None

    Settings.logger.info("setup fix_deploy_handler_fail")
    config_catch_up = Config.settings["catch_up"]
    Config.settings["catch_up"] = {"interval": 1}

    audit = Audit(req_message="fix_deploy_handler_fail")
    DeployHandler._lazy_init(audit, rediscover=True)

    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._lazy_init',
                        monkeyed_deploy_handler_init)
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.put',
                        monkeyed_deploy_handler_put)
    monkeypatch.setattr('policyhandler.deploy_handler.DeployHandler._requests_session.get',
                        monkeyed_deploy_handler_get)

    yield fix_deploy_handler_fail
    Settings.logger.info("teardown fix_deploy_handler_fail")
    Config.settings["catch_up"] = config_catch_up


@pytest.fixture()
def fix_cherrypy_engine_exit(monkeypatch):
    """monkeyed cherrypy.engine.exit()"""
    Settings.logger.info("setup fix_cherrypy_engine_exit")

    def monkeyed_cherrypy_engine_exit():
        """monkeypatch for deploy_handler"""
        Settings.logger.info("cherrypy_engine_exit()")

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
            LOADED_POLICIES: [
                {POLICY_NAME: "{0}.{1}.xml".format(
                    MockPolicyEngine.get_policy_id(policy_index), policy_index + 1),
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
            counter = 0
            while self.sock.connected:
                counter += 1
                Settings.logger.info("MonkeyedWebSocket sleep %s...", counter)
                time.sleep(5)
            Settings.logger.info("MonkeyedWebSocket exit %s", counter)

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
    policy_id, expected_policy = MockPolicyEngine.gen_policy_latest(3)

    audit = Audit(job_name="test_get_policy_latest",
                  req_message="get /policy_latest/{0}".format(policy_id or ""))
    policy_latest = PolicyRest.get_latest_policy((audit, policy_id, None, None)) or {}
    audit.audit_done(result=json.dumps(policy_latest))

    Settings.logger.info("expected_policy: %s", json.dumps(expected_policy))
    Settings.logger.info("policy_latest: %s", json.dumps(policy_latest))
    assert Utils.are_the_same(policy_latest, expected_policy)



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
        policy_id, expected_policy = MockPolicyEngine.gen_policy_latest(3)

        self.getPage("/policy_latest/{0}".format(policy_id or ""))
        self.assertStatus('200 OK')

        policy_latest = json.loads(self.body)

        Settings.logger.info("policy_latest: %s", self.body)
        Settings.logger.info("expected_policy: %s", json.dumps(expected_policy))
        assert Utils.are_the_same(policy_latest, expected_policy)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    @pytest.mark.usefixtures("fix_deploy_handler")
    def test_web_all_policies_latest(self):
        """test GET /policies_latest"""
        expected_policies = MockPolicyEngine.gen_all_policies_latest()

        result = self.getPage("/policies_latest")
        Settings.logger.info("result: %s", result)
        Settings.logger.info("body: %s", self.body)
        self.assertStatus('200 OK')

        policies_latest = json.loads(self.body)
        self.assertIn(LATEST_POLICIES, policies_latest)
        policies_latest = policies_latest[LATEST_POLICIES]

        Settings.logger.info("policies_latest: %s", json.dumps(policies_latest))
        Settings.logger.info("expected_policies: %s", json.dumps(expected_policies))
        assert Utils.are_the_same(policies_latest, expected_policies)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        match_to_policy_name = MockPolicyEngine.scope_prefix + "amet.*"
        expected_policies = MockPolicyEngine.gen_policies_latest(match_to_policy_name)

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

        policies_latest = json.loads(self.body)[LATEST_POLICIES]

        Settings.logger.info("policies_latest: %s", json.dumps(policies_latest))
        Settings.logger.info("expected_policies: %s", json.dumps(expected_policies))
        assert Utils.are_the_same(policies_latest, expected_policies)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_policy_updates_and_catch_ups(self):
        """test run policy handler with policy updates and catchups"""
        Settings.logger.info("start policy_updates_and_catch_ups")
        audit = Audit(job_name="test_zzz_policy_updates_and_catch_ups",
                      req_message="start policy_updates_and_catch_ups")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 30 before shutdown...")
        time.sleep(30)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_catch_up_on_deploy_handler_changed(self):
        """test run policy handler with deployment-handler changed underneath"""
        Settings.logger.info("start zzz_catch_up_on_deploy_handler_changed")
        audit = Audit(job_name="test_zzz_catch_up_on_deploy_handler_changed",
                      req_message="start zzz_catch_up_on_deploy_handler_changed")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.deploy_handler_instance_uuid = str(uuid.uuid4())
        Settings.logger.info("new deploy-handler uuid=%s", Settings.deploy_handler_instance_uuid)

        MonkeyedWebSocket.send_notification([2, 4])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_get_catch_up(self):
        """test /catch_up"""
        Settings.logger.info("start /catch_up")
        audit = Audit(job_name="test_zzz_get_catch_up", req_message="start /catch_up")
        PolicyReceiver.run(audit)
        time.sleep(5)
        result = self.getPage("/catch_up")
        Settings.logger.info("catch_up result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got catch_up: %s", self.body)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_policy_receiver_websocket",
        "fix_cherrypy_engine_exit")
    def test_zzzzz_shutdown(self):
        """test shutdown"""
        Settings.logger.info("start shutdown")
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="start shutdown")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        WebServerTest.do_gc_test = False
        Settings.logger.info("shutdown...")
        result = self.getPage("/shutdown")
        Settings.logger.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got shutdown: %s", self.body)
        time.sleep(1)


@pytest.mark.usefixtures("fix_pdp_post_boom")
class WebServerPDPBoomTest(CPWebCase):
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
        policy_id, _ = MockPolicyEngine.gen_policy_latest(3)

        self.getPage("/policy_latest/{0}".format(policy_id or ""))
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    @pytest.mark.usefixtures("fix_deploy_handler")
    def test_web_all_policies_latest(self):
        """test GET /policies_latest"""
        result = self.getPage("/policies_latest")
        Settings.logger.info("result: %s", result)
        Settings.logger.info("body: %s", self.body)
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        match_to_policy_name = MockPolicyEngine.scope_prefix + "amet.*"

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
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_policy_updates_and_catch_ups(self):
        """test run policy handler with policy updates and catchups"""
        Settings.logger.info("start policy_updates_and_catch_ups")
        audit = Audit(job_name="test_zzz_policy_updates_and_catch_ups",
                      req_message="start policy_updates_and_catch_ups")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 30 before shutdown...")
        time.sleep(30)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_catch_up_on_deploy_handler_changed(self):
        """test run policy handler with deployment-handler changed underneath"""
        Settings.logger.info("start zzz_catch_up_on_deploy_handler_changed")
        audit = Audit(job_name="test_zzz_catch_up_on_deploy_handler_changed",
                      req_message="start zzz_catch_up_on_deploy_handler_changed")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.deploy_handler_instance_uuid = str(uuid.uuid4())
        Settings.logger.info("new deploy-handler uuid=%s", Settings.deploy_handler_instance_uuid)

        MonkeyedWebSocket.send_notification([2, 4])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_get_catch_up(self):
        """test /catch_up"""
        Settings.logger.info("start /catch_up")
        audit = Audit(job_name="test_zzz_get_catch_up", req_message="start /catch_up")
        PolicyReceiver.run(audit)
        time.sleep(5)
        result = self.getPage("/catch_up")
        Settings.logger.info("catch_up result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got catch_up: %s", self.body)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_policy_receiver_websocket",
        "fix_cherrypy_engine_exit")
    def test_zzzzz_shutdown(self):
        """test shutdown"""
        Settings.logger.info("start shutdown")
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="start shutdown")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        WebServerPDPBoomTest.do_gc_test = False
        Settings.logger.info("shutdown...")
        result = self.getPage("/shutdown")
        Settings.logger.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got shutdown: %s", self.body)
        time.sleep(1)


@pytest.mark.usefixtures("fix_pdp_post", "fix_select_latest_policies_boom")
class WebServerInternalBoomTest(CPWebCase):
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
        policy_id, _ = MockPolicyEngine.gen_policy_latest(3)

        self.getPage("/policy_latest/{0}".format(policy_id or ""))
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    @pytest.mark.usefixtures("fix_deploy_handler")
    def test_web_all_policies_latest(self):
        """test GET /policies_latest"""
        result = self.getPage("/policies_latest")
        Settings.logger.info("result: %s", result)
        Settings.logger.info("body: %s", self.body)
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        match_to_policy_name = MockPolicyEngine.scope_prefix + "amet.*"

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
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_policy_updates_and_catch_ups(self):
        """test run policy handler with policy updates and catchups"""
        Settings.logger.info("start policy_updates_and_catch_ups")
        audit = Audit(job_name="test_zzz_policy_updates_and_catch_ups",
                      req_message="start policy_updates_and_catch_ups")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 30 before shutdown...")
        time.sleep(30)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_catch_up_on_deploy_handler_changed(self):
        """test run policy handler with deployment-handler changed underneath"""
        Settings.logger.info("start zzz_catch_up_on_deploy_handler_changed")
        audit = Audit(job_name="test_zzz_catch_up_on_deploy_handler_changed",
                      req_message="start zzz_catch_up_on_deploy_handler_changed")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.deploy_handler_instance_uuid = str(uuid.uuid4())
        Settings.logger.info("new deploy-handler uuid=%s", Settings.deploy_handler_instance_uuid)

        MonkeyedWebSocket.send_notification([2, 4])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_get_catch_up(self):
        """test /catch_up"""
        Settings.logger.info("start /catch_up")
        audit = Audit(job_name="test_zzz_get_catch_up", req_message="start /catch_up")
        PolicyReceiver.run(audit)
        time.sleep(5)
        result = self.getPage("/catch_up")
        Settings.logger.info("catch_up result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got catch_up: %s", self.body)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_policy_receiver_websocket",
        "fix_cherrypy_engine_exit")
    def test_zzzzz_shutdown(self):
        """test shutdown"""
        Settings.logger.info("start shutdown")
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="start shutdown")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MonkeyedWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        WebServerInternalBoomTest.do_gc_test = False
        Settings.logger.info("shutdown...")
        result = self.getPage("/shutdown")
        Settings.logger.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got shutdown: %s", self.body)
        time.sleep(1)


@pytest.mark.usefixtures(
    "fix_pdp_post_big",
    "fix_deploy_handler_fail",
    "fix_policy_receiver_websocket"
)
def test_catch_ups_failed_dh():
    """test run policy handler with catchups and failed deployment-handler"""
    Settings.logger.info("start test_catch_ups_failed_dh")
    audit = Audit(job_name="test_catch_ups_failed_dh",
                  req_message="start test_catch_ups_failed_dh")
    PolicyReceiver.run(audit)

    Settings.logger.info("sleep 50 before shutdown...")
    time.sleep(50)

    health = audit.health(full=True)
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)

    PolicyReceiver.shutdown(audit)
    time.sleep(1)

    health = audit.health(full=True)
    Settings.logger.info("healthcheck: %s", json.dumps(health))
