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

import json
import time
import uuid

import pytest
import cherrypy
from cherrypy.test.helper import CPWebCase

from policyhandler.onap.audit import REQUEST_X_ECOMP_REQUESTID, Audit
from policyhandler.policy_consts import LATEST_POLICIES, POLICY_NAME
from policyhandler.policy_receiver import PolicyReceiver
from policyhandler.policy_utils import Utils
from policyhandler.web_server import _PolicyWeb

from .mock_policy_engine import MockPolicyEngine
from .mock_settings import Settings
from .mock_tracker import Tracker
from .mock_websocket import MockWebSocket


@pytest.mark.usefixtures("fix_pdp_post", "fix_discovery")
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

        Tracker.validate()

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

        Tracker.validate()

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

        Tracker.validate()

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

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_policy_updates_and_catch_ups(self):
        """test run policy handler with policy updates and catchups"""
        Settings.logger.info("start policy_updates_and_catch_ups")
        assert not PolicyReceiver.is_running()

        audit = Audit(job_name="test_zzz_policy_updates_and_catch_ups",
                      req_message="start policy_updates_and_catch_ups")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MockWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 10 before shutdown...")
        time.sleep(10)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)
        assert not PolicyReceiver.is_running()

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_catch_up_on_deploy_handler_changed(self):
        """test run policy handler with deployment-handler changed underneath"""
        Settings.logger.info("start zzz_catch_up_on_deploy_handler_changed")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzz_catch_up_on_deploy_handler_changed",
                      req_message="start zzz_catch_up_on_deploy_handler_changed")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MockWebSocket.send_notification([1])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.deploy_handler_instance_uuid = str(uuid.uuid4())
        Settings.logger.info("new deploy-handler uuid=%s", Settings.deploy_handler_instance_uuid)

        MockWebSocket.send_notification([2, 4])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        Settings.logger.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)
        assert not PolicyReceiver.is_running()

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_get_catch_up(self):
        """test /catch_up"""
        Settings.logger.info("start /catch_up")
        assert not PolicyReceiver.is_running()
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
        assert not PolicyReceiver.is_running()

        Tracker.validate()

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_policy_receiver_websocket",
        "fix_cherrypy_engine_exit")
    def test_zzzzz_shutdown(self):
        """test shutdown"""
        Settings.logger.info("start shutdown")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="start shutdown")
        PolicyReceiver.run(audit)

        Settings.logger.info("sleep before send_notification...")
        time.sleep(2)

        MockWebSocket.send_notification([1, 3, 5])
        Settings.logger.info("sleep after send_notification...")
        time.sleep(3)

        result = self.getPage("/healthcheck")
        Settings.logger.info("healthcheck result: %s", result)

        WebServerTest.do_gc_test = False
        Settings.logger.info("shutdown...")
        audit.audit_done("shutdown")
        result = self.getPage("/shutdown")
        Settings.logger.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        Settings.logger.info("got shutdown: %s", self.body)
        time.sleep(1)
        assert not PolicyReceiver.is_running()

        Tracker.validate()
