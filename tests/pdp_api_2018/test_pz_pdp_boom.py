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
"""test policyhandler web-server when pdp booms = fails"""

import json
import time
import uuid

import cherrypy
import pytest
from cherrypy.test.helper import CPWebCase

from policyhandler.config import Config
from policyhandler.onap.audit import (REQUEST_X_ECOMP_REQUESTID, Audit,
                                      AuditHttpCode)
from policyhandler.pdp_api_2018.pdp_consts import POLICY_NAME
from policyhandler.policy_receiver import PolicyReceiver
from policyhandler.utils import Utils
from policyhandler.web_server import _PolicyWeb

from ..mock_settings import MockSettings
from ..mock_tracker import Tracker
from .mock_policy_engine import MockPolicyEngine2018
from .mock_websocket import MockWebSocket

_LOGGER = Utils.get_logger(__file__)

@pytest.mark.usefixtures(
    "fix_pdp_api_2018",
    "fix_discovery",
    "fix_pdp_post_boom"
)
class WebServerPDPBoom2018Test(CPWebCase):
    """testing the web-server - runs tests in alphabetical order of method names"""
    def setup_server():
        """setup the web-server"""
        cherrypy.tree.mount(_PolicyWeb(), '/')

    setup_server = staticmethod(setup_server)

    def test_web_healthcheck(self):
        """test /healthcheck"""
        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)
        _LOGGER.info("got healthcheck: %s", self.body)
        self.assertStatus('200 OK')

        Tracker.validate()

    def test_web_policy_latest(self):
        """test /policy_latest/<policy-id>"""
        policy_id, _ = MockPolicyEngine2018.gen_policy_latest(3)

        self.getPage("/policy_latest/{0}".format(policy_id or ""))
        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler")
    def test_web_all_policies_latest(self):
        """test GET /policies_latest"""
        result = self.getPage("/policies_latest")
        _LOGGER.info("result: %s", result)
        _LOGGER.info("body: %s", self.body)

        if Config.is_pdp_api_default():
            self.assertStatus('404 Not Found')
            return

        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        Tracker.validate()

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        match_to_policy_name = MockPolicyEngine2018.scope_prefix + "amet.*"

        body = json.dumps({POLICY_NAME: match_to_policy_name})
        result = self.getPage("/policies_latest", method='POST',
                              body=body,
                              headers=[
                                  (REQUEST_X_ECOMP_REQUESTID, str(uuid.uuid4())),
                                  ("Content-Type", "application/json"),
                                  ('Content-Length', str(len(body)))
                              ])
        _LOGGER.info("result: %s", result)
        _LOGGER.info("body: %s", self.body)

        if Config.is_pdp_api_default():
            self.assertStatus('404 Not Found')
            return

        self.assertStatus(AuditHttpCode.SERVER_INTERNAL_ERROR.value)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_policy_updates_and_catch_ups(self):
        """test run policy handler with policy updates and catchups"""
        if Config.is_pdp_api_default():
            _LOGGER.info("passive for new PDP API")
            return

        _LOGGER.info("start policy_updates_and_catch_ups")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzz_policy_updates_and_catch_ups",
                      req_message="start policy_updates_and_catch_ups")
        PolicyReceiver.run(audit)

        _LOGGER.info("sleep before send_notification...")
        time.sleep(2)

        MockWebSocket.send_notification([1, 3, 5])
        _LOGGER.info("sleep after send_notification...")
        time.sleep(3)

        _LOGGER.info("sleep 10 before shutdown...")
        time.sleep(10)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)
        assert not PolicyReceiver.is_running()

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_catch_up_on_deploy_handler_changed(self):
        """test run policy handler with deployment-handler changed underneath"""
        if Config.is_pdp_api_default():
            _LOGGER.info("passive for new PDP API")
            return

        _LOGGER.info("start zzz_catch_up_on_deploy_handler_changed")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzz_catch_up_on_deploy_handler_changed",
                      req_message="start zzz_catch_up_on_deploy_handler_changed")
        PolicyReceiver.run(audit)

        _LOGGER.info("sleep before send_notification...")
        time.sleep(2)

        MockWebSocket.send_notification([1])
        _LOGGER.info("sleep after send_notification...")
        time.sleep(3)

        MockSettings.deploy_handler_instance_uuid = str(uuid.uuid4())
        _LOGGER.info("new deploy-handler uuid=%s", MockSettings.deploy_handler_instance_uuid)

        MockWebSocket.send_notification([2, 4])
        _LOGGER.info("sleep after send_notification...")
        time.sleep(3)

        _LOGGER.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(1)
        assert not PolicyReceiver.is_running()

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler", "fix_policy_receiver_websocket")
    def test_zzz_get_catch_up(self):
        """test /catch_up"""
        if Config.is_pdp_api_default():
            _LOGGER.info("passive for new PDP API")
            return

        _LOGGER.info("start /catch_up")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzz_get_catch_up", req_message="start /catch_up")
        PolicyReceiver.run(audit)
        time.sleep(5)
        result = self.getPage("/catch_up")
        _LOGGER.info("catch_up result: %s", result)
        self.assertStatus('200 OK')
        _LOGGER.info("got catch_up: %s", self.body)

        _LOGGER.info("sleep 5 before shutdown...")
        time.sleep(5)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

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
        _LOGGER.info("start shutdown")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="start shutdown")
        PolicyReceiver.run(audit)

        _LOGGER.info("sleep before send_notification...")
        time.sleep(2)

        MockWebSocket.send_notification([1, 3, 5])
        _LOGGER.info("sleep after send_notification...")
        time.sleep(3)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        WebServerPDPBoom2018Test.do_gc_test = False
        _LOGGER.info("shutdown...")
        audit.audit_done("shutdown")
        result = self.getPage("/shutdown")
        _LOGGER.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        _LOGGER.info("got shutdown: %s", self.body)
        time.sleep(1)
        assert not PolicyReceiver.is_running()

        if Config.is_pdp_api_default():
            _LOGGER.info("passive for new PDP API")
            return

        Tracker.validate()
