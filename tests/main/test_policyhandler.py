# ============LICENSE_START=======================================================
# Copyright (c) 2017-2020 AT&T Intellectual Property. All rights reserved.
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

"""test of the package for policy-handler of DCAE-Controller"""

import json
import time
import uuid

import pytest
import cherrypy

from cherrypy.test.helper import CPWebCase
from policyhandler.onap.audit import (REQUEST_X_ECOMP_REQUESTID,
                                      REQUEST_X_ONAP_REQUESTID, Audit)
from policyhandler.policy_receiver import PolicyReceiver
from policyhandler.utils import Utils
from policyhandler.web_server import _PolicyWeb

from ..mock_tracker import Tracker

_LOGGER = Utils.get_logger(__file__)


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
        _LOGGER.info("healthcheck result: %s", result)
        _LOGGER.info("got healthcheck: %s", self.body)
        self.assertStatus('200 OK')

        Tracker.validate()

    def test_web_policy_latest(self):
        """test /policy_latest/<policy-id>"""
        policy_id = "test_scope_prefix.pdp_decision_sit"
        expected_policy = {
            "policy_id": "test_scope_prefix.pdp_decision_sit",
            "policy_body": {
                "type": "unit.test.type.policies",
                "version": "1.0.0",
                "metadata": {
                    "policy-id": "test_scope_prefix.pdp_decision_sit",
                    "policy-version": "4.4.4",
                    "description": "description for test_scope_prefix.pdp_decision_sit"
                },
                "policyName": "test_scope_prefix.pdp_decision_sit.4-4-4.xml",
                "policyVersion": "4.4.4",
                "config": {
                    "policy_updated_from_ver": 3,
                    "policy_updated_to_ver": 4,
                    "policy_hello": "world!",
                    "updated_policy_id": "test_scope_prefix.pdp_decision_sit"
                }
            }
        }

        self.getPage("/policy_latest/{0}".format(policy_id or ""))
        self.assertStatus('200 OK')

        policy_latest = json.loads(self.body)

        _LOGGER.info("policy_latest: %s", self.body)
        _LOGGER.info("expected_policy: %s", json.dumps(expected_policy))
        assert Utils.are_the_same(policy_latest, expected_policy)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        Tracker.validate()

    @pytest.mark.usefixtures("fix_deploy_handler")
    def test_web_all_policies_latest(self):
        """test GET /policies_latest"""

        result = self.getPage("/policies_latest")
        _LOGGER.info("result: %s", result)
        _LOGGER.info("body: %s", self.body)

        self.assertStatus('200 OK')

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        body = json.dumps({"junk": "to-be-developed"})
        request_id = str(uuid.uuid4())
        result = self.getPage("/policies_latest", method='POST',
                              body=body,
                              headers=[
                                  (REQUEST_X_ECOMP_REQUESTID, request_id),
                                  (REQUEST_X_ONAP_REQUESTID, request_id),
                                  ("Content-Type", "application/json"),
                                  ('Content-Length', str(len(body)))
                              ])
        _LOGGER.info("result: %s", result)
        _LOGGER.info("body: %s", self.body)

        self.assertStatus('404 Not Found')

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_dmaap_mr",
        "fix_cherrypy_engine_exit")
    def test_zzzzz_shutdown(self):
        """test shutdown"""
        _LOGGER.info("testing the shutdown")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="testing the shutdown")
        PolicyReceiver.run(audit)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        time.sleep(1)

        WebServerTest.do_gc_test = False
        _LOGGER.info("shutdown...")
        audit.audit_done("shutdown")
        result = self.getPage("/shutdown")
        _LOGGER.info("shutdown result: %s", result)
        self.assertStatus('200 OK')
        _LOGGER.info("got shutdown: %s", self.body)
        time.sleep(5)
        assert not PolicyReceiver.is_running()

        Tracker.validate()

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_dmaap_mr",
        "fix_cherrypy_engine_exit")
    def test_zzz_policy_updates_and_catch_ups(self):
        """test run policy handler with policy updates and catchups"""
        _LOGGER.info("start policy_updates_and_catch_ups")
        assert not PolicyReceiver.is_running()

        audit = Audit(job_name="test_zzz_policy_updates_and_catch_ups",
                      req_message="start policy_updates_and_catch_ups")
        PolicyReceiver.run(audit)

        _LOGGER.info("sleep 20 before shutdown...")
        time.sleep(20)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        PolicyReceiver.shutdown(audit)
        time.sleep(5)
        assert not PolicyReceiver.is_running()

        Tracker.validate()
