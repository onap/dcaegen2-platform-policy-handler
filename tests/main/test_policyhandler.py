# ============LICENSE_START=======================================================
# Copyright (c) 2017-2019 AT&T Intellectual Property. All rights reserved.
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

import cherrypy
import pytest
from cherrypy.test.helper import CPWebCase

from policyhandler.config import Config
from policyhandler.onap.audit import REQUEST_X_ECOMP_REQUESTID, Audit
from policyhandler.pdp_api.pdp_consts import POLICY_NAME
from policyhandler.policy_consts import LATEST_POLICIES
from policyhandler.policy_receiver import PolicyReceiver
from policyhandler.utils import Utils
from policyhandler.web_server import _PolicyWeb

from ..mock_tracker import Tracker
from .mock_policy_engine import MockPolicyEngine

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
        policy_id, expected_policy = MockPolicyEngine.gen_policy_latest(3)

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

        self.assertStatus('404 Not Found')

    def test_web_policies_latest(self):
        """test POST /policies_latest with policyName"""
        body = json.dumps({"junk": "to-be-developed"})
        result = self.getPage("/policies_latest", method='POST',
                              body=body,
                              headers=[
                                  (REQUEST_X_ECOMP_REQUESTID, str(uuid.uuid4())),
                                  ("Content-Type", "application/json"),
                                  ('Content-Length', str(len(body)))
                              ])
        _LOGGER.info("result: %s", result)
        _LOGGER.info("body: %s", self.body)

        self.assertStatus('404 Not Found')

    @pytest.mark.usefixtures(
        "fix_deploy_handler",
        "fix_cherrypy_engine_exit")
    def test_zzzzz_shutdown(self):
        """test shutdown"""
        _LOGGER.info("start shutdown")
        assert not PolicyReceiver.is_running()
        audit = Audit(job_name="test_zzzzz_shutdown", req_message="start shutdown")
        PolicyReceiver.run(audit)

        result = self.getPage("/healthcheck")
        _LOGGER.info("healthcheck result: %s", result)

        WebServerTest.do_gc_test = False
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
