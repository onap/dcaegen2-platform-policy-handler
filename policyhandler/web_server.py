"""web-service for policy_handler"""

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

import logging
import json
from datetime import datetime
import cherrypy

from .config import Config
from .onap.audit import Audit
from .policy_rest import PolicyRest
from .policy_engine import PolicyEngineClient

class PolicyWeb(object):
    """Main static class for REST API of policy-handler"""
    logger = logging.getLogger("policy_handler.web_cherrypy")

    @staticmethod
    def run():
        """run forever the web-server of the policy-handler"""
        PolicyWeb.logger.info("policy_handler web-service at port(%d)...", \
            Config.wservice_port)
        cherrypy.config.update({"server.socket_host": "0.0.0.0", \
            'server.socket_port': Config.wservice_port})
        cherrypy.tree.mount(PolicyLatest(), '/policy_latest')
        cherrypy.tree.mount(PoliciesLatest(), '/policies_latest')
        cherrypy.tree.mount(PoliciesCatchUp(), '/catch_up')
        cherrypy.quickstart(Shutdown(), '/shutdown')

class Shutdown(object):
    """Shutdown the policy-handler"""
    @cherrypy.expose
    def index(self):
        """shutdown event"""
        audit = Audit(req_message="get /shutdown", headers=cherrypy.request.headers)
        PolicyWeb.logger.info("--------- stopping REST API of policy-handler -----------")
        cherrypy.engine.exit()
        PolicyEngineClient.shutdown(audit)
        PolicyWeb.logger.info("--------- the end -----------")
        res = str(datetime.now())
        audit.info_requested(res)
        return "goodbye! shutdown requested {0}".format(res)

class PoliciesLatest(object):
    """REST API of the policy-hanlder"""

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def index(self):
        """find the latest policy by policy_id or all latest policies"""
        audit = Audit(req_message="get /policies_latest", headers=cherrypy.request.headers)
        res = PolicyRest.get_latest_policies(audit) or {}
        PolicyWeb.logger.info("PoliciesLatest: %s", json.dumps(res))
        audit.audit_done(result=json.dumps(res))
        return res

@cherrypy.popargs('policy_id')
class PolicyLatest(object):
    """REST API of the policy-hanlder"""

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def index(self, policy_id):
        """find the latest policy by policy_id or all latest policies"""
        audit = Audit(req_message="get /policy_latest/{0}".format(policy_id or ""), \
            headers=cherrypy.request.headers)
        PolicyWeb.logger.info("PolicyLatest policy_id=%s headers=%s", \
            policy_id, json.dumps(cherrypy.request.headers))
        res = PolicyRest.get_latest_policy((audit, policy_id)) or {}
        PolicyWeb.logger.info("PolicyLatest policy_id=%s res=%s", policy_id, json.dumps(res))
        audit.audit_done(result=json.dumps(res))
        return res

class PoliciesCatchUp(object):
    """catch up with all DCAE policies"""
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def index(self):
        """catch up with all policies"""
        started = str(datetime.now())
        audit = Audit(req_message="get /catch_up", headers=cherrypy.request.headers)
        PolicyEngineClient.catch_up(audit)
        res = {"catch-up requested": started}
        PolicyWeb.logger.info("PoliciesCatchUp: %s", json.dumps(res))
        audit.info_requested(started)
        return res
