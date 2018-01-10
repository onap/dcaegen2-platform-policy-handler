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
from .policy_receiver import PolicyReceiver

class PolicyWeb(object):
    """run REST API of policy-handler"""
    logger = logging.getLogger("policy_handler.policy_web")

    @staticmethod
    def run_forever(audit):
        """run the web-server of the policy-handler forever"""
        PolicyWeb.logger.info("policy_handler web-service at port(%d)...", Config.wservice_port)
        cherrypy.config.update({"server.socket_host": "0.0.0.0",
                                'server.socket_port': Config.wservice_port})
        cherrypy.tree.mount(_PolicyWeb(), '/')
        audit.info("running policy_handler web-service at port({0})".format(Config.wservice_port))
        cherrypy.engine.start()

class _PolicyWeb(object):
    """REST API of policy-handler"""

    @staticmethod
    def _get_request_info(request):
        """returns info about the http request"""
        return "{0} {1}{2}".format(request.method, request.script_name, request.path_info)

    @cherrypy.expose
    @cherrypy.popargs('policy_id')
    @cherrypy.tools.json_out()
    def policy_latest(self, policy_id):
        """retireves the latest policy identified by policy_id"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(req_message=req_info, headers=cherrypy.request.headers)
        PolicyWeb.logger.info("%s policy_id=%s headers=%s", \
            req_info, policy_id, json.dumps(cherrypy.request.headers))

        res = PolicyRest.get_latest_policy((audit, policy_id, None, None)) or {}

        PolicyWeb.logger.info("res %s policy_id=%s res=%s", req_info, policy_id, json.dumps(res))

        success, http_status_code, response_description = audit.audit_done(result=json.dumps(res))
        if not success:
            raise cherrypy.HTTPError(http_status_code, response_description)
        return res

    def _get_all_policies_latest(self):
        """retireves all the latest policies on GET /policies_latest"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s", req_info)

        valid_policies, errored_policies = PolicyRest.get_latest_policies(audit)

        res = {"valid_policies": valid_policies, "errored_policies": errored_policies}
        PolicyWeb.logger.info("result %s: %s", req_info, json.dumps(res))

        success, http_status_code, response_description = audit.audit_done(result=json.dumps(res))
        if not success:
            raise cherrypy.HTTPError(http_status_code, response_description)
        return res

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def policies_latest(self):
        """
        on :GET: retrieves all the latest policies from policy-engine that are
        in the scope of the policy-handler.

        on :POST: expects to receive the params that mimic the /getConfig of policy-engine
        and retrieves the matching policies from policy-engine and picks the latest on each policy.

        sample request - policies filter

        {
            "configAttributes": { "key1":"value1" },
            "configName": "alex_config_name",
            "ecompName": "DCAE",
            "policyName": "DCAE_alex.Config_alex_.*",
            "unique": false
        }

        sample response

        {
            "DCAE_alex.Config_alex_priority": {
                "policy_body": {
                    "policyName": "DCAE_alex.Config_alex_priority.3.xml",
                    "policyConfigMessage": "Config Retrieved! ",
                    "responseAttributes": {},
                    "policyConfigStatus": "CONFIG_RETRIEVED",
                    "type": "JSON",
                    "matchingConditions": {
                        "priority": "10",
                        "key1": "value1",
                        "ECOMPName": "DCAE",
                        "ConfigName": "alex_config_name"
                    },
                    "property": null,
                    "config": {
                        "foo": "bar",
                        "foo_updated": "2017-10-06T16:54:31.696Z"
                    },
                    "policyVersion": "3"
                },
                "policy_id": "DCAE_alex.Config_alex_priority"
            }
        }
        """
        if cherrypy.request.method == "GET":
            return self._get_all_policies_latest()

        if cherrypy.request.method != "POST":
            raise cherrypy.HTTPError(404, "unexpected method {0}".format(cherrypy.request.method))

        policy_filter = cherrypy.request.json or {}
        str_policy_filter = json.dumps(policy_filter)

        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(req_message="{0}: {1}".format(req_info, str_policy_filter), \
            headers=cherrypy.request.headers)
        PolicyWeb.logger.info("%s: policy_filter=%s headers=%s", \
            req_info, str_policy_filter, json.dumps(cherrypy.request.headers))

        res, _ = PolicyRest.get_latest_policies(audit, policy_filter=policy_filter) or {}

        PolicyWeb.logger.info("result %s: policy_filter=%s res=%s", \
            req_info, str_policy_filter, json.dumps(res))

        success, http_status_code, response_description = audit.audit_done(result=json.dumps(res))
        if not success:
            raise cherrypy.HTTPError(http_status_code, response_description)
        return res

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def catch_up(self):
        """catch up with all DCAE policies"""
        started = str(datetime.now())
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s", req_info)
        PolicyReceiver.catch_up(audit)

        res = {"catch-up requested": started}
        PolicyWeb.logger.info("requested %s: %s", req_info, json.dumps(res))
        audit.info_requested(started)
        return res

    @cherrypy.expose
    def shutdown(self):
        """Shutdown the policy-handler"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s: --- stopping REST API of policy-handler ---", req_info)

        cherrypy.engine.exit()

        PolicyReceiver.shutdown(audit)

        health = json.dumps(Audit.health())
        audit.info("policy_handler health: {0}".format(health))
        PolicyWeb.logger.info("policy_handler health: %s", health)
        PolicyWeb.logger.info("%s: --------- the end -----------", req_info)
        res = str(datetime.now())
        audit.info_requested(res)
        return "goodbye! shutdown requested {0}".format(res)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def healthcheck(self):
        """returns the healthcheck results"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s", req_info)

        res = Audit.health()

        PolicyWeb.logger.info("healthcheck %s: res=%s", req_info, json.dumps(res))

        audit.audit_done(result=json.dumps(res))
        return res
