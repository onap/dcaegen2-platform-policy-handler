# ================================================================================
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

"""web-service for policy_handler"""

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
        audit = Audit(job_name="get_latest_policy",
                      req_message=req_info, headers=cherrypy.request.headers)
        PolicyWeb.logger.info("%s policy_id=%s headers=%s", \
            req_info, policy_id, json.dumps(cherrypy.request.headers))

        latest_policy = PolicyRest.get_latest_policy((audit, policy_id, None, None)) or {}

        PolicyWeb.logger.info("res %s policy_id=%s latest_policy=%s",
                              req_info, policy_id, json.dumps(latest_policy))

        success, http_status_code, _ = audit.audit_done(result=json.dumps(latest_policy))
        if not success:
            cherrypy.response.status = http_status_code

        return latest_policy

    def _get_all_policies_latest(self):
        """retireves all the latest policies on GET /policies_latest"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(job_name="get_all_policies_latest",
                      req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s", req_info)

        result = PolicyRest.get_latest_policies(audit)

        PolicyWeb.logger.info("result %s: %s", req_info, json.dumps(result))

        success, http_status_code, _ = audit.audit_done(result=json.dumps(result))
        if not success:
            cherrypy.response.status = http_status_code

        return result

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
            "onapName": "DCAE",
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
                        "ONAPName": "DCAE",
                        "ConfigName": "alex_config_name"
                    },
                    "property": null,
                    "config": {
                        "foo": "bar",
                        "foo_updated": "2018-10-06T16:54:31.696Z"
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
        audit = Audit(job_name="get_latest_policies",
                      req_message="{0}: {1}".format(req_info, str_policy_filter), \
            headers=cherrypy.request.headers)
        PolicyWeb.logger.info("%s: policy_filter=%s headers=%s", \
            req_info, str_policy_filter, json.dumps(cherrypy.request.headers))

        result = PolicyRest.get_latest_policies(audit, policy_filter=policy_filter) or {}

        PolicyWeb.logger.info("result %s: policy_filter=%s result=%s", \
            req_info, str_policy_filter, json.dumps(result))

        success, http_status_code, _ = audit.audit_done(result=json.dumps(result))
        if not success:
            cherrypy.response.status = http_status_code

        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def catch_up(self):
        """catch up with all DCAE policies"""
        started = str(datetime.utcnow())
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(job_name="catch_up", req_message=req_info, headers=cherrypy.request.headers)

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
        audit = Audit(job_name="shutdown", req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s: --- stopping REST API of policy-handler ---", req_info)

        cherrypy.engine.exit()

        PolicyReceiver.shutdown(audit)

        PolicyWeb.logger.info("policy_handler health: {0}"
                              .format(json.dumps(audit.health(full=True))))
        PolicyWeb.logger.info("%s: --------- the end -----------", req_info)
        res = str(datetime.utcnow())
        audit.info_requested(res)
        PolicyWeb.logger.info("process_info: %s", json.dumps(audit.process_info()))
        return "goodbye! shutdown requested {0}".format(res)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def healthcheck(self):
        """returns the healthcheck results"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(job_name="healthcheck",
                      req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s", req_info)

        res = audit.health()

        PolicyWeb.logger.info("healthcheck %s: res=%s", req_info, json.dumps(res))

        audit.audit_done(result=json.dumps(res))
        return res
