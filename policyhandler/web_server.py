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

"""web-server for policy_handler"""

import json
import logging
from datetime import datetime

import cherrypy

from .config import Config
from .deploy_handler import PolicyUpdateMessage
from .onap.audit import Audit, AuditHttpCode
from .policy_matcher import PolicyMatcher
from .policy_receiver import PolicyReceiver
from .policy_rest import PolicyRest


class PolicyWeb(object):
    """run http API of policy-handler on 0.0.0.0:wservice_port - any incoming address"""
    DATA_NOT_FOUND_ERROR = 404
    HOST_INADDR_ANY = ".".join("0"*4)
    logger = logging.getLogger("policy_handler.policy_web")

    @staticmethod
    def run_forever(audit):
        """run the web-server of the policy-handler forever"""
        cherrypy.config.update({"server.socket_host": PolicyWeb.HOST_INADDR_ANY,
                                "server.socket_port": Config.wservice_port})

        protocol = "http"
        tls_info = ""
        # if Config.tls_server_cert_file and Config.tls_private_key_file:
        #     cherrypy.server.ssl_module = 'builtin'
        #     cherrypy.server.ssl_certificate = Config.tls_server_cert_file
        #     cherrypy.server.ssl_private_key = Config.tls_private_key_file
        #     if Config.tls_server_ca_chain_file:
        #         cherrypy.server.ssl_certificate_chain = Config.tls_server_ca_chain_file
        #     protocol = "https"
        #     tls_info = "cert: {} {} {}".format(Config.tls_server_cert_file,
        #                                        Config.tls_private_key_file,
        #                                        Config.tls_server_ca_chain_file)

        cherrypy.tree.mount(_PolicyWeb(), '/')

        PolicyWeb.logger.info(
            "%s with config: %s", audit.info("running policy_handler as {}://{}:{} {}".format(
                protocol, cherrypy.server.socket_host, cherrypy.server.socket_port, tls_info)),
            json.dumps(cherrypy.config))
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
        PolicyWeb.logger.info("%s policy_id=%s headers=%s",
                              req_info, policy_id, json.dumps(cherrypy.request.headers))

        latest_policy = PolicyRest.get_latest_policy((audit, policy_id, None, None)) or {}

        PolicyWeb.logger.info("res %s policy_id=%s latest_policy=%s",
                              req_info, policy_id, json.dumps(latest_policy))

        _, http_status_code, _ = audit.audit_done(result=json.dumps(latest_policy))
        if http_status_code == AuditHttpCode.DATA_NOT_FOUND_OK.value:
            http_status_code = PolicyWeb.DATA_NOT_FOUND_ERROR
        cherrypy.response.status = http_status_code

        return latest_policy

    def _get_all_policies_latest(self):
        """retireves all the latest policies on GET /policies_latest"""
        req_info = _PolicyWeb._get_request_info(cherrypy.request)
        audit = Audit(job_name="get_all_policies_latest",
                      req_message=req_info, headers=cherrypy.request.headers)

        PolicyWeb.logger.info("%s", req_info)

        result, policies, policy_filters = PolicyMatcher.get_deployed_policies(audit)
        if not result:
            result, policy_update = PolicyMatcher.build_catch_up_message(
                audit, policies, policy_filters)
            if policy_update and isinstance(policy_update, PolicyUpdateMessage):
                result["policy_update"] = policy_update.get_message()

        result_str = json.dumps(result, sort_keys=True)
        PolicyWeb.logger.info("result %s: %s", req_info, result_str)

        _, http_status_code, _ = audit.audit_done(result=result_str)
        if http_status_code == AuditHttpCode.DATA_NOT_FOUND_OK.value:
            http_status_code = PolicyWeb.DATA_NOT_FOUND_ERROR
        cherrypy.response.status = http_status_code

        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def policies_latest(self):
        """
        on :GET: retrieves all the latest policies from policy-engine that are deployed

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
                      req_message="{0}: {1}".format(req_info, str_policy_filter),
                      headers=cherrypy.request.headers)
        PolicyWeb.logger.info("%s: policy_filter=%s headers=%s",
                              req_info, str_policy_filter, json.dumps(cherrypy.request.headers))

        result = PolicyRest.get_latest_policies(audit, policy_filter=policy_filter) or {}
        result_str = json.dumps(result, sort_keys=True)

        PolicyWeb.logger.info("result %s: policy_filter=%s result=%s",
                              req_info, str_policy_filter, result_str)

        _, http_status_code, _ = audit.audit_done(result=result_str)
        if http_status_code == AuditHttpCode.DATA_NOT_FOUND_OK.value:
            http_status_code = PolicyWeb.DATA_NOT_FOUND_ERROR
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
