""" send notification to deploy-handler"""

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
import requests

from .config import Config
from .discovery import DiscoveryClient
from .onap.audit import REQUEST_X_ECOMP_REQUESTID, Audit, AuditHttpCode

class DeployHandler(object):
    """ deploy-handler """
    _logger = logging.getLogger("policy_handler.deploy_handler")
    _lazy_inited = False
    _config = None
    _url = None
    _url_path = None
    _target_entity = None

    @staticmethod
    def _lazy_init():
        """ set static properties """
        if DeployHandler._lazy_inited:
            return
        DeployHandler._lazy_inited = True
        DeployHandler._target_entity = Config.config["deploy_handler"]
        DeployHandler._url = DiscoveryClient.get_service_url(DeployHandler._target_entity)
        DeployHandler._url_path = DeployHandler._url + '/policy'
        DeployHandler._logger.info("DeployHandler url(%s)", DeployHandler._url)

    @staticmethod
    def policy_update(audit, latest_policies):
        """ post policy_updated message to deploy-handler """
        DeployHandler._lazy_init()
        msg = {"latest_policies":latest_policies}
        sub_aud = Audit(aud_parent=audit, targetEntity=DeployHandler._target_entity,
                        targetServiceName=DeployHandler._url_path)
        headers = {REQUEST_X_ECOMP_REQUESTID : sub_aud.request_id}

        msg_str = json.dumps(msg)
        headers_str = json.dumps(headers)

        log_line = "post to deployment-handler {0} msg={1} headers={2}".format(
            DeployHandler._url_path, msg_str, headers_str)
        sub_aud.metrics_start(log_line)
        DeployHandler._logger.info(log_line)

        res = None
        try:
            res = requests.post(DeployHandler._url_path, json=msg, headers=headers)
        except requests.exceptions.RequestException as ex:
            error_msg = "failed to post to deployment-handler {0} {1} msg={2} headers={3}" \
                .format(DeployHandler._url_path, str(ex), msg_str, headers_str)
            DeployHandler._logger.exception(error_msg)
            sub_aud.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            audit.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            sub_aud.metrics(error_msg)
            return

        sub_aud.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)

        sub_aud.metrics(
            "response from deployment-handler to post {0}: {1} msg={2} text={3} headers={4}" \
            .format(DeployHandler._url_path, res.status_code, msg_str, res.text,
                    res.request.headers))

        if res.status_code == requests.codes.ok:
            return res.json()
