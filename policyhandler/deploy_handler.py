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

""" send notification to deploy-handler"""

import json
import logging

import requests

from .config import Config
from .customize import CustomizerUser
from .discovery import DiscoveryClient
from .onap.audit import REQUEST_X_ECOMP_REQUESTID, Audit, AuditHttpCode

POOL_SIZE = 1

class DeployHandler(object):
    """ deploy-handler """
    _logger = logging.getLogger("policy_handler.deploy_handler")
    _lazy_inited = False

    _requests_session = None
    _config = None
    _url = None
    _url_policy = None
    _target_entity = None
    _custom_kwargs = None
    _server_instance_uuid = None

    @staticmethod
    def _lazy_init(audit):
        """ set static properties """
        if DeployHandler._lazy_inited:
            return
        DeployHandler._lazy_inited = True

        DeployHandler._custom_kwargs = CustomizerUser.get_customizer() \
                                            .get_deploy_handler_kwargs(audit)
        if not DeployHandler._custom_kwargs \
        or not isinstance(DeployHandler._custom_kwargs, dict):
            DeployHandler._custom_kwargs = {}

        DeployHandler._requests_session = requests.Session()
        DeployHandler._requests_session.mount(
            'https://',
            requests.adapters.HTTPAdapter(pool_connections=POOL_SIZE, pool_maxsize=POOL_SIZE)
        )
        DeployHandler._requests_session.mount(
            'http://',
            requests.adapters.HTTPAdapter(pool_connections=POOL_SIZE, pool_maxsize=POOL_SIZE)
        )

        config_dh = Config.config.get("deploy_handler")
        if config_dh and isinstance(config_dh, dict):
            # dns based routing to deployment-handler
            # config for policy-handler >= 2.4.0
            # "deploy_handler" : {
            #     "target_entity" : "deployment_handler",
            #     "url" : "http://deployment_handler:8188"
            # }
            DeployHandler._target_entity = config_dh.get("target_entity", "deployment_handler")
            DeployHandler._url = config_dh.get("url")
            DeployHandler._logger.info("dns based routing to %s: url(%s)",
                DeployHandler._target_entity, DeployHandler._url)

        if not DeployHandler._url:
            # discover routing to deployment-handler at consul-services
            if not isinstance(config_dh, dict):
                # config for policy-handler <= 2.3.1
                # "deploy_handler" : "deployment_handler"
                DeployHandler._target_entity = str(config_dh or "deployment_handler")
            DeployHandler._url = DiscoveryClient.get_service_url(audit, DeployHandler._target_entity)

        DeployHandler._url_policy = str(DeployHandler._url or "") + '/policy'
        DeployHandler._logger.info(
            "got %s policy url(%s)", DeployHandler._target_entity, DeployHandler._url_policy)

    @staticmethod
    def policy_update(audit, message):
        """
        post policy_updated message to deploy-handler

        returns condition whether it needs to catch_up
        """
        if not message:
            return

        DeployHandler._lazy_init(audit)
        sub_aud = Audit(aud_parent=audit, targetEntity=DeployHandler._target_entity,
                        targetServiceName=DeployHandler._url_policy)
        headers = {REQUEST_X_ECOMP_REQUESTID : sub_aud.request_id}

        msg_str = json.dumps(message)
        headers_str = json.dumps(headers)

        log_action = "post to {0} at {1}".format(
            DeployHandler._target_entity, DeployHandler._url_policy)
        log_data = " msg={0} headers={1}".format(msg_str, headers_str)
        log_line = log_action + log_data
        DeployHandler._logger.info(log_line)
        sub_aud.metrics_start(log_line)

        if not DeployHandler._url:
            error_msg = "no url found to {0}".format(log_line)
            DeployHandler._logger.error(error_msg)
            sub_aud.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            audit.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            sub_aud.metrics(error_msg)
            return

        res = None
        try:
            res = DeployHandler._requests_session.post(
                DeployHandler._url_policy, json=message, headers=headers,
                **DeployHandler._custom_kwargs
            )
        except requests.exceptions.RequestException as ex:
            error_msg = "failed to {0}: {1}{2}".format(log_action, str(ex), log_data)
            DeployHandler._logger.exception(error_msg)
            sub_aud.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            audit.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            sub_aud.metrics(error_msg)
            return

        sub_aud.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)

        log_line = "response {0} from {1}: text={2}{3}" \
            .format(res.status_code, log_action, res.text, log_data)
        sub_aud.metrics(log_line)
        DeployHandler._logger.info(log_line)

        if res.status_code != requests.codes.ok:
            return

        result = res.json() or {}
        prev_server_instance_uuid = DeployHandler._server_instance_uuid
        DeployHandler._server_instance_uuid = result.get("server_instance_uuid")

        deployment_handler_changed = (prev_server_instance_uuid
            and prev_server_instance_uuid != DeployHandler._server_instance_uuid)
        if deployment_handler_changed:
            log_line = "deployment_handler_changed: {1} != {0}" \
                .format(prev_server_instance_uuid, DeployHandler._server_instance_uuid)
            sub_aud.info(log_line)
            DeployHandler._logger.info(log_line)

        return deployment_handler_changed
