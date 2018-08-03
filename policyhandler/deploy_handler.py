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

"""send policy-update notification to deployment-handler"""

import json
import logging
from copy import copy, deepcopy

import requests

from .config import Config
from .customize import CustomizerUser
from .discovery import DiscoveryClient
from .onap.audit import (REQUEST_X_ECOMP_REQUESTID, AuditHttpCode,
                         AuditResponseCode, Metrics)
from .policy_consts import (CATCH_UP, LATEST_POLICIES, POLICIES,
                            POLICY_FILTER_MATCHES, POLICY_FILTERS,
                            REMOVED_POLICIES)


class PolicyUpdateMessage(object):
    """class for messages to deployment-handler on policy-update"""
    BYTES_IN_MB = 1 << 2 * 10

    def __init__(self, latest_policies=None,
                 removed_policies=None, policy_filter_matches=None, catch_up=True):
        """init"""
        self._catch_up = catch_up
        self._latest_policies = deepcopy(latest_policies or {})
        self._removed_policies = copy(removed_policies or {})
        self._policy_filter_matches = deepcopy(policy_filter_matches or {})

        self._message = {
            CATCH_UP: self._catch_up,
            LATEST_POLICIES: self._latest_policies,
            REMOVED_POLICIES: self._removed_policies,
            POLICY_FILTER_MATCHES: self._policy_filter_matches
        }
        self.msg_length = 0
        self._calc_stats()

    def _calc_stats(self):
        """generate the message and calc stats"""
        self.msg_length = len(json.dumps(self._message))

    def empty(self):
        """checks whether have any data"""
        return (not self._latest_policies
                and not self._removed_policies
                and not self._policy_filter_matches)

    def add(self, policy_id, latest_policy=None, policy_filter_ids=None, removed_policy=None):
        """add the parts from the other message to the current message"""
        if not policy_id or not (latest_policy or policy_filter_ids or removed_policy):
            return

        if latest_policy:
            self._latest_policies[policy_id] = deepcopy(latest_policy)

        if policy_filter_ids:
            if policy_id not in self._policy_filter_matches:
                self._policy_filter_matches[policy_id] = {}
            self._policy_filter_matches[policy_id].update(policy_filter_ids)

        if removed_policy is not None:
            self._removed_policies[policy_id] = removed_policy

        self._calc_stats()

    def get_message(self):
        """expose the copy of the message"""
        return deepcopy(self._message)

    def __str__(self):
        """to string"""
        return json.dumps(self._message)

    def _iter_over_removed_policies(self):
        """generator of iterator over removed_policies"""
        for (policy_id, value) in self._removed_policies.items():
            yield (policy_id, value)

    def _iter_over_latest_policies(self):
        """generator of iterator over latest_policies and policy_filter_matches"""
        for (policy_id, policy) in self._latest_policies.items():
            yield (policy_id, policy, self._policy_filter_matches.get(policy_id))

    def gen_segmented_messages(self, max_msg_length_mb):
        """
        Break the policy-update message into a list of segmented messages.

        Each segmented message should not exceed the max_msg_length_mb from config.
        """
        max_msg_length_mb = (max_msg_length_mb or 10) * PolicyUpdateMessage.BYTES_IN_MB

        messages = []
        curr_message = PolicyUpdateMessage(catch_up=self._catch_up)

        for (policy_id, value) in self._iter_over_removed_policies():
            if (not curr_message.empty()
                    and (len(policy_id) + len(str(value)) + curr_message.msg_length
                         > max_msg_length_mb)):
                messages.append(curr_message.get_message())
                curr_message = PolicyUpdateMessage(catch_up=self._catch_up)
            curr_message.add(policy_id, removed_policy=value)

        for (policy_id, policy, policy_filter_ids) in self._iter_over_latest_policies():
            if (not curr_message.empty()
                    and (2 * len(policy_id) + len(json.dumps(policy))
                         + len(json.dumps(policy_filter_ids))
                         + curr_message.msg_length > max_msg_length_mb)):
                messages.append(curr_message.get_message())
                curr_message = PolicyUpdateMessage(catch_up=self._catch_up)
            curr_message.add(policy_id, latest_policy=policy, policy_filter_ids=policy_filter_ids)

        if not curr_message.empty():
            messages.append(curr_message.get_message())

        msg_count = len(messages)
        if msg_count > 1:
            msg_count = "/" + str(msg_count)
            for idx, msg in enumerate(messages):
                msg["data_segment"] = str((idx+1)) + msg_count

        return messages


class DeployHandler(object):
    """calling the deployment-handler web apis"""
    _logger = logging.getLogger("policy_handler.deploy_handler")
    _lazy_inited = False

    _requests_session = None
    _url = None
    _url_policy = None
    _max_msg_length_mb = 10
    _target_entity = None
    _custom_kwargs = None
    _server_instance_uuid = None
    server_instance_changed = False

    @staticmethod
    def _lazy_init(audit, rediscover=False):
        """ set static properties """
        if DeployHandler._lazy_inited and not rediscover:
            return

        DeployHandler._custom_kwargs = (CustomizerUser.get_customizer()
                                        .get_deploy_handler_kwargs(audit))
        if (not DeployHandler._custom_kwargs
                or not isinstance(DeployHandler._custom_kwargs, dict)):
            DeployHandler._custom_kwargs = {}

        if not DeployHandler._requests_session:
            pool_size = Config.settings.get("pool_connections", 20)
            DeployHandler._requests_session = requests.Session()
            DeployHandler._requests_session.mount(
                'https://',
                requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
            )
            DeployHandler._requests_session.mount(
                'http://',
                requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
            )

        config_dh = Config.settings.get("deploy_handler")
        if config_dh and isinstance(config_dh, dict):
            # dns based routing to deployment-handler
            # config for policy-handler >= 2.4.0
            # "deploy_handler" : {
            #     "target_entity" : "deployment_handler",
            #     "url" : "http://deployment_handler:8188",
            #     "max_msg_length_mb" : 100
            # }
            DeployHandler._target_entity = config_dh.get("target_entity", "deployment_handler")
            DeployHandler._url = config_dh.get("url")
            DeployHandler._max_msg_length_mb = config_dh.get("max_msg_length_mb",
                                                             DeployHandler._max_msg_length_mb)
            DeployHandler._logger.info("dns based routing to %s: url(%s)",
                                       DeployHandler._target_entity, DeployHandler._url)

        if not DeployHandler._url:
            # discover routing to deployment-handler at consul-services
            if not isinstance(config_dh, dict):
                # config for policy-handler <= 2.3.1
                # "deploy_handler" : "deployment_handler"
                DeployHandler._target_entity = str(config_dh or "deployment_handler")
            DeployHandler._url = DiscoveryClient.get_service_url(audit,
                                                                 DeployHandler._target_entity)

        DeployHandler._url_policy = str(DeployHandler._url or "") + '/policy'
        DeployHandler._logger.info(
            "got %s policy url(%s)", DeployHandler._target_entity, DeployHandler._url_policy)

        DeployHandler._lazy_inited = bool(DeployHandler._url)


    @staticmethod
    def policy_update(audit, policy_update_message, rediscover=False):
        """
        segments the big policy_update_message limited by size
        and sequatially sends each segment as put to deployment-handler at /policy.

        param policy_update_message is of PolicyUpdateMessage type
        """
        if not policy_update_message or policy_update_message.empty():
            return

        DeployHandler._lazy_init(audit, rediscover)

        str_metrics = "policy_update {0}".format(str(policy_update_message))

        metrics_total = Metrics(
            aud_parent=audit,
            targetEntity="{0} total policy_update".format(DeployHandler._target_entity),
            targetServiceName=DeployHandler._url_policy)

        metrics_total.metrics_start("started {}".format(str_metrics))
        messages = policy_update_message.gen_segmented_messages(DeployHandler._max_msg_length_mb)
        for message in messages:
            DeployHandler._policy_update(audit, message)
            if not audit.is_success():
                break
        metrics_total.metrics("done {}".format(str_metrics))

    @staticmethod
    def _policy_update(audit, message):
        """
        sends the put message to deployment-handler at /policy

        detects whether server_instance_changed condition on deployment-handler
        that is the cause to catch_up
        """
        if not message:
            return

        metrics = Metrics(aud_parent=audit, targetEntity=DeployHandler._target_entity,
                          targetServiceName=DeployHandler._url_policy)
        headers = {REQUEST_X_ECOMP_REQUESTID : metrics.request_id}

        log_action = "put to {0} at {1}".format(
            DeployHandler._target_entity, DeployHandler._url_policy)
        log_data = " msg={0} headers={1}".format(json.dumps(message),
                                                 json.dumps(headers))
        log_line = log_action + log_data
        DeployHandler._logger.info(log_line)
        metrics.metrics_start(log_line)

        if not DeployHandler._url:
            error_msg = "no url found to {0}".format(log_line)
            DeployHandler._logger.error(error_msg)
            metrics.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            audit.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            metrics.metrics(error_msg)
            return

        res = None
        try:
            res = DeployHandler._requests_session.put(
                DeployHandler._url_policy, json=message, headers=headers,
                **DeployHandler._custom_kwargs
            )
        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = ("failed to {0} {1}: {2}{3}"
                         .format(log_action, type(ex).__name__, str(ex), log_data))
            DeployHandler._logger.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return

        metrics.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)

        log_line = "response {0} from {1}: text={2}{3}".format(res.status_code, log_action,
                                                               res.text, log_data)
        metrics.metrics(log_line)

        if res.status_code != requests.codes.ok:
            DeployHandler._logger.error(log_line)
            return

        DeployHandler._logger.info(log_line)
        result = res.json() or {}
        DeployHandler._server_instance_changed(result, metrics)


    @staticmethod
    def get_deployed_policies(audit, rediscover=False):
        """
        Retrieves policies and policy-filters from components
        that were deployed by deployment-handler
        """
        DeployHandler._lazy_init(audit, rediscover)
        metrics = Metrics(aud_parent=audit, targetEntity=DeployHandler._target_entity,
                          targetServiceName=DeployHandler._url_policy)
        headers = {REQUEST_X_ECOMP_REQUESTID : metrics.request_id}

        log_action = "get {0}: {1}".format(DeployHandler._target_entity, DeployHandler._url_policy)
        log_data = " headers={}".format(json.dumps(headers))
        log_line = log_action + log_data
        DeployHandler._logger.info(log_line)
        metrics.metrics_start(log_line)

        if not DeployHandler._url:
            error_msg = "no url found to {0}".format(log_line)
            DeployHandler._logger.error(error_msg)
            metrics.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            audit.set_http_status_code(AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value)
            metrics.metrics(error_msg)
            return None, None

        res = None
        try:
            res = DeployHandler._requests_session.get(
                DeployHandler._url_policy, headers=headers,
                **DeployHandler._custom_kwargs
            )
        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = ("failed to {0} {1}: {2}{3}"
                         .format(log_action, type(ex).__name__, str(ex), log_data))
            DeployHandler._logger.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return None, None

        metrics.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)

        log_line = ("response {0} from {1}: text={2}{3}"
                    .format(res.status_code, log_action, res.text, log_data))
        metrics.metrics(log_line)

        if res.status_code != requests.codes.ok:
            DeployHandler._logger.error(log_line)
            return None, None

        result = res.json() or {}
        DeployHandler._server_instance_changed(result, metrics)

        policies = result.get(POLICIES, {})
        policy_filters = result.get(POLICY_FILTERS, {})
        if not policies and not policy_filters:
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
            DeployHandler._logger.warning(audit.warn(
                "found no deployed policies or policy-filters: {}".format(log_line),
                error_code=AuditResponseCode.DATA_ERROR))
            return policies, policy_filters

        DeployHandler._logger.info(log_line)
        return policies, policy_filters

    @staticmethod
    def _server_instance_changed(result, metrics):
        """Checks whether the deployment-handler instance changed since last call."""
        prev_server_instance_uuid = DeployHandler._server_instance_uuid
        DeployHandler._server_instance_uuid = result.get("server_instance_uuid")

        if (prev_server_instance_uuid
                and prev_server_instance_uuid != DeployHandler._server_instance_uuid):
            DeployHandler.server_instance_changed = True

            log_line = ("deployment_handler_changed: {1} != {0}"
                        .format(prev_server_instance_uuid, DeployHandler._server_instance_uuid))
            metrics.info(log_line)
            DeployHandler._logger.info(log_line)
