# ================================================================================
# Copyright (c) 2019-2020 AT&T Intellectual Property. All rights reserved.
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

"""
    ask service_activator for the mode_of_operation
    that is whether the current site/cluster is active versus passive

    active is the default and expects the polisy-handler
        to receive the push notifications from policy-engine
        as well as to periodically run the catch_up process

    passive expects the polisy-handler
        to stop listening for the policy-updates from the policy-engine
        and to stop doing the periodic catch_up
"""

import json
from copy import deepcopy
from urllib.parse import urljoin

import requests

from .config import Config, Settings
from .discovery import DiscoveryClient
from .onap.audit import Audit, AuditHttpCode, Metrics
from .policy_consts import TARGET_ENTITY
from .utils import Utils

_LOGGER = Utils.get_logger(__file__)

class ServiceActivator(object):
    """calling the service_activator web api to determine the mode_of_operation"""
    DEFAULT_TARGET_ENTITY = "service_activator"
    DEFAULT_TIMEOUT_IN_SECS = 10
    MODE_OF_OPERATION_ACTIVE = "active"
    SERVICE_MODE = "service_mode"

    _lazy_inited = False
    _settings = Settings(Config.MODE_OF_OPERATION, Config.SERVICE_ACTIVATOR)

    _mode_of_operation = None
    _url = None
    _url_register = None
    _post_register = {}
    _target_entity = None
    _custom_kwargs = {}
    _timeout_in_secs = DEFAULT_TIMEOUT_IN_SECS


    @staticmethod
    def _init(audit):
        """
        initialize service-activator client config based on discovered config:

            "mode_of_operation" : "active",
            "service_activator" : {
                "target_entity" : "service_activator",
                "url" : "https://service-activator-service:123",
                "path_register" : "/register",
                "tls_ca_mode" : "cert_directory",
                "timeout_in_secs": 20,
                "post_register" : {
                    "component_name" : "policy_handler",
                    "reconfigure_path" : "/reconfigure",
                    "http_protocol" : "http"
                }
            }
        """
        ServiceActivator._custom_kwargs = {}
        ServiceActivator._url = ServiceActivator._url_register = ""
        Audit.register_item_health(ServiceActivator.SERVICE_MODE, ServiceActivator._get_service_mode)

        try:
            _, ServiceActivator._mode_of_operation = ServiceActivator._settings.get_by_key(
                Config.MODE_OF_OPERATION, ServiceActivator._mode_of_operation)

            _, config_sa = ServiceActivator._settings.get_by_key(Config.SERVICE_ACTIVATOR)
            if config_sa and isinstance(config_sa, dict):
                ServiceActivator._target_entity = config_sa.get(
                    TARGET_ENTITY, ServiceActivator.DEFAULT_TARGET_ENTITY)
                ServiceActivator._url = config_sa.get("url", "")
                if not ServiceActivator._url:
                    ServiceActivator._url = DiscoveryClient.get_service_url(audit,
                                                             ServiceActivator._target_entity)
                if ServiceActivator._url:
                    ServiceActivator._url_register = urljoin(ServiceActivator._url,
                                                             config_sa.get("path_register", ""))
                ServiceActivator._post_register = deepcopy(config_sa.get("post_register", {}))
                tls_ca_mode = config_sa.get(Config.TLS_CA_MODE)
                ServiceActivator._custom_kwargs = Config.get_requests_kwargs(tls_ca_mode)

                _LOGGER.info(audit.info(
                    "dns based routing to %s: url(%s) tls_ca_mode(%s) custom_kwargs(%s)",
                    ServiceActivator._target_entity, ServiceActivator._url_register,
                    tls_ca_mode, json.dumps(ServiceActivator._custom_kwargs)))

                ServiceActivator._timeout_in_secs = config_sa.get(Config.TIMEOUT_IN_SECS)
                if not ServiceActivator._timeout_in_secs or ServiceActivator._timeout_in_secs < 1:
                    ServiceActivator._timeout_in_secs = ServiceActivator.DEFAULT_TIMEOUT_IN_SECS

            ServiceActivator._settings.commit_change()
        except Exception:
            pass
        ServiceActivator._lazy_inited = True

    @staticmethod
    def reconfigure(audit):
        """reconfigure"""
        ServiceActivator._settings.set_config(Config.discovered_config)
        if not ServiceActivator._settings.is_changed():
            ServiceActivator._settings.commit_change()
            return False

        ServiceActivator._lazy_inited = False
        ServiceActivator._init(audit)
        return True

    @staticmethod
    def _lazy_init(audit):
        """set config"""
        if ServiceActivator._lazy_inited:
            return

        ServiceActivator._settings.set_config(Config.discovered_config)
        ServiceActivator._init(audit)

    @staticmethod
    def _get_service_mode():
        """returns the service_mode as json to be reported by the healthcheck"""
        return {
            "is_active_mode_of_operation": ServiceActivator.is_active_mode_of_operation(),
            "is_pdp_api_default": Config.is_pdp_api_default(log_status=False)
        }

    @staticmethod
    def is_active_mode_of_operation(audit=None):
        """
        mode_of_operation - whether the service is
            active == True or passive == False
            based on the current value of the mode_of_operation
        """
        active = (ServiceActivator._mode_of_operation is None
                  or ServiceActivator._mode_of_operation
                  == ServiceActivator.MODE_OF_OPERATION_ACTIVE)

        if audit:
            _LOGGER.info(audit.info("mode_of_operation = {} active = {}".format(
                ServiceActivator._mode_of_operation, active)))
        return active

    @staticmethod
    def determine_mode_of_operation(audit):
        """retrieves the mode_of_operation from service_activator"""
        try:
            ServiceActivator._lazy_init(audit)

            target_entity = ServiceActivator._target_entity

            if not ServiceActivator._url:
                _LOGGER.info(audit.info("no url found for {}".format(target_entity)))
                return ServiceActivator.is_active_mode_of_operation(audit)

            url = ServiceActivator._url_register
            json_body = deepcopy(ServiceActivator._post_register)
            timeout_in_secs = ServiceActivator._timeout_in_secs
            custom_kwargs = deepcopy(ServiceActivator._custom_kwargs)

            metrics = Metrics(aud_parent=audit,
                              targetEntity="{} determine_mode_of_operation".format(target_entity),
                              targetServiceName=url)
            headers = metrics.put_request_id_into_headers()

            log_action = "post to {} at {}".format(target_entity, url)
            log_data = "headers={}, json_body={}, timeout_in_secs={}, custom_kwargs({})".format(
                json.dumps(headers), json.dumps(json_body), timeout_in_secs,
                json.dumps(custom_kwargs))
            log_line = log_action + " " + log_data

            _LOGGER.info(log_line)
            metrics.metrics_start(log_line)

            res = None
            try:
                res = requests.post(url, json=json_body, headers=headers, timeout=timeout_in_secs,
                                    **custom_kwargs)
            except Exception as ex:
                error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                              if isinstance(ex, requests.exceptions.RequestException)
                              else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
                error_msg = "failed to {} {}: {} {}".format(
                    log_action, type(ex).__name__, str(ex), log_data)
                _LOGGER.exception(error_msg)
                metrics.set_http_status_code(error_code)
                audit.set_http_status_code(error_code)
                metrics.metrics(error_msg)
                return ServiceActivator.is_active_mode_of_operation(audit)

            metrics.set_http_status_code(res.status_code)
            audit.set_http_status_code(res.status_code)

            log_line = "response {} from {}: text={} {}".format(
                res.status_code, log_action, res.text, log_data)
            metrics.metrics(log_line)

            if res.status_code != requests.codes.ok:
                _LOGGER.error(log_line)
                return ServiceActivator.is_active_mode_of_operation(audit)

            result = res.json() or {}

            ServiceActivator._mode_of_operation = (result.get(Config.MODE_OF_OPERATION)
                                                   or ServiceActivator._mode_of_operation)
            return ServiceActivator.is_active_mode_of_operation(audit)

        except Exception as ex:
            return ServiceActivator.is_active_mode_of_operation(audit)
