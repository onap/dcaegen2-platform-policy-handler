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

"""client to talk to consul services and kv"""

import base64
import json
import logging

import requests

from .config import Config
from .customize import CustomizerUser
from .onap.audit import AuditHttpCode, Metrics


class DiscoveryClient(object):
    """talking to consul at Config.consul_url

    Config.consul_url is populated
        from env var $CONSUL_URL
        if not provided, then from consul_url in etc/config.json
        if not provided, then from hardcoded value of http://consul:8500

    relies on proper --add-host "consul:<consul-agent ip>" in
    docker run command that runs along the consul-agent:

    docker run --name ${APPNAME} -d
        -e HOSTNAME -e CONSUL_URL
        --add-host "consul:<consul-agent ip>"
        -v ${BASEDIR}/logs:${TARGETDIR}/logs
        -v ${BASEDIR}/etc:${TARGETDIR}/etc
        -p <outport>:<innerport>
        ${APPNAME}:latest
    """
    CONSUL_ENTITY = "consul"
    CONSUL_SERVICE_MASK = "{}/v1/catalog/service/{}"
    CONSUL_KV_MASK = "{}/v1/kv/{}"
    _logger = logging.getLogger("policy_handler.discovery")

    @staticmethod
    def _discover_service(audit, service_name, service_path):
        """find the service record in consul"""
        response = requests.get(service_path, timeout=Config.consul_timeout_in_secs)
        DiscoveryClient._logger.info(audit.info("response {} from {}: {}".format(
            response.status_code, service_path, response.text)))

        response.raise_for_status()
        status_code = response.status_code
        service = response.json()[0]
        return (status_code,
                CustomizerUser.get_customizer().get_service_url(audit, service_name, service))

    @staticmethod
    def get_service_url(audit, service_name):
        """find the service record in consul"""
        service_path = DiscoveryClient.CONSUL_SERVICE_MASK.format(Config.consul_url, service_name)
        metrics = Metrics(aud_parent=audit, targetEntity=DiscoveryClient.CONSUL_ENTITY,
                          targetServiceName=service_path)

        log_line = "get from {} at {}".format(DiscoveryClient.CONSUL_ENTITY, service_path)

        DiscoveryClient._logger.info(metrics.metrics_start(log_line))
        status_code = None
        try:
            (status_code,
             service_url) = DiscoveryClient._discover_service(audit, service_name, service_path)
        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = ("failed {}/{} to {} {}: {}".format(status_code, error_code, log_line,
                                                            type(ex).__name__, str(ex)))
            DiscoveryClient._logger.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return None

        if not service_url:
            error_code = AuditHttpCode.DATA_ERROR.value
            error_msg = "failed {}/{} to {}".format(status_code, error_code, log_line)
            DiscoveryClient._logger.error(audit.error(error_msg))
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return None

        log_line = "response {} {}".format(status_code, log_line)
        DiscoveryClient._logger.info(audit.info("got service_url: {} after {}"
                                                .format(service_url, log_line)))

        metrics.set_http_status_code(status_code)
        audit.set_http_status_code(status_code)
        metrics.metrics(log_line)
        return service_url

    @staticmethod
    def _get_value_from_kv(url):
        """get the value from consul-kv at discovery url"""
        response = requests.get(url, timeout=Config.consul_timeout_in_secs)
        response.raise_for_status()
        data = response.json()
        value = base64.b64decode(data[0]["Value"]).decode("utf-8")
        return response.status_code, json.loads(value)

    @staticmethod
    def get_value(audit, key):
        """get the value for the key from consul-kv"""
        discovery_url = DiscoveryClient.CONSUL_KV_MASK.format(Config.consul_url, key)
        metrics = Metrics(aud_parent=audit, targetEntity=DiscoveryClient.CONSUL_ENTITY,
                          targetServiceName=discovery_url)

        log_line = "get from {} at {}".format(DiscoveryClient.CONSUL_ENTITY, discovery_url)

        DiscoveryClient._logger.info(metrics.metrics_start(log_line))
        status_code = None
        try:
            status_code, value = DiscoveryClient._get_value_from_kv(discovery_url)
        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = ("failed {}/{} to {} {}: {}".format(status_code, error_code, log_line,
                                                            type(ex).__name__, str(ex)))
            DiscoveryClient._logger.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return None

        log_line = "response {} {}".format(status_code, log_line)
        metrics.set_http_status_code(status_code)
        audit.set_http_status_code(status_code)
        metrics.metrics(log_line)
        return value
