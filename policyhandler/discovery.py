"""client to talk to consul at the standard port 8500"""

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
import base64
import requests

class DiscoveryClient(object):
    """talking to consul at http://consul:8500

    relies on proper --add-host "consul:<consul-agent ip>" in
    docker run command that runs along the consul-agent:

    docker run --name ${APPNAME} -d
        -e HOSTNAME
        --add-host "consul:<consul-agent ip>"
        -v ${BASEDIR}/logs:${TARGETDIR}/logs
        -v ${BASEDIR}/etc:${TARGETDIR}/etc
        -p <outport>:<innerport>
        ${APPNAME}:latest
    """
    CONSUL_SERVICE_MASK = "http://consul:8500/v1/catalog/service/{0}"
    CONSUL_KV_MASK = "http://consul:8500/v1/kv/{0}"
    SERVICE_MASK = "http://{0}:{1}"
    _logger = logging.getLogger("policy_handler.discovery")


    @staticmethod
    def get_service_url(service_name):
        """find the service record in consul"""
        service_path = DiscoveryClient.CONSUL_SERVICE_MASK.format(service_name)
        DiscoveryClient._logger.info("discover %s", service_path)
        response = requests.get(service_path)
        response.raise_for_status()
        service = response.json()[0]
        return DiscoveryClient.SERVICE_MASK.format( \
                service["ServiceAddress"], service["ServicePort"])

    @staticmethod
    def get_value(key):
        """get the value for the key from consul-kv"""
        response = requests.get(DiscoveryClient.CONSUL_KV_MASK.format(key))
        response.raise_for_status()
        data = response.json()[0]
        value = base64.b64decode(data["Value"]).decode("utf-8")
        DiscoveryClient._logger.info("consul-kv key=%s data=%s value(%s)", \
            key, json.dumps(data), value)
        return json.loads(value)

    @staticmethod
    def put_kv(key, value):
        """put the value under the key in consul-kv"""
        response = requests.put(DiscoveryClient.CONSUL_KV_MASK.format(key), data=value)
        response.raise_for_status()
