"""read and use the config"""

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

import os
import json
import copy
import re
import base64
import logging
import logging.config

from .discovery import DiscoveryClient

logging.basicConfig(
    filename='logs/policy_handler.log', \
    format='%(asctime)s.%(msecs)03d %(levelname)+8s ' + \
           '%(threadName)s %(name)s.%(funcName)s: %(message)s', \
    datefmt='%Y%m%d_%H%M%S', level=logging.DEBUG)

class Config(object):
    """main config of the application"""
    CONFIG_FILE_PATH = "etc/config.json"
    LOGGER_CONFIG_FILE_PATH = "etc/common_logger.config"
    SERVICE_NAME_POLICY_HANDLER = "policy_handler"
    FIELD_SYSTEM = "system"
    FIELD_WSERVICE_PORT = "wservice_port"
    FIELD_POLICY_ENGINE = "policy_engine"
    wservice_port = 25577
    _logger = logging.getLogger("policy_handler.config")
    config = None

    @staticmethod
    def merge(new_config):
        """merge the new_config into current config - override the values"""
        if not new_config:
            return

        if not Config.config:
            Config.config = new_config
            return

        new_config = copy.deepcopy(new_config)
        Config.config.update(new_config)

    @staticmethod
    def get_system_name():
        """find the name of the policy-handler system
        to be used as the key in consul-kv for config of policy-handler
        """
        system_name = None
        if Config.config:
            system_name = Config.config.get(Config.FIELD_SYSTEM)

        return system_name or Config.SERVICE_NAME_POLICY_HANDLER

    @staticmethod
    def discover():
        """bring and merge the config settings from the discovery service"""
        discovery_key = Config.get_system_name()
        new_config = DiscoveryClient.get_value(discovery_key)

        if not new_config or not isinstance(new_config, dict):
            Config._logger.warn("unexpected config from discovery: %s", new_config)
            return

        Config._logger.debug("loaded config from discovery(%s): %s", \
            discovery_key, json.dumps(new_config))
        Config._logger.debug("config before merge from discovery: %s", json.dumps(Config.config))
        Config.merge(new_config.get(Config.SERVICE_NAME_POLICY_HANDLER))
        Config._logger.debug("merged config from discovery: %s", json.dumps(Config.config))

    @staticmethod
    def upload_to_discovery():
        """upload the current config settings to the discovery service"""
        if not Config.config or not isinstance(Config.config, dict):
            Config._logger.error("unexpected config: %s", Config.config)
            return

        discovery_key = Config.get_system_name()
        latest_config = json.dumps({Config.SERVICE_NAME_POLICY_HANDLER:Config.config})
        DiscoveryClient.put_kv(discovery_key, latest_config)
        Config._logger.debug("uploaded config to discovery(%s): %s", \
            discovery_key, latest_config)

    @staticmethod
    def load_from_file(file_path=None):
        """read and store the config from config file"""
        if not file_path:
            file_path = Config.CONFIG_FILE_PATH

        loaded_config = None
        if os.access(file_path, os.R_OK):
            with open(file_path, 'r') as config_json:
                loaded_config = json.load(config_json)

        if not loaded_config:
            Config._logger.info("config not loaded from file: %s", file_path)
            return

        Config._logger.info("config loaded from file: %s", file_path)
        logging_config = loaded_config.get("logging")
        if logging_config:
            logging.config.dictConfig(logging_config)

        Config.wservice_port = loaded_config.get(Config.FIELD_WSERVICE_PORT, Config.wservice_port)
        Config.merge(loaded_config.get(Config.SERVICE_NAME_POLICY_HANDLER))
        return True

class PolicyEngineConfig(object):
    """main config of the application"""
    # PATH_TO_PROPERTIES = r'logs/policy_engine.properties'
    PATH_TO_PROPERTIES = r'tmp/policy_engine.properties'
    PYPDP_URL = "PYPDP_URL = {0}{1}, {2}, {3}\n"
    CLIENT_ID = "CLIENT_ID = {0}\n"
    CLIENT_KEY = "CLIENT_KEY = {0}\n"
    ENVIRONMENT = "ENVIRONMENT = {0}\n"
    _logger = logging.getLogger("policy_handler.pe_config")

    @staticmethod
    def save_to_file():
        """create the policy_engine.properties for policy-engine client"""
        file_path = PolicyEngineConfig.PATH_TO_PROPERTIES

        try:
            config = Config.config[Config.FIELD_POLICY_ENGINE]
            headers = config["headers"]
            remove_basic = re.compile(r"(^Basic )")
            client_parts = base64.b64decode(remove_basic.sub("", headers["ClientAuth"])).split(":")
            auth_parts = base64.b64decode(remove_basic.sub("", headers["Authorization"])).split(":")

            props = PolicyEngineConfig.PYPDP_URL.format(config["url"], config["path_pdp"],
                                                        auth_parts[0], auth_parts[1])
            props += PolicyEngineConfig.CLIENT_ID.format(client_parts[0])
            props += PolicyEngineConfig.CLIENT_KEY.format(base64.b64encode(client_parts[1]))
            props += PolicyEngineConfig.ENVIRONMENT.format(headers["Environment"])

            with open(file_path, 'w') as prp_file:
                prp_file.write(props)
            PolicyEngineConfig._logger.info("created %s", file_path)
        except IOError:
            PolicyEngineConfig._logger.error("failed to save to %s", file_path)
        except KeyError:
            PolicyEngineConfig._logger.error("unexpected config for %s", Config.FIELD_POLICY_ENGINE)
