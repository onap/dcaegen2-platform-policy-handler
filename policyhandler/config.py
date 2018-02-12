# org.onap.dcae
# ================================================================================
# Copyright (c) 2017,2018 AT&T Intellectual Property. All rights reserved.
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

"""read and use the config"""

import os
import json
import copy
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
        return (Config.config or {}).get(Config.FIELD_SYSTEM, Config.SERVICE_NAME_POLICY_HANDLER)

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
