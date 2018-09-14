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

"""read and use the config"""

import copy
import json
import logging
import logging.config
import os

from .discovery import DiscoveryClient
from .onap.audit import Audit
from .policy_utils import Utils

LOGS_DIR = 'logs'

try:
    os.makedirs(LOGS_DIR, mode=0o770, exist_ok=True)
except Exception:
    pass

logging.basicConfig(
    filename=os.path.join(LOGS_DIR, 'policy_handler.log'),
    format=('%(asctime)s.%(msecs)03d %(levelname)+8s ' +
            '%(threadName)s %(name)s.%(funcName)s: %(message)s'),
    datefmt='%Y%m%d_%H%M%S', level=logging.DEBUG)

class Settings(object):
    """settings of module or an application
    that is the config filtered by the collection of config-keys.

    keeps track of changes versus the previous set_config unless committed
    """
    def __init__(self, *config_keys):
        """provide the collection of top level keys in config to limit the config"""
        self._config_keys = config_keys
        self._changed = False
        self._config = None
        self._prev_config = None

    def __str__(self):
        """get str of the config"""
        if not self._changed:
            return Audit.json_dumps({
                "config_keys": self._config_keys,
                "config": self._config
            })

        return Audit.json_dumps({
            "config_keys": self._config_keys,
            "changed": self._changed,
            "config": self._config,
            "prev_config": self._prev_config
        })

    def is_loaded(self):
        """whether loaded already"""
        return bool(self._config)

    def commit_change(self):
        """set the prev config to the latest config"""
        self._prev_config = copy.deepcopy(self._config)
        self._changed = False

    def _set_changed(self):
        """determine whether the config changed"""
        self._changed = not (self._prev_config
                             and Utils.are_the_same(self._prev_config, self._config,
                                                    Audit.json_dumps))

    def set_config(self, config, auto_commit=False):
        """update the config"""
        self.commit_change()

        if isinstance(config, Settings):
            config = config._config

        if not isinstance(config, dict):
            config = {}

        self._config = copy.deepcopy(dict((k, v) for (k, v) in config.items()
                                          if not self._config_keys or k in self._config_keys))

        if auto_commit:
            self.commit_change()
        else:
            self._set_changed()

    def is_changed(self):
        """whether the config has changed"""
        return self._changed

    def get_by_key(self, config_key, default=None):
        """get the latest sub config by config_key and whether it has changed"""
        if not config_key or not isinstance(config_key, str):
            return False, default

        value = copy.deepcopy(self._config.get(config_key, default))
        if not self._prev_config:
            return True, value
        prev_value = self._prev_config.get(config_key, default)
        return self._changed and not Utils.are_the_same(prev_value, value, Audit.json_dumps), value

    def update(self, config_key, value=None):
        """set the latest sub config by config_key and determine whether the config has changed"""
        if not config_key:
            return

        self._config[config_key] = copy.deepcopy(value)
        self._set_changed()


class Config(object):
    """main config of the application"""
    _logger = logging.getLogger("policy_handler.config")
    CONFIG_FILE_PATH = "etc/config.json"
    LOGGER_CONFIG_FILE_PATH = "etc/common_logger.config"
    SERVICE_NAME_POLICY_HANDLER = "policy_handler"

    FIELD_SYSTEM = "system"
    FIELD_WSERVICE_PORT = "wservice_port"
    FIELD_TLS = "tls"
    FIELD_POLICY_ENGINE = "policy_engine"
    POOL_CONNECTIONS = "pool_connections"
    DEPLOY_HANDLER = "deploy_handler"
    THREAD_POOL_SIZE = "thread_pool_size"
    POLICY_RETRY_COUNT = "policy_retry_count"
    POLICY_RETRY_SLEEP = "policy_retry_sleep"
    RECONFIGURE = "reconfigure"
    TIMER_INTERVAL = "interval"
    REQUESTS_VERIFY = "verify"
    TLS_CA_MODE = "tls_ca_mode"
    TLS_WSS_CA_MODE = "tls_wss_ca_mode"
    TLS_CA_MODE_DO_NOT_VERIFY = "do_not_verify"

    system_name = SERVICE_NAME_POLICY_HANDLER
    wservice_port = 25577
    tls_cacert_file = None
    tls_server_cert_file = None
    tls_private_key_file = None

    _local_config = Settings()
    discovered_config = Settings()

    @staticmethod
    def _set_tls_config(tls_config):
        """verify and set tls certs in config"""
        try:
            Config.tls_cacert_file = None
            Config.tls_server_cert_file = None
            Config.tls_private_key_file = None

            if not (tls_config and isinstance(tls_config, dict)):
                Config._logger.info("no tls in config: %s", json.dumps(tls_config))
                return

            cert_directory = tls_config.get("cert_directory")

            if not (cert_directory and isinstance(cert_directory, str)):
                Config._logger.info("unexpected tls.cert_directory: %r", cert_directory)
                return

            cert_directory = os.path.join(
                os.path.dirname(os.path.dirname(os.path.realpath(__file__))), cert_directory)
            if not (cert_directory and os.path.isdir(cert_directory)):
                Config._logger.info("ignoring invalid cert_directory: %s", cert_directory)
                return

            cacert = tls_config.get("cacert")
            if cacert:
                tls_cacert_file = os.path.join(cert_directory, cacert)
                if not os.path.isfile(tls_cacert_file):
                    Config._logger.error("invalid tls_cacert_file: %s", tls_cacert_file)
                else:
                    Config.tls_cacert_file = tls_cacert_file

            server_cert = tls_config.get("server_cert")
            if server_cert:
                tls_server_cert_file = os.path.join(cert_directory, server_cert)
                if not os.path.isfile(tls_server_cert_file):
                    Config._logger.error("invalid tls_server_cert_file: %s", tls_server_cert_file)
                else:
                    Config.tls_server_cert_file = tls_server_cert_file

            private_key = tls_config.get("private_key")
            if private_key:
                tls_private_key_file = os.path.join(cert_directory, private_key)
                if not os.path.isfile(tls_private_key_file):
                    Config._logger.error("invalid tls_private_key_file: %s", tls_private_key_file)
                else:
                    Config.tls_private_key_file = tls_private_key_file

        finally:
            Config._logger.info("tls_cacert_file = %s", Config.tls_cacert_file)
            Config._logger.info("tls_server_cert_file = %s", Config.tls_server_cert_file)
            Config._logger.info("tls_private_key_file = %s", Config.tls_private_key_file)

    @staticmethod
    def init_config(file_path=None):
        """read and store the config from config file"""
        if Config._local_config.is_loaded():
            Config._logger.info("config already inited: %s", Config._local_config)
            return

        if not file_path:
            file_path = Config.CONFIG_FILE_PATH

        loaded_config = None
        if os.access(file_path, os.R_OK):
            with open(file_path, 'r') as config_json:
                loaded_config = json.load(config_json)

        if not loaded_config:
            Config._logger.warning("config not loaded from file: %s", file_path)
            return

        Config._logger.info("config loaded from file: %s", file_path)
        logging_config = loaded_config.get("logging")
        if logging_config:
            logging.config.dictConfig(logging_config)

        Config.wservice_port = loaded_config.get(Config.FIELD_WSERVICE_PORT, Config.wservice_port)

        local_config = loaded_config.get(Config.SERVICE_NAME_POLICY_HANDLER, {})
        Config.system_name = local_config.get(Config.FIELD_SYSTEM, Config.system_name)

        Config._set_tls_config(local_config.get(Config.FIELD_TLS))

        Config._local_config.set_config(local_config, auto_commit=True)
        Config._logger.info("config loaded from file(%s): %s", file_path, Config._local_config)

    @staticmethod
    def discover(audit):
        """bring and merge the config settings from the discovery service"""
        discovery_key = Config.system_name
        new_config = DiscoveryClient.get_value(audit, discovery_key)

        if not new_config or not isinstance(new_config, dict):
            Config._logger.warning("unexpected config from discovery: %s", new_config)
            return

        Config._logger.debug("loaded config from discovery(%s): %s",
                             discovery_key, Audit.json_dumps(new_config))

        Config.discovered_config.set_config(new_config.get(Config.SERVICE_NAME_POLICY_HANDLER))
        Config._logger.info("config from discovery: %s", Config.discovered_config)


    @staticmethod
    def get_tls_verify(tls_ca_mode=None):
        """
        generate verify value based on tls_ca_mode

        tls_ca_mode can be one of:

        "cert_directory" - use the cacert.pem stored locally in cert_directory.
        this is the default if cacert.pem file is found

        "os_ca_bundle" - use the public ca_bundle provided by linux system.
        this is the default if cacert.pem file not found

        "do_not_verify" - special hack to turn off the verification by cacert and hostname
        """
        if tls_ca_mode == Config.TLS_CA_MODE_DO_NOT_VERIFY:
            return False

        if tls_ca_mode == "os_ca_bundle" or not Config.tls_cacert_file:
            return True

        return Config.tls_cacert_file

    @staticmethod
    def get_requests_kwargs(tls_ca_mode=None):
        """generate kwargs with verify for requests based on the tls_ca_mode"""
        return {Config.REQUESTS_VERIFY: Config.get_tls_verify(tls_ca_mode)}
