# ============LICENSE_START=======================================================
# Copyright (c) 2018-2020 AT&T Intellectual Property. All rights reserved.
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
"""settings that are general to all tests"""

import copy
import importlib
import json
import os
import sys
import uuid
from functools import wraps

from policyhandler import LogWriter
from policyhandler.config import Config
from policyhandler.discovery import DiscoveryClient
from policyhandler.onap.audit import Audit
from policyhandler.service_activator import ServiceActivator
from policyhandler.utils import Utils

_LOGGER = Utils.get_logger(__file__)

def _fix_discover_config(func):
    """the decorator"""
    if not func:
        return None

    def mocked_discover_get_value(*_):
        """monkeypatch for get from consul"""
        return copy.deepcopy(MockSettings.mock_config)

    @wraps(func)
    def wrapper(*args, **kwargs):
        """override the DiscoveryClient.get_value to fake discovering the config"""

        old_get_value = DiscoveryClient.get_value
        DiscoveryClient.get_value = mocked_discover_get_value

        func_result = func(*args, **kwargs)

        DiscoveryClient.get_value = old_get_value

        return func_result
    return wrapper

class MockSettings(object):
    """init all locals"""
    PDP_API_VERSION = "PDP_API_VERSION"
    OLD_PDP_API_VERSION = "pdp_api_v0"
    _loaded = False
    mock_config = None
    deploy_handler_instance_uuid = str(uuid.uuid4())

    @staticmethod
    def init_mock_config():
        """init configs"""
        if MockSettings._loaded:
            _LOGGER.info("testing policy_handler with config: %s", Config.discovered_config)
            return
        MockSettings._loaded = True

        _LOGGER.info("init MockSettings")

        MockSettings.reinit_mock_config()

        with open("tests/mock_config.json", 'r') as config_json:
            MockSettings.mock_config = json.load(config_json)

        sys.stdout = LogWriter(_LOGGER.info)
        sys.stderr = LogWriter(_LOGGER.error)

        print("print is expected to be in the log")
        _LOGGER.info("========== run_policy_handler ==========")
        Audit.init(Config.system_name, Config.LOGGER_CONFIG_FILE_PATH)
        MockSettings.rediscover_config()

    @staticmethod
    @_fix_discover_config
    def rediscover_config(updated_config=None):
        """rediscover the config"""
        if updated_config is not None:
            MockSettings.mock_config = copy.deepcopy(updated_config)

        audit = Audit(req_message="rediscover_config")

        Config.discover(audit)
        ServiceActivator.determine_mode_of_operation(audit)

        _LOGGER.info("testing policy_handler with config: %s", Config.discovered_config)

        audit.audit_done(" -- started")

    @staticmethod
    def setup_pdp_api(pdp_api_version=None):
        """set the environment var for pdp_api"""
        if Config._pdp_api_version == pdp_api_version:
            _LOGGER.info("unchanged setup_pdp_api %s", pdp_api_version)
            return

        _LOGGER.info("setup_pdp_api %s -> %s", Config._pdp_api_version, pdp_api_version)

        if pdp_api_version:
            os.environ[MockSettings.PDP_API_VERSION] = pdp_api_version
        elif MockSettings.PDP_API_VERSION in os.environ:
            del os.environ[MockSettings.PDP_API_VERSION]
        Config._pdp_api_version = pdp_api_version

        importlib.reload(importlib.import_module("policyhandler.pdp_client"))
        _LOGGER.info("done setup_pdp_api %s", Config._pdp_api_version)

    @staticmethod
    def reinit_mock_config():
        """reload the init configs"""
        Config.init_config("tests/etc_config.json")
