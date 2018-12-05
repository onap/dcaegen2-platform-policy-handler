# ============LICENSE_START=======================================================
# Copyright (c) 2018 AT&T Intellectual Property. All rights reserved.
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
"""settings that are general to all tests"""

import copy
import json
import logging
import sys
import uuid
from datetime import datetime
from functools import wraps

from policyhandler import LogWriter
from policyhandler.config import Config
from policyhandler.discovery import DiscoveryClient
from policyhandler.onap.audit import Audit


def _fix_discover_config(func):
    """the decorator"""
    if not func:
        return None

    def mocked_discover_get_value(*_):
        """monkeypatch for get from consul"""
        return copy.deepcopy(Settings.mock_config)

    @wraps(func)
    def wrapper(*args, **kwargs):
        """override the DiscoveryClient.get_value to fake discovering the config"""

        old_get_value = DiscoveryClient.get_value
        DiscoveryClient.get_value = mocked_discover_get_value

        func_result = func(*args, **kwargs)

        DiscoveryClient.get_value = old_get_value

        return func_result
    return wrapper

class Settings(object):
    """init all locals"""
    _loaded = False
    logger = None
    mock_config = None
    deploy_handler_instance_uuid = str(uuid.uuid4())

    @staticmethod
    def init():
        """init configs"""
        if Settings._loaded:
            Settings.logger.info("testing policy_handler with config: %s", Config.discovered_config)
            return
        Settings._loaded = True

        Config.init_config()

        Config.consul_url = "http://unit-test-consul:850000"

        with open("tests/mock_config.json", 'r') as config_json:
            Settings.mock_config = json.load(config_json)

        Settings.logger = logging.getLogger("policy_handler.unit_test")
        sys.stdout = LogWriter(Settings.logger.info)
        sys.stderr = LogWriter(Settings.logger.error)

        print("print is expected to be in the log")
        Settings.logger.info("========== run_policy_handler ==========")
        Audit.init(Config.system_name, Config.LOGGER_CONFIG_FILE_PATH)
        Settings.rediscover_config()

    @staticmethod
    @_fix_discover_config
    def rediscover_config(updated_config=None):
        """rediscover the config"""
        if updated_config is not None:
            Settings.mock_config = copy.deepcopy(updated_config)

        audit = Audit(req_message="rediscover_config")

        Config.discover(audit)

        Settings.logger.info("testing policy_handler with config: %s", Config.discovered_config)

        audit.audit_done(" -- started")
