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


class MonkeyHttpResponse(object):
    """Monkey http reposne"""
    def __init__(self, headers):
        self.headers = headers or {}


class MonkeyedResponse(object):
    """Monkey response"""
    def __init__(self, full_path, res_json, json_body=None, headers=None):
        self.full_path = full_path
        self.req_json = json_body or {}
        self.status_code = 200
        self.request = MonkeyHttpResponse(headers)
        self.res = res_json
        self.text = json.dumps(self.res)

    def json(self):
        """returns json of response"""
        return self.res

    def raise_for_status(self):
        """ignoring"""
        pass


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
    RUN_TS = datetime.utcnow().isoformat()[:-3] + 'Z'
    mock_config = None
    deploy_handler_instance_uuid = str(uuid.uuid4())

    @staticmethod
    @_fix_discover_config
    def init():
        """init configs"""
        if Settings._loaded:
            return
        Settings._loaded = True

        Config.init_config()

        with open("tests/mock_config.json", 'r') as config_json:
            Settings.mock_config = json.load(config_json)

        Settings.logger = logging.getLogger("policy_handler.unit_test")
        sys.stdout = LogWriter(Settings.logger.info)
        sys.stderr = LogWriter(Settings.logger.error)

        print("print is expected to be in the log")
        Settings.logger.info("========== run_policy_handler ==========")
        Audit.init(Config.system_name, Config.LOGGER_CONFIG_FILE_PATH)
        audit = Audit(req_message="start testing policy handler")

        Config.discover(audit)

        Settings.logger.info("testing policy_handler with config: %s", Config.discovered_config)

        audit.audit_done(" -- started")
