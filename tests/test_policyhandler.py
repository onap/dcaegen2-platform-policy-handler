# ============LICENSE_START=======================================================
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

import sys
import json
import re
import logging
from datetime import datetime

# import pytest

from policyhandler.config import Config
from policyhandler.policy_handler import LogWriter
from policyhandler.onap.audit import Audit
from policyhandler.policy_rest import PolicyRest, PolicyUtils
from policyhandler.policy_consts import POLICY_ID, POLICY_VERSION, POLICY_NAME, \
    POLICY_BODY, POLICY_CONFIG

class Settings(object):
    """init all locals"""
    logger = None
    RUN_TS = datetime.utcnow().isoformat()[:-3] + 'Z'

    @staticmethod
    def init():
        """init locals"""
        Config.load_from_file()
        Config.load_from_file("etc_upload/config.json")

        Settings.logger = logging.getLogger("policy_handler")
        sys.stdout = LogWriter(Settings.logger.info)
        sys.stderr = LogWriter(Settings.logger.error)

        Settings.logger.info("========== run_policy_handler ==========")
        Audit.init(Config.get_system_name(), Config.LOGGER_CONFIG_FILE_PATH)

        Settings.logger.info("starting policy_handler with config:")
        Settings.logger.info(Audit.log_json_dumps(Config.config))

        PolicyRest._lazy_init()

Settings.init()

class MonkeyPolicyBody(object):
    """policy body that policy-engine returns"""
    @staticmethod
    def create_policy_body(policy_id, policy_version=1):
        """returns a fake policy-body"""
        prev_ver = str(policy_version - 1)
        this_ver = str(policy_version)
        config = {
            "policy_updated_from_ver": prev_ver,
            "policy_updated_to_ver": this_ver,
            "policy_hello": "world!",
            "policy_updated_ts": Settings.RUN_TS,
            "updated_policy_id": policy_id
        }
        return {
            "policyConfigMessage": "Config Retrieved! ",
            "policyConfigStatus": "CONFIG_RETRIEVED",
            "type": "JSON",
            POLICY_NAME: "{0}.{1}.xml".format(policy_id, this_ver),
            POLICY_VERSION: this_ver,
            POLICY_CONFIG: json.dumps(config),
            "matchingConditions": {
                "ECOMPName": "DCAE",
                "ConfigName": "alex_config_name"
            },
            "responseAttributes": {},
            "property": None
        }

    @staticmethod
    def is_the_same_dict(policy_body_1, policy_body_2):
        """check whether both policy_body objects are the same"""
        if not isinstance(policy_body_1, dict) or not isinstance(policy_body_2, dict):
            return False
        for key in policy_body_1.keys():
            if key not in policy_body_2:
                return False
            if isinstance(policy_body_1[key], dict):
                return MonkeyPolicyBody.is_the_same_dict(
                    policy_body_1[key], policy_body_2[key])
            if (policy_body_1[key] is None and policy_body_2[key] is not None) \
            or (policy_body_1[key] is not None and policy_body_2[key] is None) \
            or (policy_body_1[key] != policy_body_2[key]):
                return False
        return True

class MonkeyPolicyEngine(object):
    """pretend this is the policy-engine"""
    _scope_prefix = Config.config["scope_prefixes"][0]
    LOREM_IPSUM = """Lorem ipsum dolor sit amet consectetur""".split()
    _policies = []

    @staticmethod
    def init():
        """init static vars"""
        MonkeyPolicyEngine._policies = [
            MonkeyPolicyBody.create_policy_body(
                MonkeyPolicyEngine._scope_prefix + policy_id, policy_version)
            for policy_id in MonkeyPolicyEngine.LOREM_IPSUM
            for policy_version in range(1, 1 + MonkeyPolicyEngine.LOREM_IPSUM.index(policy_id))]

    @staticmethod
    def get_config(policy_name):
        """find policy the way the policy-engine finds"""
        if not policy_name:
            return []
        if policy_name[-2:] == ".*":
            policy_name = policy_name[:-2]
        return [policy for policy in MonkeyPolicyEngine._policies
                if re.match(policy_name, policy[POLICY_NAME])]

    @staticmethod
    def get_policy_id(policy_index):
        """get the policy_id by index"""
        return MonkeyPolicyEngine._scope_prefix \
             + MonkeyPolicyEngine.LOREM_IPSUM[policy_index % len(MonkeyPolicyEngine.LOREM_IPSUM)]

MonkeyPolicyEngine.init()

class MonkeyHttpResponse(object):
    """Monkey http reposne"""
    def __init__(self, headers):
        self.headers = headers or {}

class MonkeyedResponse(object):
    """Monkey response"""
    def __init__(self, full_path, json_body, headers):
        self.full_path = full_path
        self.req_json = json_body or {}
        self.status_code = 200
        self.request = MonkeyHttpResponse(headers)
        self.req_policy_name = self.req_json.get(POLICY_NAME)
        self.res = MonkeyPolicyEngine.get_config(self.req_policy_name)
        self.text = json.dumps(self.res)

    def json(self):
        """returns json of response"""
        return self.res

def monkeyed_policy_rest_post(full_path, json={}, headers={}):
    """monkeypatch for the POST to policy-engine"""
    return MonkeyedResponse(full_path, json, headers)

def test_get_policy_latest(monkeypatch):
    """test /policy_latest/<policy-id>"""
    monkeypatch.setattr('policyhandler.policy_rest.PolicyRest._requests_session.post', \
        monkeyed_policy_rest_post)
    policy_index = 3
    policy_id = MonkeyPolicyEngine.get_policy_id(policy_index)
    expected_policy = {
        POLICY_ID : policy_id,
        POLICY_BODY : MonkeyPolicyBody.create_policy_body(policy_id, policy_index)
    }
    expected_policy = PolicyUtils.parse_policy_config(expected_policy)

    audit = Audit(req_message="get /policy_latest/{0}".format(policy_id or ""))
    policy_latest = PolicyRest.get_latest_policy((audit, policy_id)) or {}
    audit.audit_done(result=json.dumps(policy_latest))

    Settings.logger.info("expected_policy: {0}".format(json.dumps(expected_policy)))
    Settings.logger.info("policy_latest: {0}".format(json.dumps(policy_latest)))
    assert MonkeyPolicyBody.is_the_same_dict(policy_latest, expected_policy)
    assert MonkeyPolicyBody.is_the_same_dict(expected_policy, policy_latest)
