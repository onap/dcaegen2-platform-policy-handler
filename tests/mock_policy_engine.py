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
"""mocking for the policy-engine - shared by many tests"""

import copy
import json
import re

from policyhandler.policy_consts import (POLICY_BODY, POLICY_CONFIG, POLICY_ID,
                                         POLICY_NAME, POLICY_VERSION)
from policyhandler.policy_utils import PolicyUtils

from .mock_settings import Settings


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
            "updated_policy_id": policy_id
        }
        return {
            "policyConfigMessage": "Config Retrieved! ",
            "policyConfigStatus": "CONFIG_RETRIEVED",
            "type": "JSON",
            POLICY_NAME: "{0}.{1}.xml".format(policy_id, this_ver),
            POLICY_VERSION: this_ver,
            POLICY_CONFIG: json.dumps(config, sort_keys=True),
            "matchingConditions": {
                "ONAPName": "DCAE",
                "ConfigName": "alex_config_name"
            },
            "responseAttributes": {},
            "property": None
        }


class MockPolicyEngine(object):
    """pretend this is the policy-engine"""
    scope_prefix = "test_scope_prefix.Config_"
    LOREM_IPSUM = """Lorem ipsum dolor sit amet consectetur ametist""".split()
    LONG_TEXT = "0123456789" * 100
    _policies = []

    _inited = False

    @staticmethod
    def init():
        """init static vars"""
        if MockPolicyEngine._inited:
            return
        MockPolicyEngine._inited = True

        MockPolicyEngine._policies = [
            MonkeyPolicyBody.create_policy_body(
                MockPolicyEngine.scope_prefix + policy_id, policy_index + 1)
            for policy_id in MockPolicyEngine.LOREM_IPSUM
            for policy_index in range(1 + MockPolicyEngine.LOREM_IPSUM.index(policy_id))]
        Settings.logger.info("MockPolicyEngine._policies: %s",
                             json.dumps(MockPolicyEngine._policies))

    @staticmethod
    def get_config(policy_name):
        """find policy the way the policy-engine finds"""
        if not policy_name:
            return []
        return [copy.deepcopy(policy)
                for policy in MockPolicyEngine._policies
                if re.match(policy_name, policy[POLICY_NAME])]

    @staticmethod
    def get_configs_all():
        """get all policies the way the policy-engine finds"""
        policies = [copy.deepcopy(policy)
                    for policy in MockPolicyEngine._policies]
        for policy in policies:
            policy["config"] = MockPolicyEngine.LONG_TEXT
        return policies

    @staticmethod
    def get_policy_id(policy_index):
        """get the policy_id by index"""
        return (MockPolicyEngine.scope_prefix
                + MockPolicyEngine.LOREM_IPSUM[
                    policy_index % len(MockPolicyEngine.LOREM_IPSUM)])

    @staticmethod
    def gen_policy_latest(policy_index, version_offset=0):
        """generate the policy response by policy_index = version - 1"""
        policy_id = MockPolicyEngine.get_policy_id(policy_index)
        policy = {
            POLICY_ID: policy_id,
            POLICY_BODY: MonkeyPolicyBody.create_policy_body(
                policy_id, policy_index + 1 - version_offset)
        }
        return policy_id, PolicyUtils.parse_policy_config(policy)

    @staticmethod
    def gen_all_policies_latest(version_offset=0):
        """generate all latest policies"""
        return dict(MockPolicyEngine.gen_policy_latest(policy_index, version_offset=version_offset)
                    for policy_index in range(len(MockPolicyEngine.LOREM_IPSUM)))

    @staticmethod
    def gen_policies_latest(match_to_policy_name):
        """generate all latest policies"""
        return dict((k, v)
                    for k, v in MockPolicyEngine.gen_all_policies_latest().items()
                    if re.match(match_to_policy_name, k))
