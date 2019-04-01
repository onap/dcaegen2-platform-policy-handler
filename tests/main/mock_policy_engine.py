# ============LICENSE_START=======================================================
# Copyright (c) 2018-2019 AT&T Intellectual Property. All rights reserved.
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
"""mocking for the policy-engine - shared by many tests"""

import copy
import json

from policyhandler.pdp_api.pdp_consts import (PDP_METADATA,
                                              PDP_POLICY_ID,
                                              PDP_POLICY_VERSION,
                                              PDP_POLICIES, PDP_PROPERTIES)
from policyhandler.pdp_api.policy_utils import PolicyUtils
from policyhandler.utils import Utils

_LOGGER = Utils.get_logger(__file__)


class MockPolicyEngine(object):
    """pretend this is the policy-engine"""
    scope_prefix = "test_scope_prefix.pdp_desition_"
    LOREM_IPSUM = """Lorem ipsum dolor sit amet consectetur ametist""".split()
    LONG_TEXT = "0123456789" * 100
    _policies = {}

    _inited = False

    @staticmethod
    def init():
        """init collection of policies: policy_version = policy_index + 1"""
        if MockPolicyEngine._inited:
            return
        MockPolicyEngine._inited = True

        MockPolicyEngine._policies = dict(
            (policy_id, MockPolicyEngine._create_policy_body(policy_id, policy_version))
            for policy_id, policy_version in
            [(MockPolicyEngine.get_policy_id(policy_index), policy_index + 1)
             for policy_index in range(1 + len(MockPolicyEngine.LOREM_IPSUM))]
        )
        _LOGGER.info("_policies: %s", json.dumps(MockPolicyEngine._policies))

    @staticmethod
    def get_policy_id(policy_index):
        """get the policy_id by policy_index"""
        return (MockPolicyEngine.scope_prefix
                + MockPolicyEngine.LOREM_IPSUM[
                    policy_index % len(MockPolicyEngine.LOREM_IPSUM)])

    @staticmethod
    def get_policy(policy_id):
        """find policy the way the policy-engine finds"""
        if policy_id not in MockPolicyEngine._policies:
            return {}
        return {PDP_POLICIES: {policy_id: copy.deepcopy(MockPolicyEngine._policies[policy_id])}}

    @staticmethod
    def gen_policy_latest(policy_index, version_offset=0):
        """generate the policy response from policy-handler by policy_index = version - 1"""
        policy_id = MockPolicyEngine.get_policy_id(policy_index)
        policy = PolicyUtils.convert_to_policy(
            MockPolicyEngine._create_policy_body(policy_id, policy_index + 1 - version_offset)
        )
        return policy_id, policy

    @staticmethod
    def _create_policy_body(policy_id, policy_version=1):
        """returns a fake policy-body"""
        return {
            "type": "unit.test.type.policies",
            "version": "1.0.0",
            PDP_METADATA: {
                PDP_POLICY_ID: policy_id,
                PDP_POLICY_VERSION: policy_version,
                "description": "description for {}".format(policy_id)
            },
            PDP_PROPERTIES: {
                "policy_updated_from_ver": (policy_version - 1),
                "policy_updated_to_ver": policy_version,
                "policy_hello": "world!",
                "updated_policy_id": policy_id
            }
        }
