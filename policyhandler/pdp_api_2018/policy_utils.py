# ================================================================================
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
# ECOMP is a trademark and service mark of AT&T Intellectual Property.

"""utils for policy usage and conversions"""

import re

from ..policy_consts import POLICY_BODY, POLICY_ID
from ..utils import Utils
from .pdp_consts import POLICY_CONFIG, POLICY_NAME, POLICY_VERSION


class PolicyUtils(object):
    """policy-client utils"""
    _policy_name_ext = re.compile('[.][0-9]+[.][a-zA-Z]+$')

    @staticmethod
    def extract_policy_id(policy_name):
        """ policy_name  = policy_id + "." + <version> + "." + <extension>
        For instance,
        policy_name      = DCAE_alex.Config_alex_policy_number_1.3.xml
               policy_id = DCAE_alex.Config_alex_policy_number_1
            policy_scope = DCAE_alex
            policy_class = Config
          policy_version = 3
        type = extension = xml
               delimiter = "."
        policy_class_delimiter = "_"
        policy_name in PAP = DCAE_alex.alex_policy_number_1
        """
        if not policy_name:
            return
        return PolicyUtils._policy_name_ext.sub('', policy_name)

    @staticmethod
    def parse_policy_config(policy):
        """try parsing the config in policy."""
        if not policy:
            return policy
        config = policy.get(POLICY_BODY, {}).get(POLICY_CONFIG)
        if config:
            policy[POLICY_BODY][POLICY_CONFIG] = Utils.safe_json_parse(config)
        return policy

    @staticmethod
    def convert_to_policy(policy_body):
        """wrap policy_body received from policy-engine with policy_id."""
        if not policy_body:
            return None
        policy_name = policy_body.get(POLICY_NAME)
        policy_version = policy_body.get(POLICY_VERSION)
        if not policy_name or not policy_version:
            return None
        policy_id = PolicyUtils.extract_policy_id(policy_name)
        if not policy_id:
            return None
        return {POLICY_ID:policy_id, POLICY_BODY:policy_body}

    @staticmethod
    def select_latest_policy(policy_bodies, expected_versions=None, ignore_policy_names=None):
        """For some reason, the policy-engine returns all version of the policy_bodies.
        DCAE-Controller is only interested in the latest version
        """
        if not policy_bodies:
            return
        latest_policy_body = {}
        for policy_body in policy_bodies:
            policy_name = policy_body.get(POLICY_NAME)
            policy_version = policy_body.get(POLICY_VERSION)
            if not policy_name or not policy_version or not policy_version.isdigit():
                continue
            if expected_versions and policy_version not in expected_versions:
                continue
            if ignore_policy_names and policy_name in ignore_policy_names:
                continue

            if (not latest_policy_body
                    or int(latest_policy_body[POLICY_VERSION]) < int(policy_version)):
                latest_policy_body = policy_body

        return PolicyUtils.parse_policy_config(PolicyUtils.convert_to_policy(latest_policy_body))

    @staticmethod
    def select_latest_policies(policy_bodies):
        """For some reason, the policy-engine returns all version of the policy_bodies.
        DCAE-Controller is only interested in the latest versions
        """
        if not policy_bodies:
            return {}
        policies = {}
        for policy_body in policy_bodies:
            policy = PolicyUtils.convert_to_policy(policy_body)
            if not policy:
                continue
            policy_id = policy.get(POLICY_ID)
            policy_version = policy.get(POLICY_BODY, {}).get(POLICY_VERSION)
            if not policy_id or not policy_version or not policy_version.isdigit():
                continue
            if (policy_id not in policies
                    or int(policy_version) > int(policies[policy_id][POLICY_BODY][POLICY_VERSION])):
                policies[policy_id] = policy

        for policy_id in policies:
            policies[policy_id] = PolicyUtils.parse_policy_config(policies[policy_id])

        return policies
