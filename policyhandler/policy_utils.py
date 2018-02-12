# org.onap.dcae
# ================================================================================
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

"""policy-client communicates with policy-engine thru REST API"""

import logging
import json
import re

from .policy_consts import POLICY_ID, POLICY_VERSION, POLICY_NAME, POLICY_BODY, POLICY_CONFIG

class PolicyUtils(object):
    """policy-client utils"""
    _logger = logging.getLogger("policy_handler.policy_utils")
    _policy_name_ext = re.compile('[.][0-9]+[.][a-zA-Z]+$')

    @staticmethod
    def safe_json_parse(json_str):
        """try parsing json without exception - returns the json_str back if fails"""
        if not json_str:
            return json_str
        try:
            return json.loads(json_str)
        except (ValueError, TypeError) as err:
            PolicyUtils._logger.warn("unexpected json %s: %s", str(json_str), str(err))
        return json_str

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
            policy[POLICY_BODY][POLICY_CONFIG] = PolicyUtils.safe_json_parse(config)
        return policy

    @staticmethod
    def convert_to_policy(policy_config):
        """wrap policy_config received from policy-engine with policy_id."""
        if not policy_config:
            return
        policy_name = policy_config.get(POLICY_NAME)
        policy_version = policy_config.get(POLICY_VERSION)
        if not policy_name or not policy_version:
            return
        policy_id = PolicyUtils.extract_policy_id(policy_name)
        if not policy_id:
            return
        return {POLICY_ID:policy_id, POLICY_BODY:policy_config}

    @staticmethod
    def select_latest_policy(policy_configs, min_version_expected=None, ignore_policy_names=None):
        """For some reason, the policy-engine returns all version of the policy_configs.
        DCAE-Controller is only interested in the latest version
        """
        if not policy_configs:
            return
        latest_policy_config = {}
        for policy_config in policy_configs:
            policy_name = policy_config.get(POLICY_NAME)
            policy_version = policy_config.get(POLICY_VERSION)
            if not policy_name or not policy_version or not policy_version.isdigit():
                continue
            policy_version = int(policy_version)
            if min_version_expected and policy_version < min_version_expected:
                continue
            if ignore_policy_names and policy_name in ignore_policy_names:
                continue

            if not latest_policy_config \
            or int(latest_policy_config[POLICY_VERSION]) < policy_version:
                latest_policy_config = policy_config

        return PolicyUtils.parse_policy_config(PolicyUtils.convert_to_policy(latest_policy_config))

    @staticmethod
    def select_latest_policies(policy_configs):
        """For some reason, the policy-engine returns all version of the policy_configs.
        DCAE-Controller is only interested in the latest versions
        """
        if not policy_configs:
            return {}
        policies = {}
        for policy_config in policy_configs:
            policy = PolicyUtils.convert_to_policy(policy_config)
            if not policy:
                continue
            policy_id = policy.get(POLICY_ID)
            policy_version = policy.get(POLICY_BODY, {}).get(POLICY_VERSION)
            if not policy_id or not policy_version or not policy_version.isdigit():
                continue
            if policy_id not in policies \
            or int(policy_version) > int(policies[policy_id][POLICY_BODY][POLICY_VERSION]):
                policies[policy_id] = policy

        for policy_id in policies:
            policies[policy_id] = PolicyUtils.parse_policy_config(policies[policy_id])

        return policies
