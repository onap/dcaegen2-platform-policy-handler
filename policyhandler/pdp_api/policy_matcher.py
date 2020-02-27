# ================================================================================
# Copyright (c) 2019-2020 AT&T Intellectual Property. All rights reserved.
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

"""policy-matcher matches the policies from deployment-handler to policies from policy-engine"""

import os

from ..deploy_handler import DeployHandler, PolicyUpdateMessage
from ..policy_consts import (ERRORED_POLICIES, LATEST_POLICIES, POLICY_BODY,
                             POLICY_VERSIONS)
from ..utils import Utils
from .pdp_consts import POLICY_VERSION
from .policy_rest import PolicyRest

_LOGGER = Utils.get_logger(__file__)

class PolicyMatcher(object):
    """policy-matcher - static class"""
    PENDING_UPDATE = "pending_update"
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))

    @staticmethod
    def build_catch_up_message(audit, deployed_policies, _=None):
        """find the latest policies from policy-engine for the deployed policies"""

        if not deployed_policies:
            error_txt = "no deployed policies"
            _LOGGER.warning(error_txt)
            return {"error": error_txt}, None

        pdp_response = PolicyRest.get_latest_policies(audit, policy_ids=list(deployed_policies))

        if not audit.is_success():
            error_txt = "failed to retrieve policies from policy-engine"
            _LOGGER.warning(error_txt)
            return {"error": error_txt}, None

        latest_policies = pdp_response.get(LATEST_POLICIES, {})
        errored_policies = pdp_response.get(ERRORED_POLICIES, {})

        latest_policies, changed_policies = PolicyMatcher._match_policies(
            latest_policies, deployed_policies)

        errored_policies = dict((policy_id, policy)
                                for (policy_id, policy) in errored_policies.items()
                                if deployed_policies.get(policy_id, {}).get(POLICY_VERSIONS))

        removed_policies = dict(
            (policy_id, True)
            for (policy_id, deployed_policy) in deployed_policies.items()
            if deployed_policy.get(POLICY_VERSIONS)
            and policy_id not in latest_policies
            and policy_id not in errored_policies
        )

        return ({LATEST_POLICIES: latest_policies, ERRORED_POLICIES: errored_policies},
                PolicyUpdateMessage(changed_policies, removed_policies))

    @staticmethod
    def match_to_deployed_policies(audit, policies_updated, policies_removed):
        """match the policies_updated, policies_removed versus deployed policies"""
        _, deployed_policies, _ = DeployHandler.get_deployed_policies(audit)
        if not audit.is_success():
            return {}, {}, {}

        _, changed_policies = PolicyMatcher._match_policies(policies_updated, deployed_policies)

        policies_removed = dict((policy_id, policy)
                                for (policy_id, policy) in policies_removed.items()
                                if deployed_policies.get(policy_id, {}).get(POLICY_VERSIONS))

        return changed_policies, policies_removed, {}


    @staticmethod
    def _match_policies(policies, deployed_policies):
        """
        Match policies to deployed policies by policy_id.

        Also calculates the policies that changed in comparison to deployed policies
        """
        matching_policies = {}
        changed_policies = {}

        policies = policies or {}
        deployed_policies = deployed_policies or {}

        for (policy_id, policy) in policies.items():
            new_version = policy.get(POLICY_BODY, {}).get(POLICY_VERSION)
            deployed_policy = deployed_policies.get(policy_id)

            if deployed_policy:
                matching_policies[policy_id] = policy

            policy_changed = (deployed_policy and new_version
                              and (deployed_policy.get(PolicyMatcher.PENDING_UPDATE)
                                   or {new_version} ^
                                   deployed_policy.get(POLICY_VERSIONS, {}).keys()))
            if policy_changed:
                changed_policies[policy_id] = policy

        return matching_policies, changed_policies
