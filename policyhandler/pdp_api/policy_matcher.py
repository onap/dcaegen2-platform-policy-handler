# ================================================================================
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
# Copyright (C) 2020 Wipro Limited.
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
from ..policy_consts import (ERRORED_POLICIES, LATEST_POLICIES, POLICY_VERSIONS, POLICY_BODY)
from .pdp_consts import PDP_POLICY_VERSION, POLICY_VERSION
from .policy_rest import PolicyRest
from ..utils import Utils

_LOGGER = Utils.get_logger(__file__)


class PolicyMatcher(object):
    """policy-matcher - static class"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    PENDING_UPDATE = "pending_update"

    @staticmethod
    def get_deployed_policies(audit):
        """get the deployed policies and policy-filters"""
        deployed_policies, deployed_policy_filters = DeployHandler.get_deployed_policies(audit)

        if audit.is_not_found():
            warning_txt = "got no deployed policies or policy-filters"
            _LOGGER.warning(warning_txt)
            return {"warning": warning_txt}, None, None

        if not audit.is_success() or (not deployed_policies and not deployed_policy_filters):
            error_txt = "failed to retrieve policies from deployment-handler"
            _LOGGER.error(error_txt)
            return {"error": error_txt}, None, None

        return None, deployed_policies, deployed_policy_filters

    @staticmethod
    def build_catch_up_message(audit, deployed_policies, deployed_policy_filters):
        """
        find the latest policies from policy-engine for the deployed policies and policy-filters
        """

        if not (deployed_policies or deployed_policy_filters):
            error_txt = "no deployed policies or policy-filters"
            _LOGGER.warning(error_txt)
            return {"error": error_txt}, None

        policies = [policy_id for policy_id in deployed_policies]

        pdp_response = PolicyRest.get_latest_policies(audit, policies)

        if not audit.is_success():
            error_txt = "failed to retrieve policies from policy-engine"
            _LOGGER.warning(error_txt)
            return {"error": error_txt}, None

        latest_policies = pdp_response.get(LATEST_POLICIES, {})
        errored_policies = pdp_response.get(ERRORED_POLICIES, {})

        latest_policies, changed_policies, policy_filter_matches = PolicyMatcher._match_policies(
            audit, latest_policies, deployed_policies)

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
                PolicyUpdateMessage(changed_policies,
                                    removed_policies,
                                    policy_filter_matches))

    @staticmethod
    def match_to_deployed_policies(audit, policies_updated, policies_removed):
        """match the policies_updated, policies_removed versus deployed policies"""

        deployed_policies, deployed_policy_filters = DeployHandler.get_deployed_policies(audit)

        policy_filter = {}

        if not audit.is_success():
            _LOGGER("Audit failed")
            return {}, {}, {}

        _, changed_policies, __ = PolicyMatcher._match_policies(
            audit, policies_updated, deployed_policies)

        policies_removed = dict((policy_id, policy)
                                for (policy_id, policy) in policies_removed.items()
                                if deployed_policies.get(policy_id, {}).get(POLICY_VERSIONS))

        _LOGGER.info("Changed_policies {}, policies_removed {}, policy filter matches {}".format(changed_policies,
                     policies_removed, policy_filter))

        return changed_policies, policies_removed, policy_filter

    @staticmethod
    def _match_policies(audit, policies, deployed_policies):
        """
        Match policies to deployed policies by policy_id.

        Also calculates the policies that changed in comparison to deployed policies
        """
        policy_filter_matches = {}
        matching_policies = {}
        changed_policies = {}

        policies = policies or {}
        deployed_policies = deployed_policies or {}

        for (policy_id, policy) in policies.items():
            new_version = policy.get(POLICY_BODY).get(PDP_POLICY_VERSION)
            if not new_version:
                _LOGGER.info("new version during catchup")
                new_version = policy.get(POLICY_BODY).get(POLICY_VERSION)
            else:
                new_version = new_version.split('.')[0]
            deployed_policy = deployed_policies.get(policy_id)

            if deployed_policy:
                matching_policies[policy_id] = policy

            _LOGGER.info("new version {}".format(new_version))

            policy_changed = (deployed_policy and new_version
                              and (deployed_policy.get(PolicyMatcher.PENDING_UPDATE)
                                   or {new_version} ^
                                   deployed_policy.get(POLICY_VERSIONS, {}).keys()))
            _LOGGER.info("Policy changed {}".format(policy_changed))
            if policy_changed:
                changed_policies[policy_id] = policy


        return matching_policies, changed_policies, policy_filter_matches
