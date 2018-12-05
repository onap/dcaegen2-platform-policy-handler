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

"""policy-matcher matches the policies from deployment-handler to policies from policy-engine"""

import json
import logging
import re

from .deploy_handler import DeployHandler, PolicyUpdateMessage
from .onap.audit import AuditHttpCode, AuditResponseCode
from .policy_consts import (ERRORED_POLICIES, LATEST_POLICIES,
                            MATCHING_CONDITIONS, POLICY_BODY, POLICY_FILTER,
                            POLICY_NAME, POLICY_VERSION, POLICY_VERSIONS)
from .policy_rest import PolicyRest
from .policy_utils import RegexCoarser


class PolicyMatcher(object):
    """policy-matcher - static class"""
    _logger = logging.getLogger("policy_handler.policy_matcher")
    PENDING_UPDATE = "pending_update"

    @staticmethod
    def get_deployed_policies(audit):
        """get the deployed policies and policy-filters"""
        deployed_policies, deployed_policy_filters = DeployHandler.get_deployed_policies(audit)

        if audit.is_not_found():
            warning_txt = "got no deployed policies or policy-filters"
            PolicyMatcher._logger.warning(warning_txt)
            return {"warning": warning_txt}, None, None

        if not audit.is_success() or (not deployed_policies and not deployed_policy_filters):
            error_txt = "failed to retrieve policies from deployment-handler"
            PolicyMatcher._logger.error(error_txt)
            return {"error": error_txt}, None, None

        return None, deployed_policies, deployed_policy_filters


    @staticmethod
    def build_catch_up_message(audit, deployed_policies, deployed_policy_filters):
        """
        find the latest policies from policy-engine for the deployed policies and policy-filters
        """

        if not (deployed_policies or deployed_policy_filters):
            error_txt = "no deployed policies or policy-filters"
            PolicyMatcher._logger.warning(error_txt)
            return {"error": error_txt}, None

        coarse_regex_patterns = PolicyMatcher.calc_coarse_patterns(
            audit, deployed_policies, deployed_policy_filters)

        if not coarse_regex_patterns:
            error_txt = ("failed to construct the coarse_regex_patterns from " +
                         "deployed_policies: {} and deployed_policy_filters: {}"
                         .format(deployed_policies, deployed_policy_filters))
            PolicyMatcher._logger.error(audit.error(
                error_txt, error_code=AuditResponseCode.DATA_ERROR))
            audit.set_http_status_code(AuditHttpCode.DATA_ERROR.value)
            return {"error": error_txt}, None

        pdp_response = PolicyRest.get_latest_policies(
            audit, policy_filters=[{POLICY_NAME: policy_name_pattern}
                                   for policy_name_pattern in coarse_regex_patterns]
        )

        if not audit.is_success():
            error_txt = "failed to retrieve policies from policy-engine"
            PolicyMatcher._logger.warning(error_txt)
            return {"error": error_txt}, None

        latest_policies = pdp_response.get(LATEST_POLICIES, {})
        errored_policies = pdp_response.get(ERRORED_POLICIES, {})

        latest_policies, changed_policies, policy_filter_matches = PolicyMatcher._match_policies(
            audit, latest_policies, deployed_policies, deployed_policy_filters)

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
    def calc_coarse_patterns(audit, deployed_policies, deployed_policy_filters):
        """calculate the coarsed patterns on policy-names in policies and policy-filters"""
        coarse_regex = RegexCoarser()
        for policy_id in deployed_policies or {}:
            coarse_regex.add_regex_pattern(policy_id)

        for policy_filter in (deployed_policy_filters or {}).values():
            policy_name_pattern = policy_filter.get(POLICY_FILTER, {}).get(POLICY_NAME)
            coarse_regex.add_regex_pattern(policy_name_pattern)

        coarse_regex_patterns = coarse_regex.get_coarse_regex_patterns()
        PolicyMatcher._logger.debug(
            audit.debug("coarse_regex_patterns({}) combined_regex_pattern({}) for patterns({})"
                        .format(coarse_regex_patterns,
                                coarse_regex.get_combined_regex_pattern(),
                                coarse_regex.patterns)))
        return coarse_regex_patterns


    @staticmethod
    def match_to_deployed_policies(audit, policies_updated, policies_removed):
        """match the policies_updated, policies_removed versus deployed policies"""
        deployed_policies, deployed_policy_filters = DeployHandler.get_deployed_policies(audit)
        if not audit.is_success():
            return {}, {}, {}

        _, changed_policies, policy_filter_matches = PolicyMatcher._match_policies(
            audit, policies_updated, deployed_policies, deployed_policy_filters)

        policies_removed = dict((policy_id, policy)
                                for (policy_id, policy) in policies_removed.items()
                                if deployed_policies.get(policy_id, {}).get(POLICY_VERSIONS))

        return changed_policies, policies_removed, policy_filter_matches


    @staticmethod
    def _match_policies(audit, policies, deployed_policies, deployed_policy_filters):
        """
        Match policies to deployed policies either by policy_id or the policy-filters.

        Also calculates the policies that changed in comparison to deployed policies
        """
        matching_policies = {}
        changed_policies = {}
        policy_filter_matches = {}

        policies = policies or {}
        deployed_policies = deployed_policies or {}
        deployed_policy_filters = deployed_policy_filters or {}

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
                policy_filter_matches[policy_id] = {}

            in_filters = False
            for (policy_filter_id, policy_filter) in deployed_policy_filters.items():
                if not PolicyMatcher._match_policy_to_filter(
                        audit, policy_id, policy,
                        policy_filter_id, policy_filter.get(POLICY_FILTER)):
                    continue

                if policy_changed or not deployed_policy:
                    in_filters = True
                    if policy_id not in policy_filter_matches:
                        policy_filter_matches[policy_id] = {}
                    policy_filter_matches[policy_id][policy_filter_id] = True

            if not deployed_policy and in_filters:
                matching_policies[policy_id] = policy
                changed_policies[policy_id] = policy

        return matching_policies, changed_policies, policy_filter_matches


    @staticmethod
    def _match_policy_to_filter(audit, policy_id, policy, policy_filter_id, policy_filter):
        """Match the policy to the policy-filter"""
        if not policy_id or not policy or not policy_filter or not policy_filter_id:
            return False

        filter_policy_name = policy_filter.get(POLICY_NAME)
        if not filter_policy_name:
            return False

        policy_body = policy.get(POLICY_BODY)
        if not policy_body:
            return False

        policy_name = policy_body.get(POLICY_NAME)
        if not policy_name:
            return False

        log_line = "policy {} to filter id {}: {}".format(json.dumps(policy),
                                                          policy_filter_id,
                                                          json.dumps(policy_filter))
        # PolicyMatcher._logger.debug(audit.debug("matching {}...".format(log_line)))

        if (filter_policy_name != policy_id and filter_policy_name != policy_name
                and not re.match(filter_policy_name, policy_name)):
            PolicyMatcher._logger.debug(
                audit.debug("not match by policyName: {} != {}: {}"
                            .format(policy_name, filter_policy_name, log_line)))
            return False

        matching_conditions = policy_body.get(MATCHING_CONDITIONS, {})
        if not isinstance(matching_conditions, dict):
            return False

        filter_onap_name = policy_filter.get("onapName")
        policy_onap_name = matching_conditions.get("ONAPName")
        if filter_onap_name and filter_onap_name != policy_onap_name:
            PolicyMatcher._logger.debug(
                audit.debug("not match by ONAPName: {} != {}: {}"
                            .format(policy_onap_name, filter_onap_name, log_line)))
            return False

        filter_config_name = policy_filter.get("configName")
        policy_config_name = matching_conditions.get("ConfigName")
        if filter_config_name and filter_config_name != policy_config_name:
            PolicyMatcher._logger.debug(
                audit.debug("not match by configName: {} != {}: {}"
                            .format(policy_config_name, filter_config_name, log_line)))
            return False

        filter_config_attributes = policy_filter.get("configAttributes")
        if filter_config_attributes and isinstance(filter_config_attributes, dict):
            for filter_key, filter_config_attribute in filter_config_attributes.items():
                if (filter_key not in matching_conditions
                        or filter_config_attribute != matching_conditions.get(filter_key)):
                    PolicyMatcher._logger.debug(
                        audit.debug("not match by configAttributes: {} != {}: {}"
                                    .format(json.dumps(matching_conditions),
                                            json.dumps(filter_config_attributes),
                                            log_line)))
                    return False

        PolicyMatcher._logger.debug(audit.debug("matched {}".format(log_line)))
        return True
