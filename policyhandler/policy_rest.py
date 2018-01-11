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

"""policy-client communicates with policy-engine thru REST API"""

import logging
import json
import copy
import time
from multiprocessing.dummy import Pool as ThreadPool
import requests

from .config import Config
from .policy_consts import POLICY_ID, POLICY_NAME, POLICY_BODY, POLICY_CONFIG
from .onap.audit import REQUEST_X_ECOMP_REQUESTID, Audit, AuditHttpCode, AuditResponseCode
from .policy_utils import PolicyUtils

class PolicyRest(object):
    """ policy-engine """
    _logger = logging.getLogger("policy_handler.policy_rest")
    _lazy_inited = False
    POLICY_GET_CONFIG = 'getConfig'
    POLICY_CONFIG_STATUS = "policyConfigStatus"
    CONFIG_RETRIEVED = "CONFIG_RETRIEVED"
    POLICY_CONFIG_MESSAGE = "policyConfigMessage"
    NO_RESPONSE_RECEIVED = "No Response Received"

    MIN_VERSION_EXPECTED = "min_version_expected"
    IGNORE_POLICY_NAMES = "ignore_policy_names"

    _requests_session = None
    _url_get_config = None
    _headers = None
    _target_entity = None
    _thread_pool_size = 4
    _scope_prefixes = None
    _scope_thread_pool_size = 4
    _policy_retry_count = 1
    _policy_retry_sleep = 0

    @staticmethod
    def _lazy_init():
        """init static config"""
        if PolicyRest._lazy_inited:
            return
        PolicyRest._lazy_inited = True

        config = Config.config[Config.FIELD_POLICY_ENGINE]

        pool_size = config.get("pool_connections", 20)
        PolicyRest._requests_session = requests.Session()
        PolicyRest._requests_session.mount(
            'https://',
            requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        )
        PolicyRest._requests_session.mount(
            'http://',
            requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        )

        PolicyRest._url_get_config = config["url"] \
                                   + config["path_api"] + PolicyRest.POLICY_GET_CONFIG
        PolicyRest._headers = config["headers"]
        PolicyRest._target_entity = config.get("target_entity", Config.FIELD_POLICY_ENGINE)
        PolicyRest._thread_pool_size = Config.config.get("thread_pool_size", 4)
        if PolicyRest._thread_pool_size < 2:
            PolicyRest._thread_pool_size = 2
        PolicyRest._scope_prefixes = Config.config["scope_prefixes"]
        PolicyRest._scope_thread_pool_size = min(PolicyRest._thread_pool_size, \
                                             len(PolicyRest._scope_prefixes))

        PolicyRest._policy_retry_count = Config.config.get("policy_retry_count", 1) or 1
        PolicyRest._policy_retry_sleep = Config.config.get("policy_retry_sleep", 0)

        PolicyRest._logger.info("PolicyClient url(%s) headers(%s) scope-prefixes(%s)", \
            PolicyRest._url_get_config, Audit.log_json_dumps(PolicyRest._headers), \
            json.dumps(PolicyRest._scope_prefixes))

    @staticmethod
    def _pdp_get_config(audit, json_body):
        """Communication with the policy-engine"""
        sub_aud = Audit(aud_parent=audit, targetEntity=PolicyRest._target_entity, \
            targetServiceName=PolicyRest._url_get_config)

        msg = json.dumps(json_body)
        headers = copy.copy(PolicyRest._headers)
        headers[REQUEST_X_ECOMP_REQUESTID] = sub_aud.request_id
        headers_str = Audit.log_json_dumps(headers)

        log_line = "post to PDP {0} msg={1} headers={2}".format(
            PolicyRest._url_get_config, msg, headers_str)
        sub_aud.metrics_start(log_line)
        PolicyRest._logger.info(log_line)
        res = None
        try:
            res = PolicyRest._requests_session.post(
                PolicyRest._url_get_config, json=json_body, headers=headers)
        except requests.exceptions.RequestException as ex:
            error_code = AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
            error_msg = "failed to post to PDP {0} {1} msg={2} headers={3}" \
                .format(PolicyRest._url_get_config, str(ex), msg, headers_str)

            PolicyRest._logger.exception(error_msg)
            sub_aud.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            sub_aud.metrics(error_msg)
            return (error_code, None)

        log_line = "response from PDP to post {0}: {1} msg={2} text={3} headers={4}".format(
            PolicyRest._url_get_config, res.status_code, msg, res.text,
            Audit.log_json_dumps(dict(res.request.headers.items())))

        res_data = None
        if res.status_code == requests.codes.ok:
            res_data = res.json()

            if res_data and isinstance(res_data, list) and len(res_data) == 1:
                result = res_data[0]
                if result and not result.get(POLICY_NAME):
                    res_data = None
                if result.get(PolicyRest.POLICY_CONFIG_MESSAGE) == PolicyRest.NO_RESPONSE_RECEIVED:
                    error_code = AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                    error_msg = "unexpected {0}".format(log_line)

                    PolicyRest._logger.error(error_msg)
                    sub_aud.set_http_status_code(error_code)
                    audit.set_http_status_code(error_code)
                    sub_aud.metrics(error_msg)
                    return (error_code, None)

        sub_aud.set_http_status_code(res.status_code)
        sub_aud.metrics(log_line)
        PolicyRest._logger.info(log_line)
        return res.status_code, res_data

    @staticmethod
    def validate_policy(policy):
        """Validates the config on policy"""
        if not policy:
            return

        policy_body = policy.get(POLICY_BODY)

        return bool(
            policy_body
            and policy_body.get(PolicyRest.POLICY_CONFIG_STATUS) == PolicyRest.CONFIG_RETRIEVED
            and policy_body.get(POLICY_CONFIG)
        )

    @staticmethod
    def validate_policies(policies):
        """Validate the config on policies.  Returns (valid, errored) tuple"""
        if not policies:
            return None, policies

        valid_policies = {}
        errored_policies = {}
        for (policy_id, policy) in policies.iteritems():
            if PolicyRest.validate_policy(policy):
                valid_policies[policy_id] = policy
            else:
                errored_policies[policy_id] = policy

        return valid_policies, errored_policies

    @staticmethod
    def get_latest_policy(aud_policy_id):
        """Get the latest policy for the policy_id from the policy-engine"""
        PolicyRest._lazy_init()
        audit, policy_id, min_version_expected, ignore_policy_names = aud_policy_id

        status_code = 0
        policy_configs = None
        latest_policy = None
        expect_policy_removed = (ignore_policy_names and not min_version_expected)

        for retry in xrange(1, PolicyRest._policy_retry_count + 1):
            PolicyRest._logger.debug("%s", policy_id)

            status_code, policy_configs = PolicyRest._pdp_get_config(
                audit, {POLICY_NAME:policy_id}
            )

            PolicyRest._logger.debug("%s %s policy_configs: %s",
                                     status_code, policy_id, json.dumps(policy_configs or []))

            latest_policy = PolicyUtils.select_latest_policy(
                policy_configs, min_version_expected, ignore_policy_names
            )

            if not latest_policy and not expect_policy_removed:
                audit.error("received unexpected policy data from PDP for policy_id={0}: {1}"
                            .format(policy_id, json.dumps(policy_configs or [])),
                            errorCode=AuditResponseCode.DATA_ERROR.value,
                            errorDescription=AuditResponseCode.get_human_text(
                                AuditResponseCode.DATA_ERROR))

            if latest_policy or not audit.retry_get_config \
            or (expect_policy_removed and not policy_configs) \
            or not PolicyRest._policy_retry_sleep \
            or audit.is_serious_error(status_code):
                break

            if retry == PolicyRest._policy_retry_count:
                audit.warn("gave up retrying {0} from PDP after #{1} for policy_id={2}"
                           .format(PolicyRest._url_get_config, retry, policy_id),
                           errorCode=AuditResponseCode.DATA_ERROR.value,
                           errorDescription=AuditResponseCode.get_human_text(
                               AuditResponseCode.DATA_ERROR))
                break

            audit.warn(
                "retry #{0} {1} from PDP in {2} secs for policy_id={3}".format(
                    retry, PolicyRest._url_get_config, PolicyRest._policy_retry_sleep, policy_id),
                errorCode=AuditResponseCode.DATA_ERROR.value,
                errorDescription=AuditResponseCode.get_human_text(
                    AuditResponseCode.DATA_ERROR))
            time.sleep(PolicyRest._policy_retry_sleep)

        if expect_policy_removed and not latest_policy \
        and AuditHttpCode.RESPONSE_ERROR.value == status_code:
            audit.set_http_status_code(AuditHttpCode.HTTP_OK.value)
            return None

        audit.set_http_status_code(status_code)
        if not PolicyRest.validate_policy(latest_policy):
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
            audit.error(
                "received invalid policy from PDP: {0}".format(json.dumps(latest_policy)),
                errorCode=AuditResponseCode.DATA_ERROR.value,
                errorDescription=AuditResponseCode.get_human_text(AuditResponseCode.DATA_ERROR)
            )

        return latest_policy

    @staticmethod
    def get_latest_updated_policies(aud_policy_updates):
        """Get the latest policies of the list of policy_names from the policy-engine"""
        PolicyRest._lazy_init()
        audit, policies_updated, policies_removed = aud_policy_updates
        if not policies_updated and not policies_removed:
            return

        str_metrics = "policies_updated[{0}]: {1} policies_removed[{2}]: {3}".format(
            len(policies_updated), json.dumps(policies_updated),
            len(policies_removed), json.dumps(policies_removed))
        audit.metrics_start("get_latest_updated_policies {0}".format(str_metrics))
        PolicyRest._logger.debug(str_metrics)

        policies_to_find = {}
        for (policy_name, policy_version) in policies_updated:
            policy_id = PolicyUtils.extract_policy_id(policy_name)
            if not policy_id or not policy_version.isdigit():
                continue
            policy = policies_to_find.get(policy_id)
            if not policy:
                policies_to_find[policy_id] = {
                    POLICY_ID: policy_id,
                    PolicyRest.MIN_VERSION_EXPECTED: int(policy_version),
                    PolicyRest.IGNORE_POLICY_NAMES: {}
                }
                continue
            if int(policy[PolicyRest.MIN_VERSION_EXPECTED]) < int(policy_version):
                policy[PolicyRest.MIN_VERSION_EXPECTED] = int(policy_version)

        for (policy_name, _) in policies_removed:
            policy_id = PolicyUtils.extract_policy_id(policy_name)
            if not policy_id:
                continue
            policy = policies_to_find.get(policy_id)
            if not policy:
                policies_to_find[policy_id] = {
                    POLICY_ID: policy_id,
                    PolicyRest.IGNORE_POLICY_NAMES: {policy_name:True}
                }
                continue
            policy[PolicyRest.IGNORE_POLICY_NAMES][policy_name] = True

        apns = [(audit, policy_id,
                 policy_to_find.get(PolicyRest.MIN_VERSION_EXPECTED),
                 policy_to_find.get(PolicyRest.IGNORE_POLICY_NAMES))
                for (policy_id, policy_to_find) in policies_to_find.iteritems()]

        policies = None
        apns_length = len(apns)
        if apns_length == 1:
            policies = [PolicyRest.get_latest_policy(apns[0])]
        else:
            pool = ThreadPool(min(PolicyRest._thread_pool_size, apns_length))
            policies = pool.map(PolicyRest.get_latest_policy, apns)
            pool.close()
            pool.join()

        audit.metrics("result get_latest_updated_policies {0}: {1} {2}"
                      .format(str_metrics, len(policies), json.dumps(policies)),
                      targetEntity=PolicyRest._target_entity,
                      targetServiceName=PolicyRest._url_get_config)

        updated_policies = dict((policy[POLICY_ID], policy)
                                for policy in policies
                                if policy and policy.get(POLICY_ID))

        removed_policies = dict((policy_id, True)
                                for (policy_id, policy_to_find) in policies_to_find.iteritems()
                                if not policy_to_find.get(PolicyRest.MIN_VERSION_EXPECTED)
                                and policy_to_find.get(PolicyRest.IGNORE_POLICY_NAMES)
                                and policy_id not in updated_policies)

        errored_policies = dict((policy_id, policy_to_find)
                                for (policy_id, policy_to_find) in policies_to_find.iteritems()
                                if policy_id not in updated_policies
                                and policy_id not in removed_policies)

        PolicyRest._logger.debug(
            "result updated_policies %s, removed_policies %s, errored_policies %s",
            json.dumps(updated_policies), json.dumps(removed_policies),
            json.dumps(errored_policies))

        if errored_policies:
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
            audit.error(
                "errored_policies in PDP: {0}".format(json.dumps(errored_policies)),
                errorCode=AuditResponseCode.DATA_ERROR.value,
                errorDescription=AuditResponseCode.get_human_text(AuditResponseCode.DATA_ERROR)
            )

        return updated_policies, removed_policies

    @staticmethod
    def _get_latest_policies(aud_policy_filter):
        """
        get the latest policies by policy_filter
        or all the latest policies of the same scope from the policy-engine
        """
        audit, policy_filter, error_if_not_found = aud_policy_filter
        str_policy_filter = json.dumps(policy_filter)
        PolicyRest._logger.debug("%s", str_policy_filter)

        status_code, policy_configs = PolicyRest._pdp_get_config(audit, policy_filter)

        PolicyRest._logger.debug("%s policy_configs: %s %s", status_code,
                                 str_policy_filter, json.dumps(policy_configs or []))

        latest_policies = PolicyUtils.select_latest_policies(policy_configs)
        if not latest_policies:
            if error_if_not_found:
                audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
                audit.warn(
                    "received no policies from PDP for policy_filter {0}: {1}"
                    .format(str_policy_filter, json.dumps(policy_configs or [])),
                    errorCode=AuditResponseCode.DATA_ERROR.value,
                    errorDescription=AuditResponseCode.get_human_text(
                        AuditResponseCode.DATA_ERROR)
                )
            return None, latest_policies

        audit.set_http_status_code(status_code)
        return PolicyRest.validate_policies(latest_policies)

    @staticmethod
    def get_latest_policies(audit, policy_filter=None):
        """Get the latest policies of the same scope from the policy-engine"""
        PolicyRest._lazy_init()

        aud_policy_filters = None
        str_metrics = None
        str_policy_filters = json.dumps(policy_filter or PolicyRest._scope_prefixes)
        if policy_filter is not None:
            aud_policy_filters = [(audit, policy_filter, True)]
            str_metrics = "get_latest_policies for policy_filter {0}".format(
                str_policy_filters)
        else:
            aud_policy_filters = [(audit, {POLICY_NAME:scope_prefix + ".*"}, False)
                                  for scope_prefix in PolicyRest._scope_prefixes]
            str_metrics = "get_latest_policies for scopes {0} {1}".format( \
                len(PolicyRest._scope_prefixes), str_policy_filters)

        PolicyRest._logger.debug("%s", str_policy_filters)
        audit.metrics_start(str_metrics)

        latest_policies = None
        apfs_length = len(aud_policy_filters)
        if apfs_length == 1:
            latest_policies = [PolicyRest._get_latest_policies(aud_policy_filters[0])]
        else:
            pool = ThreadPool(min(PolicyRest._scope_thread_pool_size, apfs_length))
            latest_policies = pool.map(PolicyRest._get_latest_policies, aud_policy_filters)
            pool.close()
            pool.join()

        audit.metrics("total result {0}: {1} {2}".format(
            str_metrics, len(latest_policies), json.dumps(latest_policies)), \
            targetEntity=PolicyRest._target_entity, targetServiceName=PolicyRest._url_get_config)

        # latest_policies == [(valid_policies, errored_policies), ...]
        valid_policies = dict(
            pair for (vps, _) in latest_policies if vps for pair in vps.iteritems())

        errored_policies = dict(
            pair for (_, eps) in latest_policies if eps for pair in eps.iteritems())

        PolicyRest._logger.debug(
            "got policies for policy_filters: %s. valid_policies: %s errored_policies: %s",
            str_policy_filters, json.dumps(valid_policies), json.dumps(errored_policies))

        return valid_policies, errored_policies
