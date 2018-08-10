# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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

import copy
import json
import logging
import time
from multiprocessing.dummy import Pool as ThreadPool

import requests

from .config import Config
from .onap.audit import (REQUEST_X_ECOMP_REQUESTID, AuditHttpCode,
                         AuditResponseCode, Metrics)
from .policy_consts import (ERRORED_POLICIES, LATEST_POLICIES, POLICY_BODY,
                            POLICY_CONFIG, POLICY_FILTER, POLICY_FILTERS,
                            POLICY_ID, POLICY_NAME)
from .policy_utils import PolicyUtils


class PolicyRest(object):
    """using the http API to policy-engine"""
    _logger = logging.getLogger("policy_handler.policy_rest")
    _lazy_inited = False
    POLICY_GET_CONFIG = 'getConfig'
    PDP_CONFIG_STATUS = "policyConfigStatus"
    PDP_CONFIG_RETRIEVED = "CONFIG_RETRIEVED"
    PDP_CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND"
    PDP_CONFIG_MESSAGE = "policyConfigMessage"
    PDP_NO_RESPONSE_RECEIVED = "No Response Received"
    PDP_STATUS_CODE_ERROR = 400
    PDP_DATA_NOT_FOUND = "PE300 - Data Issue: Incorrect Params passed: Decision not a Permit."

    EXPECTED_VERSIONS = "expected_versions"
    IGNORE_POLICY_NAMES = "ignore_policy_names"

    _requests_session = None
    _url_get_config = None
    _headers = None
    _target_entity = None
    _thread_pool_size = 4
    _policy_retry_count = 1
    _policy_retry_sleep = 0

    @staticmethod
    def _lazy_init():
        """init static config"""
        if PolicyRest._lazy_inited:
            return
        PolicyRest._lazy_inited = True

        config = Config.settings[Config.FIELD_POLICY_ENGINE]

        pool_size = Config.settings.get("pool_connections", 20)
        PolicyRest._requests_session = requests.Session()
        PolicyRest._requests_session.mount(
            'https://',
            requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        )
        PolicyRest._requests_session.mount(
            'http://',
            requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        )

        PolicyRest._url_get_config = (config["url"] + config["path_api"]
                                      + PolicyRest.POLICY_GET_CONFIG)
        PolicyRest._headers = config["headers"]
        PolicyRest._target_entity = config.get("target_entity", Config.FIELD_POLICY_ENGINE)
        PolicyRest._thread_pool_size = Config.settings.get("thread_pool_size", 4)
        if PolicyRest._thread_pool_size < 2:
            PolicyRest._thread_pool_size = 2

        PolicyRest._policy_retry_count = Config.settings.get("policy_retry_count", 1) or 1
        PolicyRest._policy_retry_sleep = Config.settings.get("policy_retry_sleep", 0)

        PolicyRest._logger.info(
            "PolicyClient url(%s) headers(%s)",
            PolicyRest._url_get_config, Metrics.log_json_dumps(PolicyRest._headers))

    @staticmethod
    def _pdp_get_config(audit, json_body):
        """Communication with the policy-engine"""
        metrics = Metrics(aud_parent=audit, targetEntity=PolicyRest._target_entity,
                          targetServiceName=PolicyRest._url_get_config)

        msg = json.dumps(json_body)
        headers = copy.copy(PolicyRest._headers)
        headers[REQUEST_X_ECOMP_REQUESTID] = metrics.request_id
        headers_str = Metrics.log_json_dumps(headers)

        log_line = "post to PDP {0} msg={1} headers={2}".format(
            PolicyRest._url_get_config, msg, headers_str)
        metrics.metrics_start(log_line)
        PolicyRest._logger.info(log_line)
        res = None
        try:
            res = PolicyRest._requests_session.post(
                PolicyRest._url_get_config, json=json_body, headers=headers)
        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = (
                "failed to post to PDP {0} {1}: {2} msg={3} headers={4}"
                .format(PolicyRest._url_get_config, type(ex).__name__, str(ex), msg, headers_str))

            PolicyRest._logger.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return (error_code, None)

        log_line = "response from PDP to post {0}: {1} msg={2} text={3} headers={4}".format(
            PolicyRest._url_get_config, res.status_code, msg, res.text,
            Metrics.log_json_dumps(dict(res.request.headers.items())))

        status_code, res_data = PolicyRest._extract_pdp_res_data(audit, metrics, log_line, res)

        if status_code:
            return status_code, res_data

        metrics.set_http_status_code(res.status_code)
        metrics.metrics(log_line)
        PolicyRest._logger.info(log_line)
        return res.status_code, res_data

    @staticmethod
    def _extract_pdp_res_data(audit, metrics, log_line, res):
        """special treatment of pdp response"""
        res_data = None
        if res.status_code == requests.codes.ok:
            res_data = res.json()

            if res_data and isinstance(res_data, list) and len(res_data) == 1:
                rslt = res_data[0]
                if rslt and not rslt.get(POLICY_NAME):
                    res_data = None
                if rslt.get(PolicyRest.PDP_CONFIG_MESSAGE) == PolicyRest.PDP_NO_RESPONSE_RECEIVED:
                    error_code = AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                    error_msg = "unexpected {0}".format(log_line)

                    PolicyRest._logger.error(error_msg)
                    metrics.set_http_status_code(error_code)
                    audit.set_http_status_code(error_code)
                    metrics.metrics(error_msg)
                    return error_code, None
            return None, res_data

        if res.status_code == PolicyRest.PDP_STATUS_CODE_ERROR:
            try:
                res_data = res.json()
            except ValueError:
                return None, None

            if not res_data or not isinstance(res_data, list) or len(res_data) != 1:
                return None, None

            rslt = res_data[0]
            if (rslt and not rslt.get(POLICY_NAME)
                    and rslt.get(PolicyRest.PDP_CONFIG_STATUS) == PolicyRest.PDP_CONFIG_NOT_FOUND
                    and rslt.get(PolicyRest.PDP_CONFIG_MESSAGE) == PolicyRest.PDP_DATA_NOT_FOUND):
                status_code = AuditHttpCode.DATA_NOT_FOUND_ERROR.value
                info_msg = "not found {0}".format(log_line)

                PolicyRest._logger.info(info_msg)
                metrics.set_http_status_code(status_code)
                metrics.metrics(info_msg)
                return status_code, None
        return None, None


    @staticmethod
    def _validate_policy(policy):
        """Validates the config on policy"""
        if not policy:
            return

        policy_body = policy.get(POLICY_BODY)

        return bool(
            policy_body
            and policy_body.get(PolicyRest.PDP_CONFIG_STATUS) == PolicyRest.PDP_CONFIG_RETRIEVED
            and policy_body.get(POLICY_CONFIG)
        )

    @staticmethod
    def get_latest_policy(aud_policy_id):
        """safely try retrieving the latest policy for the policy_id from the policy-engine"""
        audit, policy_id, expected_versions, ignore_policy_names = aud_policy_id
        str_metrics = "policy_id({0}), expected_versions({1}) ignore_policy_names({2})".format(
            policy_id, json.dumps(expected_versions), json.dumps(ignore_policy_names))

        try:
            return PolicyRest._get_latest_policy(
                audit, policy_id, expected_versions, ignore_policy_names, str_metrics)

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "get_latest_policy", str_metrics))

            PolicyRest._logger.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None


    @staticmethod
    def _get_latest_policy(audit, policy_id,
                           expected_versions, ignore_policy_names, str_metrics):
        """retry several times getting the latest policy for the policy_id from the policy-engine"""
        PolicyRest._lazy_init()
        latest_policy = None
        status_code = 0
        retry_get_config = audit.kwargs.get("retry_get_config")
        expect_policy_removed = (ignore_policy_names and not expected_versions)

        for retry in range(1, PolicyRest._policy_retry_count + 1):
            PolicyRest._logger.debug(str_metrics)

            done, latest_policy, status_code = PolicyRest._get_latest_policy_once(
                audit, policy_id, expected_versions, ignore_policy_names,
                expect_policy_removed)

            if done or not retry_get_config or not PolicyRest._policy_retry_sleep:
                break

            if retry == PolicyRest._policy_retry_count:
                audit.warn("gave up retrying {0} from PDP after #{1} for policy_id={2}"
                           .format(PolicyRest._url_get_config, retry, policy_id),
                           error_code=AuditResponseCode.DATA_ERROR)
                break

            audit.warn(
                "retry #{0} {1} from PDP in {2} secs for policy_id={3}".format(
                    retry, PolicyRest._url_get_config,
                    PolicyRest._policy_retry_sleep, policy_id),
                error_code=AuditResponseCode.DATA_ERROR)
            time.sleep(PolicyRest._policy_retry_sleep)

        if (expect_policy_removed and not latest_policy
                and AuditHttpCode.RESPONSE_ERROR.value == status_code):
            audit.set_http_status_code(AuditHttpCode.HTTP_OK.value)
            return None

        audit.set_http_status_code(status_code)
        if not PolicyRest._validate_policy(latest_policy):
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
            audit.error(
                "received invalid policy from PDP: {0}".format(json.dumps(latest_policy)),
                error_code=AuditResponseCode.DATA_ERROR)

        return latest_policy

    @staticmethod
    def _get_latest_policy_once(audit, policy_id,
                                expected_versions, ignore_policy_names,
                                expect_policy_removed):
        """single attempt to get the latest policy for the policy_id from the policy-engine"""

        status_code, policy_bodies = PolicyRest._pdp_get_config(audit, {POLICY_NAME:policy_id})

        PolicyRest._logger.debug("%s %s policy_bodies: %s",
                                 status_code, policy_id, json.dumps(policy_bodies or []))

        latest_policy = PolicyUtils.select_latest_policy(
            policy_bodies, expected_versions, ignore_policy_names
        )

        if not latest_policy and not expect_policy_removed:
            audit.error("received unexpected policy data from PDP for policy_id={0}: {1}"
                        .format(policy_id, json.dumps(policy_bodies or [])),
                        error_code=AuditResponseCode.DATA_ERROR)

        done = bool(latest_policy
                    or (expect_policy_removed and not policy_bodies)
                    or audit.is_serious_error(status_code))

        return done, latest_policy, status_code

    @staticmethod
    def get_latest_updated_policies(aud_policy_updates):
        """safely try retrieving the latest policies for the list of policy_names"""
        audit, policies_updated, policies_removed = aud_policy_updates
        if not policies_updated and not policies_removed:
            return None, None

        str_metrics = "policies_updated[{0}]: {1} policies_removed[{2}]: {3}".format(
            len(policies_updated), json.dumps(policies_updated),
            len(policies_removed), json.dumps(policies_removed))

        try:
            return PolicyRest._get_latest_updated_policies(
                audit, str_metrics, policies_updated, policies_removed)

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "get_latest_updated_policies", str_metrics))

            PolicyRest._logger.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None, None

    @staticmethod
    def _get_latest_updated_policies(audit, str_metrics, policies_updated, policies_removed):
        """Get the latest policies of the list of policy_names from the policy-engine"""
        PolicyRest._lazy_init()
        metrics_total = Metrics(
            aud_parent=audit,
            targetEntity="{0} total get_latest_updated_policies".format(PolicyRest._target_entity),
            targetServiceName=PolicyRest._url_get_config)

        metrics_total.metrics_start("get_latest_updated_policies {0}".format(str_metrics))
        PolicyRest._logger.debug(str_metrics)

        policies_to_find = {}
        for (policy_id, policy_version) in policies_updated:
            if not policy_id or not policy_version or not policy_version.isdigit():
                continue
            policy = policies_to_find.get(policy_id)
            if not policy:
                policies_to_find[policy_id] = {
                    POLICY_ID: policy_id,
                    PolicyRest.EXPECTED_VERSIONS: {policy_version: True},
                    PolicyRest.IGNORE_POLICY_NAMES: {}
                }
                continue
            policy[PolicyRest.EXPECTED_VERSIONS][policy_version] = True

        for (policy_id, policy_names) in policies_removed:
            if not policy_id:
                continue
            policy = policies_to_find.get(policy_id)
            if not policy:
                policies_to_find[policy_id] = {
                    POLICY_ID: policy_id,
                    PolicyRest.IGNORE_POLICY_NAMES: policy_names
                }
                continue
            policy[PolicyRest.IGNORE_POLICY_NAMES].update(policy_names)

        apns = [(audit, policy_id,
                 policy_to_find.get(PolicyRest.EXPECTED_VERSIONS),
                 policy_to_find.get(PolicyRest.IGNORE_POLICY_NAMES))
                for (policy_id, policy_to_find) in policies_to_find.items()]

        policies = None
        apns_length = len(apns)
        if apns_length == 1:
            policies = [PolicyRest.get_latest_policy(apns[0])]
        else:
            pool = ThreadPool(min(PolicyRest._thread_pool_size, apns_length))
            policies = pool.map(PolicyRest.get_latest_policy, apns)
            pool.close()
            pool.join()

        metrics_total.metrics("result get_latest_updated_policies {0}: {1} {2}"
                              .format(str_metrics, len(policies), json.dumps(policies)))

        updated_policies = dict((policy[POLICY_ID], policy)
                                for policy in policies
                                if policy and policy.get(POLICY_ID))

        removed_policies = dict((policy_id, True)
                                for (policy_id, policy_to_find) in policies_to_find.items()
                                if not policy_to_find.get(PolicyRest.EXPECTED_VERSIONS)
                                and policy_to_find.get(PolicyRest.IGNORE_POLICY_NAMES)
                                and policy_id not in updated_policies)

        errored_policies = dict((policy_id, policy_to_find)
                                for (policy_id, policy_to_find) in policies_to_find.items()
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
                error_code=AuditResponseCode.DATA_ERROR)

        return updated_policies, removed_policies


    @staticmethod
    def _get_latest_policies(aud_policy_filter):
        """get the latest policies by policy_filter from the policy-engine"""
        audit, policy_filter = aud_policy_filter
        try:
            str_policy_filter = json.dumps(policy_filter)
            PolicyRest._logger.debug("%s", str_policy_filter)

            status_code, policy_bodies = PolicyRest._pdp_get_config(audit, policy_filter)

            PolicyRest._logger.debug("%s policy_bodies: %s %s", status_code,
                                     str_policy_filter, json.dumps(policy_bodies or []))

            latest_policies = PolicyUtils.select_latest_policies(policy_bodies)

            if not latest_policies:
                audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
                audit.warn(
                    "received no policies from PDP for policy_filter {0}: {1}"
                    .format(str_policy_filter, json.dumps(policy_bodies or [])),
                    error_code=AuditResponseCode.DATA_ERROR)
                return None, latest_policies

            audit.set_http_status_code(status_code)
            valid_policies = {}
            errored_policies = {}
            for (policy_id, policy) in latest_policies.items():
                if PolicyRest._validate_policy(policy):
                    valid_policies[policy_id] = policy
                else:
                    errored_policies[policy_id] = policy
            return valid_policies, errored_policies

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: policy_filter({4})"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "_get_latest_policies", json.dumps(policy_filter)))

            PolicyRest._logger.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None, None


    @staticmethod
    def get_latest_policies(audit, policy_filter=None, policy_filters=None):
        """Get the latest policies by policy-filter(s) from the policy-engine"""
        result = {}
        aud_policy_filters = None
        str_policy_filters = None
        str_metrics = None
        target_entity = None

        try:
            PolicyRest._lazy_init()
            if policy_filter:
                aud_policy_filters = [(audit, policy_filter)]
                str_policy_filters = json.dumps(policy_filter)
                str_metrics = "get_latest_policies for policy_filter {0}".format(
                    str_policy_filters)
                target_entity = ("{0} total get_latest_policies by policy_filter"
                                 .format(PolicyRest._target_entity))
                result[POLICY_FILTER] = copy.deepcopy(policy_filter)
            elif policy_filters:
                aud_policy_filters = [
                    (audit, policy_filter)
                    for policy_filter in policy_filters
                ]
                str_policy_filters = json.dumps(policy_filters)
                str_metrics = "get_latest_policies for policy_filters {0}".format(
                    str_policy_filters)
                target_entity = ("{0} total get_latest_policies by policy_filters"
                                 .format(PolicyRest._target_entity))
                result[POLICY_FILTERS] = copy.deepcopy(policy_filters)
            else:
                return result

            PolicyRest._logger.debug("%s", str_policy_filters)
            metrics_total = Metrics(aud_parent=audit, targetEntity=target_entity,
                                    targetServiceName=PolicyRest._url_get_config)

            metrics_total.metrics_start(str_metrics)

            latest_policies = None
            apfs_length = len(aud_policy_filters)
            if apfs_length == 1:
                latest_policies = [PolicyRest._get_latest_policies(aud_policy_filters[0])]
            else:
                pool = ThreadPool(min(PolicyRest._thread_pool_size, apfs_length))
                latest_policies = pool.map(PolicyRest._get_latest_policies, aud_policy_filters)
                pool.close()
                pool.join()

            metrics_total.metrics("total result {0}: {1} {2}".format(
                str_metrics, len(latest_policies), json.dumps(latest_policies)))

            # latest_policies == [(valid_policies, errored_policies), ...]
            result[LATEST_POLICIES] = dict(
                pair for (vps, _) in latest_policies if vps for pair in vps.items())

            result[ERRORED_POLICIES] = dict(
                pair for (_, eps) in latest_policies if eps for pair in eps.items())

            PolicyRest._logger.debug("got policies for policy_filters: %s. result: %s",
                                     str_policy_filters, json.dumps(result))
            return result

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "get_latest_policies", str_metrics))

            PolicyRest._logger.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None
