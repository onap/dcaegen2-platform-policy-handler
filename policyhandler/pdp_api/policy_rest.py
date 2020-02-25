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

"""policy-client communicates with policy-engine thru REST API"""

import copy
import json
import os
import time
import urllib.parse
from multiprocessing.dummy import Pool as ThreadPool
from threading import Lock

import requests

from ..config import Config, Settings
from ..onap.audit import AuditHttpCode, AuditResponseCode, Metrics
from ..policy_consts import (ERRORED_POLICIES, LATEST_POLICIES, POLICY_BODY,
                             POLICY_ID, POLICY_NAMES)
from ..utils import Utils
from .pdp_consts import PDP_POLICIES, POLICY_NAME, POLICY_VERSION
from .policy_utils import PolicyUtils

_LOGGER = Utils.get_logger(__file__)

class PolicyRest(object):
    """using the http API to policy-engine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    EXPECTED_VERSIONS = "expected_versions"
    IGNORE_POLICY_NAMES = "ignore_policy_names"
    DEFAULT_TIMEOUT_IN_SECS = 60
    _lazy_inited = False

    _lock = Lock()
    _settings = Settings(Config.FIELD_POLICY_ENGINE, Config.POOL_CONNECTIONS,
                         Config.THREAD_POOL_SIZE,
                         Config.POLICY_RETRY_COUNT, Config.POLICY_RETRY_SLEEP)

    _target_entity = None
    _requests_session = None
    _url = None
    _url_pdp_decision = None
    _headers = None
    _custom_kwargs = {}
    _thread_pool_size = 4
    _policy_retry_count = 1
    _policy_retry_sleep = 0
    _timeout_in_secs = DEFAULT_TIMEOUT_IN_SECS

    @staticmethod
    def _init():
        """init static config"""
        PolicyRest._custom_kwargs = {}
        tls_ca_mode = None

        if not PolicyRest._requests_session:
            PolicyRest._requests_session = requests.Session()

        changed, pool_size = PolicyRest._settings.get_by_key(Config.POOL_CONNECTIONS, 20)
        if changed:
            PolicyRest._requests_session.mount(
                'https://', requests.adapters.HTTPAdapter(pool_connections=1,
                                                          pool_maxsize=pool_size))
            PolicyRest._requests_session.mount(
                'http://', requests.adapters.HTTPAdapter(pool_connections=1,
                                                         pool_maxsize=pool_size))

        _, config = PolicyRest._settings.get_by_key(Config.FIELD_POLICY_ENGINE)
        if config:
            PolicyRest._url = config.get("url")
            if PolicyRest._url:
                PolicyRest._url_pdp_decision = urllib.parse.urljoin(
                    PolicyRest._url, config.get("path_decision", "/decision/v1/"))
            PolicyRest._headers = config.get("headers", {})
            PolicyRest._target_entity = config.get("target_entity", Config.FIELD_POLICY_ENGINE)
            _, PolicyRest._thread_pool_size = PolicyRest._settings.get_by_key(
                Config.THREAD_POOL_SIZE, 4)
            if PolicyRest._thread_pool_size < 2:
                PolicyRest._thread_pool_size = 2

            _, PolicyRest._policy_retry_count = PolicyRest._settings.get_by_key(
                Config.POLICY_RETRY_COUNT, 1)
            _, PolicyRest._policy_retry_sleep = PolicyRest._settings.get_by_key(
                Config.POLICY_RETRY_SLEEP, 0)

            tls_ca_mode = config.get(Config.TLS_CA_MODE)
            PolicyRest._custom_kwargs = Config.get_requests_kwargs(tls_ca_mode)
            PolicyRest._timeout_in_secs = config.get(Config.TIMEOUT_IN_SECS)
            if not PolicyRest._timeout_in_secs or PolicyRest._timeout_in_secs < 1:
                PolicyRest._timeout_in_secs = PolicyRest.DEFAULT_TIMEOUT_IN_SECS

        _LOGGER.info(
            "PDP(%s) url(%s) headers(%s) tls_ca_mode(%s) timeout_in_secs(%s) custom_kwargs(%s): %s",
            PolicyRest._target_entity, PolicyRest._url_pdp_decision,
            Metrics.json_dumps(PolicyRest._headers), tls_ca_mode,
            PolicyRest._timeout_in_secs, json.dumps(PolicyRest._custom_kwargs),
            PolicyRest._settings)

        PolicyRest._settings.commit_change()
        PolicyRest._lazy_inited = True

    @staticmethod
    def reconfigure():
        """reconfigure"""
        with PolicyRest._lock:
            PolicyRest._settings.set_config(Config.discovered_config)
            if not PolicyRest._settings.is_changed():
                PolicyRest._settings.commit_change()
                return False

            PolicyRest._lazy_inited = False
            PolicyRest._init()
        return True

    @staticmethod
    def _lazy_init():
        """init static config"""
        if PolicyRest._lazy_inited:
            return

        with PolicyRest._lock:
            if PolicyRest._lazy_inited:
                return

            PolicyRest._settings.set_config(Config.discovered_config)
            PolicyRest._init()

    @staticmethod
    def _pdp_get_decision(audit, policy_ids):
        """get policies from the policy-engine by policy-ids"""
        if not PolicyRest._url:
            _LOGGER.error(
                audit.error("no url for PDP", error_code=AuditResponseCode.AVAILABILITY_ERROR))
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None, None

        with PolicyRest._lock:
            session = PolicyRest._requests_session
            target_entity = PolicyRest._target_entity
            url = PolicyRest._url_pdp_decision
            timeout_in_secs = PolicyRest._timeout_in_secs
            headers = copy.deepcopy(PolicyRest._headers)
            custom_kwargs = copy.deepcopy(PolicyRest._custom_kwargs)

        pdp_req = PolicyUtils.gen_req_to_pdp(policy_ids)

        metrics = Metrics(aud_parent=audit, targetEntity=target_entity, targetServiceName=url)

        headers = metrics.put_request_id_into_headers(headers)

        log_action = "post to {} at {}".format(target_entity, url)
        log_data = "msg={} headers={}, custom_kwargs({}) timeout_in_secs({})".format(
            json.dumps(pdp_req), Metrics.json_dumps(headers), json.dumps(custom_kwargs),
            timeout_in_secs)
        log_line = log_action + " " + log_data

        _LOGGER.info(metrics.metrics_start(log_line))

        res = None
        try:
            res = session.post(url, json=pdp_req, headers=headers, timeout=timeout_in_secs,
                               **custom_kwargs)
        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = ("failed {}: {} to {}".format(type(ex).__name__, str(ex), log_line))

            _LOGGER.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            return (error_code, None)

        log_line = "response {} from {}: text={} headers={}".format(
            res.status_code, log_line, res.text,
            Metrics.json_dumps(dict(res.request.headers.items())))

        _LOGGER.info(log_line)
        metrics.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)
        metrics.metrics(log_line)

        latest_policies = None
        if res.status_code == requests.codes.ok:
            policy_bodies = res.json().get(PDP_POLICIES, {})
            latest_policies = dict((policy_id, PolicyUtils.convert_to_policy(policy))
                                   for (policy_id, policy) in policy_bodies.items())

        return res.status_code, latest_policies


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

            _LOGGER.exception(error_msg)
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

        for retry in range(1, PolicyRest._policy_retry_count + 1):
            _LOGGER.debug("try(%s) retry_get_config(%s): %s", retry, retry_get_config, str_metrics)

            done, removed, latest_policy, status_code = PolicyRest._get_latest_policy_once(
                audit, policy_id, expected_versions, ignore_policy_names)

            if removed:
                audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_OK.value)
                return None

            if done or not retry_get_config or not PolicyRest._policy_retry_sleep:
                break

            if retry == PolicyRest._policy_retry_count:
                _LOGGER.error(
                    audit.error("gave up retrying after #{} for policy_id({}) from PDP {}"
                                .format(retry, policy_id, PolicyRest._url_pdp_decision),
                                error_code=AuditResponseCode.DATA_ERROR))
                break

            _LOGGER.warning(audit.warn(
                "will retry({}) for policy_id({}) in {} secs from PDP {}".format(
                    retry, policy_id, PolicyRest._policy_retry_sleep, PolicyRest._url_pdp_decision),
                error_code=AuditResponseCode.DATA_ERROR))
            time.sleep(PolicyRest._policy_retry_sleep)

        audit.set_http_status_code(status_code)
        if not PolicyUtils.validate_policy(latest_policy):
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_OK.value)
            _LOGGER.error(audit.error(
                "received invalid policy from PDP: {}".format(json.dumps(latest_policy)),
                error_code=AuditResponseCode.DATA_ERROR))

        return latest_policy

    @staticmethod
    def _get_latest_policy_once(audit, policy_id, expected_versions, ignore_policy_names):
        """single attempt to get the latest policy for the policy_id from the policy-engine"""

        status_code, latest_policies = PolicyRest._pdp_get_decision(audit, policy_id)

        if (ignore_policy_names and not expected_versions and not latest_policies
                and AuditHttpCode.HTTP_OK.value == status_code):
            return True, True, None, status_code

        log_line = "{} looking for policy_id({}) in latest_policies: {}".format(
            status_code, policy_id, json.dumps(latest_policies))
        _LOGGER.info(log_line)

        latest_policy = (latest_policies or {}).get(policy_id)

        log_error = ""
        if latest_policy:
            policy_body = latest_policy.get(POLICY_BODY, {})
            policy_version = policy_body.get(POLICY_VERSION)
            policy_name = policy_body.get(POLICY_NAME)
            if expected_versions and policy_version not in expected_versions:
                log_error = ("received unexpected policy version({}) instead of ({})"
                             " from PDP for policy_id={}: {}"
                             .format(policy_version, json.dumps(expected_versions),
                                     policy_id, json.dumps(latest_policy)))
            elif ignore_policy_names and policy_name in ignore_policy_names:
                log_error = ("unexpectedly received policy version({}) from PDP"
                             " for policy_id={}: {}. to ignore-policy-names {}"
                             .format(policy_version, policy_id,
                                     json.dumps(latest_policy),
                                     json.dumps(ignore_policy_names)))

        if not latest_policy or log_error:
            _LOGGER.error(audit.error(
                log_error or "received unexpected policy data({}) from PDP for policy_id={}: {}"
                .format(json.dumps(latest_policy), policy_id, json.dumps(latest_policies)),
                error_code=AuditResponseCode.DATA_ERROR))
            latest_policy = None

        done = bool(latest_policy or audit.is_serious_error(status_code))
        return done, False, latest_policy, status_code

    @staticmethod
    def get_latest_updated_policies(audit, updated_policies, removed_policies):
        """safely try retrieving the latest policies for the list of policy_names"""
        if not updated_policies and not removed_policies:
            return None, None

        policies_updated = [(policy_id, policy.get(POLICY_BODY, {}).get(POLICY_VERSION))
                            for policy_id, policy in updated_policies.items()]
        policies_removed = [(policy_id, policy.get(POLICY_NAMES, {}))
                            for policy_id, policy in removed_policies.items()]

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

            _LOGGER.exception(error_msg)
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
            targetServiceName=PolicyRest._url_pdp_decision)

        metrics_total.metrics_start("get_latest_updated_policies {0}".format(str_metrics))
        _LOGGER.debug(str_metrics)

        policies_to_find = {}
        for (policy_id, policy_version) in policies_updated:
            if not policy_id or policy_version is None:
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
        _LOGGER.debug("apns_length(%s) policies_to_find %s", apns_length,
                      json.dumps(policies_to_find))

        if apns_length == 1:
            policies = [PolicyRest.get_latest_policy(apns[0])]
        else:
            pool = ThreadPool(min(PolicyRest._thread_pool_size, apns_length))
            policies = pool.map(PolicyRest.get_latest_policy, apns)
            pool.close()
            pool.join()

        metrics_total.metrics("result({}) get_latest_updated_policies {}: {} {}"
                              .format(apns_length, str_metrics,
                                      len(policies), json.dumps(policies)))

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

        _LOGGER.debug(
            "result(%s) updated_policies %s, removed_policies %s, errored_policies %s",
            apns_length, json.dumps(updated_policies), json.dumps(removed_policies),
            json.dumps(errored_policies))

        if errored_policies:
            audit.set_http_status_code(AuditHttpCode.DATA_ERROR.value)
            audit.error(
                "errored_policies in PDP: {}".format(json.dumps(errored_policies)),
                error_code=AuditResponseCode.DATA_ERROR)

        return updated_policies, removed_policies


    @staticmethod
    def get_latest_policies(audit, policy_ids=None):
        """Get the latest policies by policy-ids from the policy-engine"""
        result = {}
        str_policy_ids = json.dumps(policy_ids or [])

        try:
            PolicyRest._lazy_init()
            if policy_ids:
                _, latest_policies = PolicyRest._pdp_get_decision(audit, policy_ids)

                if not latest_policies:
                    audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_OK.value)
                    _LOGGER.warning(audit.warn(
                        "received no policies from PDP for policy_ids {}"
                        .format(str_policy_ids), error_code=AuditResponseCode.DATA_ERROR))
                    return latest_policies

                valid_policies = {}
                errored_policies = {}
                for (policy_id, policy) in latest_policies.items():
                    if PolicyUtils.validate_policy(policy):
                        valid_policies[policy_id] = policy
                    else:
                        errored_policies[policy_id] = policy

                result[LATEST_POLICIES] = valid_policies
                result[ERRORED_POLICIES] = errored_policies

            _LOGGER.debug("got policies for policy_ids: %s. result: %s",
                          str_policy_ids, json.dumps(result))
            return result

        except Exception as ex:
            error_msg = ("{}: crash {} {} at {}: {}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "get_latest_policies", str_policy_ids))

            _LOGGER.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None
