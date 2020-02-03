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

"""policy-client communicates with policy-engine thru REST API"""

import copy
import json
import os
import urllib.parse
from threading import Lock

import requests

from ..config import Config, Settings
from ..onap.audit import (REQUEST_X_ECOMP_REQUESTID, AuditHttpCode,
                          AuditResponseCode, Metrics)
from ..utils import Utils
from .pdp_consts import PDP_POLICIES, PDP_POLICY_VERSION
from ..policy_consts import POLICY_ID, LATEST_POLICIES, ERRORED_POLICIES, POLICY_BODY
from .policy_utils import PolicyUtils

_LOGGER = Utils.get_logger(__file__)


class PolicyRest(object):
    """using the http API to policy-engine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    _lazy_inited = False
    DEFAULT_TIMEOUT_IN_SECS = 60

    _lock = Lock()
    _settings = Settings(Config.FIELD_POLICY_ENGINE)

    _target_entity = None
    _requests_session = None
    _url = None
    _url_pdp_decision = None
    _headers = None
    _custom_kwargs = {}
    _timeout_in_secs = DEFAULT_TIMEOUT_IN_SECS

    @staticmethod
    def _init():
        """init static config"""
        PolicyRest._custom_kwargs = {}
        tls_ca_mode = None

        if not PolicyRest._requests_session:
            PolicyRest._requests_session = requests.Session()

        _, config = PolicyRest._settings.get_by_key(Config.FIELD_POLICY_ENGINE)
        if config:
            PolicyRest._url = config.get("url")
            if PolicyRest._url:
                PolicyRest._url_pdp_decision = urllib.parse.urljoin(
                    PolicyRest._url, config.get("path_decision", "/decision/v1/"))
            PolicyRest._headers = config.get("headers", {})
            PolicyRest._target_entity = config.get("target_entity", Config.FIELD_POLICY_ENGINE)

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
    def _pdp_get_decision(audit, pdp_req):
        """Communication with the policy-engine"""
        if not PolicyRest._url:
            _LOGGER.error(
                audit.error("no url for PDP", error_code=AuditResponseCode.AVAILABILITY_ERROR))
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None

        with PolicyRest._lock:
            session = PolicyRest._requests_session
            target_entity = PolicyRest._target_entity
            url = PolicyRest._url_pdp_decision
            timeout_in_secs = PolicyRest._timeout_in_secs
            headers = copy.deepcopy(PolicyRest._headers)
            custom_kwargs = copy.deepcopy(PolicyRest._custom_kwargs)

        metrics = Metrics(aud_parent=audit, targetEntity=target_entity, targetServiceName=url)

        headers[REQUEST_X_ECOMP_REQUESTID] = metrics.request_id

        log_action = "post to {} at {}".format(target_entity, url)
        log_data = "msg={} headers={}, custom_kwargs({}) timeout_in_secs({})".format(
            json.dumps(pdp_req), Metrics.json_dumps(headers), json.dumps(custom_kwargs),
            timeout_in_secs)
        log_line = log_action + " " + log_data

        _LOGGER.info(metrics.metrics_start(log_line))

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
            return None

        log_line = "response {} from {}: text={} headers={}".format(
            res.status_code, log_line, res.text,
            Metrics.json_dumps(dict(res.request.headers.items())))

        _LOGGER.info(log_line)
        metrics.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)
        metrics.metrics(log_line)

        policy_bodies = None
        if res.status_code == requests.codes.ok:
            policy_bodies = res.json().get(PDP_POLICIES)

        return policy_bodies

    @staticmethod
    def get_latest_updated_policies(audit, updated_policies, removed_policies):
        """safely try retrieving the latest policies for the list of policies updated and removed"""
        metrics_total = Metrics(
            aud_parent=audit,
            targetEntity="{0} total get_latest_updated_policies".format(PolicyRest._target_entity),
            targetServiceName=PolicyRest._url_pdp_decision)

        policy_updated = {}
        policy_removed = []
        if not updated_policies and not removed_policies:
            return None, None

        for policy_id, policy in updated_policies.items():
            policy_updated[policy_id] = policy.get(POLICY_BODY).get(PDP_POLICY_VERSION)

        for policy_id, policy in removed_policies.items():
            policy_removed.append(policy_id)

        if not policy_updated and not policy_removed:
            return None, None

        str_metrics = "policies_updated[{0}]: {1} policies_removed[{2}]: {3}".format(
            len(policy_updated), json.dumps(policy_updated),
            len(policy_removed), json.dumps(policy_removed))

        policies_to_find = {}
        for policy_id in policy_updated:
            if not policy_id:
                continue
            else:
                policy = policies_to_find.get(policy_id)
                if not policy:
                    policies_to_find[policy_id] = {
                        POLICY_ID: policy_id
                    }

        for (policy_id) in policy_removed:
            if not policy_id:
                continue
            policy = policies_to_find.get(policy_id)
            if not policy:
                policies_to_find[policy_id] = {
                    POLICY_ID: policy_id
                }

        policies_list = [policy_id for (policy_id, policy_to_find) in policies_to_find.items()]
        apns = (audit, policies_list)
        apns_length = len(policies_list)
        _LOGGER.debug("apns_length(%s) policies_to_find %s", apns_length,
                      json.dumps(policies_to_find))

        try:
            if apns_length == 1:
                policies = [PolicyRest.get_latest_policy((audit, policies_list[0], None, None))]
            else:
                policies, _ = PolicyRest._get_latest_policies(apns)

            metrics_total.metrics("result({}) get_latest_updated_policies {}: {} {}"
                                  .format(apns_length, str_metrics,
                                          len(policies), json.dumps(policies)))

            updated_policies = dict((policy[POLICY_ID], policy)
                                    for policy in policies
                                    if policy and policy.get(POLICY_ID))

            removed_policies = dict((policy_id, True)
                                    for (policy_id, policy_to_find) in policies_to_find.items()
                                    if policy_id not in updated_policies)

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

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "get_latest_updated_policies", str_metrics))

            _LOGGER.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None, None

    @staticmethod
    def get_latest_policy(aud_policy_id):
        """safely try retrieving the latest policy for the policy_id from the policy-engine"""
        audit, policy_id, _, _ = aud_policy_id
        try:
            PolicyRest._lazy_init()

            pdp_req = PolicyUtils.gen_req_to_pdp(policy_id)
            policy_bodies = PolicyRest._pdp_get_decision(audit, pdp_req)
            errored_policies = {}

            log_line = "looking for policy_id({}) in policy_bodies: {}".format(
                policy_id, json.dumps(policy_bodies))
            _LOGGER.info(log_line)

            latest_policy = None
            if not policy_bodies:
                errored_policies[policy_id] = {}
                _LOGGER.info("policies not found or removed policies: {}".format(json.dumps(errored_policies)))

            if policy_bodies and policy_id in policy_bodies:
                latest_policy = PolicyUtils.convert_to_policy(policy_bodies[policy_id])

            if not PolicyUtils.validate_policy(latest_policy):
                audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_OK.value)
                _LOGGER.error(audit.error(
                    "received invalid policy from PDP: {}".format(json.dumps(latest_policy)),
                    error_code=AuditResponseCode.DATA_ERROR))

            return latest_policy
        except Exception as ex:
            error_msg = ("{}: get_latest_policy({}) crash {}: {}"
                         .format(audit.request_id, policy_id, type(ex).__name__, str(ex)))

            _LOGGER.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None

    @staticmethod
    def _get_policies(aud_policies):
        """safely try retrieving the valid and errored policies for the policy_ids
                             from the policy-engine for catch_up"""
        audit, policies = aud_policies
        pdp_req = PolicyUtils.gen_collective_req_to_pdp(policies)
        try:
            PolicyRest._lazy_init()
            policy_bodies = PolicyRest._pdp_get_decision(audit, pdp_req)
            valid_policies = {}
            errored_policies = {}

            for policy_id in policies:
                if policy_id not in policy_bodies:
                    errored_policies[policy_id] = {}
                    _LOGGER.info("policies not found or removed policies: {}".format(json.dumps(errored_policies)))

            for policy_id, policy_body in policy_bodies.items():
                latest_policy = (PolicyUtils.convert_to_policy(policy_body))
                if not PolicyUtils.validate_policy(latest_policy):
                    audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_OK.value)
                    _LOGGER.error(audit.error(
                        "received invalid policy from PDP: {}".format(json.dumps(latest_policy)),
                        error_code=AuditResponseCode.DATA_ERROR))
                valid_policies[policy_id] = latest_policy

            return valid_policies, errored_policies

        except Exception as ex:
            error_msg = ("{}: get_latest_policy() crash {}: {}"
                         .format(audit.request_id, type(ex).__name__, str(ex)))

            _LOGGER.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None

    @staticmethod
    def _get_latest_policies(aud_policies):
        """safely try retrieving the list of latest policies for the policy_ids from the policy-engine"""

        valid_policies, _ = PolicyRest._get_policies(aud_policies)
        return list(valid_policies.values())

    @staticmethod
    def get_latest_policies(audit, policy_ids):
        """Get the latest policies from the policy-engine"""
        result = {}

        str_metrics = None
        try:
            PolicyRest._lazy_init()

            target_entity = PolicyRest._target_entity
            metrics_total = Metrics(aud_parent=audit, targetEntity=target_entity,
                                    targetServiceName=PolicyRest._url_pdp_decision)
            str_metrics = "get_latest_policy for catchup"
            metrics_total.metrics_start(str_metrics)

            latest_policies = [PolicyRest._get_policies((audit, policy_ids))]

            metrics_total.metrics("total result {0}: {1} {2}".format(
                str_metrics, len(latest_policies), json.dumps(latest_policies)))

            # latest_policies == [(valid_policies, errored_policies), ...]
            result[LATEST_POLICIES] = dict(
                pair for (vps, _) in latest_policies if vps for pair in vps.items())

            result[ERRORED_POLICIES] = dict(
                pair for (_, eps) in latest_policies if eps for pair in eps.items())

            _LOGGER.debug("got policies result: %s", json.dumps(result))
            return result

        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: {4}"
                         .format(audit.request_id, type(ex).__name__, str(ex),
                                 "get_latest_policies", str_metrics))

            _LOGGER.exception(error_msg)
            audit.fatal(error_msg, error_code=AuditResponseCode.BUSINESS_PROCESS_ERROR)
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None
