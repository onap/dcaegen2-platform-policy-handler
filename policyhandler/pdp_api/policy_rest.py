# ================================================================================
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
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
from .pdp_consts import PDP_POLICIES
from .policy_utils import PolicyUtils

_LOGGER = Utils.get_logger(__file__)

class PolicyRest(object):
    """using the http API to policy-engine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    _lazy_inited = False
    DEFAULT_TIMEOUT_IN_SECS = 60

    _lock = Lock()
    _settings = Settings(Config.FIELD_POLICY_ENGINE, Config.POOL_CONNECTIONS)

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

        changed, pool_size = PolicyRest._settings.get_by_key(Config.POOL_CONNECTIONS, 20)
        if changed:
            PolicyRest._requests_session.mount(
                'https://', requests.adapters.HTTPAdapter(pool_connections=pool_size,
                                                          pool_maxsize=pool_size))
            PolicyRest._requests_session.mount(
                'http://', requests.adapters.HTTPAdapter(pool_connections=pool_size,
                                                         pool_maxsize=pool_size))

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
    def get_latest_policy(aud_policy_id):
        """safely try retrieving the latest policy for the policy_id from the policy-engine"""
        audit, policy_id, _, _ = aud_policy_id
        try:
            PolicyRest._lazy_init()

            pdp_req = PolicyUtils.gen_req_to_pdp(policy_id)
            policy_bodies = PolicyRest._pdp_get_decision(audit, pdp_req)

            log_line = "looking for policy_id({}) in policy_bodies: {}".format(
                policy_id, json.dumps(policy_bodies))
            _LOGGER.info(log_line)

            latest_policy = None
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
