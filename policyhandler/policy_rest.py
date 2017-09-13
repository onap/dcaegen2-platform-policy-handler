"""policy-client communicates with policy-engine thru REST API"""

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

import logging
import json
import copy
import re
import time
from multiprocessing.dummy import Pool as ThreadPool
import requests

from .config import Config
from .policy_consts import POLICY_ID, POLICY_VERSION, POLICY_NAME, POLICY_GET_CONFIG, \
    POLICY_BODY, POLICY_CONFIG
from .onap.audit import REQUEST_X_ECOMP_REQUESTID, Audit, AuditHttpCode, AuditResponseCode

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
        except ValueError as err:
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
        if policy and POLICY_BODY in policy and POLICY_CONFIG in policy[POLICY_BODY]:
            policy[POLICY_BODY][POLICY_CONFIG] = PolicyUtils.safe_json_parse(
                policy[POLICY_BODY][POLICY_CONFIG])
        return policy

    @staticmethod
    def convert_to_policy(policy_config):
        """wrap policy_config received from policy-engine with policy_id."""
        if not policy_config or POLICY_NAME not in policy_config \
        or POLICY_VERSION not in policy_config or not policy_config[POLICY_VERSION]:
            return
        policy_id = PolicyUtils.extract_policy_id(policy_config[POLICY_NAME])
        if not policy_id:
            return
        return {POLICY_ID:policy_id, POLICY_BODY:policy_config}

    @staticmethod
    def select_latest_policy(policy_configs):
        """For some reason, the policy-engine returns all version of the policy_configs.
        DCAE-Controller is only interested in the latest version
        """
        if not policy_configs:
            return
        latest_policy_config = {}
        for policy_config in policy_configs:
            if POLICY_VERSION not in policy_config or not policy_config[POLICY_VERSION] \
            or not policy_config[POLICY_VERSION].isdigit():
                continue
            if not latest_policy_config \
                or int(policy_config[POLICY_VERSION]) \
                 > int(latest_policy_config[POLICY_VERSION]):
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
            if not policy or POLICY_ID not in policy or POLICY_BODY not in policy:
                continue
            if POLICY_VERSION not in policy[POLICY_BODY] \
            or not policy[POLICY_BODY][POLICY_VERSION] \
            or not policy[POLICY_BODY][POLICY_VERSION].isdigit():
                continue
            if policy[POLICY_ID] not in policies:
                policies[policy[POLICY_ID]] = policy
                continue
            if int(policy[POLICY_BODY][POLICY_VERSION]) \
             > int(policies[policy[POLICY_ID]][POLICY_BODY][POLICY_VERSION]):
                policies[policy[POLICY_ID]] = policy

        for policy_id in policies:
            policies[policy_id] = PolicyUtils.parse_policy_config(policies[policy_id])

        return policies

class PolicyRest(object):
    """ policy-engine """
    _logger = logging.getLogger("policy_handler.policy_rest")
    _lazy_inited = False

    _requests_session = None
    _url = None
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

        PolicyRest._url = config["url"] + config["path_api"]
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
            PolicyRest._url, Audit.log_json_dumps(PolicyRest._headers), \
            json.dumps(PolicyRest._scope_prefixes))

    @staticmethod
    def _post(audit, path, json_body):
        """Communication with the policy-engine"""
        full_path = PolicyRest._url + path
        sub_aud = Audit(aud_parent=audit, targetEntity=PolicyRest._target_entity, \
            targetServiceName=full_path)

        msg = json.dumps(json_body)
        headers = copy.copy(PolicyRest._headers)
        headers[REQUEST_X_ECOMP_REQUESTID] = sub_aud.request_id
        headers_str = Audit.log_json_dumps(headers)

        log_line = "post to PDP {0} msg={1} headers={2}".format(full_path, msg, headers_str)
        sub_aud.metrics_start(log_line)
        PolicyRest._logger.info(log_line)
        res = None
        try:
            res = PolicyRest._requests_session.post(full_path, json=json_body, headers=headers)
        except requests.exceptions.RequestException as ex:
            error_code = AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
            error_msg = "failed to post to PDP {0} {1} msg={2} headers={3}" \
                .format(full_path, str(ex), msg, headers_str)

            PolicyRest._logger.exception(error_msg)
            sub_aud.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            sub_aud.metrics(error_msg)
            return (error_code, None)

        log_line = "response from PDP to post {0}: {1} msg={2} text={3} headers={4}".format( \
            full_path, res.status_code, msg, res.text, \
            Audit.log_json_dumps(dict(res.request.headers.items())))
        sub_aud.set_http_status_code(res.status_code)
        sub_aud.metrics(log_line)
        PolicyRest._logger.info(log_line)

        if res.status_code == requests.codes.ok:
            return res.status_code, res.json()

        return res.status_code, None

    @staticmethod
    def get_latest_policy(aud_policy_name):
        """Get the latest policy for the policy_name from the policy-engine"""
        PolicyRest._lazy_init()
        audit, policy_name = aud_policy_name

        status_code = 0
        latest_policy = None
        for retry in xrange(1, PolicyRest._policy_retry_count + 1):
            PolicyRest._logger.debug("%s", policy_name)
            status_code, policy_configs = PolicyRest._post(audit, POLICY_GET_CONFIG, \
                                            {POLICY_NAME:policy_name})
            PolicyRest._logger.debug("%s %s policy_configs: %s", status_code, policy_name, \
                        json.dumps(policy_configs or []))
            latest_policy = PolicyUtils.select_latest_policy(policy_configs)
            if not latest_policy:
                audit.error("received unexpected policy data from PDP for policy_name={0}: {1}" \
                    .format(policy_name, json.dumps(policy_configs or [])), \
                    errorCode=AuditResponseCode.DATA_ERROR.value, \
                    errorDescription=AuditResponseCode.get_human_text( \
                        AuditResponseCode.DATA_ERROR))

            if latest_policy or not audit.retry_get_config \
            or not PolicyRest._policy_retry_sleep \
            or AuditResponseCode.PERMISSION_ERROR.value \
            == AuditResponseCode.get_response_code(status_code).value:
                break

            if retry == PolicyRest._policy_retry_count:
                audit.warn("gave up retrying {0} from PDP after #{1} for policy_name={2}" \
                    .format(POLICY_GET_CONFIG, retry, policy_name), \
                    errorCode=AuditResponseCode.DATA_ERROR.value, \
                    errorDescription=AuditResponseCode.get_human_text( \
                            AuditResponseCode.DATA_ERROR))
                break

            audit.warn("retry #{0} {1} from PDP in {2} secs for policy_name={3}" \
                .format(retry, POLICY_GET_CONFIG, PolicyRest._policy_retry_sleep, policy_name), \
                errorCode=AuditResponseCode.DATA_ERROR.value, \
                errorDescription=AuditResponseCode.get_human_text( \
                        AuditResponseCode.DATA_ERROR))
            time.sleep(PolicyRest._policy_retry_sleep)

        audit.set_http_status_code(status_code)
        if not latest_policy:
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
        return latest_policy

    @staticmethod
    def get_latest_policies_by_names(aud_policy_names):
        """Get the latest policies of the list of policy_names from the policy-engine"""
        PolicyRest._lazy_init()
        audit, policy_names = aud_policy_names
        if not policy_names:
            return

        audit.metrics_start("get_latest_policies_by_names {0} {1}".format( \
            len(policy_names), json.dumps(policy_names)))
        PolicyRest._logger.debug("%d %s", len(policy_names), json.dumps(policy_names))

        thread_count = min(PolicyRest._thread_pool_size, len(policy_names))
        apns = [(audit, policy_name) for policy_name in policy_names]
        policies = None
        if thread_count == 1:
            policies = [PolicyRest.get_latest_policy(apns[0])]
        else:
            pool = ThreadPool(thread_count)
            policies = pool.map(PolicyRest.get_latest_policy, apns)
            pool.close()
            pool.join()

        audit.metrics("result get_latest_policies_by_names {0} {1}: {2} {3}".format( \
            len(policy_names), json.dumps(policy_names), len(policies), json.dumps(policies)), \
            targetEntity=PolicyRest._target_entity, targetServiceName=POLICY_GET_CONFIG)
        policies = dict([(policy[POLICY_ID], policy) \
            for policy in policies if policy and POLICY_ID in policy])
        PolicyRest._logger.debug("policies %s", json.dumps(policies))
        if not policies:
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
        return policies

    @staticmethod
    def _get_latest_policies(aud_scope_prefix):
        """Get the latest policies of the same scope from the policy-engine"""
        audit, scope_prefix = aud_scope_prefix
        PolicyRest._logger.debug("%s", scope_prefix)
        status_code, policy_configs = PolicyRest._post(audit, POLICY_GET_CONFIG, \
                                          {POLICY_NAME:scope_prefix + ".*"})
        audit.set_http_status_code(status_code)
        PolicyRest._logger.debug("%s policy_configs: %s %s", status_code, \
              scope_prefix, json.dumps(policy_configs or []))
        latest_policies = PolicyUtils.select_latest_policies(policy_configs)

        if not latest_policies:
            audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
            audit.error("received unexpected policies data from PDP for scope {0}: {1}".format( \
                scope_prefix, json.dumps(policy_configs or [])), \
                errorCode=AuditResponseCode.DATA_ERROR.value, \
                errorDescription=AuditResponseCode.get_human_text( \
                        AuditResponseCode.DATA_ERROR))
        return latest_policies

    @staticmethod
    def get_latest_policies(audit):
        """Get the latest policies of the same scope from the policy-engine"""
        PolicyRest._lazy_init()
        PolicyRest._logger.debug("%s", json.dumps(PolicyRest._scope_prefixes))

        audit.metrics_start("get_latest_policies for scopes {0} {1}".format( \
            len(PolicyRest._scope_prefixes), json.dumps(PolicyRest._scope_prefixes)))
        asps = [(audit, scope_prefix) for scope_prefix in PolicyRest._scope_prefixes]
        latest_policies = None
        if PolicyRest._scope_thread_pool_size == 1:
            latest_policies = [PolicyRest._get_latest_policies(asps[0])]
        else:
            pool = ThreadPool(PolicyRest._scope_thread_pool_size)
            latest_policies = pool.map(PolicyRest._get_latest_policies, asps)
            pool.close()
            pool.join()

        audit.metrics("total result get_latest_policies for scopes {0} {1}: {2} {3}".format( \
            len(PolicyRest._scope_prefixes), json.dumps(PolicyRest._scope_prefixes), \
            len(latest_policies), json.dumps(latest_policies)), \
            targetEntity=PolicyRest._target_entity, targetServiceName=POLICY_GET_CONFIG)

        latest_policies = dict(pair for lp in latest_policies if lp for pair in lp.items())
        PolicyRest._logger.debug("latest_policies: %s %s", \
              json.dumps(PolicyRest._scope_prefixes), json.dumps(latest_policies))

        return latest_policies
