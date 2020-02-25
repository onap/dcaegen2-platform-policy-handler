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
from threading import Lock

import requests

from ..config import Config, Settings
from ..onap.audit import AuditHttpCode, AuditResponseCode, Metrics
from ..utils import Utils

_LOGGER = Utils.get_logger(__file__)

class DmaapMr(object):
    """using the http API to policy-engine"""
    _lazy_inited = False
    DEFAULT_TIMEOUT_IN_SECS = 60

    _lock = Lock()
    _settings = Settings(Config.DMAAP_MR)

    _requests_session = None
    _drain = True
    _target_entity = None
    _url = None
    _query = {}
    _headers = None
    _custom_kwargs = {}
    _timeout_in_secs = DEFAULT_TIMEOUT_IN_SECS

    @staticmethod
    def _init(audit):
        """init static config"""
        DmaapMr._custom_kwargs = {}
        tls_ca_mode = None

        if not DmaapMr._requests_session:
            DmaapMr._requests_session = requests.Session()
            DmaapMr._requests_session.mount(
                'https://', requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1,
                                                          pool_block=True))
            DmaapMr._requests_session.mount(
                'http://', requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1,
                                                         pool_block=True))


        _, config = DmaapMr._settings.get_by_key(Config.DMAAP_MR)
        if config:
            DmaapMr._url = config.get("url")
            DmaapMr._headers = config.get("headers", {})
            DmaapMr._query = copy.deepcopy(config.get("query", {}))
            if DmaapMr._query.get(Config.QUERY_TIMEOUT, 0) < 1000:
                DmaapMr._query[Config.QUERY_TIMEOUT] = 15000

            DmaapMr._target_entity = config.get("target_entity", Config.DMAAP_MR)

            tls_ca_mode = config.get(Config.TLS_CA_MODE)
            DmaapMr._custom_kwargs = Config.get_requests_kwargs(tls_ca_mode)
            DmaapMr._timeout_in_secs = config.get(Config.TIMEOUT_IN_SECS)
            if not DmaapMr._timeout_in_secs or DmaapMr._timeout_in_secs < 1:
                DmaapMr._timeout_in_secs = DmaapMr.DEFAULT_TIMEOUT_IN_SECS

        _LOGGER.info(
            audit.info(("config DMaaP MR({}) url({}) query({}) headers({}) "
                        "tls_ca_mode({}) custom_kwargs({}) timeout_in_secs({}): {}").format(
                            DmaapMr._target_entity, DmaapMr._url,
                            Metrics.json_dumps(DmaapMr._query),
                            Metrics.json_dumps(DmaapMr._headers), tls_ca_mode,
                            json.dumps(DmaapMr._custom_kwargs), DmaapMr._timeout_in_secs,
                            DmaapMr._settings)))

        DmaapMr._settings.commit_change()
        DmaapMr._lazy_inited = True

    @staticmethod
    def reconfigure(audit):
        """reconfigure"""
        with DmaapMr._lock:
            DmaapMr._settings.set_config(Config.discovered_config)
            if not DmaapMr._settings.is_changed():
                DmaapMr._settings.commit_change()
                return False

            DmaapMr._lazy_inited = False
            DmaapMr._drain = True
            DmaapMr._init(audit)
        return True

    @staticmethod
    def _lazy_init(audit):
        """init static config"""
        if DmaapMr._lazy_inited:
            return

        with DmaapMr._lock:
            if DmaapMr._lazy_inited:
                return

            DmaapMr._settings.set_config(Config.discovered_config)
            DmaapMr._drain = True
            DmaapMr._init(audit)

    @staticmethod
    def get_policy_updates(audit):
        """
        get from DMaaP MR - returns json list of stringified messages

        example [
            "{\"deployed-policies\":[
                {\"policy-type\":\"onap.policies.monitoring.cdap.tca.hi.lo.app\",
                 \"policy-type-version\":\"1.0.0\",
                 \"policy-id\":\"onap.scaleout.tca\",
                 \"policy-version\":\"2.2.2\",
                 \"success-count\":3,
                 \"failure-count\":0
            }],
             \"undeployed-policies\":[
                {\"policy-type\":\"onap.policies.monitoring.cdap.tca.hi.lo.app\",
                 \"policy-type-version\":\"1.0.0\",
                 \"policy-id\":\"onap.scaleout.tca\",
                 \"policy-version\":\"1.0.0\",
                 \"success-count\":3,
                 \"failure-count\":0
            }]}"
        ]
        """
        DmaapMr._lazy_init(audit)

        if not DmaapMr._url:
            _LOGGER.error(
                audit.error("no url for DMaaP MR", error_code=AuditResponseCode.AVAILABILITY_ERROR))
            audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            return None

        with DmaapMr._lock:
            target_entity = DmaapMr._target_entity
            url = DmaapMr._url
            params = copy.deepcopy(DmaapMr._query) if not DmaapMr._drain else None
            headers = copy.deepcopy(DmaapMr._headers)
            timeout_in_secs = DmaapMr._timeout_in_secs
            custom_kwargs = copy.deepcopy(DmaapMr._custom_kwargs)
            DmaapMr._drain = False

        metrics = Metrics(aud_parent=audit, targetEntity=target_entity, targetServiceName=url)

        headers = metrics.put_request_id_into_headers(headers)

        log_line = (
            "get from {} at {} with params={}, headers={}, custom_kwargs({}) timeout_in_secs({})"
            .format(target_entity, url, json.dumps(params), Metrics.json_dumps(headers),
                    json.dumps(custom_kwargs), timeout_in_secs))

        _LOGGER.info(metrics.metrics_start(log_line))

        res = None
        try:
            res = DmaapMr._requests_session.get(url, params=params, headers=headers,
                                                timeout=timeout_in_secs, **custom_kwargs)

            log_line = "response {} from {}: text={} headers={}".format(
                res.status_code, log_line, res.text, Metrics.json_dumps(dict(res.headers.items())))
            _LOGGER.info(log_line)

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

        metrics.set_http_status_code(res.status_code)
        audit.set_http_status_code(res.status_code)
        metrics.metrics(log_line)

        policy_updates = None
        if res.status_code == requests.codes.ok:
            policy_updates = res.json()

        return policy_updates
