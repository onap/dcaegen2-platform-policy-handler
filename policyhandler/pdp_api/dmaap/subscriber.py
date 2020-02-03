# ============LICENSE_START=======================================================
#   policy-handler
#  ================================================================================
#   Copyright (C) 2020 Wipro Limited.
#  ==============================================================================
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#   ============LICENSE_END=========================================================
import copy
from datetime import datetime

import requests

from policyhandler.utils import Utils
from ...config import Config, Settings
from ...onap.audit import Metrics, AuditHttpCode
import json
_LOGGER = Utils.get_logger(__file__)


class Subscriber(object):
    """Subscribe to DMaap to listen for policy change message"""
    DMAAP_HEALTH = "DMaap_health"
    DMAAP_MESSAGE_COUNT = "message_count"
    DMAAP_ERROR_COUNT = "error_count"
    DMAAP_MESSAGE_TIMESTAMP = "message_timestamp"
    DMAAP_STATUS = "dmaap_status"
    LAST_ERROR = "last_error"

    def __init__(self):
        self._settings = Settings(Config.FIELD_DMAAP)
        self._target_entity = "None"
        self._audit = None
        self.dmaap_url = "dmaap_url"
        self.dmaap_timeout = "dmaap_timeout"
        self.http_headers = "http_headers"
        self._dmaap_health = {
            self.DMAAP_MESSAGE_COUNT: 0,
            self.DMAAP_ERROR_COUNT: 0,
            self.DMAAP_STATUS: "Disconnected",
        }

    def reconfigure(self, audit):
        self._audit = audit
        self._settings.set_config(Config.discovered_config)
        changed, config = self._settings.get_by_key(Config.FIELD_DMAAP)
        if not changed:
            self._settings.commit_change()
            return False

        prev_dmaap_url = self.dmaap_url
        prev_dmaap_timeout = self.dmaap_timeout
        prev_http_headers = self.http_headers

        self.dmaap_url = config.get("dmaap_url")
        self._target_entity = config.get("target_entity")
        self.http_headers = config.get("http_headers")
        self.dmaap_timeout = config.get("dmaap_timeout")
        log_changed = (
                "changed dmaap_url(%s): %s" % (self.dmaap_url, self._settings))

        if self.dmaap_url == prev_dmaap_url and self.dmaap_timeout == prev_dmaap_timeout and \
                self.http_headers == prev_http_headers:
            _LOGGER.info(audit.info("not {}".format(log_changed)))
            self._settings.commit_change()
            return False

        _LOGGER.info(audit.info(log_changed))
        self._settings.commit_change()
        return True

    def get_messages(self):
        audit = self._audit
        metrics = Metrics(aud_parent=audit, targetEntity=self._target_entity, targetServiceName=self.dmaap_url)
        log_action = "get from {} at {}".format(self._target_entity, self.dmaap_url)
        log_data = "get request, headers={}".format(Metrics.json_dumps(self.http_headers))

        log_line = log_action + " " + log_data

        _LOGGER.info(metrics.metrics_start(log_line))

        try:
            http_response = requests.get(self.dmaap_url, self.http_headers, timeout=self.dmaap_timeout)

        except Exception as ex:
            error_code = (AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value
                          if isinstance(ex, requests.exceptions.RequestException)
                          else AuditHttpCode.SERVER_INTERNAL_ERROR.value)
            error_msg = ("Requests Exception occurred {}".format(str(ex))
                         if isinstance(ex, requests.exceptions.RequestException)
                         else "Exception occurred {}".format(str(ex)))
            _LOGGER.exception(error_msg)
            metrics.set_http_status_code(error_code)
            audit.set_http_status_code(error_code)
            metrics.metrics(error_msg)
            self._dmaap_health[self.DMAAP_STATUS] = "disconnected"
            self._on_error(str(ex))
            return None

        log_line = "response {} from {}: text={} headers={}".format(
            http_response.status_code, log_line, http_response.text,
            Metrics.json_dumps(dict(http_response.request.headers.items())))

        _LOGGER.info(log_line)
        metrics.set_http_status_code(http_response.status_code)
        audit.set_http_status_code(http_response.status_code)
        metrics.metrics(log_line)

        if http_response.status_code == requests.codes.ok:
            self._dmaap_health[self.DMAAP_STATUS] = "connected"
            messages = http_response.json()
            self._dmaap_health[self.DMAAP_MESSAGE_TIMESTAMP] = str(datetime.utcnow())
            return messages

    def get_dmaap_health(self):
        dmaap_health = copy.deepcopy(self._dmaap_health)
        return dmaap_health

    def _on_error(self, error):
        _LOGGER.exception("policy-notification error %s", str(error))
        self._dmaap_health[self.DMAAP_STATUS] = "error"
        self._dmaap_health[self.DMAAP_ERROR_COUNT] += 1
        self._dmaap_health["last_error"] = str(error)
        _LOGGER.info("dmaap_health %s", json.dumps(self.get_dmaap_health(), sort_keys=True))
