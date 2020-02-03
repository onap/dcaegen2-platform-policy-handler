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

import requests
from ...config import Config, Settings
from policyhandler.utils import Utils

_LOGGER = Utils.get_logger(__file__)


class Subscriber:

    """Subscribe to DMaap to listen for policy change message"""
    HTTP_HEADERS = {"Accept": "application/json"}

    def __init__(self):
        self._settings = Settings(Config.FIELD_DMAAP)
        self.dmaap_url = "dmaap_url"

    def reconfigure(self, audit):
        self._settings.set_config(Config.discovered_config)
        changed, config = self._settings.get_by_key(Config.FIELD_DMAAP)
        if not changed:
            self._settings.commit_change()
            return False

        prev_dmaap_url = self.dmaap_url

        self.dmaap_url = config.get("dmaap_url")

        log_changed = (
                "changed dmaap_url(%s): %s" % (self.dmaap_url, self._settings))

        if self.dmaap_url == prev_dmaap_url:
            _LOGGER.info(audit.info("not {}".format(log_changed)))
            self._settings.commit_change()
            return False

        _LOGGER.info(audit.info(log_changed))
        self._settings.commit_change()
        return True

    def get_messages(self):
        try:
            http_response = requests.get(self.dmaap_url, Subscriber.HTTP_HEADERS)
            if http_response.status_code == requests.codes.ok:
                status = ("RESPONSE CODE FROM DMAAP : (%s)" % http_response.status_code)
                _LOGGER.info(status)
                messages = http_response.json()
                return messages
            else:
                status = (
                          "HTTP response from dmaap , status code: (%s)" % http_response.status_code)
                _LOGGER.info(status)

        except Exception as ex:
            error_msg = ("Requests Exception occurred {}".format(str(ex))
                         if isinstance(ex, requests.exceptions.RequestException)
                         else "Exception occured {}".format(str(ex)))
            _LOGGER.exception(error_msg)
            raise ex
