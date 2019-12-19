# ============LICENSE_START=======================================================
 # policy-handler
 #  ================================================================================
 # Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
 #  Copyright (C) 2019 Wipro Limited.
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
#

"""
policy-listener communicates with policy-engine
thru DMaap to receive push notifications
on updates and removal of policies.

on receiving the policy-notifications, the policy-receiver
passes the notifications to policy-updater
"""

import copy
import json
import os
import requests as r
import time
import urllib.parse
from datetime import datetime
from threading import Lock, Thread

from .DMaap import Subscriber

from ..config import Config, Settings
from ..onap.audit import Audit
from ..utils import Utils
from .pdp_consts import POLICY_NAME, POLICY_VERSION, PDP_POLICY_ID, PDP_POLICY_VERSION

REMOVED = 'deleted-policies'
ADDED = 'added-policies'


_LOGGER = Utils.get_logger(__file__)

class PolicyListener(Thread):
    """DMaap to PolicyEngine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))
    DMAAP_HEALTH = "DMaap_health"
    DMAAP_MESSAGE_COUNT = "message_count"
    DMAAP_ERROR_COUNT = "error_count"
    DMAAP_MESSAGE_TIMESTAMP = "message_timestamp"
    DMAAP_STATUS = "dmaap_status"

    def __init__(self, audit, policy_updater):
        """DMaap inside the thread to receive policy notifications from PolicyEngine"""
        Thread.__init__(self, name="policy_receiver", daemon=True)
        self._policy_updater = policy_updater
        self._lock = Lock()
        self._settings = Settings(Config.FIELD_DMAAP)
        self._keep_running = True
        self._sleep_before_restarting = 5
        self.server_info=None
        self.group=None
        self.group_id=None
        self.topic=None
        self.dmaap_timeout=10
        self._dmaap_health = {
            PolicyListener.DMAAP_MESSAGE_COUNT : 0
        }
        Audit.register_item_health(PolicyListener.DMAAP_HEALTH, self._get_health)
        self.reconfigure(audit)

    def reconfigure(self,audit):

        """configure and reconfigure the DMaap"""
        with self._lock:
            _LOGGER.info(audit.info("DMaap_HEALTH {}".format(
                json.dumps(self._get_health(), sort_keys=True))))
            self._sleep_before_restarting = 5
            self._settings.set_config(Config.discovered_config)
            changed, config = self._settings.get_by_key(Config.FIELD_DMAAP)

            if not changed:
                self._settings.commit_change()

            prev_dmaap_server_info = self.server_info
            prev_dmaap_topic = self.topic
            prev_group = self.group
            prev_group_id = self.group_id
            prev_dmaap_timeout=self.dmaap_timeout

            self.server_info=config.get("server_info")
            self.group=config.get("group")
            self.group_id=config.get("group_id")
            self.topic=config.get("topic")
            self.dmaap_timeout=config.get("dmaap_timeout")

            log_changed = (
                "changed dmaap_server_info(%s) or dmaap_topic(%s)"
                " or dmaap_group(%s) or dmaap_group_id(%s): %s" %
                (self.server_info, self.topic, self.group, self.group_id,
                 self._settings))

            if (self.server_info == prev_dmaap_server_info
                    and self.topic == prev_dmaap_topic
                    and self.group == prev_group
                    and self.group_id == prev_group_id
                    and self.dmaap_timeout == prev_dmaap_timeout):
                _LOGGER.info(audit.info("not {}".format(log_changed)))
                self._settings.commit_change()
                return False

            _LOGGER.info(audit.info(log_changed))
            self._settings.commit_change()

        self._stop_notifications()
        return True

    def run(self):
        """subscribe to dmaap and pass the policy notifications to policy-updater"""
        _LOGGER.info("starting policy_receiver...")
        restarting = False
        while True:
            if self._get_keep_running():
                break

            self._keep_running = True
            if restarting:
                with self._lock:
                    sleep_before_restarting = self._sleep_before_restarting
                _LOGGER.info(
                    "going to sleep for %s secs before restarting policy-notifications",
                    sleep_before_restarting)

                time.sleep(sleep_before_restarting)
                if not self._get_keep_running():
                    break

            dmaap_obj=Subscriber()

            with self._lock:
                dmaap_obj.server_info = self.server_info
                dmaap_obj.topic = self.topic
                dmaap_obj.group = self.group
                dmaap_obj.group_id = self.group_id
                dmaap_obj.dmaap_timeout = self.dmaap_timeout

            _LOGGER.info(
                "connecting to policy-notifications at %s with topic(%s) group(%s) and group id (%s)",
                server_info, topic, group, group_id)
            _LOGGER.info("waiting for policy-notifications...")

            while(self._get_keep_running()):
                try:
                    message,res_status=dmaap_obj.receive()
                    if res_status == r.codes.ok:
                        self._dmaap_health[PolicyListener.DMAAP_STATUS]= "connected"
                        if message=="" or message == None:
                            continue
                        else:
                            self._on_pdp_message(message)
                    else:
                        self._dmaap_health[PolicyListener.DMAAP_STATUS]= "disconnected"
                except OSError as e:
                    error = str(e)
                    self._on_error(error)

                except DMaaPError as e:
                    error = str(e)
                    self._on_error(error)

            restarting = True

        Audit.register_item_health(PolicyListener.DMAAP_HEALTH)
        _LOGGER.info("exit policy-receiver")

    def _get_keep_running(self):
        with self._lock:
            keep_running = self._keep_running
        return keep_running

    def _stop_notifications(self):
        """close the dmaap == stops the notification service if running."""
        with self._lock:
            if self._keep_running:
                self._keep_running = False
                _LOGGER.info("stopped receiving notifications from PDP")


    def _on_pdp_message(self, *args):
        """received the notification from PDP

            added-policies:
                -
                    policy-type: onap.policies.monitoring.cdap.tca.hi.lo.app
                    policy-type-version: 1.0.0
                    policy-id: onap.scaleout.tca
                    policy-version: 2.0.0
                    success-count: 3
                    failure-count: 0
                    incomplete-count: 0
            deleted-policies:
            -
                    policy-type: onap.policies.monitoring.cdap.tca.hi.lo.app
                    policy-type-version: 1.0.0
                    policy-id: onap.scaleout.tca
                    policy-version: 1.0.0
                    success-count: 3
                    failure-count: 0
                    incomplete-count: 0


        """
        self._dmaap_health[PolicyListener.DMAAP_MESSAGE_COUNT] += 1
        self._dmaap_health[PolicyListener.DMAAP_MESSAGE_TIMESTAMP] = str(datetime.utcnow())
        try:
            message = args and args[-1]
            _LOGGER.info("Received notification message: %s", message)
            _LOGGER.info("dmaap_health %s", json.dumps(self._get_health(), sort_keys=True))
            if not message:
                return
            message = json.loads(message)

            if not message or not isinstance(message, dict):
                _LOGGER.warning("unexpected message from PDP: %s", json.dumps(message))
                return

            policies_updated = [
                {POLICY_ID: policy.get(PDP_POLICY_ID),
                 POLICY_VERSION: policy.get(PDP_POLICY_VERSION)}
                for policy in message.get(ADDED, [])
            ]

            policies_removed = [
                {POLICY_ID: policy.get(PDP_POLICY_ID),
                 POLICY_VERSION: policy.get(PDP_POLICY_VERSION)}
                for policy in message.get(REMOVED, [])
            ]

            if not policies_updated and not policies_removed:
                _LOGGER.info("no policy updated or removed")
                return

            self._policy_updater.policy_update(policies_updated, policies_removed)
        except Exception as ex:
            error_msg = "crash {} {} at {}: {}".format(type(ex).__name__, str(ex),
                                                       "on_pdp_message", json.dumps(message))

            _LOGGER.exception(error_msg)



    def _get_health(self):
        """returns the healthcheck of the dmaap as json"""
        dmaap_health = copy.deepcopy(self._dmaap_health)
        return dmaap_health


    def shutdown(self, audit):
        """Shutdown the policy-listener"""
        _LOGGER.info(audit.info("shutdown policy-listener"))
        with self._lock:
            self._keep_running = False

        self._stop_notifications()

        if self.is_alive():
            self.join()

    def _on_error(self,error):
        _LOGGER.exception("policy-notification error %s", str(error))
        self._sleep_before_restarting = 60 if isinstance(error, ssl.SSLError) else 5
        self._dmaap_health[PolicyListener.DMAAP_STATUS] = "error"
        self._dmaap_health[PolicyListener.DMAAP_ERROR_COUNT] += 1
        self._dmaap_health["last_error"] = {
            "error": str(error), "timestamp": str(datetime.utcnow())
        }
        _LOGGER.info("dmaap_health %s", json.dumps(self._get_health(), sort_keys=True))
