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
# ECOMP is a trademark and service mark of AT&T Intellectual Property.

"""
policy-listener communicates with policy-engine
to receive push notifications
on updates and removal of policies.

on receiving the policy-notifications, the policy-receiver
passes the notifications to policy-updater
"""

import os

from ..utils import ToBeImplementedException, Utils

_LOGGER = Utils.get_logger(__file__)

class PolicyListener(object):
    """listener to PolicyEngine"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))

    def __init__(self, *_):
        """listener to receive the policy notifications from PolicyEngine"""
        _LOGGER.info("to_be_implemented")
        raise ToBeImplementedException()

    def reconfigure(self, _):
        """configure and reconfigure the listener"""
        _LOGGER.info("to_be_implemented")
        raise ToBeImplementedException()

    def run(self):
        """listen on web-socket and pass the policy notifications to policy-updater"""
        _LOGGER.info("to_be_implemented")
        raise ToBeImplementedException()

    def shutdown(self, _):
        """Shutdown the policy-listener"""
        _LOGGER.info("to_be_implemented")
        raise ToBeImplementedException()
