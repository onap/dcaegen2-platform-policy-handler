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

"""policy-updates accumulates the policy-update notifications from PDP"""

import os

from ..utils import Utils, ToBeImplementedException


_LOGGER = Utils.get_logger(__file__)

class PolicyUpdates(object):
    """Keep and consolidate the policy-updates (audit, policies_updated, policies_removed)"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))

    def __init__(self):
        """init and reset"""

    def reset(self):
        """resets the state"""
        self.__init__()

    def pop_policy_updates(self):
        """
        Returns the consolidated (audit, policies_updated, policies_removed)
        and resets the state
        """
        _LOGGER.info("to_be_implemented")
        return None, None, None

    def push_policy_updates(self, *_):
        """consolidate the new policies_updated, policies_removed to existing ones"""
        _LOGGER.info("to_be_implemented")
        raise ToBeImplementedException()
