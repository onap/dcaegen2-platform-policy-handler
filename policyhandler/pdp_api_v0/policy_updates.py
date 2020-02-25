# ================================================================================
# Copyright (c) 2018-2020 AT&T Intellectual Property. All rights reserved.
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

"""policy-updates accumulates the policy-update notifications from PDP"""

import json
import os

from ..onap.audit import Audit
from ..policy_consts import POLICY_ID, POLICY_NAMES
from ..utils import Utils
from .pdp_consts import POLICY_NAME
from .policy_utils import PolicyUtils


_LOGGER = Utils.get_logger(__file__)

class PolicyUpdates(object):
    """Keep and consolidate the policy-updates (audit, policies_updated, policies_removed)"""
    PDP_API_FOLDER = os.path.basename(os.path.dirname(os.path.realpath(__file__)))

    def __init__(self):
        """init and reset"""
        self._audit = None
        self._policies_updated = {}
        self._policies_removed = {}

    def reset(self):
        """resets the state - removes the pending policy-updates"""
        self.__init__()

    def pop_policy_updates(self):
        """
        Returns the consolidated (audit, policies_updated, policies_removed)
        and resets the state
        """
        if not self._audit:
            return None, None, None

        audit = self._audit
        policies_updated = self._policies_updated
        policies_removed = self._policies_removed

        self.reset()

        return audit, policies_updated, policies_removed


    def push_policy_updates(self, policies_updated, policies_removed):
        """consolidate the new policies_updated, policies_removed to existing ones"""
        for policy_body in policies_removed:
            policy = PolicyUtils.convert_to_policy(policy_body)
            if not policy:
                continue
            policy_id = policy.get(POLICY_ID)
            policy_name = policy_body.get(POLICY_NAME)

            if policy_id in self._policies_removed:
                policy = self._policies_removed[policy_id]

            if POLICY_NAMES not in policy:
                policy[POLICY_NAMES] = {}
            policy[POLICY_NAMES][policy_name] = True
            self._policies_removed[policy_id] = policy

        for policy_body in policies_updated:
            policy = PolicyUtils.convert_to_policy(policy_body)
            if not policy:
                continue
            policy_id = policy.get(POLICY_ID)
            policy_name = policy_body.get(POLICY_NAME)

            self._policies_updated[policy_id] = policy

            rm_policy_names = self._policies_removed.get(policy_id, {}).get(POLICY_NAMES)
            if rm_policy_names and policy_name in rm_policy_names:
                del rm_policy_names[policy_name]

        req_message = ("policy-update notification - updated[{0}], removed[{1}]"
                       .format(len(self._policies_updated),
                               len(self._policies_removed)))

        if not self._audit:
            self._audit = Audit(job_name="policy_update", req_message=req_message,
                                retry_get_config=True)
        self._audit.req_message = req_message

        _LOGGER.info(
            "pending(%s) for %s policies_updated %s policies_removed %s",
            self._audit.request_id, req_message,
            json.dumps(self._policies_updated), json.dumps(self._policies_removed))
