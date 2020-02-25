# ================================================================================
# Copyright (c) 2019-2020 AT&T Intellectual Property. All rights reserved.
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

from ..policy_consts import POLICY_BODY, POLICY_ID, POLICY_NAMES
from ..utils import Utils
from .pdp_consts import DEPLOYED_POLICIES, POLICY_NAME, UNDEPLOYED_POLICIES
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


    def push_policy_updates(self, audit, multi_policies_updated):
        """
        consolidate the new policies_updated, policies_removed to existing ones

        receives
        :multi_policies_updated: as [
            {DEPLOYED_POLICIES: [{PDP_METADATA: {POLICY_ID: <policy_id>,
                                                 POLICY_VERSION: <policy_version>}}, ...],
             UNDEPLOYED_POLICIES: [{PDP_METADATA: {POLICY_ID: <policy_id>,
                                                   POLICY_VERSION: <policy_version>}}, ...]
            }, ...]
        """
        for p_single_updated in multi_policies_updated:
            for p_undeployed in p_single_updated.get(UNDEPLOYED_POLICIES, []):
                policy = PolicyUtils.convert_to_policy(p_undeployed)
                if not policy:
                    continue
                policy_id = policy.get(POLICY_ID)
                policy_name = policy.get(POLICY_BODY, {}).get(POLICY_NAME)

                if policy_id in self._policies_removed:
                    policy = self._policies_removed[policy_id]

                if POLICY_NAMES not in policy:
                    policy[POLICY_NAMES] = {}
                policy[POLICY_NAMES][policy_name] = True
                self._policies_removed[policy_id] = policy

            for p_deployed in p_single_updated.get(DEPLOYED_POLICIES, []):
                policy = PolicyUtils.convert_to_policy(p_deployed)
                if not policy:
                    continue
                policy_id = policy.get(POLICY_ID)
                policy_name = policy.get(POLICY_BODY, {}).get(POLICY_NAME)

                self._policies_updated[policy_id] = policy

                rm_policy_names = self._policies_removed.get(policy_id, {}).get(POLICY_NAMES)
                if rm_policy_names and policy_name in rm_policy_names:
                    del rm_policy_names[policy_name]

        req_message = ("policy-update notification - updated[{}], removed[{}]"
                       .format(len(self._policies_updated),
                               len(self._policies_removed)))

        if not self._audit:
            self._audit = audit
        else:
            audit.audit_done(result="policy-updates queued to request_id({})"
                             .format(self._audit.request_id))
        self._audit.req_message = req_message

        _LOGGER.info(
            "pending(%s) for %s policies_updated %s policies_removed %s",
            self._audit.request_id, req_message,
            json.dumps(self._policies_updated), json.dumps(self._policies_removed))
