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

import unittest

from policyhandler.utils import Utils
from policyhandler.pdp_api.policy_updates import PolicyUpdates
from .notification import Expected


_LOGGER = Utils.get_logger(__file__)

class TestPushMessage(unittest.TestCase):

    def testPush(self):
        obj = PolicyUpdates();
        policies_updated=[{'policy-id': 'onap.scaleout.tca', 'policy-version': '2.0.0'}]
        policies_removed=[{'policy-id': 'onap.firewall.tca', 'policy-version': '6.0.0'}]
        expected_updated,expected_removed = Expected.mock_push_policy()
        PolicyUpdates.push_policy_updates(obj,policies_updated,policies_removed)

        _LOGGER.info("expected_policy_updated: %s", expected_updated)
        _LOGGER.info("expected_policy_removed: %s", expected_removed)

        _LOGGER.info("actual_policy_updated: %s", obj._policies_updated)
        _LOGGER.info("actual_policy_removed: %s", obj._policies_removed)

        self.assertEqual(obj._policies_updated,expected_updated)
        self.assertEqual(obj._policies_removed,expected_removed)

