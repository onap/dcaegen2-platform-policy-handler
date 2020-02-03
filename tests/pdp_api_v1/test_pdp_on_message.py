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

from policyhandler.onap.audit import Audit
from policyhandler.pdp_api.policy_listener import PolicyListener
from policyhandler.policy_updater import PolicyUpdater
from policyhandler.policy_receiver import PolicyReceiver
from policyhandler.utils import Utils
from .notification import Expected
from unittest.mock import patch

_LOGGER = Utils.get_logger(__file__)


class TestPdpMessage(unittest.TestCase):
    def dummy_receiver(self):
        pass

    def test_pdp_message(self):
        _policy_updater = PolicyUpdater(self.dummy_receiver)
        mock_patcher = patch('policyhandler.pdp_api.policy_listener.PolicyListener.reconfigure')
        mock_get_patcher = patch('policyhandler.policy_updater.PolicyUpdater.policy_update')
        mock_class = mock_patcher.start()
        mock_update = mock_get_patcher.start()
        message = Expected.mock_notification()
        expected_updated_policy, expected_removed_policy = Expected.mock_policy_list()
        audit = Audit(req_message="start _on_pdp_message testing")

        mock_class.return_value = True
        PolicyListener(audit, _policy_updater)._on_pdp_message(message)
        self.assertTrue(mock_update.called)
        mock_update.assert_called_with(expected_updated_policy,expected_removed_policy)


