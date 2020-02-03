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
from unittest import TestCase
from unittest.mock import Mock, patch

from policyhandler.pdp_api.dmaap.subscriber import Subscriber
from policyhandler.utils import Utils
from .notification import Expected


_LOGGER = Utils.get_logger(__file__)


class TestSubscriber(TestCase):

    def test_subscriber(self):
        expected_notification = Expected.mock_notification()
        mock_get_patcher = patch('requests.get')
        notific1 = ['{"undeployed-policies":[{"policy-type":"onap.policies.firewall","policy-type-version":"1.0.0","success-count":3,"failure-count":0,"policy-id":"onap.firewall.tca","policy-version":"6.0.0"}],"deployed-policies":[{"policy-type":"onap.policies.monitoring.cdap.tca.hi.lo.app","policy-type-version":"1.0.0","success-count":3,"failure-count":0,"policy-id":"onap.scaleout.tca","policy-version":"2.0.0"}]}']


        notific2 = []
        exp = None
        mock_get = mock_get_patcher.start()

        mock_get.return_value.status_code = 200

        mock_get.return_value.json.return_value = notific1

        message = Subscriber().get_messages()
        _LOGGER.info("expected_notification: %s", expected_notification)
        _LOGGER.info("message: %s", message)
        assert Utils.are_the_same(message, expected_notification)

        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = notific2
        message = Subscriber().get_messages()
        assert Utils.are_the_same(message, [])

        mock_get.return_value.status_code = 400
        mock_get.return_value.json.return_value = exp
        message = Subscriber().get_messages()
        assert Utils.are_the_same(message, None)
