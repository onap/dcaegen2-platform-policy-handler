import unittest
from unittest.mock import patch, Mock, MagicMock

from policyhandler.onap.audit import Audit
from policyhandler.pdp_api.policy_matcher import PolicyMatcher
from policyhandler import pdp_client
from policyhandler.utils import Utils
from . import notification
_LOGGER = Utils.get_logger(__file__)


class TestMatcher(unittest.TestCase):

    def test_update_matcher(self):
        audit = Audit(req_message="start matcher testing")

        policies_updated = notification.mock_policies_updated()

        deployed_policies = notification.mock_deployed_policy()

        catchup_updated_policies = notification.match_catchup_policy()

        _, changed_policies, __ = PolicyMatcher._match_policies(
            audit, policies_updated, deployed_policies)

        expected_updated_policies = notification.match_update_policy()
        same_updated_policies = notification.mock_same_updated_policy()

        self.assertEqual(changed_policies, expected_updated_policies)

        _, changed_policies, __ = PolicyMatcher._match_policies(
            audit, catchup_updated_policies, deployed_policies)

        self.assertEqual(changed_policies, catchup_updated_policies)

        _, changed_policies, __ = PolicyMatcher._match_policies(
            audit, same_updated_policies, deployed_policies)

        self.assertEqual(changed_policies, {})


if __name__ == '__main__':
    unittest.main()
