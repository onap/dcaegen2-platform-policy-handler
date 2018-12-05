# ============LICENSE_START=======================================================
# Copyright (c) 2018 AT&T Intellectual Property. All rights reserved.
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
"""test policy_rest methods directly"""

import json

import pytest

from policyhandler.onap.audit import Audit
from policyhandler.policy_rest import PolicyRest
from policyhandler.policy_utils import Utils

from .mock_policy_engine import MockPolicyEngine
from .mock_settings import Settings
from .mock_tracker import Tracker


@pytest.mark.usefixtures("fix_pdp_post")
def test_get_policy_latest():
    """test /policy_latest/<policy-id>"""
    policy_id, expected_policy = MockPolicyEngine.gen_policy_latest(3)

    audit = Audit(job_name="test_get_policy_latest",
                  req_message="get /policy_latest/{}".format(policy_id or ""))
    policy_latest = PolicyRest.get_latest_policy((audit, policy_id, None, None)) or {}
    audit.audit_done(result=json.dumps(policy_latest))

    Settings.logger.info("expected_policy: %s", json.dumps(expected_policy))
    Settings.logger.info("policy_latest: %s", json.dumps(policy_latest))
    assert Utils.are_the_same(policy_latest, expected_policy)

    Tracker.validate()
