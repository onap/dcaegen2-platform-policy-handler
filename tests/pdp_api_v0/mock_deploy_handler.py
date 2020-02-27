# ============LICENSE_START=======================================================
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
"""mocking for the deployment-handler - shared by many tests"""

import json

from policyhandler.pdp_api_v0.pdp_consts import POLICY_VERSION
from policyhandler.policy_consts import POLICY_BODY, POLICY_ID, POLICY_VERSIONS
from policyhandler.utils import Utils

from ..mock_settings import MockSettings
from .mock_policy_engine import MockPolicyEngine2018

_LOGGER = Utils.get_logger(__file__)

class MockDeploymentHandler(object):
    """pretend this is the deployment-handler"""

    @staticmethod
    def default_response():
        """generate the deployed policies message"""
        return {"server_instance_uuid": MockSettings.deploy_handler_instance_uuid}

    @staticmethod
    def get_deployed_policies():
        """generate the deployed policies message"""
        all_policies = MockPolicyEngine2018.gen_all_policies_latest(version_offset=1)
        _LOGGER.info("all_policies: %s", json.dumps(all_policies))

        response = MockDeploymentHandler.default_response()
        policies = dict(
            (policy_id, {
                POLICY_ID: policy_id,
                POLICY_VERSIONS: {policy.get(POLICY_BODY, {}).get(POLICY_VERSION, "999"): True},
                "pending_update": False})
            for policy_id, policy in all_policies.items())
        response["policies"] = policies

        return response
