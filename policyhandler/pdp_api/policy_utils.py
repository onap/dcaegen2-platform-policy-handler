# ================================================================================
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
# Copyright (C) 2020 Wipro Limited.
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

"""utils for policy usage and conversions"""

from ..onap.audit import Audit
from ..policy_consts import POLICY_BODY, POLICY_ID
from .pdp_consts import (PDP_METADATA, PDP_POLICY_ID,
                         PDP_POLICY_VERSION, PDP_PROPERTIES,
                         PDP_REQ_ONAP_COMPONENT, PDP_REQ_ONAP_INSTANCE,
                         PDP_REQ_ONAP_NAME, PDP_REQ_RESOURCE, POLICY_CONFIG,
                         POLICY_NAME, POLICY_VERSION)


class PolicyUtils(object):
    """policy-client utils"""

    @staticmethod
    def gen_req_to_pdp(policy_id):
        """request to get a single policy from pdp by policy_id"""
        return {
            PDP_REQ_ONAP_NAME: "DCAE",
            PDP_REQ_ONAP_COMPONENT: Audit.service_name,
            PDP_REQ_ONAP_INSTANCE: Audit.SERVICE_INSTANCE_UUID,
            "action": "configure",
            PDP_REQ_RESOURCE: {PDP_POLICY_ID: [policy_id]}
        }

    @staticmethod
    def gen_collective_req_to_pdp(policies):
        """request to get multiple policies from pdp by policy_id"""
        return {
            PDP_REQ_ONAP_NAME: "DCAE",
            PDP_REQ_ONAP_COMPONENT: Audit.service_name,
            PDP_REQ_ONAP_INSTANCE: Audit.SERVICE_INSTANCE_UUID,
            "action": "configure",
            PDP_REQ_RESOURCE: {PDP_POLICY_ID: policies}
        }

    @staticmethod
    def convert_to_policy(policy_body):
        """
        set policy id, name, version, config=properties and
        wrap policy_body received from policy-engine with policy_id

        input:
        {
            "type": "onap.policies.monitoring.cdap.tca.hi.lo.app",
            "version": "1.0.0",
            "metadata": {
                "policy-id": "onap.scaleout.tca",
                "policy-version": 1,
                "description": "The scaleout policy for vDNS"
            },
            "properties": {
                "tca_policy": {
                    "domain": "measurementsForVfScaling",
                    "metricsPerEventName": [
                        {
                            "eventName": "vLoadBalancer",
                            "controlLoopSchemaType": "VNF",
                            "policyScope": "type=configuration"
                        }
                    ]
                }
            }
        }

        output:
        {
            "policy_id": "onap.scaleout.tca",
            "policy_body": {
                "policyName": "onap.scaleout.tca.1.xml",
                "policyVersion": 1,
                "type": "onap.policies.monitoring.cdap.tca.hi.lo.app",
                "version": "1.0.0",
                "metadata": {
                    "policy-id": "onap.scaleout.tca",
                    "policy-version": 1,
                    "description": "The scaleout policy for vDNS"
                },
                "config": {
                    "tca_policy": {
                        "domain": "measurementsForVfScaling",
                        "metricsPerEventName": [
                            {
                                "eventName": "vLoadBalancer",
                                "controlLoopSchemaType": "VNF",
                                "policyScope": "type=configuration"
                            }
                        ]
                    }
                }
            }
        }
        """
        if not policy_body or not policy_body.get(PDP_PROPERTIES):
            return None

        pdp_metadata = policy_body.get(PDP_METADATA, {})
        policy_id = pdp_metadata.get(PDP_POLICY_ID)
        policy_version = pdp_metadata.get(PDP_POLICY_VERSION)
        if not policy_id or not policy_version:
            return None

        policy_body[POLICY_NAME] = "{}.{}.xml".format(policy_id, policy_version)
        policy_body[POLICY_VERSION] = str(policy_version)
        policy_body[POLICY_CONFIG] = policy_body[PDP_PROPERTIES]
        del policy_body[PDP_PROPERTIES]

        return {POLICY_ID:policy_id, POLICY_BODY:policy_body}

    @staticmethod
    def validate_policy(policy):
        """validate have non-empty config in policy"""
        if not policy:
            return False

        policy_body = policy.get(POLICY_BODY)
        return bool(policy_body and policy_body.get(POLICY_CONFIG))
