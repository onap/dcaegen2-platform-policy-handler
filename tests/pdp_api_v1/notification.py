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


def mock_notification():
    message = ['{"undeployed-policies":[{"policy-type":"onap.policies.firewall","policy-type-version":"1.0.0",'
               '"success-count":3,"failure-count":0,"policy-id":"onap.firewall.tca","policy-version":"6.0.0"}],'
               '"deployed-policies":[{"policy-type":"onap.policies.monitoring.cdap.tca.hi.lo.app",'
               '"policy-type-version":"1.0.0","success-count":3,"failure-count":0,'
               '"policy-id":"onap.scaleout.tca","policy-version":"2.0.0"}]}']
    return message


def mock_multiple_notification():
    message = ['{"undeployed-policies":[{"policy-type":"onap.policies.firewall","policy-type-version":"1.0.0",'
               '"success-count":3,"failure-count":0,"policy-id":"onap.firewall.tca","policy-version":"6.0.0"}],'
               '"deployed-policies":[{"policy-type":"onap.policies.monitoring.cdap.tca.hi.lo.app",'
               '"policy-type-version":"1.0.0","success-count":3,"failure-count":0,'
               '"policy-id":"onap.scaleout.tca","policy-version":"2.0.0"}]}',
               '{"undeployed-policies":[{"policy-type":"onap.policies.firewall","policy-type-version":"1.0.0",'
               '"success-count":3,"failure-count":0,"policy-id":"onap.krishna.tca","policy-version":"6.0.0"}],'
               '"deployed-policies":[{"policy-type":"onap.policies.monitoring.cdap.tca.hi.lo.app",'
               '"policy-type-version":"1.0.0","success-count":3,"failure-count":0,'
               '"policy-id":"onap.aviral.tca","policy-version":"2.0.0"}]}'
               ]
    return message


def mock_multiple_policy_list():
    expected_updated = [{'policy-id': 'onap.scaleout.tca', 'policy-version': '2.0.0'},
                        {'policy-id': 'onap.aviral.tca', 'policy-version': '2.0.0'}]
    expected_removed = [{'policy-id': 'onap.firewall.tca', 'policy-version': '6.0.0'},
                        {'policy-id': 'onap.krishna.tca', 'policy-version': '6.0.0'}]

    return expected_updated, expected_removed


def mock_policy_list():
    policy_updated = [{'policy-id': 'onap.scaleout.tca', 'policy-version': '2.0.0'}]
    policy_removed = [{'policy-id': 'onap.firewall.tca', 'policy-version': '6.0.0'}]
    return policy_updated, policy_removed


def match_update_policy():
    expected_updated_policies = {'Config_PCIMS_CONFIG_POLICY': {'policy-id': 'Config_PCIMS_CONFIG_POLICY',
                                                                'policy_body': {
                                                                    'policy-id': 'Config_PCIMS_CONFIG_POLICY',
                                                                    'policy-version': '2.0.0'}}}
    return expected_updated_policies


def mock_same_updated_policy():
    same_updated_policies = {"Config_PCIMS_CONFIG_POLICY": {"policy-id": "Config_PCIMS_CONFIG_POLICY",
                                                            "policy_body": {
                                                                "policy-id": "Config_PCIMS_CONFIG_POLICY",
                                                                "policy-version": "1.0.0"}}}
    return same_updated_policies


def mock_deployed_policy():
    deployed_policies = {"Config_PCIMS_CONFIG_POLICY":
                             {"pending_update": False, "policy_id": "Config_PCIMS_CONFIG_POLICY",
                              "policy_versions": {"1": True}}}
    return deployed_policies


def mock_policies_updated():
    policies_updated = {"Config_PCIMS_CONFIG_POLICY": {"policy-id": "Config_PCIMS_CONFIG_POLICY",
                                                       "policy_body": {"policy-id": "Config_PCIMS_CONFIG_POLICY",
                                                                       "policy-version": "2.0.0"}}}
    return policies_updated


def match_catchup_policy():
    catchup_updated_policies = {'Config_PCIMS_CONFIG_POLICY': {
        'policy_body': {'type_version': '1.0.0', 'version': '2.0.0', 'name': 'Config_PCIMS_CONFIG_POLICY',
                        'policyName': 'Config_PCIMS_CONFIG_POLICY.2.xml', 'config': {'PCI_SDNR_TARGET_NAME': 'SDNR',
                                                                                     'PCI_OPTMIZATION_ALGO_CATEGORY_IN_OOF': 'OOF-PCI-OPTIMIZATION',
                                                                                     'PCI_NEIGHBOR_CHANGE_CLUSTER_TIMEOUT_IN_SECS': 120,
                                                                                     'PCI_MODCONFIGANR_POLICY_NAME': 'ControlLoop-vSONH-7d4baf04-8875-4d1f-946d-06b874048b61',
                                                                                     'PCI_MODCONFIG_POLICY_NAME': 'ControlLoop-vPCI-fb41f388-a5f2-11e8-98d0-529269fb1459'},
                        'policyVersion': '2', 'type': 'onap.policies.monitoring.docker.sonhandler.app',
                        'metadata': {'policy-id': 'Config_PCIMS_CONFIG_POLICY', 'policy-version': '2'}},
        'policy_id': 'Config_PCIMS_CONFIG_POLICY'}}
    return catchup_updated_policies


def mock_push_policy():
    expected_updated = {'onap.scaleout.tca': {'policy-id': 'onap.scaleout.tca',
                                              'policy_body': {'policy-id': 'onap.scaleout.tca',
                                                              'policy-version': '2.0.0'}}}
    expected_removed = {'onap.firewall.tca': {'policy-id': 'onap.firewall.tca',
                                              'policy_body': {'policy-id': 'onap.firewall.tca',
                                                              'policy-version': '6.0.0'}}}

    return expected_updated, expected_removed
