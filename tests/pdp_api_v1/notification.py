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

class Expected:
    def __init__(self):
        pass

    def mock_notification():
        message = ['{"undeployed-policies":[{"policy-type":"onap.policies.firewall","policy-type-version":"1.0.0","success-count":3,"failure-count":0,"policy-id":"onap.firewall.tca","policy-version":"6.0.0"}],"deployed-policies":[{"policy-type":"onap.policies.monitoring.cdap.tca.hi.lo.app","policy-type-version":"1.0.0","success-count":3,"failure-count":0,"policy-id":"onap.scaleout.tca","policy-version":"2.0.0"}]}']
        return message


    def mock_policy_list():
        policy_updated = [{'policy-id': 'onap.scaleout.tca', 'policy-version': '2.0.0'}]
        policy_removed = [{'policy-id': 'onap.firewall.tca', 'policy-version': '6.0.0'}]
        return policy_updated,policy_removed




    def mock_push_policy():
        expected_updated = {'onap.scaleout.tca': {'policy-id': 'onap.scaleout.tca',
                                                  'policy_body': {'policy-id': 'onap.scaleout.tca',
                                                                  'policy-version': '2.0.0'}}}
        expected_removed = {'onap.firewall.tca': {'policy-id': 'onap.firewall.tca',
                                                  'policy_body': {'policy-id': 'onap.firewall.tca',
                                                                  'policy-version': '6.0.0'}}}

        return expected_updated,expected_removed
