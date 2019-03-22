# ================================================================================
# Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
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
"""contants of PDP"""

# fields from pdp API 2018
POLICY_NAME = "policyName"
POLICY_VERSION = "policyVersion"
POLICY_CONFIG = 'config'

# fields from pdp API 2019
PDP_POLICIES = 'policies'
PDP_PROPERTIES = 'properties'
PDP_METADATA = 'metadata'
PDP_POLICY_ID = 'policy-id'
PDP_POLICY_VERSION = 'policy-version'

# req to PDP
PDP_REQ_ONAP_NAME = "ONAPName"   # always "DCAE"
PDP_REQ_ONAP_COMPONENT = "ONAPComponent"
PDP_REQ_ONAP_INSTANCE = "ONAPInstance"
PDP_REQ_RESOURCE = "resource"
