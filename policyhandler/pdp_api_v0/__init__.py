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

"""<=2018 http api to policy-engine /getConfig that is going to be replaced in 2019"""

from .policy_matcher import PolicyMatcher
from .policy_rest import PolicyRest
from .policy_listener import PolicyListener
from .policy_updates import PolicyUpdates

def get_pdp_api_info():
    """info on which version of pdp api is in effect"""
    return ("folders: PolicyMatcher({}), PolicyRest({}), PolicyListener({}), PolicyUpdates({})"
            .format(PolicyMatcher.PDP_API_FOLDER, PolicyRest.PDP_API_FOLDER,
                    PolicyListener.PDP_API_FOLDER, PolicyUpdates.PDP_API_FOLDER
                   ))
