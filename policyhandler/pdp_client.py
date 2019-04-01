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

"""policy-client communicates with policy-engine thru REST API"""

from .config import Config
from .utils import Utils

if Config.is_pdp_api_default():
    from .pdp_api import *
else:
    from .pdp_api_v0 import *

_LOGGER = Utils.get_logger(__file__)
_LOGGER.info(get_pdp_api_info())
