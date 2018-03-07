# ================================================================================
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

"""contains the Customizer class with method overrides per company specification"""

from .customizer_base import CustomizerBase

class Customizer(CustomizerBase):
    """
    the Customizer class inherits CustomizerBase that is owned by ONAP

    :Customizer: class is owned by the company that needs to customize the policy-handler

    :override: any method defined in the CustomizerBase class to customize the behavior of the policy-handler
    """
    def __init__(self):
        """class that contains the customization"""
        super(Customizer, self).__init__()

    # uncomment the following lines for the samples of code

    # def get_service_url(self, audit, service_name, service):
    #     """
    #     returns the service url when called from DiscoveryClient

    #     this is just a sample code - replace it with the real customization
    #     """
    #     service_url = super(Customizer, self).get_service_url(audit, service_name, service)
    #     audit.info("TODO: customization for service_url on {0}".format(service_name))
    #     return service_url

    # def get_deploy_handler_kwargs(self, audit):
    #     """
    #     returns the optional dict-kwargs for requests.post to deploy-handler

    #     this is just a sample code - replace it with the real customization
    #     """
    #     kwargs = {"verify": "/usr/local/share/ca-certificates/aafcacert.crt"}
    #     audit.info("kwargs for requests.post to deploy-handler: {0}".format(json.dumps(kwargs)))
    #     return kwargs
