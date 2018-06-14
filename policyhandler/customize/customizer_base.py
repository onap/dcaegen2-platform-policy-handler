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

"""
contains the base class :CustomizerBase:
that defines the signatures and default behavior of the methods called by the policy-handler

the methods are expected to be overriden by the child class Cutomizer that is company specific

:do NOT change: this class and/or this file - it is owned by ONAP
"""

import logging

class CustomizerBase(object):
    """
    base class for Customizer class

    do NOT change this class and/or this file - it is owned by ONAP

    policy-hanlder is using the instance of the child Customizer class to get the overriden methods

    the methods defined in this class are the placeholders and are expected
    to be overriden by the Customizer class
    """

    def __init__(self):
        """base class for customization contains the default methods"""
        self._logger = logging.getLogger("policy_handler.customizer")
        self._logger.info("created customizer")

    def get_service_url(self, audit, service_name, service):
        """returns the service url when called from DiscoveryClient"""
        service_url = "http://{0}:{1}".format(
            service.get("ServiceAddress", ""), service.get("ServicePort", ""))

        info = "no customization for service_url: {0} on {1}".format(service_url, service_name)
        self._logger.info(info)
        audit.info(info)
        return service_url

    def get_deploy_handler_kwargs(self, audit):
        """returns the optional dict-kwargs for requests.post to deploy_handler"""
        info = "no optional kwargs for requests.post to deploy_handler"
        self._logger.info(info)
        audit.info(info)
        kwargs = {}
        return kwargs
