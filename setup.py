# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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

"""package for policy-handler of DCAE-Controller"""

from setuptools import setup

setup(
    name='policyhandler',
    description='DCAE-Controller policy-handler to communicate with policy-engine',
    version="4.2.0",
    author='Alex Shatov',
    packages=['policyhandler'],
    zip_safe=False,
    install_requires=[
        "CherryPy>=15.0.0,<16.0.0",
        "psutil>=5.4.5,<6.0.0",
        "requests>=2.18.4,<3.0.0",
        "websocket-client==0.49.0"
    ],
    keywords='policy dcae controller',
    classifiers=[
        'Programming Language :: Python :: 3.6'
    ]
)
