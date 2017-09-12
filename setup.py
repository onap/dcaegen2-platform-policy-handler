"""package for policy-handler of DCAE-Controller"""

# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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

from setuptools import setup

setup(
    name='policyhandler',
    description='DCAE-Controller policy-handler to communicate with policy-engine',
    version="1.0.0",
    author='Alex Shatov',
    packages=['policyhandler'],
    zip_safe=False,
    install_requires=[
        "CherryPy>=10.2.2",
        "enum34>=1.1.6",
        "future>=0.16.0",
        "requests>=2.13.0",
        "six>=1.10.0",
        "websocket-client>=0.40.0"
    ],
    keywords='policy dcae controller',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2.7'
    ]
)
