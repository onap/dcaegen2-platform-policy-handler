# ============LICENSE_START=======================================================
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
"""expected message history per test"""


HISTORY_EXPECTED = {
    "tests.test_policy_rest::test_get_policy_latest" : [
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_sit"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_web_all_policies_latest": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_web_policies_latest": [
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_amet.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_web_policy_latest": [
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_sit"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_zzz_get_catch_up": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "0",
                                    "policy_updated_to_ver": "1",
                                    "updated_policy_id": "test_scope_prefix.Config_Lorem"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "6",
                                    "policy_updated_to_ver": "7",
                                    "updated_policy_id": "test_scope_prefix.Config_ametist"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "0",
                                    "policy_updated_to_ver": "1",
                                    "updated_policy_id": "test_scope_prefix.Config_Lorem"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "6",
                                    "policy_updated_to_ver": "7",
                                    "updated_policy_id": "test_scope_prefix.Config_ametist"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_zzz_policy_updates_and_catch_ups": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "0",
                                    "policy_updated_to_ver": "1",
                                    "updated_policy_id": "test_scope_prefix.Config_Lorem"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "6",
                                    "policy_updated_to_ver": "7",
                                    "updated_policy_id": "test_scope_prefix.Config_ametist"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_ipsum"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_sit"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_consectetur"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": False,
                    "latest_policies": {
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_zzzzz_shutdown": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "0",
                                    "policy_updated_to_ver": "1",
                                    "updated_policy_id": "test_scope_prefix.Config_Lorem"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "6",
                                    "policy_updated_to_ver": "7",
                                    "updated_policy_id": "test_scope_prefix.Config_ametist"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_ipsum"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_sit"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_consectetur"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": False,
                    "latest_policies": {
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_policyhandler::WebServerTest::test_zzz_catch_up_on_deploy_handler_changed": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "0",
                                    "policy_updated_to_ver": "1",
                                    "updated_policy_id": "test_scope_prefix.Config_Lorem"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "6",
                                    "policy_updated_to_ver": "7",
                                    "updated_policy_id": "test_scope_prefix.Config_ametist"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_ipsum"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": False,
                    "latest_policies": {
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_ipsum": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_dolor"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_amet"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": False,
                    "latest_policies": {
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_dolor": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "0",
                                    "policy_updated_to_ver": "1",
                                    "updated_policy_id": "test_scope_prefix.Config_Lorem"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "4",
                                    "policy_updated_to_ver": "5",
                                    "updated_policy_id": "test_scope_prefix.Config_amet"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "6",
                                    "policy_updated_to_ver": "7",
                                    "updated_policy_id": "test_scope_prefix.Config_ametist"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "5",
                                    "policy_updated_to_ver": "6",
                                    "updated_policy_id": "test_scope_prefix.Config_consectetur"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "2",
                                    "policy_updated_to_ver": "3",
                                    "updated_policy_id": "test_scope_prefix.Config_dolor"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "1",
                                    "policy_updated_to_ver": "2",
                                    "updated_policy_id": "test_scope_prefix.Config_ipsum"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": {
                                    "policy_hello": "world!",
                                    "policy_updated_from_ver": "3",
                                    "policy_updated_to_ver": "4",
                                    "updated_policy_id": "test_scope_prefix.Config_sit"
                                },
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_catch_up::test_catch_up_failed_dh": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 413
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 413
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "catch_up": True,
                    "latest_policies": {
                        "test_scope_prefix.Config_Lorem": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_Lorem.1.xml",
                                "policyVersion": "1",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_Lorem"
                        },
                        "test_scope_prefix.Config_amet": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_amet.5.xml",
                                "policyVersion": "5",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_amet"
                        },
                        "test_scope_prefix.Config_ametist": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ametist.7.xml",
                                "policyVersion": "7",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ametist"
                        },
                        "test_scope_prefix.Config_consectetur": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_consectetur.6.xml",
                                "policyVersion": "6",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_consectetur"
                        },
                        "test_scope_prefix.Config_dolor": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_dolor.3.xml",
                                "policyVersion": "3",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_dolor"
                        },
                        "test_scope_prefix.Config_ipsum": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_ipsum.2.xml",
                                "policyVersion": "2",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_ipsum"
                        },
                        "test_scope_prefix.Config_sit": {
                            "policy_body": {
                                "config": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                                "matchingConditions": {
                                    "ConfigName": "alex_config_name",
                                    "ONAPName": "DCAE"
                                },
                                "policyConfigMessage": "Config Retrieved! ",
                                "policyConfigStatus": "CONFIG_RETRIEVED",
                                "policyName": "test_scope_prefix.Config_sit.4.xml",
                                "policyVersion": "4",
                                "property": None,
                                "responseAttributes": {},
                                "type": "JSON"
                            },
                            "policy_id": "test_scope_prefix.Config_sit"
                        }
                    },
                    "policy_filter_matches": {
                        "test_scope_prefix.Config_Lorem": {},
                        "test_scope_prefix.Config_amet": {},
                        "test_scope_prefix.Config_ametist": {},
                        "test_scope_prefix.Config_consectetur": {},
                        "test_scope_prefix.Config_dolor": {},
                        "test_scope_prefix.Config_ipsum": {},
                        "test_scope_prefix.Config_sit": {}
                    },
                    "removed_policies": {}
                },
                "method": "put",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 413
        }
    ],
    "tests.test_pz_catch_up::test_catch_up_dh_404": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_pdp_boom::WebServerPDPBoomTest::test_web_all_policies_latest": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_pdp_boom::WebServerPDPBoomTest::test_zzz_catch_up_on_deploy_handler_changed": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_pdp_boom::WebServerPDPBoomTest::test_zzz_get_catch_up": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_pdp_boom::WebServerPDPBoomTest::test_zzz_policy_updates_and_catch_ups": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_pdp_boom::WebServerPDPBoomTest::test_zzzzz_shutdown": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_web_all_policies_latest": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_web_policies_latest": [
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_amet.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_web_policy_latest": [
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_sit"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_zzz_catch_up_on_deploy_handler_changed": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_zzz_get_catch_up": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_zzz_policy_updates_and_catch_ups": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ],
    "tests.test_pz_ph_boom::WebServerInternalBoomTest::test_zzzzz_shutdown": [
        {
            "request": {
                "headers": {
                    "X-ECOMP-RequestID": "*"
                },
                "json": None,
                "method": "get",
                "params": {
                    "cfy_tenant_name": "default_tenant"
                },
                "uri": "http://unit-test-deployment_handler:8188000/policy"
            },
            "res": "*",
            "status_code": 200
        },
        {
            "request": {
                "headers": {
                    "Accept": "application/json",
                    "Authorization": "Basic auth",
                    "ClientAuth": "Basic user",
                    "Content-Type": "application/json",
                    "Environment": "TEST",
                    "X-ECOMP-RequestID": "*"
                },
                "json": {
                    "policyName": "test_scope_prefix.Config_.*"
                },
                "method": "post",
                "params": None,
                "uri": "https://unit-test-pdp-server:8081000/pdp/api/getConfig"
            },
            "res": "*",
            "status_code": 200
        }
    ]
}
