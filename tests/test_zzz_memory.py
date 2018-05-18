# ============LICENSE_START=======================================================
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

"""test of the package for policy-handler of DCAE-Controller"""

import gc
import json
import time

from policyhandler.onap.audit import Audit, AuditHttpCode, Metrics

from .mock_settings import Settings

Settings.init()

class Node(object):
    """making the cycled objects"""
    def __init__(self, name):
        self.name = name
        self.next = None
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.name)


def test_healthcheck():
    """test /healthcheck"""
    audit = Audit(job_name="test_healthcheck",
                  req_message="get /healthcheck")
    metrics = Metrics(aud_parent=audit, targetEntity="test_healthcheck")
    metrics.metrics_start("test /healthcheck")
    time.sleep(0.1)

    metrics.metrics("test /healthcheck")
    health = audit.health(full=True)
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)


def test_healthcheck_with_error():
    """test /healthcheck"""
    audit = Audit(job_name="test_healthcheck_with_error",
                  req_message="get /healthcheck")
    metrics = Metrics(aud_parent=audit, targetEntity="test_healthcheck_with_error")
    metrics.metrics_start("test /healthcheck")
    time.sleep(0.2)
    audit.error("error from test_healthcheck_with_error")
    audit.fatal("fatal from test_healthcheck_with_error")
    audit.debug("debug from test_healthcheck_with_error")
    audit.warn("debug from test_healthcheck_with_error")
    audit.info_requested("debug from test_healthcheck_with_error")
    if audit.is_success():
        audit.set_http_status_code(AuditHttpCode.DATA_NOT_FOUND_ERROR.value)
    audit.set_http_status_code(AuditHttpCode.SERVER_INTERNAL_ERROR.value)
    metrics.metrics("test /healthcheck")

    health = audit.health(full=True)
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)


def test_healthcheck_with_garbage():
    """test /healthcheck"""
    gc_found = gc.collect()
    gc.set_debug(gc.DEBUG_LEAK)

    node1 = Node("one")
    node2 = Node("two")
    node3 = Node("three")
    node1.next = node2
    node2.next = node3
    node3.next = node1
    node1 = node2 = node3 = None
    gc_found = gc.collect()

    audit = Audit(job_name="test_healthcheck_with_garbage",
                  req_message="get /test_healthcheck_with_garbage")
    health = audit.health(full=True)
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("test_healthcheck_with_garbage[%s]: %s", gc_found, json.dumps(health))
    assert bool(health)
    assert bool(health.get("runtime", {}).get("gc", {}).get("gc_garbage"))

    Settings.logger.info("clearing up garbage...")
    for obj in gc.garbage:
        if isinstance(obj, Node):
            Settings.logger.info("in garbage: %s 0x%x", obj, id(obj))
            obj.next = None

    gc_found = gc.collect()
    Settings.logger.info("after clear test_healthcheck_with_garbage[%s]: %s",
                         gc_found, json.dumps(audit.health(full=True)))

    gc.set_debug(False)

    gc_found = gc.collect()
    Settings.logger.info("after turned off gc debug test_healthcheck_with_garbage[%s]: %s",
                         gc_found, json.dumps(audit.health(full=True)))
