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
import logging
import subprocess
import sys

from policyhandler.config import Config
from policyhandler.onap.audit import Audit
from policyhandler.policy_handler import LogWriter

Config.load_from_file()

try:
    POLICY_HANDLER_VERSION = subprocess.check_output(["python", "setup.py", "--version"]).strip()
except subprocess.CalledProcessError:
    POLICY_HANDLER_VERSION = "2.4.1"

class Node(object):
    """making the cycled objects"""
    def __init__(self, name):
        self.name = name
        self.next = None
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.name)


def test_healthcheck_with_garbage():
    """test /healthcheck"""

    Audit.init(Config.get_system_name(), POLICY_HANDLER_VERSION, Config.LOGGER_CONFIG_FILE_PATH)


    logger = logging.getLogger("policy_handler.unit_test_memory")
    sys.stdout = LogWriter(logger.info)
    sys.stderr = LogWriter(logger.error)

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

    logger.info("test_healthcheck_with_garbage[%s]: %s", gc_found, json.dumps(health))
    assert bool(health)
    assert bool(health.get("runtime", {}).get("gc", {}).get("gc_garbage"))

    logger.info("clearing up garbage...")
    for obj in gc.garbage:
        if isinstance(obj, Node):
            logger.info("in garbage: %s 0x%x", obj, id(obj))
            obj.next = None

    gc_found = gc.collect()
    health = audit.health(full=True)
    logger.info("after clear test_healthcheck_with_garbage[%s]: %s", gc_found, json.dumps(health))
    assert bool(health)

    gc.set_debug(not gc.DEBUG_LEAK)
