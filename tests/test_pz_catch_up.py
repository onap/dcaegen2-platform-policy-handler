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
"""test policy catch_up methods directly"""

import json
import time

import pytest

from policyhandler.onap.audit import Audit
from policyhandler.policy_receiver import PolicyReceiver

from .mock_settings import Settings
from .mock_tracker import Tracker


@pytest.mark.usefixtures(
    "fix_auto_catch_up",
    "fix_discovery",
    "fix_pdp_post_big",
    "fix_deploy_handler_413",
    "fix_policy_receiver_websocket"
)
def test_catch_up_failed_dh():
    """test run policy handler with catchups and failed deployment-handler"""
    Settings.logger.info("start test_catch_up_failed_dh")
    assert not PolicyReceiver.is_running()
    audit = Audit(job_name="test_catch_up_failed_dh",
                  req_message="start test_catch_up_failed_dh")
    PolicyReceiver.run(audit)

    Settings.logger.info("sleep 12 before shutdown...")
    time.sleep(12)

    health = audit.health(full=True)
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)

    PolicyReceiver.shutdown(audit)
    time.sleep(1)
    assert not PolicyReceiver.is_running()

    health = audit.health(full=True)
    Settings.logger.info("healthcheck: %s", json.dumps(health))

    Tracker.validate()

@pytest.mark.usefixtures(
    "fix_auto_catch_up",
    "fix_discovery",
    "fix_pdp_post",
    "fix_deploy_handler_404",
    "fix_policy_receiver_websocket"
)
def test_catch_up_dh_404():
    """test run policy handler with catchups and failed deployment-handler"""
    Settings.logger.info("start test_catch_up_dh_404")
    assert not PolicyReceiver.is_running()
    audit = Audit(job_name="test_catch_up_dh_404",
                  req_message="start test_catch_up_dh_404")
    PolicyReceiver.run(audit)

    Settings.logger.info("sleep 12 before shutdown...")
    time.sleep(12)

    health = audit.health(full=True)
    audit.audit_done(result=json.dumps(health))

    Settings.logger.info("healthcheck: %s", json.dumps(health))
    assert bool(health)

    PolicyReceiver.shutdown(audit)
    time.sleep(1)
    assert not PolicyReceiver.is_running()

    health = audit.health(full=True)
    Settings.logger.info("healthcheck: %s", json.dumps(health))

    Tracker.validate()
