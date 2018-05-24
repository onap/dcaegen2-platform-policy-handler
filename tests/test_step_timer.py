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

"""test of the step_timer"""

import json
import logging
import time
from datetime import datetime

from policyhandler.config import Config
from policyhandler.step_timer import StepTimer

Config.load_from_file()


class MockTimerController(object):
    """testing step_timer"""
    logger = logging.getLogger("policy_handler.unit_test.step_timer")

    INIT = "init"
    NEXT = "next"
    STARTED = "started"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"

    def __init__(self, name, interval):
        """step_timer test settings"""
        self.name = name or "step_timer"
        self.interval = interval or 5
        self.step_timer = None
        self.status = None
        self.run_counter = 0
        self.status_ts = datetime.utcnow()
        self.exe_ts = None
        self.exe_interval = None
        self.set_status(MockTimerController.INIT)

    def __enter__(self):
        """constructor"""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """destructor"""
        self.stop_timer()

    def on_time(self, *args, **kwargs):
        """timer event"""
        self.exe_ts = datetime.utcnow()
        self.exe_interval = (self.exe_ts - self.status_ts).total_seconds()
        MockTimerController.logger.info("run on_time[%s] (%s, %s) in %s for %s",
                                        self.run_counter, json.dumps(args), json.dumps(kwargs),
                                        self.exe_interval, self.get_status())
        time.sleep(3)
        MockTimerController.logger.info("done on_time[%s] (%s, %s) in %s for %s",
                                        self.run_counter, json.dumps(args), json.dumps(kwargs),
                                        self.exe_interval, self.get_status())

    def verify_last_event(self):
        """assertions needs to be in the main thread"""
        if self.exe_interval is None:
            MockTimerController.logger.info("not executed: %s", self.get_status())
            return

        MockTimerController.logger.info("verify exe %s for %s",
                                        self.exe_interval, self.get_status())
        assert self.exe_interval >= (self.interval - 0.01)
        assert self.exe_interval < 2 * self.interval
        MockTimerController.logger.info("success %s", self.get_status())

    def run_timer(self):
        """create and start the step_timer"""
        if self.step_timer:
            self.step_timer.next()
            self.set_status(MockTimerController.NEXT)
            return

        self.step_timer = StepTimer(
            self.name, self.interval, MockTimerController.on_time,
            MockTimerController.logger,
            self
        )
        self.step_timer.start()
        self.set_status(MockTimerController.STARTED)

    def pause_timer(self):
        """pause step_timer"""
        if self.step_timer:
            self.step_timer.pause()
            self.set_status(MockTimerController.PAUSED)

    def stop_timer(self):
        """stop step_timer"""
        if self.step_timer:
            self.set_status(MockTimerController.STOPPING)
            self.step_timer.stop()
            self.step_timer.join()
            self.step_timer = None
            self.set_status(MockTimerController.STOPPED)

    def set_status(self, status):
        """set the status of the timer"""
        if status in [MockTimerController.NEXT, MockTimerController.STARTED]:
            self.run_counter += 1

        self.status = status
        utcnow = datetime.utcnow()
        time_step = (utcnow - self.status_ts).total_seconds()
        self.status_ts = utcnow
        MockTimerController.logger.info("[%s]: %s", time_step, self.get_status())

    def get_status(self):
        """string representation"""
        status = "{0}[{1}] {2} in {3} from {4} last exe {5}".format(
            self.status, self.run_counter, self.name, self.interval,
            str(self.status_ts), str(self.exe_ts)
        )
        if self.step_timer:
            return "{0}: {1}".format(status, self.step_timer.get_timer_status())
        return status


def test_step_timer():
    """test step_timer"""
    MockTimerController.logger.info("============ test_step_timer =========")
    with MockTimerController("step_timer", 5) as step_timer:
        step_timer.run_timer()
        time.sleep(1)
        step_timer.verify_last_event()

        time.sleep(1 + step_timer.interval)
        step_timer.verify_last_event()

        step_timer.pause_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.pause_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(3 * step_timer.interval)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(3 * step_timer.interval)
        step_timer.verify_last_event()


def test_interrupt_step_timer():
    """test step_timer"""
    MockTimerController.logger.info("============ test_interrupt_step_timer =========")
    with MockTimerController("step_timer", 5) as step_timer:
        step_timer.run_timer()
        time.sleep(1)
        step_timer.verify_last_event()

        step_timer.pause_timer()
        time.sleep(2 + step_timer.interval)
        step_timer.verify_last_event()

        step_timer.pause_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.pause_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(2 + step_timer.interval)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.pause_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(2)
        step_timer.verify_last_event()

        step_timer.run_timer()
        time.sleep(3 * step_timer.interval)
        step_timer.verify_last_event()
