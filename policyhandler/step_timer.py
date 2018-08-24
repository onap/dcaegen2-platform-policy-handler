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

"""periodically callback"""

import json
from datetime import datetime
from threading import Event, RLock, Thread


class StepTimer(Thread):
    """call on_time after interval number of seconds, then wait to continue"""
    STATE_INIT = "init"
    STATE_NEXT = "next"
    STATE_STARTED = "started"
    STATE_PAUSED = "paused"
    STATE_STOPPING = "stopping"
    STATE_STOPPED = "stopped"

    def __init__(self, name, interval, on_time, logger, *args, **kwargs):
        """create step timer with controlled start. next step and pause"""
        Thread.__init__(self, name=name)
        self._interval = interval
        self._on_time = on_time
        self._logger = logger
        self._args = args
        self._kwargs = kwargs

        self._lock = RLock()

        self._timeout = Event()
        self._waiting_for_timeout = False
        self._next = Event()
        self._paused = False
        self._finished = False

        self._request = StepTimer.STATE_INIT
        self._req_count = 0
        self._req_time = 0
        self._req_ts = datetime.utcnow()

        self._substep = None
        self._substep_time = 0
        self._substep_ts = datetime.utcnow()

    def get_timer_status(self):
        """returns timer status"""
        with self._lock:
            return "{0}[{1}] {2}: timeout({3}), paused({4}), next({5}), finished({6})".format(
                self._request,
                self._req_count,
                self._substep,
                self._timeout.is_set(),
                self._paused,
                self._next.is_set(),
                self._finished,
            )

    def next(self, interval=None):
        """continue with the next timeout"""
        with self._lock:
            if interval:
                self._interval = interval
            self._paused = False
            if self._waiting_for_timeout:
                self._next.set()
                self._timeout.set()
            else:
                self._next.set()
            self._request_to_timer(StepTimer.STATE_NEXT)

    def pause(self):
        """pause the timer"""
        with self._lock:
            self._paused = True
            self._next.clear()
            self._request_to_timer(StepTimer.STATE_PAUSED)

    def stop(self):
        """stop the timer if it hasn't finished yet"""
        with self._lock:
            self._finished = True
            self._timeout.set()
            self._next.set()
            self._request_to_timer(StepTimer.STATE_STOPPING)

    def _request_to_timer(self, request):
        """set the request on the timer"""
        with self._lock:
            if request in [StepTimer.STATE_NEXT, StepTimer.STATE_STARTED]:
                self._req_count += 1

            prev_req = self._request
            self._request = request
            utcnow = datetime.utcnow()
            self._req_time = (utcnow - self._req_ts).total_seconds()
            self._req_ts = utcnow
            self._logger.info("{0}[{1}] {2}->{3}".format(
                self.name, self._req_time, prev_req, self.get_timer_status()))

    def _log_substep(self, substep):
        """log timer substep"""
        with self._lock:
            self._substep = substep
            utcnow = datetime.utcnow()
            self._substep_time = (utcnow - self._substep_ts).total_seconds()
            self._substep_ts = utcnow
            self._logger.info("[{0}] {1}".format(self._substep_time, self.get_timer_status()))

    def _on_time_event(self):
        """execute the _on_time event"""
        if self._paused:
            self._log_substep("paused - skip on_time event")
            return

        try:
            self._log_substep("on_time event")
            self._on_time(*self._args, **self._kwargs)
        except Exception as ex:
            error_msg = ("{0}: crash {1} {2} at {3}: args({4}), kwargs({5})"
                         .format(self.name, type(ex).__name__, str(ex), "_on_time",
                                 json.dumps(self._args), json.dumps(self._kwargs)))
            self._logger.exception(error_msg)

    def run(self):
        """loop one step a time until stopped=finished"""
        self._request_to_timer(StepTimer.STATE_STARTED)
        while True:
            with self._lock:
                self._timeout.clear()
                self._waiting_for_timeout = True
                self._log_substep("waiting for timeout {0}...".format(self._interval))

            interrupted = self._timeout.wait(self._interval)

            with self._lock:
                self._waiting_for_timeout = False
                self._log_substep("woke up after {0}timeout"
                                  .format((interrupted and "interrupted ") or ""))

                if self._finished:
                    self._log_substep("finished")
                    break

                if self._next.is_set() and interrupted:
                    self._next.clear()
                    self._log_substep("restart timer")
                    continue

            self._on_time_event()

            self._log_substep("waiting for next...")
            self._next.wait()
            with self._lock:
                self._next.clear()
                self._log_substep("woke up on next")

            if self._finished:
                self._log_substep("finished")
                break

        self._request_to_timer(StepTimer.STATE_STOPPED)
