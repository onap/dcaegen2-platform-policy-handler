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

from datetime import datetime
from threading import Event, Lock, Thread


class StepTimer(Thread):
    """call on_time after interval number of seconds, then wait to continue"""
    INIT = "init"
    NEXT = "next"
    STARTED = "started"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"

    def __init__(self, name, interval, on_time, logger, *args, **kwargs):
        """create step timer with controlled start. next step and pause"""
        Thread.__init__(self, name=name)
        self._interval = interval
        self._on_time = on_time
        self._logger = logger
        self._args = args
        self._kwargs = kwargs

        self._lock = Lock()

        self._timeout = Event()
        self._paused = Event()
        self._next = Event()
        self._finished = Event()

        self._event = StepTimer.INIT
        self._event_counter = 0
        self._event_time = 0
        self._event_ts = datetime.now()

        self._substep = None
        self._substep_time = 0
        self._substep_ts = datetime.now()

    def get_status(self):
        """returns status of events"""
        with self._lock:
            return "{0}[{1}] {2}: timeout({3}), paused({4}), next({5}), finished({6})".format(
                self._event,
                self._event_counter,
                self._substep,
                self._timeout.is_set(),
                self._paused.is_set(),
                self._next.is_set(),
                self._finished.is_set(),
            )

    def next(self):
        """continue with the next timeout"""
        self._paused.clear()
        self._next.set()
        self._timeout.set()
        self._set_timer_event(StepTimer.NEXT)

    def pause(self):
        """pause the timer"""
        self._paused.set()
        self._next.clear()
        self._set_timer_event(StepTimer.PAUSED)

    def stop(self):
        """stop the timer if it hasn't finished yet"""
        self._finished.set()
        self._timeout.set()
        self._next.set()
        self._set_timer_event(StepTimer.STOPPING)

    def _set_timer_event(self, event):
        """set the event on the timer"""
        with self._lock:
            if event in [StepTimer.NEXT, StepTimer.STARTED]:
                self._event_counter += 1

            self._event = event
            now = datetime.now()
            self._event_time = (now - self._event_ts).total_seconds()
            self._event_ts = now
        self._logger.info("[{0}] {1} {2}".format(
            self._event_time, self.name, self.get_status()))

    def _timer_substep(self, substep):
        """log exe step"""
        with self._lock:
            self._substep = substep
            now = datetime.now()
            self._substep_time = (now - self._substep_ts).total_seconds()
            self._substep_ts = now
        self._logger.info("[{0}] {1}".format(self._substep_time, self.get_status()))

    def run(self):
        """loop one step a time until stopped=finished"""
        self._set_timer_event(StepTimer.STARTED)
        while True:
            self._timer_substep("waiting for timeout {0}...".format(self._interval))
            self._timeout.wait(self._interval)
            self._timer_substep("woke up after timeout")

            if self._finished.is_set():
                self._timer_substep("finished")
                break

            if self._next.is_set():
                self._next.clear()
                self._timeout.clear()
                self._timer_substep("restart timer")
                continue

            if self._paused.is_set():
                self._timer_substep("paused - skip on_time event")
            else:
                self._timer_substep("on_time event")
                self._on_time(*self._args, **self._kwargs)

            self._timer_substep("waiting for next...")
            self._next.wait()
            self._next.clear()
            self._timeout.clear()
            self._timer_substep("woke up on next")

            if self._finished.is_set():
                self._timer_substep("finished")
                break

        self._set_timer_event(StepTimer.STOPPED)
