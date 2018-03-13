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

from threading import Event, Thread


class StepTimer(Thread):
    """call on_time after interval number of seconds, then wait to continue"""
    def __init__(self, name, interval, on_time, *args, **kwargs):
        Thread.__init__(self, name=name)
        self._interval = interval
        self._on_time = on_time
        self._args = args
        self._kwargs = kwargs

        self._timeout = Event()
        self._paused = Event()
        self._continue = Event()
        self._finished = Event()

    def next(self):
        """continue with the next timeout"""
        self._paused.clear()
        self._continue.set()

    def pause(self):
        """pause the timer"""
        self._paused.set()

    def stop(self):
        """stop the timer if it hasn't finished yet"""
        self._finished.set()
        self._timeout.set()
        self._continue.set()

    def run(self):
        """loop until stopped=finished"""
        while True:
            self._timeout.wait(self._interval)
            if self._finished.is_set():
                break
            self._timeout.clear()
            self._continue.clear()
            if not self._paused.is_set():
                self._on_time(*self._args, **self._kwargs)
            self._continue.wait()
