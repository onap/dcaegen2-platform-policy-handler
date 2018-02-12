# org.onap.dcae
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

"""generic class to keep track of app health"""

import uuid
from threading import Lock
from datetime import datetime

class HealthStats(object):
    """keep track of stats for calls"""
    def __init__(self, name):
        """keep track of stats for metrics calls"""
        self._name = name or "stats_" + str(uuid.uuid4())
        self._lock = Lock()
        self._call_count = 0
        self._error_count = 0
        self._longest_timer = 0
        self._total_timer = 0
        self._last_success = None
        self._last_error = None

    def dump(self):
        """returns dict of stats"""
        dump = None
        with self._lock:
            dump = {
                "call_count" : self._call_count,
                "error_count" : self._error_count,
                "last_success" : str(self._last_success),
                "last_error" : str(self._last_error),
                "longest_timer_millisecs" : self._longest_timer,
                "ave_timer_millisecs" : (float(self._total_timer)/self._call_count \
                                         if self._call_count else 0)
            }
        return dump

    def success(self, timer):
        """records the successful execution"""
        with self._lock:
            self._call_count += 1
            self._last_success = datetime.now()
            self._total_timer += timer
            if not self._longest_timer or self._longest_timer < timer:
                self._longest_timer = timer

    def error(self, timer):
        """records the errored execution"""
        with self._lock:
            self._call_count += 1
            self._error_count += 1
            self._last_error = datetime.now()
            self._total_timer += timer
            if not self._longest_timer or self._longest_timer < timer:
                self._longest_timer = timer

class Health(object):
    """Health stats for multiple requests"""
    def __init__(self):
        """Health stats for application"""
        self._all_stats = {}
        self._lock = Lock()

    def _add_or_get_stats(self, stats_name):
        """add to or get from the ever growing dict of HealthStats"""
        stats = None
        with self._lock:
            stats = self._all_stats.get(stats_name)
            if not stats:
                self._all_stats[stats_name] = stats = HealthStats(stats_name)
        return stats

    def success(self, stats_name, timer):
        """records the successful execution on stats_name"""
        stats = self._add_or_get_stats(stats_name)
        stats.success(timer)

    def error(self, stats_name, timer):
        """records the error execution on stats_name"""
        stats = self._add_or_get_stats(stats_name)
        stats.error(timer)

    def dump(self):
        """returns dict of stats"""
        with self._lock:
            stats = dict((k, v.dump()) for (k, v) in self._all_stats.iteritems())

        return stats
