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
        self._active_count = 0

        self._longest_timer = 0
        self._total_timer = 0

        self._last_success = None
        self._last_error = None
        self._last_start = None
        self._longest_end_ts = None

        self._last_success_request_id = None
        self._last_error_request_id = None
        self._last_started_request_id = None
        self._longest_request_id = None


    def dump(self):
        """returns dict of stats"""
        dump = None
        with self._lock:
            dump = {
                "total" : {
                    "call_count" : self._call_count,
                    "ave_timer_millisecs" : (float(self._total_timer)/self._call_count
                                             if self._call_count else 0)
                },
                "success" : {
                    "success_count" : (self._call_count - self._error_count),
                    "last_success" : str(self._last_success),
                    "last_success_request_id" : self._last_success_request_id
                },
                "error" : {
                    "error_count" : self._error_count,
                    "last_error" : str(self._last_error),
                    "last_error_request_id" : self._last_error_request_id
                },
                "active" : {
                    "active_count" : self._active_count,
                    "last_start" : str(self._last_start),
                    "last_started_request_id" : self._last_started_request_id
                },
                "longest" : {
                    "longest_timer_millisecs" : self._longest_timer,
                    "longest_request_id" : self._longest_request_id,
                    "longest_end" : str(self._longest_end_ts)
                }
            }
        return dump


    def start(self, request_id=None):
        """records the start of active execution"""
        with self._lock:
            self._active_count += 1
            self._last_start = datetime.utcnow()
            self._last_started_request_id = request_id


    def success(self, timer, request_id=None):
        """records the successful execution"""
        with self._lock:
            self._active_count -= 1
            self._call_count += 1
            self._last_success = datetime.utcnow()
            self._last_success_request_id = request_id
            self._total_timer += timer
            if not self._longest_timer or self._longest_timer < timer:
                self._longest_timer = timer
                self._longest_request_id = request_id
                self._longest_end_ts = self._last_success


    def error(self, timer, request_id=None):
        """records the errored execution"""
        with self._lock:
            self._active_count -= 1
            self._call_count += 1
            self._error_count += 1
            self._last_error = datetime.utcnow()
            self._last_error_request_id = request_id
            self._total_timer += timer
            if not self._longest_timer or self._longest_timer < timer:
                self._longest_timer = timer
                self._longest_request_id = request_id
                self._longest_end_ts = self._last_error


class Health(object):
    """Health stats for multiple requests"""
    def __init__(self):
        """Health stats for application"""
        self._all_stats = {}
        self._lock = Lock()


    def _add_or_get_stats(self, stats_name):
        """add to or get from the ever growing dict of HealthStats"""
        with self._lock:
            stats = self._all_stats.get(stats_name)
            if not stats:
                self._all_stats[stats_name] = stats = HealthStats(stats_name)
            return stats


    def start(self, stats_name, request_id=None):
        """records the start of execution on stats_name"""
        stats = self._add_or_get_stats(stats_name)
        stats.start(request_id)


    def success(self, stats_name, timer, request_id=None):
        """records the successful execution on stats_name"""
        stats = self._add_or_get_stats(stats_name)
        stats.success(timer, request_id)


    def error(self, stats_name, timer, request_id=None):
        """records the error execution on stats_name"""
        stats = self._add_or_get_stats(stats_name)
        stats.error(timer, request_id)


    def dump(self):
        """returns dict of stats"""
        with self._lock:
            stats = dict((k, v.dump()) for (k, v) in self._all_stats.items())
        return stats
