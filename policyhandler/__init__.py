# ================================================================================
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

"""policyhandler package"""

class LogWriter(object):
    """redirect the standard out + err to the logger"""
    def __init__(self, logger_func):
        self.logger_func = logger_func

    def write(self, log_line):
        """actual writer to be used in place of stdout or stderr"""
        log_line = log_line.rstrip()
        if log_line:
            self.logger_func(log_line)

    def flush(self):
        """no real flushing of the buffer"""
        pass
