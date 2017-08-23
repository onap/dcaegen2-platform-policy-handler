"""run as server: python -m policyhandler/policy_handler"""

# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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

import sys
import logging

from policyhandler.config import Config
from policyhandler.onap.audit import Audit
from policyhandler.web_server import PolicyWeb
from policyhandler.policy_engine import PolicyEngineClient

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

def run_policy_handler():
    """main run function for policy-handler"""
    Config.load_from_file()
    Config.discover()

    logger = logging.getLogger("policy_handler")
    sys.stdout = LogWriter(logger.info)
    sys.stderr = LogWriter(logger.error)

    logger.info("========== run_policy_handler ==========")
    Audit.init(Config.get_system_name(), Config.LOGGER_CONFIG_FILE_PATH)

    logger.info("starting policy_handler with config:")
    logger.info(Audit.log_json_dumps(Config.config))

    PolicyEngineClient.run()
    PolicyWeb.run()

def upload_config_to_discovery():
    """read the config from file and upload it to discovery"""
    logger = logging.getLogger("policy_handler")
    sys.stdout = LogWriter(logger.info)
    sys.stderr = LogWriter(logger.error)

    Config.load_from_file()

    if not Config.load_from_file(Config.UPLOAD_CONFIG_FILE_PATH):
        logger.info("not found config %s", Config.UPLOAD_CONFIG_FILE_PATH)
        return

    logger.info("========== upload_config_to_discovery ==========")
    Config.upload_to_discovery()

    logger.info("========== upload_config_to_discovery - get it back ==========")
    Config.config = None
    Config.load_from_file()
    Config.discover()
    logger.info("========== upload_config_to_discovery - done ==========")
    return True

if __name__ == "__main__":
    if not upload_config_to_discovery():
        run_policy_handler()
