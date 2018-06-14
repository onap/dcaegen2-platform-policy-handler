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
"""settings that are general to all tests"""

import json
import logging
import sys
import uuid
from datetime import datetime

from policyhandler import LogWriter
from policyhandler.config import Config
from policyhandler.onap.audit import Audit


class Settings(object):
    """init all locals"""
    logger = None
    RUN_TS = datetime.utcnow().isoformat()[:-3] + 'Z'
    dicovered_config = None
    deploy_handler_instance_uuid = str(uuid.uuid4())

    @staticmethod
    def init():
        """init configs"""
        Config.load_from_file()

        with open("etc_upload/config.json", 'r') as config_json:
            Settings.dicovered_config = json.load(config_json)

        Config.load_from_file("etc_upload/config.json")

        Config.config["catch_up"] = {"interval": 10, "max_skips": 2}

        Settings.logger = logging.getLogger("policy_handler.unit_test")
        sys.stdout = LogWriter(Settings.logger.info)
        sys.stderr = LogWriter(Settings.logger.error)

        print("print ========== run_policy_handler ==========")
        Settings.logger.info("========== run_policy_handler ==========")
        Audit.init(Config.get_system_name(), Config.LOGGER_CONFIG_FILE_PATH)

        Settings.logger.info("starting policy_handler with config:")
        Settings.logger.info(Audit.log_json_dumps(Config.config))
