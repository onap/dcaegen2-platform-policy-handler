# ================================================================================
# Copyright (c) 2017-2019 AT&T Intellectual Property. All rights reserved.
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

"""
    run as server:
    python -m policyhandler

    that will invoke this module __main__.py in folder of policyhandler
"""

import sys

from policyhandler.config import Config
from policyhandler.onap.audit import Audit
from policyhandler.utils import Utils


def run_policy_handler():
    """main run function for policy-handler"""
    Config.init_config()

    from policyhandler import LogWriter
    from policyhandler.policy_receiver import PolicyReceiver
    from policyhandler.service_activator import ServiceActivator
    from policyhandler.web_server import PolicyWeb

    logger = Utils.get_logger(__file__)
    sys.stdout = LogWriter(logger.info)
    sys.stderr = LogWriter(logger.error)

    logger.info("========== run_policy_handler ========== %s", __package__)
    Audit.init(Config.system_name, Config.LOGGER_CONFIG_FILE_PATH)

    audit = Audit(req_message="start policy handler")

    Config.discover(audit)
    ServiceActivator.determine_mode_of_operation(audit)
    logger.info(audit.info(
        "starting policy_handler with config: {}".format(Config.discovered_config)))

    PolicyReceiver.run(audit)
    PolicyWeb.run_forever(audit)


if __name__ == "__main__":
    run_policy_handler()
