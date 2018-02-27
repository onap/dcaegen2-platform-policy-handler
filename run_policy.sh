#!/bin/bash

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

mkdir -p logs
LOG_FILE=logs/policy_handler.log
echo "---------------------------------------------" >> ${LOG_FILE} 2>&1
export APP_VER=$(python setup.py --version)
echo "APP_VER=${APP_VER}" | tee -a ${LOG_FILE}

echo "/etc/hosts" | tee -a ${LOG_FILE}
cat /etc/hosts | tee -a ${LOG_FILE}
python -m policyhandler/policy_handler >> ${LOG_FILE} 2>&1 &
PID=$!

echo "running policy_handler as" ${PID} "log" ${LOG_FILE} | tee -a ${LOG_FILE}
function finish {
  echo "killing policy_handler ${PID}" $(date +%Y_%m%d-%H:%M:%S.%N) | tee -a ${LOG_FILE}
  kill -9 ${PID}
  echo "killed policy_handler ${PID}" $(date +%Y_%m%d-%H:%M:%S.%N)  | tee -a ${LOG_FILE}
}
trap finish SIGHUP SIGINT SIGTERM

wait ${PID}
echo "---------------------------------------------" >> ${LOG_FILE} 2>&1
mv ${LOG_FILE} ${LOG_FILE}.$(date +%Y-%m-%d_%H%M%S)
