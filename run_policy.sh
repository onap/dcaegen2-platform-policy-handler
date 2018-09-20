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
exec &>> >(tee -a ${LOG_FILE})
echo "---------------------------------------------"
STARTED=$(date +%Y-%m-%d_%T.%N)
echo "${STARTED}: running ${BASH_SOURCE[0]}"
echo "APP_VER =" $(python setup.py --version)
echo "HOSTNAME =${HOSTNAME}"
echo "CONSUL_URL =${CONSUL_URL}"
(pwd; uname -a; echo "/etc/hosts"; cat /etc/hosts; openssl version -a)

python -m policyhandler &
PID=$!

function finish {
  echo "killing policy_handler ${PID}" $(date +%Y_%m%d-%T.%N)
  kill -9 ${PID}
  echo "killed policy_handler ${PID}" $(date +%Y_%m%d-%T.%N)
}
trap finish SIGHUP SIGINT SIGTERM

echo "running policy_handler as ${PID} logs to ${LOG_FILE}"
(free -h; df -h; ps afxvw; ss -aepi)

wait ${PID}
exec &>> >(tee -a ${LOG_FILE})
echo "---------------------------------------------"
echo "$(date +%Y-%m-%d_%T.%N): exit ${BASH_SOURCE[0]} that was started on ${STARTED}"

mv ${LOG_FILE} ${LOG_FILE}.$(date +%Y-%m-%d_%H%M%S)
