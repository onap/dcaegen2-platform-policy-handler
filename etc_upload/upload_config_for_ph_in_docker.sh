#!/bin/bash

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

echo "to upload the config to consul-kv discovery:"
echo "  - place it into etc_upload/config.json"
echo "  - and run this script: etc_upload/upload_config_for_ph_in_docker.sh"
echo "    from main dir == on the same level as etc_upload/"

APPNAME=policy_handler

if [[ -n ${DOCKER_HOST} ]]; then
  # DOCKER_HOSTNAME=${DOCKER_HOST//*(tcp:|:*[0-9]|\/)/}
  DOCKER_HOSTNAME=${DOCKER_HOST//tcp:/}
  DOCKER_HOSTNAME=${DOCKER_HOSTNAME//:*[0-9]/}
  DOCKER_HOSTNAME=${DOCKER_HOSTNAME//\//}
  CONSUL_HOST=${DOCKER_HOSTNAME}
else
  CONSUL_HOST=devcnsl00.dcae.sic.research.att.com
fi

echo "uploading etc_upload/config.json for ${APPNAME} to CONSUL_HOST=${CONSUL_HOST}"

curl -X PUT -H 'Content-Type: application/json' --data-binary "$(cat etc_upload/config.json)" http://${CONSUL_HOST}:8500/v1/kv/${APPNAME}
