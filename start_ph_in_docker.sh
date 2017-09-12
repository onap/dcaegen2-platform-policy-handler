#!/bin/bash

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

APPNAME=policy_handler


if [[ -n ${DOCKER_HOST} ]]; then
  # DOCKER_HOSTNAME=${DOCKER_HOST//*(tcp:|:*[0-9]|\/)/}
  DOCKER_HOSTNAME=${DOCKER_HOST//tcp:/}
  DOCKER_HOSTNAME=${DOCKER_HOSTNAME//:*[0-9]/}
  DOCKER_HOSTNAME=${DOCKER_HOSTNAME//\//}
  echo "${APPNAME} on DOCKER_HOSTNAME=${DOCKER_HOSTNAME}"
  export HOSTNAME=${DOCKER_HOSTNAME}

  # replace CONSUL_IP with docker-host-ip if consul-agent is local
  CONSUL_HOST=${HOSTNAME}
  CONSUL_IP=$(host ${CONSUL_HOST} | awk '/has address/ { print $4 ; exit }')
  if [ "0${CONSUL_IP}" = "0" ]; then
    CONSUL_IP=${CONSUL_HOST}
  fi

  echo "starting ${APPNAME} on HOSTNAME=${HOSTNAME} CONSUL_HOST=${CONSUL_HOST} CONSUL_IP=${CONSUL_IP}"

  docker run --name ${APPNAME} -d -e HOSTNAME --add-host consul:${CONSUL_IP} -P ${APPNAME}
else
  export HOSTNAME=$(hostname --fqdn)

  # replace CONSUL_IP with docker-host-ip if consul-agent is local
  CONSUL_HOST=${HOSTNAME}
  CONSUL_IP=$(host ${CONSUL_HOST} | awk '/has address/ { print $4 ; exit }')

  echo "starting ${APPNAME} on HOSTNAME=${HOSTNAME} CONSUL_HOST=${CONSUL_HOST} CONSUL_IP=${CONSUL_IP}"

  BASEDIR=$(pwd)
  TARGETDIR=/opt/app/${APPNAME}

  mkdir -p ${BASEDIR}/logs

  docker run --name ${APPNAME} -d \
    -e HOSTNAME \
    --add-host consul:${CONSUL_IP} \
    -v ${BASEDIR}/etc:${TARGETDIR}/etc \
    -v ${BASEDIR}/logs:${TARGETDIR}/logs \
    -p 25577:25577 \
    ${APPNAME}
fi

docker ps -a | grep ${APPNAME}
echo "--- --- --- --- ---"
docker exec ${APPNAME} sh -c "whoami;pwd;set;ls -la;ls -l logs"
echo "copy logs: docker cp ${APPNAME}:/opt/app/${APPNAME}/logs logs/"
echo "export logs: docker logs ${APPNAME} > logs/"'$(date +%Y_%m%d-%H%M%S)_'"${APPNAME}.log 2>&1"
