# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
# Copyright 2020 Deutsche Telekom. All rights reserved.
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

# Use the recommended by SECCOM Python as the base image
FROM python:3.8.2-alpine3.11

ARG user=onap
ARG group=onap

RUN addgroup -S $group && adduser -S -D -h /home/$user $user $group && \
    chown -R $user:$group /home/$user &&  \
    mkdir /var/log/$user && \
    chown -R $user:$group /var/log/$user && \
    mkdir /app && \
    chown -R $user:$group /app

WORKDIR /app

# Make port 25577 available to the world outside this container
EXPOSE 25577

# Copy the current directory content into the container at WORKDIR
COPY ./*.py ./
COPY ./*.in ./
COPY ./*.txt ./
COPY ./run_policy.sh ./
COPY ./policyhandler/ ./policyhandler/
COPY ./etc/ ./etc/
COPY ./etc_customize/ ./etc_customize/

RUN apk add build-base linux-headers openssl iproute2 bash && \
    pip install -r requirements.txt

RUN mkdir -p logs \
 && chown -R $user:$group . \
 && chmod a+w logs \
 && chmod 500 etc \
 && chmod 500 run_policy.sh \
 && (CUST_SH=./etc_customize/customize.sh && test -e $CUST_SH && chmod 500 $CUST_SH \
   && ($CUST_SH | tee -a logs/"customize_$user_$(date +%Y_%m%d-%H%M%S).log" 2>&1)) \
 && ls -laR .

USER $user

VOLUME logs

# Run run_policy.sh when the container launches
CMD ["./run_policy.sh"]
