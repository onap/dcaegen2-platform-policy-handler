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

# Use the official Python as the base image
FROM python:3.6

ENV INSROOT /opt/app
ENV APPUSER policy_handler
ENV APPDIR ${INSROOT}/${APPUSER}

RUN useradd -d ${APPDIR} ${APPUSER}

WORKDIR ${APPDIR}

# Make port 25577 available to the world outside this container
EXPOSE 25577

# Copy the current directory content into the container at ${APPDIR}
COPY ./*.py ./
COPY ./*.in ./
COPY ./*.txt ./
COPY ./run_policy.sh ./
COPY ./policyhandler/ ./policyhandler/
COPY ./etc/ ./etc/
COPY ./etc_customize/ ./etc_customize/

RUN mkdir -p ${APPDIR}/logs \
 && chown -R ${APPUSER}:${APPUSER} ${APPDIR} \
 && chmod a+w ${APPDIR}/logs \
 && chmod 500 ${APPDIR}/etc \
 && chmod 500 ${APPDIR}/run_policy.sh \
 && pip install -r requirements.txt \
 && (CUST_SH=./etc_customize/customize.sh && test -e ${CUST_SH} && chmod 500 ${CUST_SH} \
   && (${CUST_SH} | tee -a logs/"customize_${APPUSER}_$(date +%Y_%m%d-%H%M%S).log" 2>&1)) \
 && ls -laR ${APPDIR}/

USER ${APPUSER}

VOLUME ${APPDIR}/logs

# Run run_policy.sh when the container launches
CMD ["./run_policy.sh"]
