# Use an official Python runtime as a base image
FROM python:2.7

ENV INSROOT /opt/app
ENV APPUSER policy_handler
ENV APPDIR ${INSROOT}/${APPUSER}

RUN useradd -d ${APPDIR} ${APPUSER}

WORKDIR ${APPDIR}

# Make port 25577 available to the world outside this container
EXPOSE 25577

# Copy the current directory contents into the container at ${APPDIR}
COPY ./*.py ./
COPY ./*.in ./
COPY ./*.txt ./
COPY ./*.sh ./
COPY ./policyhandler/ ./policyhandler/
COPY ./etc/ ./etc/

RUN mkdir -p ${APPDIR}/logs \
 && mkdir -p ${APPDIR}/tmp \
 && mkdir -p ${APPDIR}/etc \
 && chown -R ${APPUSER}:${APPUSER} ${APPDIR} \
 && chmod a+w ${APPDIR}/logs \
 && chmod 700 ${APPDIR}/tmp \
 && chmod 500 ${APPDIR}/etc \
 && chmod 500 ${APPDIR}/run_policy.sh \
 && ls -la && ls -la ./policyhandler

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt

USER ${APPUSER}

VOLUME ${APPDIR}/logs

# Run run_policy.sh when the container launches
CMD ["./run_policy.sh"]
