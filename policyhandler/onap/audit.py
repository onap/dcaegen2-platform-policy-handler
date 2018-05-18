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

"""generic class to keep track of request handling
 from receiving it through reponse and log all the activities

 call Audit.init("component-name", "path/to/config_file") to init the loggers before any requests

 start each outside request with creation of the Audit object
 audit = Audit(request_id=None, headers=None, msg=None)
"""

import copy
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from enum import Enum

from .CommonLogger import CommonLogger
from .health import Health
from .process_info import ProcessInfo

REQUEST_X_ECOMP_REQUESTID = "X-ECOMP-RequestID"
REQUEST_REMOTE_ADDR = "Remote-Addr"
REQUEST_HOST = "Host"
HOSTNAME = "HOSTNAME"

AUDIT_REQUESTID = 'requestID'
AUDIT_IPADDRESS = 'IPAddress'
AUDIT_SERVER = 'server'
AUDIT_TARGET_ENTITY = 'targetEntity'
AUDIT_METRICS = 'metrics'
AUDIT_TOTAL_STATS = 'audit_total_stats'
METRICS_TOTAL_STATS = 'metrics_total_stats'

HEADER_CLIENTAUTH = "clientauth"
HEADER_AUTHORIZATION = "authorization"

ERROR_CODE = "errorCode"
ERROR_DESCRIPTION = "errorDescription"


class AuditHttpCode(Enum):
    """audit http codes"""
    HTTP_OK = 200
    PERMISSION_UNAUTHORIZED_ERROR = 401
    PERMISSION_FORBIDDEN_ERROR = 403
    RESPONSE_ERROR = 400
    DATA_NOT_FOUND_ERROR = 404
    SERVER_INTERNAL_ERROR = 500
    SERVICE_UNAVAILABLE_ERROR = 503
    DATA_ERROR = 1030
    SCHEMA_ERROR = 1040


class AuditResponseCode(Enum):
    """audit response codes"""
    SUCCESS = 0
    PERMISSION_ERROR = 100
    AVAILABILITY_ERROR = 200
    DATA_ERROR = 300
    SCHEMA_ERROR = 400
    BUSINESS_PROCESS_ERROR = 500
    UNKNOWN_ERROR = 900

    @staticmethod
    def get_response_code(http_status_code):
        """calculates the response_code from max_http_status_code"""
        response_code = AuditResponseCode.UNKNOWN_ERROR
        if http_status_code <= AuditHttpCode.HTTP_OK.value:
            response_code = AuditResponseCode.SUCCESS

        elif http_status_code in [AuditHttpCode.PERMISSION_UNAUTHORIZED_ERROR.value,
                                  AuditHttpCode.PERMISSION_FORBIDDEN_ERROR.value]:
            response_code = AuditResponseCode.PERMISSION_ERROR
        elif http_status_code == AuditHttpCode.SERVICE_UNAVAILABLE_ERROR.value:
            response_code = AuditResponseCode.AVAILABILITY_ERROR
        elif http_status_code == AuditHttpCode.SERVER_INTERNAL_ERROR.value:
            response_code = AuditResponseCode.BUSINESS_PROCESS_ERROR
        elif http_status_code in [AuditHttpCode.DATA_ERROR.value,
                                  AuditHttpCode.RESPONSE_ERROR.value,
                                  AuditHttpCode.DATA_NOT_FOUND_ERROR.value]:
            response_code = AuditResponseCode.DATA_ERROR
        elif http_status_code == AuditHttpCode.SCHEMA_ERROR.value:
            response_code = AuditResponseCode.SCHEMA_ERROR

        return response_code

    @staticmethod
    def get_human_text(response_code):
        """convert enum name into human readable text"""
        if not response_code:
            return "unknown"
        return response_code.name.lower().replace("_", " ")


class _Audit(object):
    """put the audit object on stack per each initiating request in the system

    :request_id: is the X-ECOMP-RequestID for tracing

    :req_message: is the request message string for logging

    :aud_parent: is the parent request - used for sub-query metrics to other systems

    :kwargs: - put any request related params into kwargs
    """
    _service_name = ""
    _service_version = ""
    _service_instance_uuid = str(uuid.uuid4())
    _started = datetime.utcnow()
    _key_format = re.compile(r"\W")
    _logger_debug = None
    _logger_error = None
    _logger_metrics = None
    _logger_audit = None
    _health = Health()
    _py_ver = sys.version.replace("\n", "")
    _packages = []

    @staticmethod
    def init(service_name, service_version, config_file_path):
        """init static invariants and loggers"""
        _Audit._service_name = service_name
        _Audit._service_version = service_version
        _Audit._logger_debug = CommonLogger(config_file_path, "debug", \
            instanceUUID=_Audit._service_instance_uuid, serviceName=_Audit._service_name)
        _Audit._logger_error = CommonLogger(config_file_path, "error", \
            instanceUUID=_Audit._service_instance_uuid, serviceName=_Audit._service_name)
        _Audit._logger_metrics = CommonLogger(config_file_path, "metrics", \
            instanceUUID=_Audit._service_instance_uuid, serviceName=_Audit._service_name)
        _Audit._logger_audit = CommonLogger(config_file_path, "audit", \
            instanceUUID=_Audit._service_instance_uuid, serviceName=_Audit._service_name)
        ProcessInfo.init()
        try:
            _Audit._packages = filter(None, subprocess.check_output(["pip", "freeze"]).splitlines())
        except subprocess.CalledProcessError:
            pass


    def health(self, full=False):
        """returns json for health check"""
        utcnow = datetime.utcnow()
        health = {
            "server" : {
                "service_name" : _Audit._service_name,
                "service_version" : _Audit._service_version,
                "service_instance_uuid" : _Audit._service_instance_uuid
            },
            "runtime" : {
                "started" : str(_Audit._started),
                "utcnow" : str(utcnow),
                "uptime" : str(utcnow - _Audit._started),
                "active_threads" : ProcessInfo.active_threads(),
                "gc" : ProcessInfo.gc_info(full),
                "virtual_memory" : ProcessInfo.virtual_memory(),
                "process_memory" : ProcessInfo.process_memory()
            },
            "stats" : _Audit._health.dump(),
            "soft" : {"python" : _Audit._py_ver, "packages" : _Audit._packages}
        }
        self.info("{} health: {}".format(_Audit._service_name, json.dumps(health)))
        return health

    def process_info(self):
        """get the debug info on all the threads and memory"""
        process_info = ProcessInfo.get_all()
        self.info("{} process_info: {}".format(_Audit._service_name, json.dumps(process_info)))
        return process_info

    def __init__(self, job_name=None, request_id=None, req_message=None, **kwargs):
        """create audit object per each request in the system

        :job_name: is the name of the audit job for health stats
        :request_id: is the X-ECOMP-RequestID for tracing
        :req_message: is the request message string for logging
        :kwargs: - put any request related params into kwargs
        """
        self.job_name = _Audit._key_format.sub('_', job_name or req_message or _Audit._service_name)
        self.request_id = request_id
        self.req_message = req_message or ""
        self.kwargs = kwargs or {}

        self.max_http_status_code = 0
        self._lock = threading.Lock()


    def merge_all_kwargs(self, **kwargs):
        """returns the merge of copy of self.kwargs with the param kwargs"""
        all_kwargs = self.kwargs.copy()
        if kwargs:
            all_kwargs.update(kwargs)
        return all_kwargs

    def set_http_status_code(self, http_status_code):
        """accumulate the highest(worst) http status code"""
        with self._lock:
            if self.max_http_status_code < AuditHttpCode.SERVER_INTERNAL_ERROR.value:
                self.max_http_status_code = max(http_status_code, self.max_http_status_code)

    def get_max_http_status_code(self):
        """returns the highest(worst) http status code"""
        with self._lock:
            max_http_status_code = self.max_http_status_code
        return max_http_status_code

    @staticmethod
    def get_status_code(success):
        """COMPLETE versus ERROR"""
        if success:
            return 'COMPLETE'
        return 'ERROR'

    def is_serious_error(self, status_code):
        """returns whether the response_code is success and a human text for response code"""
        return (AuditResponseCode.PERMISSION_ERROR.value
                == AuditResponseCode.get_response_code(status_code).value
                or self.get_max_http_status_code() >= AuditHttpCode.SERVER_INTERNAL_ERROR.value)

    def _get_response_status(self):
        """calculates the response status fields from max_http_status_code"""
        max_http_status_code = self.get_max_http_status_code()
        response_code = AuditResponseCode.get_response_code(max_http_status_code)
        success = (response_code.value == AuditResponseCode.SUCCESS.value)
        response_description = AuditResponseCode.get_human_text(response_code)
        return success, max_http_status_code, response_code, response_description

    def is_success(self):
        """returns whether the response_code is success and a human text for response code"""
        success, _, _, _ = self._get_response_status()
        return success

    def debug(self, log_line, **kwargs):
        """debug - the debug=lowest level of logging"""
        _Audit._logger_debug.debug(log_line, **self.merge_all_kwargs(**kwargs))

    def info(self, log_line, **kwargs):
        """debug - the info level of logging"""
        _Audit._logger_debug.info(log_line, **self.merge_all_kwargs(**kwargs))

    def info_requested(self, result=None, **kwargs):
        """info "requested ..." - the info level of logging"""
        self.info("requested {0} {1}".format(self.req_message, result or ""), \
            **self.merge_all_kwargs(**kwargs))

    def warn(self, log_line, error_code=None, **kwargs):
        """debug+error - the warn level of logging"""
        all_kwargs = self.merge_all_kwargs(**kwargs)

        if error_code and isinstance(error_code, AuditResponseCode):
            all_kwargs[ERROR_CODE] = error_code.value
            all_kwargs[ERROR_DESCRIPTION] = AuditResponseCode.get_human_text(error_code)

        _Audit._logger_debug.warn(log_line, **all_kwargs)
        _Audit._logger_error.warn(log_line, **all_kwargs)

    def error(self, log_line, error_code=None, **kwargs):
        """debug+error - the error level of logging"""
        all_kwargs = self.merge_all_kwargs(**kwargs)

        if error_code and isinstance(error_code, AuditResponseCode):
            all_kwargs[ERROR_CODE] = error_code.value
            all_kwargs[ERROR_DESCRIPTION] = AuditResponseCode.get_human_text(error_code)

        _Audit._logger_debug.error(log_line, **all_kwargs)
        _Audit._logger_error.error(log_line, **all_kwargs)

    def fatal(self, log_line, error_code=None, **kwargs):
        """debug+error - the fatal level of logging"""
        all_kwargs = self.merge_all_kwargs(**kwargs)

        if error_code and isinstance(error_code, AuditResponseCode):
            all_kwargs[ERROR_CODE] = error_code.value
            all_kwargs[ERROR_DESCRIPTION] = AuditResponseCode.get_human_text(error_code)

        _Audit._logger_debug.fatal(log_line, **all_kwargs)
        _Audit._logger_error.fatal(log_line, **all_kwargs)

    @staticmethod
    def hide_secrets(obj):
        """hides the known secret field values of the dictionary"""
        if not isinstance(obj, dict):
            return obj

        for key in obj:
            if key.lower() in [HEADER_CLIENTAUTH, HEADER_AUTHORIZATION]:
                obj[key] = "*"
            elif isinstance(obj[key], dict):
                obj[key] = _Audit.hide_secrets(obj[key])

        return obj

    @staticmethod
    def log_json_dumps(obj, **kwargs):
        """hide the known secret field values of the dictionary and return json.dumps"""
        if not isinstance(obj, dict):
            return json.dumps(obj, **kwargs)

        return json.dumps(_Audit.hide_secrets(copy.deepcopy(obj)), **kwargs)

    @staticmethod
    def get_elapsed_time(started):
        """returns the elapsed time since started in milliseconds"""
        return int(round(1000 * (time.time() - (started or 0))))


class Audit(_Audit):
    """Audit class to track the high level operations"""

    def __init__(self, job_name=None, request_id=None, req_message=None, **kwargs):
        """create audit object per each request in the system

        :job_name: is the name of the audit job for health stats
        :request_id: is the X-ECOMP-RequestID for tracing
        :req_message: is the request message string for logging
        :aud_parent: is the parent Audit - used for sub-query metrics to other systems
        :kwargs: - put any request related params into kwargs
        """
        super(Audit, self).__init__(job_name=job_name,
                                    request_id=request_id,
                                    req_message=req_message,
                                    **kwargs)

        headers = self.kwargs.get("headers", {})
        if headers:
            if not self.request_id:
                self.request_id = headers.get(REQUEST_X_ECOMP_REQUESTID)
            if AUDIT_IPADDRESS not in self.kwargs:
                self.kwargs[AUDIT_IPADDRESS] = headers.get(REQUEST_REMOTE_ADDR)
            if AUDIT_SERVER not in self.kwargs:
                self.kwargs[AUDIT_SERVER] = headers.get(REQUEST_HOST)

        created_req = ""
        if not self.request_id:
            created_req = " with new"
            self.request_id = str(uuid.uuid4())

        if AUDIT_SERVER not in self.kwargs:
            self.kwargs[AUDIT_SERVER] = os.environ.get(HOSTNAME)

        self.kwargs[AUDIT_REQUESTID] = self.request_id

        _Audit._health.start(self.job_name, self.request_id)
        _Audit._health.start(AUDIT_TOTAL_STATS, self.request_id)

        self._started = time.time()
        self._start_event = Audit._logger_audit.getStartRecordEvent()

        self.info("new audit{0} request_id {1}, msg({2}), kwargs({3})"\
            .format(created_req, self.request_id, self.req_message, json.dumps(self.kwargs)))


    def audit_done(self, result=None, **kwargs):
        """debug+audit - the audit=top level of logging"""
        all_kwargs = self.merge_all_kwargs(**kwargs)
        success, max_http_status_code, response_code, response_description = \
            self._get_response_status()
        log_line = "{0} {1}".format(self.req_message, result or "").strip()
        audit_func = None
        timer = _Audit.get_elapsed_time(self._started)
        if success:
            log_line = "done: {0}".format(log_line)
            self.info(log_line, **all_kwargs)
            audit_func = _Audit._logger_audit.info
            _Audit._health.success(self.job_name, timer, self.request_id)
            _Audit._health.success(AUDIT_TOTAL_STATS, timer, self.request_id)
        else:
            log_line = "failed: {0}".format(log_line)
            self.error(log_line, errorCode=response_code.value,
                       errorDescription=response_description, **all_kwargs)
            audit_func = _Audit._logger_audit.error
            _Audit._health.error(self.job_name, timer, self.request_id)
            _Audit._health.error(AUDIT_TOTAL_STATS, timer, self.request_id)

        audit_func(log_line, begTime=self._start_event, timer=timer,
                   statusCode=_Audit.get_status_code(success),
                   responseCode=response_code.value,
                   responseDescription=response_description,
                   **all_kwargs)

        return (success, max_http_status_code, response_description)


class Metrics(_Audit):
    """Metrics class to track the calls to outside systems"""

    def __init__(self, aud_parent, **kwargs):
        """create audit object per each request in the system

        :aud_parent: is the parent Audit - used for sub-query metrics to other systems
        :kwargs: - put any request related params into kwargs
        """
        super(Metrics, self).__init__(job_name=aud_parent.job_name,
                                      request_id=aud_parent.request_id,
                                      req_message=aud_parent.req_message,
                                      **aud_parent.merge_all_kwargs(**kwargs))
        self.aud_parent = aud_parent
        self._metrics_name = _Audit._key_format.sub(
            '_', AUDIT_METRICS + "_" + self.kwargs.get(AUDIT_TARGET_ENTITY, self.job_name))

        self._metrics_started = None
        self._metrics_start_event = None


    def metrics_start(self, log_line=None, **kwargs):
        """reset metrics timing"""
        self.merge_all_kwargs(**kwargs)
        self._metrics_started = time.time()
        self._metrics_start_event = _Audit._logger_metrics.getStartRecordEvent()
        if log_line:
            self.info(log_line, **self.merge_all_kwargs(**kwargs))
        _Audit._health.start(self._metrics_name, self.request_id)
        _Audit._health.start(METRICS_TOTAL_STATS, self.request_id)


    def metrics(self, log_line, **kwargs):
        """debug+metrics - the metrics=sub-audit level of logging"""
        all_kwargs = self.merge_all_kwargs(**kwargs)
        success, max_http_status_code, response_code, response_description = \
            self._get_response_status()
        metrics_func = None
        timer = _Audit.get_elapsed_time(self._metrics_started)
        if success:
            log_line = "done: {0}".format(log_line)
            self.info(log_line, **all_kwargs)
            metrics_func = _Audit._logger_metrics.info
            _Audit._health.success(self._metrics_name, timer, self.request_id)
            _Audit._health.success(METRICS_TOTAL_STATS, timer, self.request_id)
        else:
            log_line = "failed: {0}".format(log_line)
            self.error(log_line, errorCode=response_code.value,
                       errorDescription=response_description, **all_kwargs)
            metrics_func = _Audit._logger_metrics.error
            _Audit._health.error(self._metrics_name, timer, self.request_id)
            _Audit._health.error(METRICS_TOTAL_STATS, timer, self.request_id)

        metrics_func(
            log_line,
            begTime=(self._metrics_start_event or _Audit._logger_metrics.getStartRecordEvent()),
            timer=timer,
            statusCode=_Audit.get_status_code(success),
            responseCode=response_code.value,
            responseDescription=response_description,
            **all_kwargs)

        return (success, max_http_status_code, response_description)
