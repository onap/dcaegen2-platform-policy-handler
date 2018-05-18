# ================================================================================
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

"""generic class to keep get real time info about the current process"""

import gc
import sys
import threading
import traceback
from functools import wraps

import psutil


def safe_operation(func):
    """safequard the function against any exception"""
    if not func:
        return

    @wraps(func)
    def wrapper(*args, **kwargs):
        """wrapper around the function"""
        try:
            return func(*args, **kwargs)
        except Exception as ex:
            return "%s: %s" % (type(ex).__name__, str(ex))
    return wrapper


class ProcessInfo(object):
    """static class to calculate process info"""
    _BIBYTES_SYMBOLS = ('KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB')
    _BIBYTES_VALS = {}

    @staticmethod
    def init():
        """init static constants"""
        for i, bibytes_symbol in enumerate(ProcessInfo._BIBYTES_SYMBOLS):
            ProcessInfo._BIBYTES_VALS[bibytes_symbol] = 1 << (i + 1) * 10
        ProcessInfo._BIBYTES_SYMBOLS = list(reversed(ProcessInfo._BIBYTES_SYMBOLS))

    @staticmethod
    def bytes_to_bibytes(byte_count):
        """converts byte count to human value in kibi-mebi-gibi-...-bytes"""
        if byte_count is None:
            return "unknown"
        if not byte_count or not isinstance(byte_count, int):
            return byte_count
        if not ProcessInfo._BIBYTES_VALS:
            ProcessInfo.init()

        for bibytes_symbol in ProcessInfo._BIBYTES_SYMBOLS:
            bibytes_value = ProcessInfo._BIBYTES_VALS[bibytes_symbol]
            if byte_count >= bibytes_value:
                value = float(byte_count) / bibytes_value
                return '%.2f %s' % (value, bibytes_symbol)
        return "%s B" % byte_count

    @staticmethod
    @safe_operation
    def process_memory():
        """calculates the memory usage of the current process"""
        process = psutil.Process()
        with process.oneshot():
            return dict((k, ProcessInfo.bytes_to_bibytes(v))
                        for k, v in vars(process.memory_full_info()).iteritems())


    @staticmethod
    @safe_operation
    def virtual_memory():
        """calculates the virtual memory usage of the whole vm"""
        return dict((k, ProcessInfo.bytes_to_bibytes(v))
                    for k, v in vars(psutil.virtual_memory()).iteritems())


    @staticmethod
    @safe_operation
    def active_threads():
        """list of active threads"""
        return sorted([thr.name + "(" + str(thr.ident) + ")" for thr in threading.enumerate()])


    @staticmethod
    @safe_operation
    def thread_stacks():
        """returns the current threads with their stack"""
        thread_names = dict((thr.ident, thr.name) for thr in threading.enumerate())
        return [
            {
                "thread_id" : thread_id,
                "thread_name" : thread_names.get(thread_id),
                "thread_stack" : [
                    {
                        "filename" : filename,
                        "lineno" : lineno,
                        "function" : function_name,
                        "line" : line.strip() if line else None
                    }
                    for filename, lineno, function_name, line in traceback.extract_stack(stack)
                ]
            }
            for thread_id, stack in sys._current_frames().items()
        ]


    @staticmethod
    @safe_operation
    def gc_info(full=False):
        """gets info from garbage collector"""
        gc_info = {
            "gc_count" : str(gc.get_count()),
            "gc_threshold" : str(gc.get_threshold())
        }
        if gc.garbage:
            gc_info["gc_garbage"] = ([repr(stuck) for stuck in gc.garbage]
                                     if full else len(gc.garbage))
        return gc_info

    @staticmethod
    def get_all():
        """all info"""
        return {
            "active_threads" : ProcessInfo.active_threads(),
            "gc" : ProcessInfo.gc_info(full=True),
            "process_memory" : ProcessInfo.process_memory(),
            "virtual_memory" : ProcessInfo.virtual_memory(),
            "thread_stacks" : ProcessInfo.thread_stacks()
        }
