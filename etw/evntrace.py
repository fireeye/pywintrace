########################################################################
# Copyright 2017 FireEye Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
########################################################################

import ctypes as ct
import ctypes.wintypes as wt

from etw.GUID import GUID
from etw import evntcons as ec
from etw import evntprov as ep

from etw.common import TIME_ZONE_INFORMATION
from etw.wmistr import WNODE_HEADER

# Remarkably, TRACEHANDLE is not typedef'd to a HANDLE, but, in fact, to a UINT64
TRACEHANDLE = ct.c_ulonglong

INVALID_PROCESSTRACE_HANDLE = TRACEHANDLE(-1)

# TRACE_LEVEL flags
TRACE_LEVEL_NONE = 0         # Tracing is not on
TRACE_LEVEL_CRITICAL = 1     # Abnormal exit or termination
TRACE_LEVEL_ERROR = 2        # Severe errors that need logging
TRACE_LEVEL_WARNING = 3      # Warnings such as allocation failure
TRACE_LEVEL_INFORMATION = 4  # Includes non-error cases(e.g.,Entry-Exit)
TRACE_LEVEL_VERBOSE = 5      # Detailed traces from intermediate steps

# EVENT_CONTROL flags
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_CONTROL_CODE_CAPTURE_STATE = 2

# ControlTrace Codes
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_UPDATE = 2

EVENT_TRACE_REAL_TIME_MODE = 0x00000100


class ENABLE_TRACE_PARAMETERS(ct.Structure):
    _fields_ = [('Version', ct.c_ulong),
                ('EnableProperty', ct.c_ulong),
                ('ControlFlags', ct.c_ulong),
                ('SourceId', GUID),
                ('EnableFilterDesc', ct.POINTER(ep.EVENT_FILTER_DESCRIPTOR)),
                ('FilterDescCount', ct.c_ulong)]


class EVENT_TRACE_PROPERTIES(ct.Structure):
    _fields_ = [('Wnode', WNODE_HEADER),
                ('BufferSize', ct.c_ulong),
                ('MinimumBuffers', ct.c_ulong),
                ('MaximumBuffers', ct.c_ulong),
                ('MaximumFileSize', ct.c_ulong),
                ('LogFileMode', ct.c_ulong),
                ('FlushTimer', ct.c_ulong),
                ('EnableFlags', ct.c_ulong),
                ('AgeLimit', ct.c_ulong),
                ('NumberOfBuffers', ct.c_ulong),
                ('FreeBuffers', ct.c_ulong),
                ('EventsLost', ct.c_ulong),
                ('BuffersWritten', ct.c_ulong),
                ('LogBuffersLost', ct.c_ulong),
                ('RealTimeBuffersLost', ct.c_ulong),
                ('LoggerThreadId', wt.HANDLE),
                ('LogFileNameOffset', ct.c_ulong),
                ('LoggerNameOffset', ct.c_ulong)]


# This is a structure defined in a union within EVENT_TRACE_HEADER
class EVENT_TRACE_HEADER_CLASS(ct.Structure):
    _fields_ = [('Type', ct.c_ubyte),
                ('Level', ct.c_ubyte),
                ('Version', ct.c_uint16)]


class EVENT_TRACE_HEADER(ct.Structure):
    _fields_ = [('Size', ct.c_ushort),
                ('HeaderType', ct.c_ubyte),
                ('MarkerFlags', ct.c_ubyte),
                ('Class', EVENT_TRACE_HEADER_CLASS),
                ('ThreadId', ct.c_ulong),
                ('ProcessId', ct.c_ulong),
                ('TimeStamp', wt.LARGE_INTEGER),
                ('Guid', GUID),
                ('ClientContext', ct.c_ulong),
                ('Flags', ct.c_ulong)]


class EVENT_TRACE(ct.Structure):
    _fields_ = [('Header', EVENT_TRACE_HEADER),
                ('InstanceId', ct.c_ulong),
                ('ParentInstanceId', ct.c_ulong),
                ('ParentGuid', GUID),
                ('MofData', ct.c_void_p),
                ('MofLength', ct.c_ulong),
                ('ClientContext', ct.c_ulong)]


class TRACE_LOGFILE_HEADER(ct.Structure):
    _fields_ = [('BufferSize', ct.c_ulong),
                ('MajorVersion', ct.c_byte),
                ('MinorVersion', ct.c_byte),
                ('SubVersion', ct.c_byte),
                ('SubMinorVersion', ct.c_byte),
                ('ProviderVersion', ct.c_ulong),
                ('NumberOfProcessors', ct.c_ulong),
                ('EndTime', wt.LARGE_INTEGER),
                ('TimerResolution', ct.c_ulong),
                ('MaximumFileSize', ct.c_ulong),
                ('LogFileMode', ct.c_ulong),
                ('BuffersWritten', ct.c_ulong),
                ('StartBuffers', ct.c_ulong),
                ('PointerSize', ct.c_ulong),
                ('EventsLost', ct.c_ulong),
                ('CpuSpeedInMHz', ct.c_ulong),
                ('LoggerName', ct.c_wchar_p),
                ('LogFileName', ct.c_wchar_p),
                ('TimeZone', TIME_ZONE_INFORMATION),
                ('BootTime', wt.LARGE_INTEGER),
                ('PerfFreq', wt.LARGE_INTEGER),
                ('StartTime', wt.LARGE_INTEGER),
                ('ReservedFlags', ct.c_ulong),
                ('BuffersLost', ct.c_ulong)]


# This must be "forward declared", because of the callback type below,
# which is contained in the ct.Structure.
class EVENT_TRACE_LOGFILE(ct.Structure):
    pass


# The type for event trace callbacks.
EVENT_RECORD_CALLBACK = ct.WINFUNCTYPE(None, ct.POINTER(ec.EVENT_RECORD))
EVENT_TRACE_BUFFER_CALLBACK = ct.WINFUNCTYPE(ct.c_ulong,
                                             ct.POINTER(EVENT_TRACE_LOGFILE))

EVENT_TRACE_LOGFILE._fields_ = [
    ('LogFileName', ct.c_wchar_p),
    ('LoggerName', ct.c_wchar_p),
    ('CurrentTime', ct.c_longlong),
    ('BuffersRead', ct.c_ulong),
    ('ProcessTraceMode', ct.c_ulong),
    ('CurrentEvent', EVENT_TRACE),
    ('LogfileHeader', TRACE_LOGFILE_HEADER),
    ('BufferCallback', EVENT_TRACE_BUFFER_CALLBACK),
    ('BufferSize', ct.c_ulong),
    ('Filled', ct.c_ulong),
    ('EventsLost', ct.c_ulong),
    ('EventRecordCallback', EVENT_RECORD_CALLBACK),
    ('IsKernelTrace', ct.c_ulong),
    ('Context', ct.c_void_p)]


# Function Definitions
StartTraceW = ct.windll.advapi32.StartTraceW
StartTraceW.argtypes = [ct.POINTER(TRACEHANDLE),
                        ct.c_wchar_p,
                        ct.POINTER(EVENT_TRACE_PROPERTIES)]
StartTraceW.restype = ct.c_ulong

ControlTraceW = ct.windll.advapi32.ControlTraceW
ControlTraceW.argtypes = [TRACEHANDLE,
                          ct.c_wchar_p,
                          ct.POINTER(EVENT_TRACE_PROPERTIES),
                          ct.c_ulong]
ControlTraceW.restype = ct.c_ulong

# TODO: Ensure we are using the correct library based on the version of Windows.
EnableTraceEx2 = ct.windll.advapi32.EnableTraceEx2
EnableTraceEx2.argtypes = [TRACEHANDLE,
                           ct.POINTER(GUID),
                           ct.c_ulong,
                           ct.c_char,
                           ct.c_ulonglong,
                           ct.c_ulonglong,
                           ct.c_ulong,
                           ct.POINTER(ENABLE_TRACE_PARAMETERS)]
EnableTraceEx2.restype = ct.c_ulong

OpenTraceW = ct.windll.advapi32.OpenTraceW
OpenTraceW.argtypes = [ct.POINTER(EVENT_TRACE_LOGFILE)]
OpenTraceW.restype = TRACEHANDLE

ProcessTrace = ct.windll.advapi32.ProcessTrace
ProcessTrace.argtypes = [ct.POINTER(TRACEHANDLE),
                         ct.c_ulong,
                         ct.POINTER(wt.FILETIME),
                         ct.POINTER(wt.FILETIME)]
ProcessTrace.restype = ct.c_ulong

CloseTrace = ct.windll.advapi32.CloseTrace
CloseTrace.argtypes = [TRACEHANDLE]
CloseTrace.restype = ct.c_ulong
