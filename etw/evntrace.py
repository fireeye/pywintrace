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


KERNEL_LOGGER_NAME = "NT Kernel Logger"
KERNEL_LOGGER_NAME_LOWER = "nt kernel logger"


ENABLE_TRACE_PARAMETERS_VERSION = 1
ENABLE_TRACE_PARAMETERS_VERSION_2 = 2


EVENT_TRACE_FLAG_PROCESS = 0x00000001
EVENT_TRACE_FLAG_THREAD = 0x00000002
EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004
EVENT_TRACE_FLAG_DISK_IO = 0x00000100
EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200
EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS = 0x00001000
EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS = 0x00002000
EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000
EVENT_TRACE_FLAG_REGISTRY = 0x00020000
EVENT_TRACE_FLAG_DBGPRINT = 0x00040000
EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x00000008
EVENT_TRACE_FLAG_CSWITCH = 0x00000010
EVENT_TRACE_FLAG_DPC = 0x00000020
EVENT_TRACE_FLAG_INTERRUPT = 0x00000040
EVENT_TRACE_FLAG_SYSTEMCALL = 0x00000080
EVENT_TRACE_FLAG_DISK_IO_INIT = 0x00000400
EVENT_TRACE_FLAG_ALPC = 0x00100000
EVENT_TRACE_FLAG_SPLIT_IO = 0x00200000
EVENT_TRACE_FLAG_DRIVER = 0x00800000
EVENT_TRACE_FLAG_PROFILE = 0x01000000
EVENT_TRACE_FLAG_FILE_IO = 0x02000000
EVENT_TRACE_FLAG_FILE_IO_INIT = 0x0400000


DEFAULT_NT_KERNEL_LOGGER_FLAGS = (EVENT_TRACE_FLAG_PROCESS |
                                  EVENT_TRACE_FLAG_THREAD |
                                  EVENT_TRACE_FLAG_DISK_IO |
                                  EVENT_TRACE_FLAG_NETWORK_TCPIP)


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
TRACE_LEVEL_RESERVED6 = 6
TRACE_LEVEL_RESERVED7 = 7
TRACE_LEVEL_RESERVED8 = 8
TRACE_LEVEL_RESERVED9 = 9

# EVENT_CONTROL flags
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_CONTROL_CODE_CAPTURE_STATE = 2

# ControlTrace Codes
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_UPDATE = 2


# Logger Mode flags
EVENT_TRACE_FILE_MODE_NONE = 0x00000000  # Logfile is off
EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001  # Log sequentially
EVENT_TRACE_FILE_MODE_CIRCULAR = 0x00000002  # Log in circular manner
EVENT_TRACE_FILE_MODE_APPEND = 0x00000004  # Append sequential log

EVENT_TRACE_REAL_TIME_MODE = 0x00000100  # Real time mode on
EVENT_TRACE_DELAY_OPEN_FILE_MODE = 0x00000200  # Delay opening file
EVENT_TRACE_BUFFERING_MODE = 0x00000400  # Buffering mode only
EVENT_TRACE_PRIVATE_LOGGER_MODE = 0x00000800  # Process Private Logger
EVENT_TRACE_ADD_HEADER_MODE = 0x00001000  # Add a logfile header

EVENT_TRACE_USE_GLOBAL_SEQUENCE = 0x00004000  # Use global sequence no.
EVENT_TRACE_USE_LOCAL_SEQUENCE = 0x00008000  # Use local sequence no.

EVENT_TRACE_RELOG_MODE = 0x00010000  # Relogger

EVENT_TRACE_USE_PAGED_MEMORY = 0x01000000  # Use pageable buffers

# Logger Mode flags on XP and above
EVENT_TRACE_FILE_MODE_NEWFILE = 0x00000008  # Auto-switch log file
EVENT_TRACE_FILE_MODE_PREALLOCATE = 0x00000020  # Pre-allocate mode

# Logger Mode flags on Vista and above
EVENT_TRACE_NONSTOPPABLE_MODE = 0x00000040  # Session cannot be stopped (Autologger only)
EVENT_TRACE_SECURE_MODE = 0x00000080  # Secure session
EVENT_TRACE_USE_KBYTES_FOR_SIZE = 0x00002000  # Use KBytes as file size unit
EVENT_TRACE_PRIVATE_IN_PROC = 0x00020000  # In process private logger

EVENT_TRACE_MODE_RESERVED = 0x00100000  # Reserved bit, used to signal Heap/Critsec tracing

# Logger Mode flags on Win7 and above
EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000  # Use this for low frequency sessions.

# Logger Mode flags on Win8 and above
EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000  # Receive events from SystemTraceProvider
EVENT_TRACE_ADDTO_TRIAGE_DUMP = 0x80000000  # Add ETW buffers to triage dumps
EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN = 0x00400000  # Stop on hybrid shutdown
EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN = 0x00800000  # Persist on hybrid shutdown

# Logger Mode flags on Blue and above
EVENT_TRACE_INDEPENDENT_SESSION_MODE = 0x08000000  # Independent logger session


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
