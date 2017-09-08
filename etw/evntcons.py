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
from etw import evntprov as ep

EVENT_HEADER_FLAG_32_BIT_HEADER = 0x20
EVENT_HEADER_FLAG_64_BIT_HEADER = 0x40

# Definitions from evntcons.h file
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000


class EVENT_HEADER(ct.Structure):
    _fields_ = [('Size', ct.c_ushort),
                ('HeaderType', ct.c_ushort),
                ('Flags', ct.c_ushort),
                ('EventProperty', ct.c_ushort),
                ('ThreadId', ct.c_ulong),
                ('ProcessId', ct.c_ulong),
                ('TimeStamp', wt.LARGE_INTEGER),
                ('ProviderId', GUID),
                ('EventDescriptor', ep.EVENT_DESCRIPTOR),
                ('KernelTime', ct.c_ulong),
                ('UserTime', ct.c_ulong),
                ('ActivityId', GUID)]


class ETW_BUFFER_CONTEXT(ct.Structure):
    _fields_ = [('ProcessorNumber', ct.c_ubyte),
                ('Alignment', ct.c_ubyte),
                ('LoggerId', ct.c_ushort)]


class EVENT_HEADER_EXTENDED_DATA_ITEM(ct.Structure):
    _fields_ = [('Reserved1', ct.c_ushort),
                ('ExtType', ct.c_ushort),
                ('Linkage', ct.c_ushort),    # struct{USHORT :1, USHORT :15}
                ('DataSize', ct.c_ushort),
                ('DataPtr', ct.c_ulonglong)]


class EVENT_RECORD(ct.Structure):
    _fields_ = [('EventHeader', EVENT_HEADER),
                ('BufferContext', ETW_BUFFER_CONTEXT),
                ('ExtendedDataCount', ct.c_ushort),
                ('UserDataLength', ct.c_ushort),
                ('ExtendedData', ct.POINTER(EVENT_HEADER_EXTENDED_DATA_ITEM)),
                ('UserData', ct.c_void_p),
                ('UserContext', ct.c_void_p)]
