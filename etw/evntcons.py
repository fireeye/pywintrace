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

# see https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracelog/event_header.htm
EVENT_HEADER_FLAG_EXTENDED_INFO = 0x01
EVENT_HEADER_FLAG_PRIVATE_SESSION = 0x02
EVENT_HEADER_FLAG_STRING_ONLY = 0x04
EVENT_HEADER_FLAG_TRACE_MESSAGE = 0x08
EVENT_HEADER_FLAG_NO_CPUTIME = 0x10
EVENT_HEADER_FLAG_32_BIT_HEADER = 0x20
EVENT_HEADER_FLAG_64_BIT_HEADER = 0x40
EVENT_HEADER_FLAG_CLASSIC_HEADER = 0x100
EVENT_HEADER_FLAG_PROCESSOR_INDEX = 0x200

EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = 0x0001
EVENT_HEADER_EXT_TYPE_SID = 0x0002
EVENT_HEADER_EXT_TYPE_TS_ID = 0x0003
EVENT_HEADER_EXT_TYPE_INSTANCE_INFO = 0x0004
EVENT_HEADER_EXT_TYPE_STACK_TRACE32 = 0x0005
EVENT_HEADER_EXT_TYPE_STACK_TRACE64 = 0x0006
EVENT_HEADER_EXT_TYPE_PEBS_INDEX = 0x0007
EVENT_HEADER_EXT_TYPE_PMC_COUNTERS = 0x0008
EVENT_HEADER_EXT_TYPE_PSM_KEY = 0x0009
EVENT_HEADER_EXT_TYPE_EVENT_KEY = 0x000A
EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL = 0x000B
EVENT_HEADER_EXT_TYPE_PROV_TRAITS = 0x000C
EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY = 0x000D
EVENT_HEADER_EXT_TYPE_MAX = 0x000E

EVENT_ENABLE_PROPERTY_SID = 0x00000001
EVENT_ENABLE_PROPERTY_TS_ID = 0x00000002
EVENT_ENABLE_PROPERTY_STACK_TRACE = 0x00000004
EVENT_ENABLE_PROPERTY_PSM_KEY = 0x00000008
EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 = 0x00000010
EVENT_ENABLE_PROPERTY_PROVIDER_GROUP = 0x00000020
EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0 = 0x00000040
EVENT_ENABLE_PROPERTY_PROCESS_START_KEY = 0x00000080

# Definitions from evntcons.h file
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000


class EVENT_EXTENDED_ITEM_PROCESS_START_KEY(ct.Structure):
    _fields_ = [('ProcessStartKey', ct.c_ulonglong)]


class EVENT_EXTENDED_ITEM_RELATED_ACTIVITYID(ct.Structure):
    _fields_ = [('RelatedActivityId', GUID)]


class EVENT_EXTENDED_ITEM_TS_ID(ct.Structure):
    _fields_ = [('SessionId', ct.c_ulong)]


class EVENT_EXTENDED_ITEM_INSTANCE(ct.Structure):
    _fields_ = [('InstanceId', ct.c_ulong),
                ('ParentInstanceId', ct.c_ulong),
                ('ParentGuid', GUID),
                ]


class EVENT_EXTENDED_ITEM_EVENT_KEY(ct.Structure):
    _fields_ = [('Key', ct.c_ulonglong)]


class EVENT_EXTENDED_ITEM_STACK_TRACE32(ct.Structure):
    _fields_ = [('MatchId', ct.c_ulonglong),
                ('Address', ct.c_ulong * 1),
                ]


class EVENT_EXTENDED_ITEM_STACK_TRACE64(ct.Structure):
    _fields_ = [('MatchId', ct.c_ulonglong),
                ('Address', ct.c_ulonglong * 1),
                ]


class EVENT_EXTENDED_ITEM_PEBS_INDEX(ct.Structure):
    _fields_ = [('PebsIndex', ct.c_ulonglong)]


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
