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


EVENT_FILTER_TYPE_NONE = 0x00000000
EVENT_FILTER_TYPE_SCHEMATIZED = 0x80000000
EVENT_FILTER_TYPE_SYSTEM_FLAGS = 0x80000001
VENT_FILTER_TYPE_TRACEHANDLE = 0x80000002
EVENT_FILTER_TYPE_PID = 0x80000004
EVENT_FILTER_TYPE_EXECUTABLE_NAME = 0x80000008
EVENT_FILTER_TYPE_PACKAGE_ID = 0x80000010
EVENT_FILTER_TYPE_PACKAGE_APP_ID = 0x80000020
EVENT_FILTER_TYPE_PAYLOAD = 0x80000100
EVENT_FILTER_TYPE_EVENT_ID = 0x80000200
EVENT_FILTER_TYPE_STACKWALK = 0x80001000


MAX_EVENT_FILTER_EVENT_ID_COUNT = 64
MAX_EVENT_FILTER_DATA_SIZE = 1024


class EVENT_FILTER_DESCRIPTOR(ct.Structure):
    _fields_ = [('Ptr', ct.c_ulonglong),
                ('Size', ct.c_ulong),
                ('Type', ct.c_ulong)]


class EVENT_FILTER_HEADER(ct.Structure):
    _fields_ = [('Id', wt.USHORT),
                ('Version', wt.CHAR),
                ('Reserved', wt.CHAR * 5),
                ('InstanceId',  ct.c_ulonglong),
                ('Size', wt.ULONG),
                ('NextOffset', wt.ULONG)]


class EVENT_FILTER_EVENT_ID(ct.Structure):
    _fields_ = [('FilterIn', wt.BOOLEAN),
                ('Reserved', wt.CHAR),
                ('Count', wt.USHORT),
                ('Events', wt.USHORT * 0)]

    def __init__(self, filter_in, events):
        struct_size = len(events) * ct.sizeof(wt.USHORT) + ct.sizeof(EVENT_FILTER_EVENT_ID)
        self._buf = (ct.c_char * struct_size)()
        self._props = ct.cast(ct.pointer(self._buf), ct.POINTER(EVENT_FILTER_EVENT_ID))
        self._props.contents.FilterIn = filter_in
        self._props.contents.Reserved = 0
        self._props.contents.Count = len(events)

        for i in range(len(events)):
            ct.memmove(ct.cast(ct.addressof(self._buf) + ct.sizeof(EVENT_FILTER_EVENT_ID) + (ct.sizeof(wt.WCHAR) * i),
                               ct.c_void_p),
                       ct.byref(wt.USHORT(events[i])),
                       ct.sizeof(wt.WCHAR))

    def get(self):
            return self._props


class EVENT_FILTER_LEVEL_KW(ct.Structure):
    _fields_ = [('MatchAnyKeyword', ct.c_ulonglong),
                ('MatchAllKeyword', ct.c_ulonglong),
                ('Level', wt.CHAR),
                ('FilterIn', wt.BOOLEAN)]


class EVENT_FILTER_EVENT_NAME(ct.Structure):
    _fields_ = [('MatchAnyKeyword', ct.c_ulonglong),
                ('MatchAllKeyword', ct.c_ulonglong),
                ('Level', wt.CHAR),
                ('FilterIn', wt.BOOLEAN),
                ('NameCount', wt.USHORT),
                ('Names', wt.CHAR * 0)]

    def __init__(self, match_any, match_all, level, filter_in, names):
        struct_size = ((sum([len(name) for name in names]) * ct.sizeof(wt.CHAR)) + (ct.sizeof(wt.CHAR) * len(names))) +\
                      ct.sizeof(EVENT_FILTER_EVENT_NAME)
        self._buf = (ct.c_char * struct_size)()
        self._props = ct.cast(ct.pointer(self._buf), ct.POINTER(EVENT_FILTER_EVENT_NAME))
        self._props.contents.MatchAnyKeyword = match_any
        self._props.contents.MatchAllKeyword = match_all
        self._props.contents.Level = level
        self._props.contents.FilterIn = filter_in
        self._props.contents.NameCount = len(names)

        str_off = 0
        for i in range(len(names)):
            ct.memmove(ct.cast(ct.addressof(self._buf) + ct.sizeof(EVENT_FILTER_EVENT_NAME) + str_off,
                               ct.c_void_p),
                       names[i],
                       len(names[i]))
            str_off += len(names[i]) + ct.sizeof(wt.CHAR)

    def get(self):
            return self._props


class EVENT_DESCRIPTOR(ct.Structure):
    _fields_ = [('Id', ct.c_ushort),
                ('Version', ct.c_ubyte),
                ('Channel', ct.c_ubyte),
                ('Level', ct.c_ubyte),
                ('Opcode', ct.c_ubyte),
                ('Task', ct.c_ushort),
                ('Keyword', ct.c_ulonglong)]
