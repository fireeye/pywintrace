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


class EVENT_FILTER_DESCRIPTOR(ct.Structure):
    _fields_ = [('Ptr', ct.c_ulonglong),
                ('Size', ct.c_ulong),
                ('Type', ct.c_ulong)]


class EVENT_DESCRIPTOR(ct.Structure):
    _fields_ = [('Id', ct.c_ushort),
                ('Version', ct.c_ubyte),
                ('Channel', ct.c_ubyte),
                ('Level', ct.c_ubyte),
                ('Opcode', ct.c_ubyte),
                ('Task', ct.c_ushort),
                ('Keyword', ct.c_ulonglong)]
