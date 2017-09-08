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


# WNODE_HEADER flags
WNODE_FLAG_TRACED_GUID = 0x00020000


class WNODE_HEADER(ct.Structure):
    _fields_ = [('BufferSize', ct.c_ulong),
                ('ProviderId', ct.c_ulong),
                ('HistoricalContext', ct.c_uint64),
                ('TimeStamp', wt.LARGE_INTEGER),
                ('Guid', GUID),
                ('ClientContext', ct.c_ulong),
                ('Flags', ct.c_ulong)]
