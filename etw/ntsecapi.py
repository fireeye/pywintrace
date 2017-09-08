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

# This GUID allow us to enable and disable file share auditing
audit_objectaccess_share = GUID("{0cce9224-69ae-11d9-bed3-505054503030}")

POLICY_AUDIT_EVENT_SUCCESS = 0x1
POLICY_AUDIT_EVENT_FAILURE = 0x2
POLICY_AUDIT_EVENT_NONE = 0x4


class AUDIT_POLICY_INFORMATION(ct.Structure):
    _fields_ = [('AuditSubCategoryGuid', GUID),
                ('AuditingInformation', wt.ULONG),
                ('AuditCategoryGuid', GUID)]


# Function Definitions
AuditSetSystemPolicy = ct.windll.advapi32.AuditSetSystemPolicy
AuditSetSystemPolicy.argtypes = [ct.POINTER(AUDIT_POLICY_INFORMATION),
                                 wt.ULONG]
AuditSetSystemPolicy.restype = wt.BOOLEAN
