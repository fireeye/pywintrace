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

import ctypes.wintypes as wt


RPC_C_IMP_LEVEL_DEFAULT = 0
RPC_C_IMP_LEVEL_ANONYMOUS = 1
RPC_C_IMP_LEVEL_IDENTIFY = 2
RPC_C_IMP_LEVEL_IMPERSONATE = 3
RPC_C_IMP_LEVEL_DELEGATE = 4

RPC_C_AUTHN_LEVEL_DEFAULT = 0
RPC_C_AUTHN_LEVEL_NONE = 1
RPC_C_AUTHN_LEEL_CONNECT = 2
RPC_C_AUTHN_LEVEL_CALL = 3
RPC_C_AUTHN_LEVEL_PKT = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6

RPC_AUTH_IDENTITY_HANDLE = wt.HANDLE
RPC_AUTHZ_HANDLE = wt.HANDLE

RPC_C_AUTHN_NONE = 0
RPC_C_AUTHN_DCE_PRIVATE = 1
RPC_C_AUTHN_DCE_PUBLIC = 2
RPC_C_AUTHN_DEC_PUBLIC = 4
RPC_C_AUTHN_GSS_NEGOTIATE = 9
RPC_C_AUTHN_WINNT = 10
RPC_C_AUTHN_GSS_SCHANNEL = 14
RPC_C_AUTHN_GSS_KERBEROS = 16
RPC_C_AUTHN_DPA = 17
RPC_C_AUTHN_MSN = 18
RPC_C_AUTHN_DIGEST = 21
RPC_C_AUTHN_KERNEL = 20

RPC_C_AUTHZ_NONE = 0
RPC_C_AUTHZ_NAME = 1
RPC_C_AUTHZ_DCE = 2
RPC_C_AUTHZ_DEFAULT = 0xffffffff
