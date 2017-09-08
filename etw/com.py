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
from etw.GUID import GUID
from etw import tdh


CLSCTX_INPROC_SERVER = 0x1
CLSCTX_INPROC_HANDLER = 0x2
CLSCTX_LOCAL_SERVER = 0x4
CLSCTX_INPROC_SERVER16 = 0x8
CLSCTX_REMOTE_SERVER = 0x10
CLSCTX_INPROC_HANDLER16 = 0x20
CLSCTX_RESERVED1 = 0x40
CLSCTX_RESERVED2 = 0x80
CLSCTX_RESERVED3 = 0x100
CLSCTX_RESERVED4 = 0x200
CLSCTX_NO_CODE_DOWNLOAD = 0x400
CLSCTX_RESERVED5 = 0x800
CLSCTX_NO_CUSTOM_MARSHAL = 0x1000
CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000
CLSCTX_NO_FAILURE_LOG = 0x4000
CLSCTX_DISABLE_AAA = 0x8000
CLSCTX_ENABLE_AAA = 0x10000
CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000
CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000
CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000
CLSCTX_ENABLE_CLOAKING = 0x100000
CLSCTX_APPCONTAINER = 0x400000
CLSCTX_ACTIVATE_AAA_AS_IU = 0x800000
CLSCTX_PS_DLL = 0x80000000

CLSCTX_SERVER = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER

COINIT_MULTITHREADED = 0
COINIT_APARTMENTTHREADED = 2


class ComException(Exception):
    """
    Raise for an COM exception
    """


class ComClassInstance:
    this = None
    vtbl = None

    def __init__(self, this, vtbl):
        self.this = this
        self.vtbl = vtbl


class COM:
    '''
    COM wrapper class. Wraps COM initialization / uninitialization via ctxmgr.

    N.B. If using this class, do not call init() and fini() directly. Only use through via ctxmgr
    '''
    def __init__(self, coinit=COINIT_MULTITHREADED):
        self.coinit = coinit
        self.initialized = False

    def __enter__(self):
        self.init()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fini()

    def init(self):
        result = ct.windll.ole32.CoInitializeEx(None, self.coinit)
        if result != tdh.ERROR_SUCCESS:
            raise ct.WinError()
        self.initialized = True

    def fini(self):
        ct.windll.ole32.CoUninitialize()
        self.initialized = False

    def create_instance(self, clsid, type, iid):

        if self.initialized is False:
            raise ComException('COM must be initialized before calling CoCreateInstance()')

        ptr = ct.c_void_p(0)
        error = ct.windll.ole32.CoCreateInstance(ct.byref(GUID(clsid)),
                                                 None,
                                                 type,
                                                 ct.byref(GUID(iid)),
                                                 ct.byref(ptr))
        if error != tdh.ERROR_SUCCESS:
            raise ct.WinError()
        return ptr

    def init_security(self, desc, auth_svc, as_auth_svc, auth_level, imp_level, auth_list, capabilities):

        if self.initialized is False:
            raise ComException('COM must be initialized before calling CoInitializeSecurity()')

        error = ct.windll.ole32.CoInitializeSecurity(desc,
                                                     auth_svc,
                                                     as_auth_svc,
                                                     None,
                                                     auth_level,
                                                     imp_level,
                                                     auth_list,
                                                     capabilities,
                                                     None)
        if error != tdh.ERROR_SUCCESS:
            raise ct.WinError()

    def set_proxy_blanket(self, proxy, auth_svc, authz_svc, name, auth_level, imp_level, auth_info, capabilities):

        if self.initialized is False:
            raise ComException('COM must be initialized before calling CoSetProxyBlanket()')

        error = ct.windll.ole32.CoSetProxyBlanket(proxy,
                                                  auth_svc,
                                                  authz_svc,
                                                  name,
                                                  auth_level,
                                                  imp_level,
                                                  auth_info,
                                                  capabilities)
        if error != tdh.ERROR_SUCCESS:
            raise ct.WinError()
