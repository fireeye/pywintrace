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
from etw import com
from etw import ole
from etw import rpc
from etw import tdh


# enum tag_WBEM_GENERIC_FLAG_TYPE
#     {
#         WBEM_FLAG_RETURN_IMMEDIATELY	= 0x10,
#         WBEM_FLAG_RETURN_WBEM_COMPLETE	= 0,
#         WBEM_FLAG_BIDIRECTIONAL	= 0,
#         WBEM_FLAG_FORWARD_ONLY	= 0x20,
#         WBEM_FLAG_NO_ERROR_OBJECT	= 0x40,
#         WBEM_FLAG_RETURN_ERROR_OBJECT	= 0,
#         WBEM_FLAG_SEND_STATUS	= 0x80,
#         WBEM_FLAG_DONT_SEND_STATUS	= 0,
#         WBEM_FLAG_ENSURE_LOCATABLE	= 0x100,
#         WBEM_FLAG_DIRECT_READ	= 0x200,
#         WBEM_FLAG_SEND_ONLY_SELECTED	= 0,
#         WBEM_RETURN_WHEN_COMPLETE	= 0,
#         WBEM_RETURN_IMMEDIATELY	= 0x10,
#         WBEM_MASK_RESERVED_FLAGS	= 0x1f000,
#         WBEM_FLAG_USE_AMENDED_QUALIFIERS	= 0x20000,
#         WBEM_FLAG_STRONG_VALIDATION	= 0x100000
#     } 	WBEM_GENERIC_FLAG_TYPE;


WBEM_FLAG_RETURN_IMMEDIATELY = 0x10
WBEM_FLAG_RETURN_WBEM_COMPLETE = 0
WBEM_FLAG_BIDIRECTIONAL = 0
WBEM_FLAG_FORWARD_ONLY = 0x20
WBEM_FLAG_NO_ERROR_OBJECT = 0x40
WBEM_FLAG_RETURN_ERROR_OBJECT = 0
WBEM_FLAG_SEND_STATUS = 0x80
WBEM_FLAG_DONT_SEND_STATUS = 0
WBEM_FLAG_ENSURE_LOCATABLE = 0x100
WBEM_FLAG_DIRECT_READ = 0x200
WBEM_FLAG_SEND_ONLY_SELECTED = 0
WBEM_RETURN_WHEN_COMPLETE = 0
WBEM_RETURN_IMMEDIATELY = 0x10
WBEM_MASK_RESERVED_FLAGS = 0x1f000
WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x20000
WBEM_FLAG_STRONG_VALIDATION = 0x10000

HRESULT = wt.LONG

CLSID_WbemLocator = GUID("{4590f811-1d3a-11d0-891f-00aa004b2e24}")
IID_IWbemLocator = GUID("{dc12a687-737f-11cf-884d-00aa004b2e24}")

# generic prototype
Generic_Proto = ct.WINFUNCTYPE(HRESULT,
                               wt.LPVOID)

#            virtual HRESULT STDMETHODCALLTYPE QueryInterface(
#                /* [in] */ REFIID riid,
#                /* [iid_is][out] */ _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppvObject) = 0;
#
#            virtual ULONG STDMETHODCALLTYPE AddRef( void) = 0;
#
#            virtual ULONG STDMETHODCALLTYPE Release( void) = 0;


# IUnknown method prototypes
IUnknown_QueryInterface_Proto = ct.WINFUNCTYPE(HRESULT,
                                               wt.LPVOID, ct.POINTER(GUID), ct.POINTER(wt.LPVOID))

IUnknown_AddRef_Proto = ct.WINFUNCTYPE(HRESULT,
                                       wt.LPVOID)

IUnknown_Release_Proto = ct.WINFUNCTYPE(HRESULT,
                                        wt.LPVOID)


#       virtual HRESULT STDMETHODCALLTYPE Reset( void) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE Next(
#           /* [in] */ long lTimeout,
#           /* [in] */ ULONG uCount,
#           /* [length_is][size_is][out] */ __RPC__out_ecount_part(uCount, *puReturned) IWbemClassObject **apObjects,
#           /* [out] */ __RPC__out ULONG *puReturned) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE NextAsync(
#           /* [in] */ ULONG uCount,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pSink) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE Clone(
#           /* [out] */ __RPC__deref_out_opt IEnumWbemClassObject **ppEnum) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE Skip(
#           /* [in] */ long lTimeout,
#           /* [in] */ ULONG nCount) = 0;

# IEnumWbemClassObject method prototypes


IEnumWbemClassObject_Reset_Proto = ct.WINFUNCTYPE(HRESULT,
                                                  wt.LPVOID)

IEnumWbemClassObject_Next_Proto = ct.WINFUNCTYPE(HRESULT,
                                                 wt.LPVOID,
                                                 wt.LONG,
                                                 wt.ULONG,
                                                 ct.POINTER(wt.LPVOID),
                                                 ct.POINTER(wt.ULONG))

IEnumWbemClassObject_NextAsync_Proto = ct.WINFUNCTYPE(HRESULT,
                                                      wt.LPVOID,
                                                      wt.ULONG,
                                                      wt.LPVOID)

IEnumWbemClassObject_Clone_Proto = ct.WINFUNCTYPE(HRESULT,
                                                  wt.LPVOID,
                                                  ct.POINTER(wt.ULONG))

IEnumWbemClassObject_Skip_Proto = ct.WINFUNCTYPE(HRESULT,
                                                 wt.LPVOID,
                                                 wt.LONG,
                                                 wt.ULONG)


class IEnumWbemClassObject(ct.Structure):
    _fields_ = [('QueryInterface', IUnknown_QueryInterface_Proto),
                ('AddRef', IUnknown_AddRef_Proto),
                ('Release', IUnknown_Release_Proto),
                ('Reset', IEnumWbemClassObject_Reset_Proto),
                ('Next', IEnumWbemClassObject_Next_Proto),
                ('NextAsync', IEnumWbemClassObject_NextAsync_Proto),
                ('Clone', IEnumWbemClassObject_Clone_Proto),
                ('Skip', IEnumWbemClassObject_Skip_Proto)]


#       virtual HRESULT STDMETHODCALLTYPE OpenNamespace(
#           /* [in] */ __RPC__in const BSTR strNamespace,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemServices **ppWorkingNamespace,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE CancelAsyncCall(
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pSink) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE QueryObjectSink(
#           /* [in] */ long lFlags,
#           /* [out] */ __RPC__deref_out_opt IWbemObjectSink **ppResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE GetObject(
#           /* [in] */ __RPC__in const BSTR strObjectPath,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemClassObject **ppObject,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppCallResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE GetObjectAsync(
#           /* [in] */ __RPC__in const BSTR strObjectPath,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE PutClass(
#           /* [in] */ __RPC__in_opt IWbemClassObject *pObject,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppCallResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE PutClassAsync(
#           /* [in] */ __RPC__in_opt IWbemClassObject *pObject,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE DeleteClass(
#           /* [in] */ __RPC__in const BSTR strClass,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppCallResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE DeleteClassAsync(
#           /* [in] */ __RPC__in const BSTR strClass,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE CreateClassEnum(
#           /* [in] */ __RPC__in const BSTR strSuperclass,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [out] */ __RPC__deref_out_opt IEnumWbemClassObject **ppEnum) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE CreateClassEnumAsync(
#           /* [in] */ __RPC__in const BSTR strSuperclass,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE PutInstance(
#           /* [in] */ __RPC__in_opt IWbemClassObject *pInst,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppCallResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE PutInstanceAsync(
#           /* [in] */ __RPC__in_opt IWbemClassObject *pInst,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE DeleteInstance(
#           /* [in] */ __RPC__in const BSTR strObjectPath,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppCallResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE DeleteInstanceAsync(
#           /* [in] */ __RPC__in const BSTR strObjectPath,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE CreateInstanceEnum(
#           /* [in] */ __RPC__in const BSTR strFilter,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [out] */ __RPC__deref_out_opt IEnumWbemClassObject **ppEnum) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE CreateInstanceEnumAsync(
#           /* [in] */ __RPC__in const BSTR strFilter,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE ExecQuery(
#           /* [in] */ __RPC__in const BSTR strQueryLanguage,
#           /* [in] */ __RPC__in const BSTR strQuery,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [out] */ __RPC__deref_out_opt IEnumWbemClassObject **ppEnum) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE ExecQueryAsync(
#           /* [in] */ __RPC__in const BSTR strQueryLanguage,
#           /* [in] */ __RPC__in const BSTR strQuery,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE ExecNotificationQuery(
#           /* [in] */ __RPC__in const BSTR strQueryLanguage,
#           /* [in] */ __RPC__in const BSTR strQuery,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [out] */ __RPC__deref_out_opt IEnumWbemClassObject **ppEnum) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE ExecNotificationQueryAsync(
#           /* [in] */ __RPC__in const BSTR strQueryLanguage,
#           /* [in] */ __RPC__in const BSTR strQuery,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE ExecMethod(
#           /* [in] */ __RPC__in const BSTR strObjectPath,
#           /* [in] */ __RPC__in const BSTR strMethodName,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemClassObject *pInParams,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemClassObject **ppOutParams,
#           /* [unique][in][out] */ __RPC__deref_opt_inout_opt IWbemCallResult **ppCallResult) = 0;
#
#       virtual HRESULT STDMETHODCALLTYPE ExecMethodAsync(
#           /* [in] */ __RPC__in const BSTR strObjectPath,
#           /* [in] */ __RPC__in const BSTR strMethodName,
#           /* [in] */ long lFlags,
#           /* [in] */ __RPC__in_opt IWbemContext *pCtx,
#           /* [in] */ __RPC__in_opt IWbemClassObject *pInParams,
#           /* [in] */ __RPC__in_opt IWbemObjectSink *pResponseHandler) = 0;


IWbemServices_ExecQuery_Proto = ct.WINFUNCTYPE(HRESULT,
                                               wt.LPVOID,
                                               wt.LPCOLESTR,
                                               wt.LPCOLESTR,
                                               wt.LONG,
                                               wt.LPVOID,
                                               ct.POINTER(wt.LPVOID))


class IWbemServices(ct.Structure):
    _fields_ = [('QueryInterface', IUnknown_QueryInterface_Proto),
                ('AddRef', IUnknown_AddRef_Proto),
                ('Release', IUnknown_Release_Proto),
                ('OpenNamespace', Generic_Proto),
                ('CancelAsyncCall', Generic_Proto),
                ('QueryObjectSink', Generic_Proto),
                ('GetObject', Generic_Proto),
                ('GetObjectAsync', Generic_Proto),
                ('PutClass', Generic_Proto),
                ('PutClassAsync', Generic_Proto),
                ('DeleteClass', Generic_Proto),
                ('DeleteClassAsync', Generic_Proto),
                ('CreateClassEnum', Generic_Proto),
                ('CreateClassEnumAsync', Generic_Proto),
                ('PutInstance', Generic_Proto),
                ('PutInstanceAsync', Generic_Proto),
                ('DeleteInstance', Generic_Proto),
                ('DeleteInstanceAsync', Generic_Proto),
                ('CreateInstanceEnum', Generic_Proto),
                ('CreateInstanceEnumAsync', Generic_Proto),
                ('ExecQuery', IWbemServices_ExecQuery_Proto),
                ('ExecQueryAsync', Generic_Proto),
                ('ExecNotificationQuery', Generic_Proto),
                ('ExecNotificationQueryAsync', Generic_Proto),
                ('ExecMethod', Generic_Proto),
                ('ExecMethodAsync', Generic_Proto)]


#       HRESULT ( STDMETHODCALLTYPE *ConnectServer )(
#           IWbemLocator * This,
#           /* [in] */ const BSTR strNetworkResource,
#           /* [in] */ const BSTR strUser,
#           /* [in] */ const BSTR strPassword,
#           /* [in] */ const BSTR strLocale,
#           /* [in] */ long lSecurityFlags,
#           /* [in] */ const BSTR strAuthority,
#           /* [in] */ IWbemContext *pCtx,
#           /* [out] */ IWbemServices **ppNamespace);


IWbemLocator_ConnectServer_Proto = ct.WINFUNCTYPE(HRESULT,
                                                  wt.LPVOID,
                                                  wt.LPCOLESTR,
                                                  wt.LPCOLESTR,
                                                  wt.LPCOLESTR,
                                                  wt.LPCOLESTR,
                                                  wt.LONG,
                                                  wt.LPCOLESTR,
                                                  wt.LPVOID,
                                                  ct.POINTER(wt.LPVOID))


class IWbemLocator(ct.Structure):
    _fields_ = [('QueryInterface', IUnknown_QueryInterface_Proto),
                ('AddRef', IUnknown_AddRef_Proto),
                ('Release', IUnknown_Release_Proto),
                ('ConnectServer', IWbemLocator_ConnectServer_Proto)]


class WMIException(Exception):
    """
    Raise for an WMI exception
    """


class WMI:
    '''
    Wrapper class for WMI interactions. WMI initialization / uninitialization are done via ctxmgr

    N.B. If using this class, do not call init() and fini() directly. Only use through via ctxmgr
    '''
    def __init__(self):
        self.locator = None
        self.svc = None
        self.text = 0
        self.connected = False
        self.com = com.COM()

    def __enter__(self):
        self.init()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fini()

    def init(self):

        self.com.init()

        self.com.init_security(
            None,
            -1,
            None,
            rpc.RPC_C_AUTHN_LEVEL_DEFAULT,
            rpc.RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            ole.EOAC_NONE)

        ptr = self.com.create_instance(
            CLSID_WbemLocator,
            com.CLSCTX_INPROC_SERVER,
            IID_IWbemLocator)

        self.locator = com.ComClassInstance(
            ptr,
            ct.cast(ct.cast(ptr, ct.POINTER(ct.c_void_p)).contents, ct.POINTER(IWbemLocator)).contents)

    def fini(self):
        if self.svc is not None:
            self.svc.vtbl.Release(self.svc.this)

        if self.locator is not None:
            self.locator.vtbl.Release(self.locator.this)

        self.com.fini()

    def connect(self, namespace):
        ptr = ct.c_void_p(0)
        result = self.locator.vtbl.ConnectServer(
            self.locator.this,
            ct.c_wchar_p(namespace),
            None,
            None,
            None,
            0,
            None,
            None,
            ct.byref(ptr))
        if result != tdh.ERROR_SUCCESS:
            raise ct.WinError()

        self.com.set_proxy_blanket(
            ptr,
            rpc.RPC_C_AUTHN_WINNT,
            rpc.RPC_C_AUTHZ_NONE,
            None,
            rpc.RPC_C_AUTHN_LEVEL_CALL,
            rpc.RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            ole.EOAC_NONE)

        self.svc = com.ComClassInstance(
            ptr,
            ct.cast(ct.cast(ptr, ct.POINTER(ct.c_void_p)).contents, ct.POINTER(IWbemServices)).contents)
        self.connected = True

    def do_query(self, query, query_type='WQL'):
        if self.connected is False:
            # log error
            raise WMIException('WMI is not connected')

        ptr = ct.c_void_p(0)
        result = self.svc.vtbl.ExecQuery(
            self.svc.this,
            ct.c_wchar_p(query_type),
            ct.c_wchar_p(query),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
            ct.byref(ptr))
        if result != tdh.ERROR_SUCCESS:
            raise ct.WinError()

        return com.ComClassInstance(
            ptr,
            ct.cast(ct.cast(ptr, ct.POINTER(ct.c_void_p)).contents, ct.POINTER(IEnumWbemClassObject)).contents)
