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

import unittest
import ctypes as ct

from etw import com
from etw import rpc
from etw import ole
from etw import wmi
from etw import tdh


class TestCOM(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.instance = com.COM()
        cls.instance.init()

        cls.instance.init_security(
            None,
            -1,
            None,
            rpc.RPC_C_AUTHN_LEVEL_DEFAULT,
            rpc.RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            ole.EOAC_NONE)

    @classmethod
    def tearDownClass(cls):
        cls.instance.fini()

    def test_create_instance(self):
        """
        Tests the ability to create a COM object instance

        :return: None
        """

        obj = self.instance.create_instance(
            wmi.CLSID_WbemLocator,
            com.CLSCTX_INPROC_SERVER,
            wmi.IID_IWbemLocator)

        obj = com.ComClassInstance(
            obj,
            ct.cast(ct.cast(obj, ct.POINTER(ct.c_void_p)).contents, ct.POINTER(wmi.IWbemLocator)).contents)
        assert(obj is not None)

        assert(obj.vtbl.Release(obj.this) == tdh.ERROR_SUCCESS)
        return

    def test_set_proxy_blanket(self):
        """
        Tests the ability to set security on object

        :return: None
        """

        locator = self.instance.create_instance(
            wmi.CLSID_WbemLocator,
            com.CLSCTX_INPROC_SERVER,
            wmi.IID_IWbemLocator)

        assert(locator is not None)
        locator = com.ComClassInstance(
            locator,
            ct.cast(ct.cast(locator, ct.POINTER(ct.c_void_p)).contents, ct.POINTER(wmi.IWbemLocator)).contents)

        obj = ct.c_void_p(0)
        result = locator.vtbl.ConnectServer(
            locator.this,
            ct.c_wchar_p('root\\CIMV2'),
            None,
            None,
            None,
            0,
            None,
            None,
            ct.byref(obj))
        assert(result == tdh.ERROR_SUCCESS)

        self.instance.set_proxy_blanket(
            obj,
            rpc.RPC_C_AUTHN_WINNT,
            rpc.RPC_C_AUTHZ_NONE,
            None,
            rpc.RPC_C_AUTHN_LEVEL_CALL,
            rpc.RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            ole.EOAC_NONE)

        obj = com.ComClassInstance(
            obj,
            ct.cast(ct.cast(obj, ct.POINTER(ct.c_void_p)).contents, ct.POINTER(wmi.IWbemServices)).contents)

        assert (obj.vtbl.Release(obj.this) == tdh.ERROR_SUCCESS)
        return


if __name__ == '__main__':
    unittest.main()
