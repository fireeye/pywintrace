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
import winreg

from etw import common
from etw import ntsecapi as nts


class TestCOMMON(unittest.TestCase):

    def test_rel_ptr_to_ptr(self):
        """
        Tests conversion of RVA to absolute address

        :return: None
        """

        assert(common.rel_ptr_to_ptr(0x1000, 0x234).value == 0x1234)
        return

    def test_convert_bool_str(self):
        """
        Tests conversion of boolean string to boolean type

        :return: None
        """

        assert(common.convert_bool_str('True') is True)
        return

    def test_args(self):
        """
        Tests setting base arguments

        :return: None
        """
        parser = common.set_base_args('test')
        args = common.parse_base_args(parser)
        assert(len(args) == 11)
        return

    def test_reg_check_val(self):
        """
        Tests checking registry value

        :return: None
        """

        key = common.reg_create_tree(winreg.HKEY_CURRENT_USER, 'TEST', 0)
        assert(key is not None)

        common.reg_set_value(key, 'TEST', winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        assert(common.reg_check_val(winreg.HKEY_CURRENT_USER, 'TEST', 'TEST', 1, 0) is True)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, 'TEST')

        return

    def test_reg_create_tree(self):
        """
        Tests creating registry keys

        :return: None
        """

        key = common.reg_create_tree(winreg.HKEY_CURRENT_USER, 'TEST', 0)
        assert(key is not None)
        winreg.CloseKey(key)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, 'TEST')

        return

    def test_reg_set_value(self):
        """
        Tests setting registry value

        :return: None
        """

        key = common.reg_create_tree(winreg.HKEY_CURRENT_USER, 'TEST', 0)
        assert(key is not None)
        common.reg_set_value(key, 'TEST', winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, 'TEST')

        return

    def test_set_sec_name_priv(self):
        """
        Tests whether we can set privilege or not

        :return: None
        """

        common.set_sec_name_priv(True, 'SeSecurityPrivilege')
        common.set_sec_name_priv(False, 'SeSecurityPrivilege')

        return

    def test_set_set_audit_policy(self):
        """
        Tests whether we can set audit policy or not

        :return: None
        """
        common.set_sec_name_priv(True, 'SeSecurityPrivilege')
        common.set_audit_policy(nts.audit_objectaccess_share, nts.POLICY_AUDIT_EVENT_SUCCESS)
        common.set_audit_policy(nts.audit_objectaccess_share, nts.POLICY_AUDIT_EVENT_NONE)
        common.set_sec_name_priv(False, 'SeSecurityPrivilege')

        return


if __name__ == '__main__':
    unittest.main()
