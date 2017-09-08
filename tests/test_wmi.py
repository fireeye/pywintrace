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

from etw import wmi
from etw import tdh


class TestWMI(unittest.TestCase):

    @classmethod
    def setUp(cls):
        cls.wmi_instance = wmi.WMI()
        cls.wmi_instance.init()

    @classmethod
    def tearDown(cls):
        cls.wmi_instance.fini()

    def test_wmi_connect(self):
        """
        Tests connecting to wmi

        :return: None
        """
        self.wmi_instance.connect('root\\cimv2')
        return

    def test_wmi_do_query(self):
        """
        Tests performing a wmi query

        :return: None
        """

        self.wmi_instance.connect('root\\cimv2')
        enum = self.wmi_instance.do_query('SELECT * FROM Win32_Process')
        assert(enum is not None)
        assert(enum.vtbl.Release(enum.this) == tdh.ERROR_SUCCESS)

        return


if __name__ == '__main__':
    unittest.main()
