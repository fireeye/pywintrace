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

from etw import common


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


if __name__ == '__main__':
    unittest.main()
