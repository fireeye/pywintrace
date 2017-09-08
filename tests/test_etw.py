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
import time
import subprocess as sp

from etw import etw
from etw.GUID import GUID
from etw import wmi


class TestETW(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Prior to running each of our tests, we should start the ETW code, create and delete a share, and capture the
        subsequent response.

        :return: None
        """

        # Instantiate our list where all of the results will be stored
        cls.event_tufo_list = list()
        cls.context_fields = {'Description', 'Task Name'}

        args = ['powershell.exe', '$PSVersionTable.PSVersion']
        p = sp.Popen(args, stdout=sp.PIPE, stderr=sp.DEVNULL)
        out, _ = p.communicate()

        cls.skip_tests = False
        version = int(out.decode('utf-8').split('\n')[3].split(' ')[0].strip())
        if version < 3:
            cls.skip_tests = True

        return

    def find_event(self, name):
        """
        Retrieves an event from the event_tufo_list  with the user's specified name. While the event
        itself is a TuFo, we only return the dictionary portion since the name is only needed during the search.

        :param name: The name of the event we want to find.
        :return: An event matching the name specified or None if no events match.
        """
        return next((tufo[1] for tufo in self.event_tufo_list if tufo[1]['Task Name'] == name), None)

    def find_all_events(self, name):
        """
        Retrieves all events matching the user's specified name from the event_tufo list. While the events themselves
        are TuFos, we only return the dictionary portion since the name is only needed during the search.

        :param name: The name of the events we want to find
        :return: A list of all events matching the name. If no events are found, an empty list is returned.
        """
        return [tufo[1] for tufo in self.event_tufo_list if tufo[1]['Task Name'] == name]

    def trim_fields(self, event):
        """
        We add additional fields for contextual information. In order to accurately test that we are parsing
        the correct fields as reported by the event, we need to trim these off.

        :return: A copy of the event without the contextual fields
        """
        return {key: event[key] for key in event.keys() if key not in self.context_fields}

    def test_etw_capture(self):
        """
        Tests the etw capture

        :return: None
        """

        if self.skip_tests:
            self.skipTest('PowerShell version must be greater than 2')

        # Instantiate an ETW object
        capture = etw.ETW({'Microsoft-Windows-PowerShell': GUID("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}")})
        capture.start(lambda event_tufo: self.event_tufo_list.append(event_tufo), None)

        # start powershell
        args = ['powershell']
        p = sp.Popen(args, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(5)
        p.kill()

        # Stop the ETW instance
        capture.stop()
        event = self.find_event('POWERSHELL CONSOLE STARTUP')
        self.assertTrue(event)
        event = self.trim_fields(event)

        # This event should have 1 field
        self.assertEqual(len(event), 1)
        self.event_tufo = []

        return

    def test_etw_capture_multi_providers(self):
        """
        Tests the etw capture class using multiple providers

        :return: None
        """

        if self.skip_tests:
            self.skipTest('PowerShell version must be greater than 2')

        # Instantiate an ETW object
        capture = etw.ETW({'Microsoft-Windows-PowerShell': GUID("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}")})

        # add provider
        capture.add_provider({'Microsoft-Windows-WMI-Activity': GUID("{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}")})

        capture.start(lambda event_tufo: self.event_tufo_list.append(event_tufo), None)

        # start powershell
        args = ['powershell']
        p = sp.Popen(args, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(5)
        p.kill()

        # do wmi query
        w = wmi.WMI()
        w.init()
        w.connect('root\\cimv2')
        enum = w.do_query('SELECT * FROM Win32_Process')
        enum.vtbl.Release(enum.this)
        w.fini()

        # Stop the ETW instance
        capture.stop()

        # check for powershell capture
        event = self.find_event('POWERSHELL CONSOLE STARTUP')
        self.assertTrue(event)
        event = self.trim_fields(event)

        # This event should have 1 field
        self.assertEqual(len(event), 1)

        # check capture
        events = self.find_all_events('MICROSOFT-WINDOWS-WMI-ACTIVITY')
        found = False
        for event in events:
            try:
                if 'SELECT * FROM Win32_Process' in str(event['Operation']):
                    found = True
                    break
            except:
                pass

        self.assertTrue(found)
        self.event_tufo = []

        return

    def test_etw_multi_providers_bitmask(self):
        """
        Tests the etw capture class using multiple providers

        :return: None
        """

        # Instantiate an ETW object
        capture = etw.ETW(
            {'Microsoft-Windows-PowerShell': GUID("{A0C1853B-5C40-4B15-8766-3CF1C58F985A}")},
            any_keywords=['Runspace'],
            all_keywords=['Pipeline'])

        assert(capture.guids['Microsoft-Windows-PowerShell'][1] == 0x0000000000000001)
        assert(capture.guids['Microsoft-Windows-PowerShell'][2] == 0x0000000000000002)

        # add provider
        capture.add_provider(
            {'Microsoft-Windows-WMI-Activity': GUID("{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}")},
            any_keywords=['Microsoft-Windows-WMI-Activity/Trace'],
            all_keywords=['Microsoft-Windows-WMI-Activity/Operational'])

        assert(capture.guids['Microsoft-Windows-WMI-Activity'][1] == 0x8000000000000000)
        assert(capture.guids['Microsoft-Windows-WMI-Activity'][2] == 0x4000000000000000)

        return

    def test_etw_get_keywords_bitmask(self):
        """
        Tests to ensure the correct bitmask is found for the provider (Windows Kernel Trace)

        :return: None
        """

        assert(etw.get_keywords_bitmask(
            GUID('{9E814AAD-3204-11D2-9A82-006008A86939}'),
            ['process']) == 0x0000000000000001)

        return


if __name__ == '__main__':
    unittest.main()
