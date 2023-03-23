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

import time
import unittest
import subprocess as sp

from examples.providers import procetw


class TestPROCETW(unittest.TestCase):

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

        # Instantiate an PROCETW object
        capture = procetw.PROCETW(event_callback=lambda event_tufo: cls.event_tufo_list.append(event_tufo),
                                  any_keywords=['WINEVENT_KEYWORD_PROCESS', 'WINEVENT_KEYWORD_THREAD'])
        capture.start()

        # start notepad
        args = ['notepad.exe']
        p = sp.Popen(args, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(5)
        p.kill()
        time.sleep(5)

        # Stop the PROCETW instance
        capture.stop()

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

    def test_thread_start(self):
        """
        Test a THREADSTART event.

        :return: None
        """

        event = self.find_event('THREADSTART')
        self.assertTrue(event)
        event = self.trim_fields(event)

        keys = event.keys()

        # This event should have 11 field
        self.assertEqual(len(event), 11)

        self.assertIn('ProcessID', keys)
        self.assertIn('StackBase', keys)
        self.assertIn('StackLimit', keys)
        self.assertIn('StartAddr', keys)
        self.assertIn('SubProcessTag', keys)
        self.assertIn('TebBase', keys)
        self.assertIn('ThreadID', keys)
        self.assertIn('UserStackBase', keys)
        self.assertIn('UserStackLimit', keys)
        self.assertIn('Win32StartAddr', keys)

        return

    def test_thread_stop(self):
        """
        Test a THREADSTOP event.

        :return: None
        """

        event = self.find_event('THREADSTOP')
        self.assertTrue(event)
        event = self.trim_fields(event)

        keys = event.keys()

        # This event should have 12 fields
        self.assertEqual(len(event), 12)

        self.assertIn('ProcessID', keys)
        self.assertIn('StackBase', keys)
        self.assertIn('StackLimit', keys)
        self.assertIn('StartAddr', keys)
        self.assertIn('SubProcessTag', keys)
        self.assertIn('TebBase', keys)
        self.assertIn('ThreadID', keys)
        self.assertIn('UserStackBase', keys)
        self.assertIn('UserStackLimit', keys)
        self.assertIn('Win32StartAddr', keys)

        return

    def test_process_start(self):
        """
        Test a PROCESSSTART event.

        :return: None
        """

        event = self.find_event('PROCESSSTART')
        self.assertTrue(event)
        event = self.trim_fields(event)

        keys = event.keys()

        # This event should have 6 fields
        self.assertGreaterEqual(len(event), 6)

        self.assertIn('ImageName', keys)
        self.assertIn('ParentProcessID', keys)
        self.assertIn('ProcessID', keys)
        self.assertIn('SessionID', keys)

        return

    def test_process_stop(self):
        """
        Test a PROCESSSTOP event.

        :return: None
        """

        event = self.find_event('PROCESSSTOP')
        self.assertTrue(event)
        event = self.trim_fields(event)

        keys = event.keys()

        # This event should have 16 fields
        self.assertGreaterEqual(len(event), 16)

        self.assertIn('ExitCode', keys)
        self.assertIn('ExitTime', keys)
        self.assertIn('HandleCount', keys)
        self.assertIn('HardFaultCount', keys)
        self.assertIn('ImageName', keys)
        self.assertIn('ProcessID', keys)
        self.assertIn('ReadOperationCount', keys)
        self.assertIn('ReadTransferKiloBytes', keys)
        self.assertIn('TokenElevationType', keys)
        self.assertIn('WriteOperationCount', keys)
        self.assertIn('WriteTransferKiloBytes', keys)

        return


if __name__ == '__main__':
    unittest.main()
