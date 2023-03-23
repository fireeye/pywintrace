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
import ctypes as ct
import ctypes.wintypes as wt
import subprocess as sp

from pywintrace import ETW, ProviderInfo
from pywintrace import GUID
from pywintrace import evntrace as et
from pywintrace import evntprov as ep
from .helpers import wininet as wi
from pywintrace import common


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
        cls.user_agent = 'TestAgent'
        cls.url = 'www.gmail.com'
        cls.port = 80
        cls.verb = 'GET'
        cls.size = 1337
        return

    def makeRequest(cls):
        """
        Issue a WININET request based on the class parameters.

        :return: None
        """
        hInternet = wi.InternetOpenW(
            cls.user_agent,
            wi.INTERNET_OPEN_TYPE_DIRECT, None, None, 0)
        if hInternet is None:
            raise ct.WinError()

        hSession = wi.InternetConnectW(hInternet, cls.url, cls.port, None, None, wi.INTERNET_SERVICE_HTTP, 0, 0)
        if hSession is None:
            raise ct.WinError()

        hRequest = wi.HttpOpenRequestW(hSession, cls.verb, '', None, None, None, 0, 0)
        if hRequest is None:
            raise ct.WinError()

        request_sent = wi.HttpSendRequestW(hRequest, None, 0, None, 0)
        if request_sent == 0:
            raise ct.WinError()

        # Setup the necessary parameters to read the server's response
        buff_size = wt.DWORD(cls.size)
        buf = (ct.c_char * buff_size.value)()
        keep_reading = 1
        bytes_read = wt.DWORD(-1)
        response_str = str()

        while keep_reading == 1 and bytes_read.value != 0:
            # Read the entire response.
            keep_reading = wi.InternetReadFile(hRequest, buf, buff_size, ct.byref(bytes_read))
            response_str += str(buf.value)

        return response_str

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

        # Instantiate an ETW object
        capture = ETW(providers=[ProviderInfo('Microsoft-Windows-WinINet',
                                              GUID("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}"))],
                      event_callback=lambda event_tufo: self.event_tufo_list.append(event_tufo))
        capture.start()

        self.makeRequest()

        # Ensure that we have a chance for all the events to come back
        time.sleep(5)

        # Stop the ETW instance
        capture.stop()
        event = self.find_event('WININET_READDATA')
        self.assertTrue(event)
        event = self.trim_fields(event)

        # This event should have 3 fields
        self.assertEqual(len(event), 3)
        self.event_tufo = []

        return


if __name__ == '__main__':
    unittest.main()
