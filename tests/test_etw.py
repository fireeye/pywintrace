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

from etw import ETW, ProviderInfo
from etw.etw import TraceProperties, ProviderParameters, EventConsumer
from etw.GUID import GUID
from etw import evntrace as et
from etw import evntprov as ep
from etw.etw import get_keywords_bitmask
from .helpers import wininet as wi
from etw import common


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

    def test_etw_capture_multi_providers(self):
        """
        Tests the etw capture class using multiple providers

        :return: None
        """

        # Instantiate an ETW object
        providers = [ProviderInfo('Microsoft-Windows-WinINet',
                                  GUID("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}")),
                     ProviderInfo('Microsoft-Windows-Kernel-Process',
                                  GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"))]

        capture = ETW(providers=providers,
                      event_callback=lambda event_tufo: self.event_tufo_list.append(event_tufo))

        capture.start()

        # start ping
        args = ['ping.exe']
        p = sp.Popen(args, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(5)
        p.kill()

        self.makeRequest()

        # Stop the ETW instance
        capture.stop()

        # check for process start
        event = self.find_event('PROCESSSTART')
        self.assertTrue(event)
        event = self.trim_fields(event)

        # This event should have 6 fields
        self.assertEqual(len(event), 6)

        event = self.find_event('WININET_READDATA')
        self.assertTrue(event)
        event = self.trim_fields(event)

        # This event should have 3 fields
        self.assertEqual(len(event), 3)

        self.event_tufo = []

        return

    def test_etw_multi_providers_bitmask(self):
        """
        Tests the etw capture class using multiple providers

        :return: None
        """

        # Instantiate an ProviderInfo object
        provider = ProviderInfo('Microsoft-Windows-Kernel-Process',
                                GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),
                                any_keywords=['WINEVENT_KEYWORD_PROCESS'],
                                all_keywords=['WINEVENT_KEYWORD_THREAD'])

        assert(provider.any_bitmask == 0x0000000000000010)
        assert(provider.all_bitmask == 0x0000000000000020)

        # add provider
        provider = ProviderInfo('Microsoft-Windows-WinINet',
                                GUID("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}"),
                                any_keywords=['WININET_KEYWORD_HANDLES'],
                                all_keywords=['WININET_KEYWORD_HTTP'])

        assert(provider.any_bitmask == 0x0000000000000001)
        assert(provider.all_bitmask == 0x0000000000000002)

        return

    def test_etw_get_keywords_bitmask(self):
        """
        Tests to ensure the correct bitmask is found for the provider (Windows Kernel Trace)

        :return: None
        """

        assert(get_keywords_bitmask(
            GUID('{9E814AAD-3204-11D2-9A82-006008A86939}'),
            ['process']) == 0x0000000000000001)

        return

    def test_etw_nt_logger(self):
        """
        Tests to ensure nt kernel logger capture works properly

        :return: None
        """

        capture = ETW(session_name='NT Kernel Logger',
                      providers=[ProviderInfo('Windows Kernel Trace',
                                              GUID("{9E814AAD-3204-11D2-9A82-006008A86939}"),
                                              any_keywords=['process'])],
                      event_callback=lambda event_tufo: self.event_tufo_list.append(event_tufo))
        capture.start()

        # start ping.exe
        args = ['ping.exe']
        p = sp.Popen(args, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        time.sleep(2)
        p.kill()
        capture.stop()

        event = self.find_event('PROCESS')
        self.assertTrue(event)
        event = self.trim_fields(event)

        # This event should have 10 fields
        self.assertEqual(len(event), 10)
        self.event_tufo = []
        return

    def test_etw_eq(self):
        """
        Test container classes comparision

        :return: None
        """

        params = et.ENABLE_TRACE_PARAMETERS()
        params.Version = 1
        other_params = et.ENABLE_TRACE_PARAMETERS()
        other_params.Version = 1

        provider = ProviderInfo('Microsoft-Windows-Kernel-Process',
                                GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),
                                any_keywords=['WINEVENT_KEYWORD_PROCESS'],
                                params=ct.pointer(params))

        other_provider = ProviderInfo('Microsoft-Windows-Kernel-Process',
                                      GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"),
                                      any_keywords=['WINEVENT_KEYWORD_PROCESS'],
                                      params=ct.pointer(other_params))
        self.assertEqual(provider, other_provider)
        other_params.Version = 2
        self.assertNotEqual(provider, other_provider)
        event_id_list = [54]
        event_filter = ep.EVENT_FILTER_EVENT_ID(common.TRUE, event_id_list).get()
        event_filters = [ep.EVENT_FILTER_DESCRIPTOR(ct.addressof(event_filter.contents),
                                                    ct.sizeof(event_filter.contents) +
                                                    ct.sizeof(wt.USHORT) * len(event_id_list),
                                                    ep.EVENT_FILTER_TYPE_EVENT_ID)]
        properties = ProviderParameters(0, event_filters)
        other_properties = ProviderParameters(0, event_filters)
        self.assertEqual(properties, other_properties)

        other_properties.get().contents.Version = 1
        self.assertNotEqual(properties, other_properties)

        params = TraceProperties(1024, 1024, 0, 10)
        other_params = TraceProperties(1024, 1024, 0, 10)
        self.assertEqual(params, other_params)
        other_params.get().contents.BufferSize = 1025

        self.assertNotEqual(params, other_params)

        return

    def test_callback_flag_good(self):
        """
        Test to check good flag value

        :return: None
        """
        self.assertNotEqual(EventConsumer('test', None, None, None, common.RETURN_RAW_DATA_ONLY), None)
        self.assertNotEqual(EventConsumer('test', None, None, None, common.RETURN_RAW_DATA_ON_ERROR), None)
        self.assertNotEqual(EventConsumer('test', None, None, None, common.RETURN_ONLY_RAW_DATA_ON_ERROR), None)
        self.assertNotEqual(EventConsumer('test', None, None, None, common.RETURN_RAW_UNFORMATTED_DATA), None)

    def test_callback_flag_bad(self):
        """
        Test to check bad flag value

        :return: None
        """
        consumer = None
        try:
            consumer = EventConsumer('test', None, None, None, 1234)
        except:
            pass
        self.assertEqual(consumer, None)


if __name__ == '__main__':
    unittest.main()
