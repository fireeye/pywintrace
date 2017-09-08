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
import ipaddress
import ctypes as ct
import ctypes.wintypes as wt

from etw import wininet as wi
from examples.providers import inetetw
from etw import httpstatus

# Constants
MAX_INT32 = 2**32 - 1
MAX_INT16 = 2**16 - 1
MAX_INT8 = 2**8 - 1


def validate_http_status(status_str):
    """
    Enumerates the possible HTTP status codes and ensures that the supplied
    status is valid.
    """
    if int(status_str, 10) in map(int, httpstatus.HTTPStatus):
        return True

    return False


def validate_verb(verb_str):
    """
    Determines whether or not the supplied verb is a valid HTTP verb.
    """
    valid_verbs = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE']

    if verb_str in valid_verbs:
        return True

    return False


def value_between(value, low, high):
    """
    Determines whether the value is in the acceptable range. low and high are inclusive. This is
    just for convenience and consistency regarding inclusive or exclusive bounds.
    """
    if low > value < high:
        return False

    return True


def validate_ip(ip_str):
    """
    Validates the entire IP Address string by ensuring there are 4 octets and
    that each octet's
    value is between 0 and 255.
    """
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return True


def validate_port(port_str):
    """
    Ensures that we ahve a valid port. In other words, the port number is
    between 0 and 65535.
    This is just for convenience as it simply wraps value_between().
    """
    return value_between(int(port_str, 10), 0, MAX_INT16)


class TestINETETW(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Prior to running each of our tests, we should start the ETW code, issue
        a request, and capture the response.

        :return: None
        """

        # Instantiate our list where all of the results will be stored
        cls.event_tufo_list = []

        # The parameters for the HTTP request
        cls.user_agent = 'TestAgent'
        cls.url = 'www.gmail.com'
        cls.port = 80
        cls.verb = 'GET'
        cls.size = 1337
        cls.context_fields = {'Description', 'Task Name'}

        # Instantiate an INETETW object
        p = inetetw.INETETW()
        p.start(lambda event_tufo: cls.event_tufo_list.append(event_tufo), [])

        # Make a WinINet request and save the actual response.
        cls.wininet_response = cls.makeRequest()

        # Ensure that we have a chance for all the events to come back
        time.sleep(5)

        # Stop capturing the WinINet provider and processing with the consumer.
        p.stop()

    @classmethod
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

    def test_wininet_usagelogrequest(self):
        """
        Test a WinINet_UsageLogRequest event.

        :return: None
        """
        event = self.find_event('WININET_USAGELOGREQUEST')
        self.assertTrue(event)
        event = self.trim_fields(event)

        event_length = len(event)
        keys = event.keys()

        self.assertTrue(value_between(event_length, 6, 24))

        # This target contains exactly 6 fields. Despite this, the RequestHeaders and
        # ResponseHeaders fields can contain an unknown amount of additional fields. So, if we have
        # over 6 fields, we ensure that they are both present.
        if event_length > 6:
            self.assertIn('RequestHeaders', keys)
            self.assertIn('ResponseHeaders', keys)

        # Assert that we captured a request with the verb that we sent.
        self.assertEqual(event['Verb'], self.verb)

        # Assert that we captured a request with user agent we supplied
        if 'User-Agent' in keys:
            self.assertEqual(event['User-Agent'], self.user_agent)

        return

    def test_wininet_readdata(self):
        """
        Test a WinINet_ReadData event.

        :return: None
        """
        event = self.find_event('WININET_READDATA')
        self.assertTrue(event)
        event = self.trim_fields(event)

        keys = event.keys()

        # This target should have 3 fields
        self.assertEqual(len(event), 3)

        # Ensure these are the 2 fields that should be there
        self.assertIn('Request', keys)
        self.assertIn('Size', keys)

        # Values like this appear to be a handle. They should be 32-bits.
        self.assertTrue(value_between(int(event['Request'], 16), 0, MAX_INT32))

        # In testing, 16384 (0x4000) appeared to be the max value for this target
        self.assertTrue(value_between(int(str(event['Size']), 10), 0, 16384))

        return

    def test_wininet_connect(self):
        """
        Test a WinINet_Connect event.

        :return:
        """
        event = self.find_event('WININET_CONNECT')
        self.assertTrue(event)
        event = self.trim_fields(event)

        event_length = len(event)
        keys = event.keys()

        # There appear to be 2 types of WININET_CONNECT targets with 2 and 8 fields respectively.
        self.assertTrue(value_between(event_length, 2, 8))

        if event_length == 2:
            self.assertIn('Request', keys)
            self.assertTrue(value_between(int(event['Request'], 16), 0, MAX_INT32))
            return

        # Ensure that the Socket field exists and is valid.
        self.assertIn('Socket', keys)
        self.assertTrue(validate_port(event['Socket']))

        # Ensure that the Protocol is exists. We don't know how many different protocols are
        # supported in this type of target.
        self.assertIn('Protocol', keys)

        # Validate that LocalAddressLength and LocalAddress both exists. They should not reflect one
        # another. THe length always appears to be 16 regardless of the address itself.
        self.assertIn('LocalAddressLength', keys)
        self.assertIn('LocalAddress', event)

        # Validate that Socket and the port number are the same. Validate the IP address.
        if int(event['LocalAddressLength'], 10) != 0:
            addr, port = event['LocalAddress'].split(':')
            self.assertEqual(port, event['Socket'])
            self.assertTrue(validate_ip(addr))

        # Validate that RemoteAddressLength and RemoteAddress both exist. They should not reflect
        # one another. The length always appears to be 16 regardless of the address itself.
        self.assertIn('RemoteAddressLength', keys)
        self.assertIn('RemoteAddress', keys)

        if int(event['RemoteAddressLength'], 10) != 0:
            addr, port = event['RemoteAddress'].split(':')
            self.assertTrue(validate_ip(addr))
            self.assertTrue(validate_port(port))

        return

    def test_wininet_dns_query(self):
        """
        Test a WinINet_DNS_Query event.

        :return:
        """

        event = self.find_event('WININET_DNS_QUERY')
        self.assertTrue(event)
        event = self.trim_fields(event)

        event_length = len(event)
        keys = event.keys()

        # There are 3 separate instances of WININET_DNS_QUERY targets with 3, 4, and 5 fields
        # respectively.
        self.assertTrue(value_between(event_length, 3, 5))

        # Every type of WININET_DNS_QUERY target has a _HostNameLength, and HostName field.
        # Ensure that they both exist and accurately reflects each other. RFC 1035 states that the
        # maximum length for a hostname is 255 bytes -- ensure that our values are valid.
        self.assertIn('_HostNameLength', keys)
        self.assertIn('HostName', keys)
        self.assertEqual(int(event['_HostNameLength'], 10), len(event['HostName']))
        self.assertTrue(value_between(int(event['_HostNameLength'], 10), 0, MAX_INT8))

        # Every type of WININET_DNS_QUERY has a RequestHandle field. We believe this should be at
        # most 4 bytes.
        self.assertIn('RequestHandle', keys)
        self.assertTrue(value_between(int(event['RequestHandle'], 16), 0, MAX_INT32))

        # The WININET_DNS_QUERY target that has 4 fields, exclusively has the Error field. We do
        # not know what the acceptable values are here.
        if event_length == 5:
            self.assertIn('Error', keys)

        # If the WININET_DNS_QUERY target has 6 fields, the _AddressListLength and AddressList
        # fields must be present. Ensure that they accurately reflect each other and that the
        # address list is a valid IP address.
        if event_length == 6:
            self.assertIn('_AddressListLength', keys)
            self.assertIn('AddressList', keys)
            self.assertEqual(int(event['_AddressListLength'], 10), len(event['AddressList']))

            for address in event['AddressList'].rstrip(';').split(';'):
                self.assertTrue(validate_ip(address))

        return

    def test_wininet_http_response(self):
        event = self.find_event('WININET_HTTP_RESPONSE')
        self.assertTrue(event)
        event = self.trim_fields(event)

        keys = event.keys()

        # There are precisely 8 fields in this structure
        self.assertEqual(len(event), 8)

        # Ensure that the ResponseCode field is present and is a valid code
        self.assertIn('ResponseCode', keys)
        self.assertTrue(validate_http_status(str(event['ResponseCode'])))

        # We believe that the RequestHandle field should be 4 bytes at most.
        self.assertIn('RequestHandle', keys)
        self.assertTrue(value_between(int(event['RequestHandle'], 16), 0, MAX_INT32))

        # We do not know what the acceptable values for the SocketHandle field
        self.assertIn('SocketHandle', keys)

        # Ensure that the Verb length and Verb are present, reflect one another, and are valid.
        self.assertIn('_VerbLength', keys)
        self.assertIn('Verb', keys)
        self.assertEqual(int(event['_VerbLength'], 0), len(event['Verb']))
        self.assertTrue(validate_verb(event['Verb']))

        # Ensure the _ContentLengthStrLength and ContentLength fields are present and that they
        # reflect one another. RFC-2616 does not place a maximum value on ContentLength -- it must
        # simply be >0.
        self.assertIn('_ContentLengthStrLength', keys)
        self.assertIn('ContentLength', keys)
        self.assertEqual(int(event['_ContentLengthStrLength'], 10), len(event['ContentLength']))
        self.assertGreaterEqual(int(event['ContentLength'], 10), 0)

    def test_wininet_capture(self):
        event_list = self.find_all_events('MICROSOFT-WINDOWS-WININET-CAPTURE')
        if not event_list:
            self.skipTest('This OS does not support WININET-CAPTURE')

        for event in event_list:
            event = self.trim_fields(event)
            keys = event.keys()

            # There are 4 fields in the WININET_CAPTURE target or 5 fields if PayloadByteLength is
            # not 0.
            self.assertTrue(value_between(len(event), 4, 5))

            # Ensure that the SessionId, SequenceNumber, and Flags fields are all present.
            self.assertIn('SessionId', keys)
            self.assertIn('SequenceNumber', keys)
            self.assertIn('Flags', keys)

            # Ensure that PayloadByteLength is present. If it is, ensure that Payload is present and
            # that PayloadByteLength is no more than the value specified globally here.
            self.assertIn('PayloadByteLength', keys)

            payload_byte_length = int(event['PayloadByteLength'], 10)
            self.assertLessEqual(payload_byte_length, self.size)

            if payload_byte_length > 0:
                self.assertIn('Payload', keys)


if __name__ == '__main__':
    unittest.main()
