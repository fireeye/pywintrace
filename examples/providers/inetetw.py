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

from etw import ETW, ProviderInfo
from etw.GUID import GUID
from etw import common
from etw import evntrace as et


class INETETW(ETW):

    def __init__(
            self,
            ring_buf_size=1024,
            max_str_len=1024,
            min_buffers=0,
            max_buffers=0,
            level=et.TRACE_LEVEL_INFORMATION,
            any_keywords=None,
            all_keywords=None,
            filters=None,
            event_callback=None,
            logfile=None,
            no_conout=False):
        """
        Initializes an instance of INETETW. The default parameters represent a very typical use case and should not be
        overridden unless the user knows what they are doing.

        :param ring_buf_size: The size of the ring buffer used for capturing events.
        :param max_str_len: The maximum length of the strings the proceed the structure.
                            Unless you know what you are doing, do not modify this value.
        :param min_buffers: The minimum number of buffers for an event tracing session.
                            Unless you know what you are doing, do not modify this value.
        :param max_buffers: The maximum number of buffers for an event tracing session.
                            Unless you know what you are doing, do not modify this value.
        :param level: Logging level
        :param any_keywords: List of keywords to match
        :param all_keywords: List of keywords that all must match
        :param filters: List of filters to apply to capture.
        :param event_callback: Callback for processing events
        :param logfile: Path to logfile.
        :param no_conout: If true does not output live capture to console.
        """

        self.logfile = logfile
        self.no_conout = no_conout
        if event_callback:
            self.event_callback = event_callback
        else:
            self.event_callback = self.on_event

        providers = [ProviderInfo('Microsoft-Windows-WinINet',
                                  GUID("{43D1A55C-76D6-4F7E-995C-64C711E5CAFE}"),
                                  level,
                                  any_keywords,
                                  all_keywords),
                     ProviderInfo('Microsoft-Windows-WinINet-Capture',
                                  GUID("{A70FF94F-570B-4979-BA5C-E59C9FEAB61B}"),
                                  level,
                                  any_keywords,
                                  all_keywords)]

        super().__init__(
            ring_buf_size=ring_buf_size,
            max_str_len=max_str_len,
            min_buffers=min_buffers,
            max_buffers=max_buffers,
            event_callback=self.event_callback,
            task_name_filters=filters,
            providers=providers)

    def on_event(self, event_tufo):
        '''
        Callback for ETW events

        :param event_tufo: tufo containing event information
        :return: Does not return anything
        '''

        common.on_event_callback(event_tufo, self.logfile, self.no_conout)


def main(args):
    """
    Main function of script. Creates object based on input parameters and calls common main.

    :param args: a dict of all args.
    :return: Does not return anything.
    """

    if args['default_filters'] is True:
        args['filters'] = ['WININET_USAGELOGREQUEST',
                           'WININET_CONNECT_HANDLE_CREATED',
                           'WININET_DNS_QUERYSTART',
                           'WININET_HTTP_REQUEST_HANDLE_CREATED',
                           'WININET_HTTPS_CLIENT_CERT_SELECTED',
                           'WININET_HTTPS_SERVER_CERT_VALIDATED',
                           'WININET_OPEN_URL_HANDLE_CREATED',
                           'WININET_ROOT_HANDLE_CREATED',
                           'WININET_TCP_CONNECTIONSTART']
    args.pop('default_filters')

    # Create an INETETW instance with the parameters provided.
    with INETETW(**args):
        # call common run function to handle command line inout / output
        common.run('wininet_etw', args['filters'])


if __name__ == '__main__':
    main(common.parse_base_args(common.set_base_args('WinInet')))
