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

from etw import ETW
from etw.GUID import GUID
from etw import common
from etw import evntrace as et


class RDPETW(ETW):

    def __init__(
            self,
            ring_buf_size=1024,
            max_str_len=1024,
            min_buffers=0,
            max_buffers=0,
            level=et.TRACE_LEVEL_INFORMATION,
            any_keywords=None,
            all_keywords=None):
        """
        Initializes an instance of RDPETW. The default parameters represent a very typical use case and should not be
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
        """

        guid = {'Microsoft-Windows-TerminalServices-RemoteConnectionManager':
                GUID("{C76BAA63-AE81-421C-B425-340B4B24157F}")}

        super().__init__(
            guid,
            ring_buf_size,
            max_str_len,
            min_buffers,
            max_buffers,
            level,
            any_keywords,
            all_keywords)

        self.add_provider(
            {'Microsoft-Windows-TerminalServices-LocalSessionManager':
             GUID("{5D896912-022D-40AA-A3A8-4FA5515C76D7}")},
            any_keywords,
            all_keywords)

    def start(self, event_callback=None, task_name_filters=None, ignore_exists_error=True):
        """
        Starts the providers and the consumers for capturing data using ETW by calling parent class start(). Also
        enables script block logging if not enabled already.

        :param event_callback: An optional parameter allowing the caller to specify a callback function for each event
                               that is parsed.
        :param task_name_filters: List of filters to apply to the ETW capture
        :param ignore_exists_error: If true (default), the library will ignore an ERROR_ALREADY_EXISTS on
                                    the EventProvider start.
        :return: Does not return anything.
        """

        super().start(event_callback, task_name_filters, ignore_exists_error)

    def stop(self):
        """
        Stops the current consumers and providers by calling parent class stop(). Also disables script block logging
        if it was enabled.

        :return: Does not return anything.
        """
        super().stop()


def main(args):
    """
    Main function of script. Creates object based on input parameters and calls common main.

    :param args: a dict of all args.
    :return: Does not return anything.
    """
    # Create an RDPETW instance with the parameters provided.
    job = RDPETW(
        args['ring_buffer_size'],
        args['max_str_len'],
        args['min_buffers'],
        args['max_buffers'],
        args['level'],
        args['any_keywords'],
        args['all_keywords'])

    if args['default_filters'] is True:
        filters = ['MICROSOFT-WINDOWS-TERMINALSERVICES-REMOTECONNECTIONMANAGER',
                   'SESSIONARBITRATION',
                   'NOTIFYLOGONTOLICENSING']
    else:
        filters = args['filters']

    common.run('rdp_etw', job, filters, args['logfile'], args['no_conout'])


if __name__ == '__main__':
    main(common.parse_base_args(common.set_base_args('RDP')))
