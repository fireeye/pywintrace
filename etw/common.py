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

import argparse
import logging
import ctypes as ct
import ctypes.wintypes as wt


ANYSIZE_ARRAY = 1

RETURN_RAW_DATA_ONLY = 0x1
RETURN_RAW_DATA_ON_ERROR = 0x2
RETURN_ONLY_RAW_DATA_ON_ERROR = 0x4
RETURN_RAW_UNFORMATTED_DATA = 0x8

if ct.sizeof(ct.c_void_p) == 8:
    ULONG_PTR = ct.c_ulonglong
else:
    ULONG_PTR = ct.c_ulong

MAX_UINT = (2 ** 32) - 1

# Defs for Microsoft's BOOL/BOOLEAN type
TRUE = 1
FALSE = 0

# Defs for the privilege functions
SE_PRIVILEGE_ENABLED = 2

# Defs for Token Permissions
TOKEN_ASSIGN_PRIMARY = 0x1
TOKEN_DUPLICATE = 0x2
TOKEN_IMPERSONATE = 0x4
TOKEN_QUERY = 0x8
TOKEN_QUERY_SOURCE = 0x10
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_ADJUST_GROUPS = 0x40
TOKEN_ADJUST_DEFAULT = 0x80
TOKEN_ADJUST_SESSIONID = 0x100

# Defs for WIN32 error codes
ERROR_NOT_ALL_ASSIGNED = 0x514


logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class SYSTEMTIME(ct.Structure):
    _fields_ = [('wYear', wt.WORD),
                ('wMonth', wt.WORD),
                ('wDayOfWeek', wt.WORD),
                ('wDay', wt.WORD),
                ('wHour', wt.WORD),
                ('wMinute', wt.WORD),
                ('wSecond', wt.WORD),
                ('wMilliseconds', wt.WORD)]


class TIME_ZONE_INFORMATION(ct.Structure):
    _fields_ = [('Bias', ct.c_long),
                ('StandardName', ct.c_wchar * 32),
                ('StandardDate', SYSTEMTIME),
                ('StandardBias', ct.c_long),
                ('DaylightName', ct.c_wchar * 32),
                ('DaylightDate', SYSTEMTIME),
                ('DaylightBias', ct.c_long)]


class ETWException(Exception):
    """
    Raise for an ETW exception
    """


def rel_ptr_to_str(base, offset):
    """
    Helper function to convert a relative offset to a string to the actual string.
    """
    return ct.cast(rel_ptr_to_ptr(base, offset), ct.c_wchar_p).value


def rel_ptr_to_ptr(base, offset):
    """
    Helper function to convert a relative offset to a void pointer.
    """
    return ct.cast((ct.cast(base, ct.c_voidp).value + offset), ct.c_voidp)


def convert_bool_str(input_string):
    """
    Helper to convert a string representation of a boolean to a real bool(tm).
    """
    if input_string.lower() in ('1', 'true'):
        return True
    return False


def set_base_args(name):
    """
     Sets base arguments for command line.

     :return: Instance of arg parser after adding base arguments.
    """

    description_format = 'Use ETW (Event Tracing for Windows) to capture {:s} events'.format(name)
    parser = argparse.ArgumentParser(description=description_format)

    parser.add_argument('--ring-buffer-size', dest='ring_buf_size', default=1024, type=int,
                        help='The size of the ring buffer used for capturing events')
    parser.add_argument('--max-str-len', default=1024, type=int,
                        help='The maximum length of the strings that proceed the structure')
    parser.add_argument('--min-buffers', default=0, type=int,
                        help='The minimum number of buffers for an event tracing session')
    parser.add_argument('--max-buffers', default=0, type=int,
                        help='The maximum number of buffers for an event tracing session')
    parser.add_argument('--filters', default=None, nargs='+',
                        help='A whitelist of task_names that we want to handle post-capture')
    parser.add_argument('--logfile', default=None,
                        help='Name of file to store events')
    parser.add_argument('--no-conout', action='store_true',
                        help='Output live capture to console')
    parser.add_argument('--level',
                        default='information',
                        choices=['critical', 'error', 'warning', 'information', 'verbose'],
                        help='Information level of the capture. Options are critical, error, warning,\
                        information(default), and verbose')
    parser.add_argument('--any-keywords', default=None, nargs='+',
                        help='Keywords to filter on pre-capture (can match any)')
    parser.add_argument('--all-keywords', default=None, nargs='+',
                        help='Keywords to filter on pre-capture (must match all)')
    parser.add_argument('--default-filters', action='store_true',
                        help='Apply default set of filters')
    return parser


def parse_base_args(parser):
    """
     parses base arguments

     :return: dict of parsed base args.
    """

    parsed_args = parser.parse_args()

    from etw import evntrace as et

    level = {'critical': et.TRACE_LEVEL_CRITICAL,
             'error': et.TRACE_LEVEL_ERROR,
             'warning': et.TRACE_LEVEL_WARNING,
             'information': et.TRACE_LEVEL_INFORMATION,
             'verbose': et.TRACE_LEVEL_VERBOSE,
             'reserved6': et.TRACE_LEVEL_RESERVED6,
             'reserved7': et.TRACE_LEVEL_RESERVED7,
             'reserved8': et.TRACE_LEVEL_RESERVED8,
             'reserved9': et.TRACE_LEVEL_RESERVED9}
    parsed_args.level = level[parsed_args.level]

    if parsed_args.default_filters is True and parsed_args.filters is not None:
        raise ETWException('Cannot specify use default filters and set filters')

    if parsed_args.no_conout is True and parsed_args.logfile is None:
        raise ETWException('Either console output or logfile must be specified')

    return vars(parsed_args)


def run(name, filters=None):
    """
     Starts the capture using ETW.

     :param name: Name of the capture class to be displayed to the user.
     :param filters: List of filters to apply to capture.
     :return: Does not return anything.
    """

    logger.setLevel(logging.INFO)
    logger.info('{:s} - Started (filters = {!s:s})'.format(name, filters))

    logger.info('Press ENTER to stop capture')
    input()

    logger.info('{:s} - Stopped'.format(name))


def on_event_callback(event_tufo, logfile=None, no_conout=False):
    """
     Starts the capture using ETW.

     :param event_tufo: tufo containing event information
     :param logfile: Path to logfile.
     :param no_conout: If true does not output live capture to console.
     :return: Does not return anything.
    """

    import pprint
    from collections import Mapping, Iterable

    def encode(data, encoding='utf-8'):
        if isinstance(data, str):
            return data.encode(encoding, 'ignore')
        elif isinstance(data, Mapping):
            return dict(map(encode, data.items()))
        elif isinstance(data, Iterable):
            return type(data)(map(encode, data))
        else:
            return data

    event_id, event = event_tufo
    if no_conout is False:
        logger.info('{:d} ({:s})\n{:s}\n'.format(event_id, event["Task Name"], pprint.pformat(encode(event))))

    if logfile is not None:
        with open(logfile, 'a') as file:
            file.write('{:d} ({:s})\n{:s}\n'.format(event_id, event["Task Name"], pprint.pformat(encode(event))))
