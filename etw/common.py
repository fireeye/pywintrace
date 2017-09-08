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

import os
import argparse
import platform
import winreg
import logging
import ctypes as ct
import ctypes.wintypes as wt

from etw import ntsecapi as nts


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


class LUID(ct.Structure):
    _fields_ = [('LowPart', wt.DWORD),
                ('HighPart', wt.LONG)]


class LUID_AND_ATTRIBUTES(ct.Structure):
    _fields_ = [('Luid', LUID),
                ('Attributes', wt.DWORD)]


class TOKEN_PRIVILEGES(ct.Structure):
    _fields_ = [('PrivilegeCount', wt.DWORD),
                ('Privileges', LUID_AND_ATTRIBUTES * 0)]


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

    parser.add_argument('--ring-buffer-size', default=1024,
                        help='The size of the ring buffer used for capturing events')
    parser.add_argument('--max-str-len', default=1024,
                        help='The maximum length of the strings that proceed the structure')
    parser.add_argument('--min-buffers', default=0,
                        help='The minimum number of buffers for an event tracing session')
    parser.add_argument('--max-buffers', default=0,
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
             'verbose': et.TRACE_LEVEL_VERBOSE}
    parsed_args.level = level[parsed_args.level]

    if parsed_args.default_filters is True and parsed_args.filters is not None:
        raise ETWException('Cannot specify use default filters and set filters')

    if parsed_args.no_conout is True and parsed_args.logfile is None:
        raise ETWException('Either console output or logfile must be specified')

    return vars(parsed_args)


def run(name, job, filters=None, logfile=None, no_conout=False):
    """
     Starts the capture using ETW.

     :param name: Name of the capture class to be displayed to the user.
     :param job: Instance of capture class.
     :param filters: List of filters to apply to capture.
     :param logfile: Path to logfile.
     :param no_conout: If true does not output live capture to console.
     :return: Does not return anything.
    """

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

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

    if logfile is not None and os.path.isfile(logfile) is True:
        os.unlink(logfile)

    def on_event(event_tufo):
        event_id, event = event_tufo
        if no_conout is False:
            logger.info('{:d} ({:s})\n{:s}\n'.format(event_id, event["Task Name"], pprint.pformat(encode(event))))

        if logfile is not None:
            with open(logfile, 'a') as file:
                file.write('{:d} ({:s})\n{:s}\n'.format(event_id, event["Task Name"], pprint.pformat(encode(event))))

    job.start(on_event, filters)
    logger.info('{:s} - Started (filters = {!s:s})'.format(name, filters))

    logger.info('Press ENTER to stop capture')
    input()

    job.stop()
    logger.info('{:s} - Stopped'.format(name))


def is_os_64bit():
    """
     Determines if the current OS is 64 bit.

     :return: Returns true if OS is 64 bit or false if not.
    """
    arch = platform.machine()
    if '64' in arch:
        return True
    return False


def is_process_wow64():
    """
     Determines if the current process is WOW64 or not.

     :return: Returns true if process is WOW64 or or false if not.
    """
    py_arch, _ = platform.architecture()
    if is_os_64bit() and '32' in py_arch:
        return True
    return False


def reg_check_val(key, sub_key, val_name, val_to_check, flags):
    """
    Checks the specified registry value against val_to_check.

    :param key: Registry key. May be winreg.HKEY_* value.
    :param sub_key: Path of the subkey.
    :param val_name: Name of the value to check.
    :param val_to_check: Value to compare to.
    :param flags: Additional access flags.
    :return: Returns True if value exists and matches the input value.
    """

    try:
        key = winreg.OpenKey(key, sub_key, 0, winreg.KEY_READ | winreg.KEY_QUERY_VALUE | flags)
        val, val_type = winreg.QueryValueEx(key, val_name)
        if val != val_to_check:
            return False
    except OSError:
        raise ct.WinError()
    return True


def reg_create_tree(key, sub_key, flags):
    """
    Creates new registry key if key does not exist, or opens key if key exists.

    :param key: Registry key. May be winreg.HKEY_* value.
    :param sub_key: Path of the subkey.
    :param flags: Additional access flags.
    :return: Returns handle to registry if successful.
    """

    # first, try to open full path
    ret_key = None
    try:
        ret_key = winreg.CreateKeyEx(key, sub_key, 0, winreg.KEY_SET_VALUE | flags)
        return ret_key
    except OSError:
        # if this failed we need to create more than one key
        pass

    # if that fails, create path in steps
    path_split = sub_key.split('\\')
    for i in range(len(path_split)):
        try:
            ret_key = winreg.CreateKeyEx(key, '\\'.join(path_split[:i + 1]), 0, winreg.KEY_SET_VALUE | flags)
        except OSError:
            raise ct.WinError()
    return ret_key


def reg_set_value(key, val_name, val_type, data):
    """
    Sets registry value

    :param key: Previously opened registry key.
    :param val_name: Name of the value to write to.
    :param val_type: Type of data to write.
    :param data: Data to write to value.
    :return: Nothing
    """

    try:
        winreg.SetValueEx(key, val_name, 0, val_type, data)
    except OSError:
        raise ct.WinError()


def set_sec_name_priv(enable_priv, priv_name):
    """
    Adjusts the privileges for the current process.

    :param enable_priv: True to enable the privilege or False to disable the privilege
    :param priv_name: The name of the privilege we want to enable/disable
    :return: Nothing
    """
    token = wt.HANDLE()

    # Get the token for our current process
    if FALSE == OpenProcessToken(GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                 ct.byref(token)):
        raise ETWException('set_sec_name_priv:OpenProcessToken failed with error code %d' % ct.GetLastError())

    luid = LUID()

    # Look up the LUID for the given privilege name
    if FALSE == LookupPrivilegeValueW(None, priv_name, ct.byref(luid)):
        CloseHandle(token)
        raise ETWException('set_sec_name_priv:LookupPrivilegeValueW failed with error code %d' % ct.GetLastError())

    # Setup the TOKEN_PRIVILEGES structure to reflect the privileges we want to change
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    privs = ct.cast(tp.Privileges, ct.POINTER(LUID_AND_ATTRIBUTES))
    privs[0].Luid = luid

    if enable_priv:
        privs[0].Attributes = SE_PRIVILEGE_ENABLED
    else:
        privs[0].Attributes = 0

    # Modify the aforementioned privileges
    if FALSE == AdjustTokenPrivileges(token,
                                      FALSE,
                                      ct.byref(tp),
                                      ct.sizeof(TOKEN_PRIVILEGES),
                                      None,
                                      None):
        CloseHandle(token)
        raise ETWException('set_sec_name_priv:AdjustTokenPrivileges failed with error code %d' % ct.GetLastError())

    # Always need to close the handle
    if FALSE == CloseHandle(token):
        raise ETWException(
            'set_sec_name_priv:CloseHandle failed to close handle with error code %d' % ct.GetLastError())


def set_audit_policy(audit_subcategory_guid, audit_information):
    """
    Modifies the detailed audit policy for a specific subcategory GUID.

    :param audit_subcategory_guid: A GUID representing the subcategory we want to set. Possible GUIDs may be found
                                   in ntsecapi.h.
    :param audit_information: Specify whether we want to audit success, failure, or nothing.
    :return: Nothing
    """
    audit_info = nts.AUDIT_POLICY_INFORMATION()
    audit_info.AuditSubCategoryGuid = audit_subcategory_guid
    audit_info.AuditingInformation = audit_information

    if FALSE == nts.AuditSetSystemPolicy(ct.byref(audit_info), 1):
        raise ETWException('set_audit_policy:AuditSetSystemPolicy failed to set audit policy with error code %d' %
                           ct.GetLastError())


# Function definitions
GetCurrentProcess = ct.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = wt.HANDLE

OpenProcessToken = ct.windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, wt.PHANDLE]
OpenProcessToken.restype = wt.BOOL

LookupPrivilegeValueW = ct.windll.advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = [wt.LPWSTR, wt.LPWSTR, ct.POINTER(LUID)]
LookupPrivilegeValueW.restype = wt.BOOL

AdjustTokenPrivileges = ct.windll.advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [wt.HANDLE,
                                  wt.BOOL,
                                  ct.POINTER(TOKEN_PRIVILEGES),
                                  wt.DWORD,
                                  ct.POINTER(TOKEN_PRIVILEGES),
                                  wt.PDWORD]
AdjustTokenPrivileges.restype = wt.BOOL

CloseHandle = ct.windll.kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL
