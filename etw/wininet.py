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

import ctypes as ct
import ctypes.wintypes as wt

from etw.common import ULONG_PTR


# Types
HINTERNET = wt.HANDLE
DWORD_PTR = ULONG_PTR
INTERNET_PORT = wt.USHORT

# Definitions
INTERNET_OPEN_TYPE_PRECONFIG = 0
INTERNET_OPEN_TYPE_DIRECT = 1
INTERNET_OPEN_TYPE_PROXY = 3

INTERNET_SERVICE_FTP = 1
INTERNET_SERVICE_GOPHER = 2
INTERNET_SERVICE_HTTP = 3

InternetOpenW = ct.windll.Wininet.InternetOpenW
InternetOpenW.argtypes = [wt.LPCWSTR,
                          wt.DWORD,
                          wt.LPCWSTR,
                          wt.LPCWSTR,
                          wt.DWORD]
InternetOpenW.restype = HINTERNET


InternetConnectW = ct.windll.Wininet.InternetConnectW
InternetConnectW.argtypes = [HINTERNET,
                             wt.LPCWSTR,
                             INTERNET_PORT,
                             wt.LPCWSTR,
                             wt.LPCWSTR,
                             wt.DWORD,
                             wt.DWORD,
                             DWORD_PTR]
InternetConnectW.restype = HINTERNET

HttpOpenRequestW = ct.windll.Wininet.HttpOpenRequestW
HttpOpenRequestW.argtypes = [HINTERNET,
                             wt.LPCWSTR,
                             wt.LPCWSTR,
                             wt.LPCWSTR,
                             wt.LPCWSTR,
                             ct.POINTER(wt.LPCWSTR),
                             wt.DWORD,
                             DWORD_PTR]
HttpOpenRequestW.restype = HINTERNET

HttpSendRequestW = ct.windll.Wininet.HttpSendRequestW
HttpSendRequestW.argtypes = [HINTERNET,
                             wt.LPCWSTR,
                             wt.DWORD,
                             wt.LPVOID,
                             wt.DWORD]
HttpSendRequestW.restype = wt.BOOL

InternetReadFile = ct.windll.Wininet.InternetReadFile
InternetReadFile.argtypes = [HINTERNET,
                             wt.LPVOID,
                             wt.DWORD,
                             wt.LPDWORD]
InternetReadFile.restype = wt.BOOL
