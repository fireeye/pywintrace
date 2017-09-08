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


def cmp(a, b):
    return (a > b) - (a < b)


BYTE = ct.c_byte
WORD = ct.c_ushort
DWORD = ct.c_ulong

_ole32 = ct.oledll.ole32

_StringFromCLSID = _ole32.StringFromCLSID
_CoTaskMemFree = ct.windll.ole32.CoTaskMemFree
_ProgIDFromCLSID = _ole32.ProgIDFromCLSID
_CLSIDFromString = _ole32.CLSIDFromString
_CLSIDFromProgID = _ole32.CLSIDFromProgID
_CoCreateGuid = _ole32.CoCreateGuid


class GUID(ct.Structure):
    _fields_ = [("Data1", DWORD),
                ("Data2", WORD),
                ("Data3", WORD),
                ("Data4", BYTE * 8)]

    def __init__(self, name=None):
        if name is not None:
            _CLSIDFromString(str(name), ct.byref(self))

    def __repr__(self):
        return 'GUID("%s")' % str(self)

    def __str__(self):
        p = ct.c_wchar_p()
        _StringFromCLSID(ct.byref(self), ct.byref(p))
        result = p.value
        _CoTaskMemFree(p)
        return result

    def __cmp__(self, other):
        if isinstance(other, GUID):
            return cmp(bytes(self), bytes(other))
        return -1

    def __nonzero__(self):
        return self != GUID_null

    def __eq__(self, other):
        return isinstance(other, GUID) and bytes(self) == bytes(other)

    def __hash__(self):
        # We make GUID instances hashable, although they are mutable.
        return hash(bytes(self))

    def copy(self):
        return GUID(str(self))

    @classmethod
    def from_progid(cls, progid):
        """Get guid from progid, ...
        """
        if hasattr(progid, "_reg_clsid_"):
            progid = progid._reg_clsid_
        if isinstance(progid, cls):
            return progid
        elif isinstance(progid, ct.basestring):
            if progid.startswith("{"):
                return cls(progid)
            inst = cls()
            _CLSIDFromProgID(str(progid), ct.byref(inst))
            return inst
        else:
            raise TypeError("Cannot construct guid from %r" % progid)

    def as_progid(self):
        "Convert a GUID into a progid"
        progid = ct.c_wchar_p()
        _ProgIDFromCLSID(ct.byref(self), ct.byref(progid))
        result = progid.value
        _CoTaskMemFree(progid)
        return result

    @classmethod
    def create_new(cls):
        "Create a brand new guid"
        guid = cls()
        _CoCreateGuid(ct.byref(guid))
        return guid


GUID_null = GUID()

__all__ = ["GUID"]
