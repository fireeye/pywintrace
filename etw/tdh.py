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

from etw.common import convert_bool_str
from etw.GUID import GUID
from etw import evntcons as ec
from etw import evntprov as ep

ERROR_SUCCESS = 0x0
ERROR_INSUFFICIENT_BUFFER = 0x7A
ERROR_NOT_FOUND = 0x490
ERROR_EVT_INVALID_EVENT_DATA = 0x3A9D
ERROR_ALREADY_EXISTS = 0xB7

# enum _TDH_IN_TYPE {
#     TDH_INTYPE_NULL,
#     TDH_INTYPE_UNICODESTRING,
#     TDH_INTYPE_ANSISTRING,
#     TDH_INTYPE_INT8,
#     TDH_INTYPE_UINT8,
#     TDH_INTYPE_INT16,
#     TDH_INTYPE_UINT16,
#     TDH_INTYPE_INT32,
#     TDH_INTYPE_UINT32,
#     TDH_INTYPE_INT64,
#     TDH_INTYPE_UINT64,
#     TDH_INTYPE_FLOAT,
#     TDH_INTYPE_DOUBLE,
#     TDH_INTYPE_BOOLEAN,
#     TDH_INTYPE_BINARY,
#     TDH_INTYPE_GUID,
#     TDH_INTYPE_POINTER,
#     TDH_INTYPE_FILETIME,
#     TDH_INTYPE_SYSTEMTIME,
#     TDH_INTYPE_SID,
#     TDH_INTYPE_HEXINT32,
#     TDH_INTYPE_HEXINT64,                    // End of winmeta intypes.
#     TDH_INTYPE_COUNTEDSTRING = 300,         // Start of TDH intypes for WBEM.
#     TDH_INTYPE_COUNTEDANSISTRING,
#     TDH_INTYPE_REVERSEDCOUNTEDSTRING,
#     TDH_INTYPE_REVERSEDCOUNTEDANSISTRING,
#     TDH_INTYPE_NONNULLTERMINATEDSTRING,
#     TDH_INTYPE_NONNULLTERMINATEDANSISTRING,
#     TDH_INTYPE_UNICODECHAR,
#     TDH_INTYPE_ANSICHAR,
#     TDH_INTYPE_SIZET,
#     TDH_INTYPE_HEXDUMP,
#     TDH_INTYPE_WBEMSID
# };

TDH_INTYPE_NULL = 0
TDH_INTYPE_UNICODESTRING = 1
TDH_INTYPE_ANSISTRING = 2
TDH_INTYPE_INT8 = 3
TDH_INTYPE_UINT8 = 4
TDH_INTYPE_INT16 = 5
TDH_INTYPE_UINT16 = 6
TDH_INTYPE_INT32 = 7
TDH_INTYPE_UINT32 = 8
TDH_INTYPE_INT64 = 9
TDH_INTYPE_UINT64 = 10
TDH_INTYPE_FLOAT = 11
TDH_INTYPE_DOUBLE = 12
TDH_INTYPE_BOOLEAN = 13
TDH_INTYPE_BINARY = 14
TDH_INTYPE_GUID = 15
TDH_INTYPE_POINTER = 16
TDH_INTYPE_FILETIME = 17
TDH_INTYPE_SYSTEMTIME = 18
TDH_INTYPE_SID = 19
TDH_INTYPE_HEXINT32 = 20
TDH_INTYPE_HEXINT64 = 21
TDH_INTYPE_COUNTEDSTRING = 300
TDH_INTYPE_COUNTEDANSISTRING = 301
TDH_INTYPE_REVERSEDCOUNTEDSTRING = 302
TDH_INTYPE_REVERSEDCOUNTEDANSISTRING = 303
TDH_INTYPE_NONNULLTERMINATEDSTRING = 304
TDH_INTYPE_NONNULLTERMINATEDANSISTRING = 305
TDH_INTYPE_UNICODECHAR = 306
TDH_INTYPE_ANSICHAR = 307
TDH_INTYPE_SIZET = 308
TDH_INTYPE_HEXDUMP = 309
TDH_INTYPE_WBEMSID = 310

# enum _TDH_OUT_TYPE {
#     TDH_OUTTYPE_NULL,
#     TDH_OUTTYPE_STRING,
#     TDH_OUTTYPE_DATETIME,
#     TDH_OUTTYPE_BYTE,
#     TDH_OUTTYPE_UNSIGNEDBYTE,
#     TDH_OUTTYPE_SHORT,
#     TDH_OUTTYPE_UNSIGNEDSHORT,
#     TDH_OUTTYPE_INT,
#     TDH_OUTTYPE_UNSIGNEDINT,
#     TDH_OUTTYPE_LONG,
#     TDH_OUTTYPE_UNSIGNEDLONG,
#     TDH_OUTTYPE_FLOAT,
#     TDH_OUTTYPE_DOUBLE,
#     TDH_OUTTYPE_BOOLEAN,
#     TDH_OUTTYPE_GUID,
#     TDH_OUTTYPE_HEXBINARY,
#     TDH_OUTTYPE_HEXINT8,
#     TDH_OUTTYPE_HEXINT16,
#     TDH_OUTTYPE_HEXINT32,
#     TDH_OUTTYPE_HEXINT64,
#     TDH_OUTTYPE_PID,
#     TDH_OUTTYPE_TID,
#     TDH_OUTTYPE_PORT,
#     TDH_OUTTYPE_IPV4,
#     TDH_OUTTYPE_IPV6,
#     TDH_OUTTYPE_SOCKETADDRESS,
#     TDH_OUTTYPE_CIMDATETIME,
#     TDH_OUTTYPE_ETWTIME,
#     TDH_OUTTYPE_XML,
#     TDH_OUTTYPE_ERRORCODE,
#     TDH_OUTTYPE_WIN32ERROR,
#     TDH_OUTTYPE_NTSTATUS,
#     TDH_OUTTYPE_HRESULT,             // End of winmeta outtypes.
#     TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME, //Culture neutral datetime string.
#     TDH_OUTTYPE_JSON,
#     TDH_OUTTYPE_REDUCEDSTRING = 300, // Start of TDH outtypes for WBEM.
#     TDH_OUTTYPE_NOPRINT
# }

TDH_OUTTYPE_NULL = 0
TDH_OUTTYPE_STRING = 1
TDH_OUTTYPE_DATETIME = 2
TDH_OUTTYPE_BYTE = 3
TDH_OUTTYPE_UNSIGNEDBYTE = 4
TDH_OUTTYPE_SHORT = 5
TDH_OUTTYPE_UNSIGNEDSHORT = 6
TDH_OUTTYPE_INT = 7
TDH_OUTTYPE_UNSIGNEDINT = 8
TDH_OUTTYPE_LONG = 9
TDH_OUTTYPE_UNSIGNEDLONG = 10
TDH_OUTTYPE_FLOAT = 11
TDH_OUTTYPE_DOUBLE = 12
TDH_OUTTYPE_BOOLEAN = 13
TDH_OUTTYPE_GUID = 14
TDH_OUTTYPE_HEXBINARY = 15
TDH_OUTTYPE_HEXINT8 = 16
TDH_OUTTYPE_HEXINT16 = 17
TDH_OUTTYPE_HEXINT32 = 18
TDH_OUTTYPE_HEXINT64 = 19
TDH_OUTTYPE_PID = 20
TDH_OUTTYPE_TID = 21
TDH_OUTTYPE_PORT = 22
TDH_OUTTYPE_IPV4 = 23
TDH_OUTTYPE_IPV6 = 24
TDH_OUTTYPE_SOCKETADDRESS = 25
TDH_OUTTYPE_CIMDATETIME = 26
TDH_OUTTYPE_ETWTIME = 27
TDH_OUTTYPE_XML = 28
TDH_OUTTYPE_ERRORCODE = 29
TDH_OUTTYPE_WIN32ERROR = 30
TDH_OUTTYPE_NTSTATUS = 31
TDH_OUTTYPE_HRESULT = 32
TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME = 33
TDH_OUTTYPE_JSON = 34
TDH_OUTTYPE_REDUCEDSTRING = 300
TDH_OUTTYPE_NOPRIN = 301

TDH_CONVERTER_LOOKUP = {
    TDH_OUTTYPE_INT: int,
    TDH_OUTTYPE_UNSIGNEDINT: int,
    TDH_OUTTYPE_LONG: int,
    TDH_OUTTYPE_UNSIGNEDLONG: int,
    TDH_OUTTYPE_FLOAT: float,
    TDH_OUTTYPE_DOUBLE: float,
    TDH_OUTTYPE_BOOLEAN: convert_bool_str
}


class PROPERTY_DATA_DESCRIPTOR(ct.Structure):
    _fields_ = [('PropertyName', ct.c_ulonglong),
                ('ArrayIndex', ct.c_ulong),
                ('Reserved', ct.c_ulong)]


PropertyStruct = 0x1
PropertyParamLength = 0x2
PropertyParamCount = 0x4
PropertyWBEMXmlFragment = 0x8
PropertyParamFixedLength = 0x10
PropertyParamFixedCount = 0x20
PropertyHasTags = 0x40
PropertyHasCustomSchema = 0x80
PROPERTY_FLAGS = ct.c_uint

# typedef enum _TDH_CONTEXT_TYPE {
#       TDH_CONTEXT_WPP_TMFFILE        = 0,
#       TDH_CONTEXT_WPP_TMFSEARCHPATH  = 1,
#       TDH_CONTEXT_WPP_GMT            = 2,
#       TDH_CONTEXT_POINTERSIZE        = 3,
#       TDH_CONTEXT_PDB_PATH           = 4,
#       TDH_CONTEXT_MAXIMUM            = 5
# } TDH_CONTEXT_TYPE;
TDH_CONTEXT_TYPE = ct.c_uint


class TDH_CONTEXT(ct.Structure):
    _fields_ = [('ParameterValue', ct.c_ulonglong),
                ('ParameterType', TDH_CONTEXT_TYPE),
                ('ParameterSize', ct.c_ulong)]


# typedef enum _DECODING_SOURCE {
#       DecodingSourceXMLFile  = 0,
#       DecodingSourceWbem     = 1,
#       DecodingSourceWPP      = 2,
#       DecodingSourceTlg      = 3
# } DECODING_SOURCE;
DECODING_SOURCE = ct.c_uint

# typedef struct _EVENT_PROPERTY_INFO {
#     PROPERTY_FLAGS Flags;
#     ULONG NameOffset;
#     union {
#         struct _nonStructType {
#             USHORT InType;
#             USHORT OutType;
#             ULONG MapNameOffset;
#         } nonStructType;
#         struct _structType {
#             USHORT StructStartIndex;
#             USHORT NumOfStructMembers;
#             ULONG padding;
#         } structType;
#     };
#     union {
#         USHORT count;
#         USHORT countPropertyIndex;
#     };
#     union {
#         USHORT length;
#         USHORT lengthPropertyIndex;
#     };
#     union {
#         ULONG Reserved;
#         struct {
#             ULONG Tags : 28;
#         };
#     };
# } EVENT_PROPERTY_INFO;


class nonStructType(ct.Structure):
    _fields_ = [('InType', ct.c_ushort),
                ('OutType', ct.c_ushort),
                ('MapNameOffset', ct.c_ulong)]


class structType(ct.Structure):
    _fields_ = [('StructStartIndex', wt.USHORT),
                ('NumOfStructMembers', wt.USHORT),
                ('padding', wt.ULONG)]


class epi_u1(ct.Union):
    _fields_ = [('nonStructType', nonStructType),
                ('structType', structType)]


class epi_u2(ct.Union):
    _fields_ = [('count', wt.USHORT),
                ('countPropertyIndex', wt.USHORT)]


class epi_u3(ct.Union):
    _fields_ = [('length', wt.USHORT),
                ('lengthPropertyIndex', wt.USHORT)]


class epi_u4(ct.Union):
    _fields_ = [('Reserved', wt.ULONG),
                ('Tags', wt.ULONG)]


class EVENT_PROPERTY_INFO(ct.Structure):
    _fields_ = [('Flags', PROPERTY_FLAGS),
                ('NameOffset', ct.c_ulong),
                ('epi_u1', epi_u1),
                ('epi_u2', epi_u2),
                ('epi_u3', epi_u3),
                ('epi_u4', epi_u4)]


class TRACE_EVENT_INFO(ct.Structure):
    _fields_ = [('ProviderGuid', GUID),
                ('EventGuid', GUID),
                ('EventDescriptor', ep.EVENT_DESCRIPTOR),
                ('DecodingSource', DECODING_SOURCE),
                ('ProviderNameOffset', ct.c_ulong),
                ('LevelNameOffset', ct.c_ulong),
                ('ChannelNameOffset', ct.c_ulong),
                ('KeywordsNameOffset', ct.c_ulong),
                ('TaskNameOffset', ct.c_ulong),
                ('OpcodeNameOffset', ct.c_ulong),
                ('EventMessageOffset', ct.c_ulong),
                ('ProviderMessageOffset', ct.c_ulong),
                ('BinaryXMLOffset', ct.c_ulong),
                ('BinaryXMLSize', ct.c_ulong),
                ('ActivityIDNameOffset', ct.c_ulong),
                ('RelatedActivityIDNameOffset', ct.c_ulong),
                ('PropertyCount', ct.c_ulong),
                ('TopLevelPropertyCount', ct.c_ulong),
                ('Flags', ct.c_ulong),
                ('EventPropertyInfoArray', EVENT_PROPERTY_INFO * 0)]


# typedef enum  {
#   EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP    = 1,
#   EVENTMAP_INFO_FLAG_MANIFEST_BITMAP      = 2,
#   EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP  = 4,
#   EVENTMAP_INFO_FLAG_WBEM_VALUEMAP        = 8,
#   EVENTMAP_INFO_FLAG_WBEM_BITMAP          = 16,
#   EVENTMAP_INFO_FLAG_WBEM_FLAG            = 32,
#   EVENTMAP_INFO_FLAG_WBEM_NO_MAP          = 64
# } MAP_FLAGS;
MAP_FLAGS = ct.c_uint


class EVENT_MAP_ENTRY(ct.Structure):
    _fields_ = [('OutputOffset', ct.c_ulong),
                ('InputOffset', ct.c_ulong)]


class EVENT_MAP_INFO(ct.Structure):
    _fields_ = [('NameOffset', ct.c_ulong),
                ('Flag', MAP_FLAGS),
                ('EntryCount', ct.c_ulong),
                ('FormatStringOffset', ct.c_ulong),
                ('MapEntryArray', EVENT_MAP_ENTRY * 0)]


TdhGetEventInformation = ct.windll.Tdh.TdhGetEventInformation
TdhGetEventInformation.argtypes = [ct.POINTER(ec.EVENT_RECORD),
                                   ct.c_ulong,
                                   ct.POINTER(TDH_CONTEXT),
                                   ct.POINTER(TRACE_EVENT_INFO),
                                   ct.POINTER(ct.c_ulong)]
TdhGetEventInformation.restype = ct.c_ulong

TdhGetPropertySize = ct.windll.Tdh.TdhGetPropertySize
TdhGetPropertySize.argtypes = [ct.POINTER(ec.EVENT_RECORD),
                               ct.c_ulong,
                               ct.POINTER(TDH_CONTEXT),
                               ct.c_ulong,
                               ct.POINTER(PROPERTY_DATA_DESCRIPTOR),
                               ct.POINTER(ct.c_ulong)]
TdhGetPropertySize.restype = ct.c_ulong

TdhGetProperty = ct.windll.Tdh.TdhGetProperty
TdhGetProperty.argtypes = [ct.POINTER(ec.EVENT_RECORD),
                           ct.c_ulong,
                           ct.POINTER(TDH_CONTEXT),
                           ct.c_ulong,
                           ct.POINTER(PROPERTY_DATA_DESCRIPTOR),
                           ct.c_ulong,
                           ct.POINTER(ct.c_byte)]
TdhGetProperty.restype = ct.c_ulong

TdhGetEventMapInformation = ct.windll.Tdh.TdhGetEventMapInformation
TdhGetEventMapInformation.argtypes = [ct.POINTER(ec.EVENT_RECORD),
                                      wt.LPWSTR,
                                      ct.POINTER(EVENT_MAP_INFO),
                                      ct.POINTER(ct.c_ulong)]
TdhGetEventMapInformation.restype = ct.c_ulong

TdhFormatProperty = ct.windll.Tdh.TdhFormatProperty
TdhFormatProperty.argtypes = [ct.POINTER(TRACE_EVENT_INFO),
                              ct.POINTER(EVENT_MAP_INFO),
                              ct.c_ulong,
                              ct.c_ushort,
                              ct.c_ushort,
                              ct.c_ushort,
                              ct.c_ushort,
                              ct.POINTER(ct.c_byte),
                              ct.POINTER(ct.c_ulong),
                              ct.c_wchar_p,
                              ct.POINTER(ct.c_ushort)]
TdhFormatProperty.restype = ct.c_ulong

# typedef enum _EVENT_FIELD_TYPE {
#   EventKeywordInformation  = 0,
#   EventLevelInformation    = 1,
#   EventChannelInformation  = 2,
#   EventTaskInformation     = 3,
#   EventOpcodeInformation   = 4,
#   EventInformationMax      = 5
# } EVENT_FIELD_TYPE;

EventKeywordInformation = 0
EventLevelInformation = 1
EventChannelInformation = 2
EventTaskInformation = 3
EventOpcodeInformation = 4
EventInformationMax = 5

EVENT_FIELD_TYPE = ct.c_uint

# typedef struct _PROVIDER_FIELD_INFO {
#   ULONG     NameOffset;
#   ULONG     DescriptionOffset;
#   ULONGLONG Value;
# } PROVIDER_FIELD_INFO;


class PROVIDER_FIELD_INFO(ct.Structure):
    _fields_ = [('NameOffset', wt.ULONG),
                ('DescriptionOffset', wt.ULONG),
                ('Value', ct.c_ulonglong)]


# typedef struct _PROVIDER_FIELD_INFOARRAY {
#   ULONG               NumberOfElements;
#   EVENT_FIELD_TYPE    FieldType;
#   PROVIDER_FIELD_INFO FieldInfoArray[ANYSIZE_ARRAY];
# } PROVIDER_FIELD_INFOARRAY;


class PROVIDER_FIELD_INFOARRAY(ct.Structure):
    _fields_ = [('NumberOfElements', wt.LONG),
                ('FieldType', EVENT_FIELD_TYPE),
                ('FieldInfoArray', PROVIDER_FIELD_INFO * 0)]


# ULONG __stdcall TdhEnumerateProviderFieldInformation(
#   _In_      LPGUID                    pGuid,
#   _In_      EVENT_FIELD_TYPE          EventFieldType,
#   _Out_opt_ PPROVIDER_FIELD_INFOARRAY pBuffer,
#   _Inout_   ULONG                     *pBufferSize
# );

TdhEnumerateProviderFieldInformation = ct.windll.Tdh.TdhEnumerateProviderFieldInformation
TdhEnumerateProviderFieldInformation.argtypes = [ct.POINTER(GUID),
                                                 EVENT_FIELD_TYPE,
                                                 ct.POINTER(PROVIDER_FIELD_INFOARRAY),
                                                 ct.POINTER(wt.ULONG)]
TdhEnumerateProviderFieldInformation.restype = ct.c_ulong
