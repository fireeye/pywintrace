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

# enum tagEOLE_AUTHENTICATION_CAPABILITIES
#     {
#         EOAC_NONE	= 0,
#         EOAC_MUTUAL_AUTH	= 0x1,
#         EOAC_STATIC_CLOAKING	= 0x20,
#         EOAC_DYNAMIC_CLOAKING	= 0x40,
#         EOAC_ANY_AUTHORITY	= 0x80,
#         EOAC_MAKE_FULLSIC	= 0x100,
#         EOAC_DEFAULT	= 0x800,
#         EOAC_SECURE_REFS	= 0x2,
#         EOAC_ACCESS_CONTROL	= 0x4,
#         EOAC_APPID	= 0x8,
#         EOAC_DYNAMIC	= 0x10,
#         EOAC_REQUIRE_FULLSIC	= 0x200,
#         EOAC_AUTO_IMPERSONATE	= 0x400,
#         EOAC_NO_CUSTOM_MARSHAL	= 0x2000,
#         EOAC_DISABLE_AAA	= 0x1000
#     } 	EOLE_AUTHENTICATION_CAPABILITIES;

EOAC_NONE = 0
EOAC_MUTUAL_AUTH = 0x1
EOAC_STATIC_CLOAKING = 0x20
EOAC_DYNAMIC_CLOAKING = 0x40
EOAC_ANY_AUTHORITY = 0x80
EOAC_MAKE_FULLSIC = 0x100
EOAC_DEFAULT = 0x800
EOAC_SECURE_REFS = 0x2
EOAC_ACCESS_CONTROL = 0x4
EOAC_APPID = 0x8
EOAC_DYNAMIC = 0x10
EOAC_REQUIRE_FULLSIC = 0x200
EOAC_AUTO_IMPERSONATE = 0x400
EOAC_NO_CUSTOM_MARSHAL = 0x2000
EOAC_DISABLE_AAA = 0x1000
