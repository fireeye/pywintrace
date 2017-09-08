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

# This simply parses a CS file containing definitions for all types of an MOF-based ETW provider.
# Ultimately, it is looking for all of the valid targets as well as their associated fields.

import sys


def main():
    if len(sys.argv) != 2:
        print('usage: parse_cs.py [PATH_TO_CS]')
        return

    with open(sys.argv[1], 'r') as cs:
        buf = cs.read()

    artifact = 'public sealed class '
    field_artifact = 'payloadNames = new string[] {'
    offset = 0
    i = -1

    while True:
        i += 1

        # Get the start of the target
        offset = buf.find(artifact, offset)
        if offset == -1:
            break

        # Increment past the artifact
        offset += len(artifact)

        # Get the end of the target
        end_offset = buf.find(' ', offset)

        # Skip the first match -- it is erroneous
        if i == 0:
            continue

        # Print the target name
        print(buf[offset:end_offset].rstrip('Args').upper())

        # Get the offset to the list of fields for this target
        offset = buf.find(field_artifact, offset)
        offset += len(field_artifact)

        # Get the offset to the end of the list of fields for this target
        end_offset = buf.find('}', offset)

        # Print each field for the current target
        for field in buf[offset:end_offset].split(','):
            print('\t- %s' % field.strip(' "'))

        print()


if __name__ == '__main__':
    main()
