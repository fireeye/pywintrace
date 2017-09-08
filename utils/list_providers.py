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
import subprocess


def write_to_log(filename, data):
    with open(filename, 'a') as file:
        file.write(data)


def format_data(data):
    # for each data provider, truncate data if PIDs are listed.
    lines = data.split('\r\n')
    formatted_data = ['\n-------------------------------------------------------------------------------']
    for line in lines:
        if 'PID' in line or 'The command completed successfully' in line:
            break
        formatted_data.append('{:s}\r'.format(line))
    return ''.join(formatted_data)


def list_all_providers(filename):

    # first, get list of all providers
    cmd = 'logman query providers'
    out = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out, _ = proc.communicate()
    except:
        print('exception occurred while trying to run {:s}'.format(cmd))
        exit(-1)

    provs = out.decode('utf-8').split('---------------------------------------'
                                      '----------------------------------------')[1]
    provs = provs.split('The command completed successfully.')[0]
    provs = provs.split('\r\n')

    # for each provider on system get list of properties for each
    for i in range(len(provs)):
        prov_name = '\"{:s}\"'.format(provs[i].split('{')[0].strip())
        if prov_name != '':
            cmd = 'logman query providers {:s}'.format(prov_name)
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
                out, _ = proc.communicate()
            except:
                print('exception occurred while trying to run {:s}'.format(cmd))
                exit(-1)
            write_to_log(filename, format_data(out.decode('utf-8')))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-o',
                        '--outfile',
                        help="file to write output to",
                        required=True)

    args = parser.parse_args()
    list_all_providers(args.outfile)
