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

import time
import pywintrace


def some_func():
    # define capture provider info
    providers = [pywintrace.ProviderInfo('Some Provider', pywintrace.GUID("{11111111-1111-1111-1111-111111111111}"))]
    # create instance of ETW class
    job = pywintrace.ETW(providers=providers, event_callback=lambda x: print(x))
    # start capture
    job.start()

    # wait some time
    time.sleep(5)

    # stop capture
    job.stop()


if __name__ == '__main__':
    some_func()
