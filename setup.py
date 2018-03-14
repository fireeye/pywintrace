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

import sys
import platform
from setuptools import setup


system = platform.system()
if system != 'Windows':
    print('ERROR: Cannot install this module on {:s}. This package is compatible with Windows only'.format(system))
    exit(-1)


if sys.getwindowsversion().major < 6 or (sys.getwindowsversion().major == 6 and sys.getwindowsversion().minor < 1):
    print('ERROR: Cannot install on Windows versions less than 7 / Server 2008 R2')
    exit(-1)


if sys.version_info < (3, 4):
    print('ERROR: Python version must be greater or equal to 3.4')
    exit(-1)


setup(name='pywintrace',
      version='0.1.1',
      description='ETW Tracing',
      author='Anthony Berglund',
      author_email='anthony.berglund@fireeye.com',
      url='https://github.com/fireeye/pywintrace',
      download_url='https://github.com/fireeye/pywintrace/archive/v0.1.1.tar.gz',
      platforms=['Windows'],
      license='Apache',
      packages=['etw'],
      scripts=['utils/list_providers.py', 'utils/parse_cs.py'],
      classifiers=['Environment :: Console',
                   'Operating System :: Microsoft :: Windows',
                   'License :: OSI Approved :: Apache Software License',
                   'Programming Language :: Python :: 3',
                   'Topic :: Software Development :: Libraries']
      )
