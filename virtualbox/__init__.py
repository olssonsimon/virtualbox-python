# Copyright 2018 Seth Michael Larson (sethmichaellarson@protonmail.com)
# Copyright 2013 Michael Dorman (mjdorma@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pythonic wrapper for the VirtualBox API
"""

from .__about__ import (  # noqa: F401
    __name__,
    __version__,
    __author__,
    __author_email__,
    __maintainer__,
    __maintainer_email__,
    __license__,
    __url__,
)
from ._xidl import *
from ._base import *
