# Copyright 2018 Seth Michael Larson (sethmichaellarson@protonmail.com)
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


import typing
from ._base import Interface
from ._enums import AudioCodecType, AudioControllerType, AudioDriverType


class _AudioAdapterProperties(dict):
    def __init__(self, interface: Interface):
        super().__init__()
        self._interface=interface

    def keys(self) -> typing.Iterable[str]:
        return iter(self._interface._get_property('propertiesList'))

    def values(self) -> typing.Iterable[str]:
        for key in self.keys():
            yield self.__getitem__(key)

    def items(self) -> typing.Iterable[typing.Tuple[str, str]]:
        for key in self.keys():
            yield (key, self.__getitem__(key))

    def __getitem__(self, item: str) -> str:
        return str(self._interface._call_method('getProperty', item))

    def __setitem__(self, key: str, value: str):
        self._interface._call_method('setProperty', key, value)

    def __iter__(self) -> typing.Iterable[str]:
        return iter(self._interface._get_property('propertiesList'))


class AudioAdapter(Interface):
    """The IAudioAdapter interface represents the virtual audio adapter of
        the virtual machine. Used in
    """
    def __init__(self, _interface=None):
        super().__init__(_interface)
        self.properties = _AudioAdapterProperties(self)

    @property
    def enabled(self) -> bool:
        """Flag whether the audio adapter is present in the
        guest system. If disabled, the virtual guest hardware will
        not contain any audio adapter. Can only be changed when
        the VM is not running.
        :rtype: bool
        """
        return bool(self._get_property('enabled'))

    @property
    def input_enabled(self) -> bool:
        """Flag whether the audio adapter is enabled for audio
        input. Only relevant if the adapter is enabled.
        :rtype: bool
        """
        return bool(self._get_property('enabledIn'))

    @property
    def output_enabled(self) -> bool:
        """Flag whether the audio adapter is enabled for audio
        output. Only relevant if the adapter is enabled.
        :rtype: bool
        """
        return bool(self._get_property('enabledOut'))

    @property
    def controller(self) -> AudioControllerType:
        """The emulated audio controller.
        :rtype: AudioControllerType
        """
        return AudioControllerType(self._get_property('audioController'))

    @property
    def codec(self) -> AudioCodecType:
        """The exact variant of audio codec hardware presented
        to the guest.
        For HDA and SB16, only one variant is available, but for AC'97,
        there are several.
        :rtype: AudioCodecType
        """
        return AudioCodecType(self._get_property('audioCodec'))

    @property
    def driver(self) -> AudioDriverType:
        """Audio driver the adapter is connected to. This setting
        can only be changed when the VM is not running.
        :rtype: AudioDriverType
        """
        return AudioDriverType(self._get_property('audioDriver'))
