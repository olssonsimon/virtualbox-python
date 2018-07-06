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

import enum


class DeviceType(enum.Enum):
    """
      Device type.

     .. describe:: NULL
        Null value, may also mean "no device" (not allowed for

     .. describe:: FLOPPY Floppy device.
     .. describe:: DVD CD/DVD-ROM device.
     .. describe:: HARD_DISK Hard disk device.
     .. describe:: NETWORK Network device.
     .. describe:: USB USB device.
     .. describe:: SHARED_FOLDER Shared folder device.
     .. describe:: GRAPHICS3_D Graphics device 3D activity.
    """
    NULL = 0
    FLOPPY = 1
    DVD = 2
    HARD_DISK = 3
    NETWORK = 4
    USB = 5
    SHARED_FOLDER = 6
    GRAPHICS3_D = 7


class NATAliasMode(enum.Enum):
    """
    """
    ALIAS_LOG = 1
    ALIAS_PROXY_ONLY = 2
    ALIAS_USE_SAME_PORTS = 4


class NATProtocol(enum.Enum):
    """Protocol definitions used with NAT port-forwarding rules.
     .. describe:: UDP Port-forwarding uses UDP protocol.
     .. describe:: TCP Port-forwarding uses TCP protocol.
    """
    UDP = 0
    TCP = 1


class AudioDriverType(enum.Enum):
    """
      Host audio driver type.

     .. describe:: NULL Null value, also means "dummy audio driver".
     .. describe:: WIN_MM Windows multimedia (Windows hosts only, not supported at the moment).
     .. describe:: OSS Open Sound System (Linux / Unix hosts only).
     .. describe:: ALSA Advanced Linux Sound Architecture (Linux hosts only).
     .. describe:: DIRECT_SOUND DirectSound (Windows hosts only).
     .. describe:: CORE_AUDIO CoreAudio (Mac hosts only).
     .. describe:: MMPM Reserved for historical reasons.
     .. describe:: PULSE PulseAudio (Linux hosts only).
     .. describe:: SOL_AUDIO Solaris audio (Solaris hosts only, not supported at the moment).
    """
    NULL = 0
    WIN_MM = 1
    OSS = 2
    ALSA = 3
    DIRECT_SOUND = 4
    CORE_AUDIO = 5
    MMPM = 6
    PULSE = 7
    SOL_AUDIO = 8


class AudioControllerType(enum.Enum):
    """
      Virtual audio controller type.

    """
    AC97 = 0
    SB16 = 1
    HDA = 2


class AudioCodecType(enum.Enum):
    """
      The exact variant of audio codec hardware presented
      to the guest; see
     .. describe:: NULL @c null value. Never used by the API.
     .. describe:: SB16 SB16; this is the only option for the SB16 device.
     .. describe:: STAC9700 A STAC9700 AC'97 codec.
     .. describe:: AD1980 An AD1980 AC'97 codec. Recommended for Linux guests.
     .. describe:: STAC9221 A STAC9221 HDA codec.
    """
    NULL = 0
    SB16 = 1
    STAC9700 = 2
    AD1980 = 3
    STAC9221 = 4


class GraphicsControllerType(enum.Enum):
    """Graphics controller type, used with
     .. describe:: NULL Reserved value, invalid.
     .. describe:: VIRTUALBOX_VGA Default VirtualBox VGA device.
     .. describe:: VMSVGA VMware SVGA II device.
    """
    NULL = 0
    VIRTUALBOX_VGA = 1
    VMSVGA = 2
