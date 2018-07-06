import typing
import re
from .._enums import GraphicsControllerType


VIDEO_CAPTURE_OPTIONS_REGEX = re.compile(r"(?:^|,)([^=]+)=([^,]+)(?:$|,)")


class _CaptureOptions(dict):
    def __init__(self, interface):
        super().__init__()
        self._interface = interface

    def __getitem__(self, item: str) -> str:
        return dict(self.items())[item]

    def __setitem__(self, key: str, value: str):
        dct = dict(self.items())
        dct[key] = value
        self._interface._set_property('videoCaptureOptions', ','.join('='.join(key_value) for key_value in dct.items()))

    def items(self) -> typing.Iterable[typing.Tuple[str, str]]:
        options = str(self._interface._get_property('videoCaptureOptions'))
        return iter(VIDEO_CAPTURE_OPTIONS_REGEX.findall(options))

    def keys(self) -> typing.Iterable[str]:
        for key, _ in self.items():
            yield key

    def values(self) -> typing.Iterable[str]:
        for _, value in self.items():
            yield value


class MachineVideo(object):
    def __init__(self, interface):
        self._interface = interface
        self.capture_options = _CaptureOptions(interface)

    @property
    def enabled(self) -> bool:
        """This setting determines whether VirtualBox uses video capturing to
        record a VM session.
        :rtype: bool
        """
        return self._interface._get_property('videoCaptureEnabled')

    @property
    def file(self) -> str:
        """This setting determines the filename VirtualBox uses to save
        the recorded content. This setting cannot be changed while video
        capturing is enabled.
        :rtype: str
        """
        return self._interface._get_property('videoCaptureFile')

    @property
    def dimensions(self) -> typing.Tuple[int, int]:
        return self.width, self.height

    @property
    def width(self) -> int:
        """This setting determines the horizontal resolution of the recorded
        video. This setting cannot be changed while video capturing is
        enabled.
        :rtype: int
        """
        return self._interface._get_property('videoCaptureWidth')

    @property
    def height(self) -> int:
        """This setting determines the vertical resolution of the recorded
        video. This setting cannot be changed while video capturing is
        enabled.
        :rtype: int
        """
        return self._interface._get_property('videoCaptureHeight')

    @property
    def bitrate(self) -> int:
        """This setting determines the bitrate in kilobits per second.
        Increasing this value makes the video look better for the
        cost of an increased file size. This setting cannot be changed
        while video capturing is enabled.
        :rtype: int
        """
        return int(self._interface._get_property('videoCaptureRate')) * 1024

    @property
    def fps(self) -> int:
        """This setting determines the maximum number of frames per second.
        Frames with a higher frequency will be skipped. Reducing this
        value increases the number of skipped frames and reduces the
        file size. This setting cannot be changed while video capturing
        is enabled.
        :rtype: int
        """
        return self._interface._get_property('videoCaptureFPS')

    @property
    def max_duration(self) -> float:
        """This setting determines the maximum amount of time in milliseconds
        the video capture will work for. The capture stops as the defined time
        interval  has elapsed. If this value is zero the capturing will not be
        limited by time. This setting cannot be changed while video capturing is
        enabled.
        :rtype: int
        """
        return int(self._interface._get_property('videoCaptureMaxTime')) / 1000.0

    @property
    def max_file_size(self):
        """This setting determines the maximal number of captured video file
        size in MB. The capture stops as the captured video file size
        has reached the defined. If this value is zero the capturing
        will not be limited by file size. This setting cannot be changed
        while video capturing is enabled.
        :rtype: int
        """
        return self._interface._get_property('videoCaptureMaxFileSize')

    @property
    def vram_size(self) -> int:
        """Video memory size in megabytes.
        :rtype: int
        """
        return self._interface._get_property('VRAMSize') * 1024 * 1024

    @property
    def accelerate_3d_enabled(self) -> bool:
        """This setting determines whether VirtualBox allows this machine to make
        use of the 3D graphics support available on the host.
        :rtype: bool
        """
        return bool(self._interface._get_property('accelerate3DEnabled'))

    @property
    def accelerate_2d_video_enabled(self) -> bool:
        """This setting determines whether VirtualBox allows this machine to make
        use of the 2D video acceleration support available on the host.
        :rtype: bool
        """
        return bool(self._interface._get_property('accelerate2DVideoEnabled'))

    @property
    def monitors_captured(self) -> typing.List[bool]:
        """This setting determines for which screens video capturing is
        enabled.
        :rtype: typing.List[bool]
        """
        return list(self._interface._get_property('videoCaptureScreens'))

    @property
    def monitors_count(self) -> int:
        """Number of virtual monitors.
        :rtype: int
        """
        return int(self._interface._get_property('monitorCount'))

    @property
    def graphics_controller_type(self) -> GraphicsControllerType:
        """Graphics controller type.
        :rtype: GraphicsControllerType
        """
        return GraphicsControllerType(self._interface._get_property('graphicsControllerType'))
