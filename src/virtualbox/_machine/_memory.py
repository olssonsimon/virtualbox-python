class MachineMemory(object):
    def __init__(self, interface):
        self._interface = interface

    @property
    def size(self) -> int:
        """System memory size in megabytes.
        :rtype: int
        """
        return int(self._interface._get_property('memorySize')) * 1024 * 1024

    @size.setter
    def size(self, value: int):
        self._interface._set_property("memorySize", value / (1024 * 1024))

    @property
    def balloon_size(self) -> int:
        """Memory balloon size in megabytes.
        :rtype: int
        """
        return int(self._interface._get_property('memoryBalloonSize')) * 1024 * 1024

    @balloon_size.setter
    def balloon_size(self, value: int):
        self._interface._set_property("memoryBalloonSize", value / (1024 * 1024))

    @property
    def page_fusion_enabled(self) -> bool:
        """This setting determines whether VirtualBox allows page
        fusion for this machine (64-bit hosts only).
        :rtype: bool
        """
        return bool(self._interface._get_property('pageFusionEnabled'))

    @page_fusion_enabled.setter
    def page_fusion_enabled(self, value: bool):
        self._interface._set_property("pageFusionEnabled", value)
