import typing
from .._enums import DeviceType


_SENTINEL = object()


class MachineDevices(object):
    def __init__(self, interface):
        self._interface = interface

    def set_boot_order(self, position: int, device_type: DeviceType):
        """Puts the given device to the specified position in
        the boot order.

        To indicate that no device is associated with the given position,
        :param int position:
            Position in the boot order (@c 1 to the total number of
          devices the machine can boot from, as returned by
        :param DeviceType device:
            The type of the device used to boot at the given position.
        """
        self._interface._call_method('setBootOrder', position, device_type)

    def get_boot_order(self, position: int) -> DeviceType:
        """Returns the device type that occupies the specified
        position in the boot order.

        @todo [remove?]
        If the machine can have more than one device of the returned type
        (such as hard disks), then a separate method should be used to
        retrieve the individual device that occupies the given position.

        If here are no devices at the given position, then
        :param int position:
            Position in the boot order (@c 1 to the total number of
          devices the machine can boot from, as returned by
        :rtype: DeviceType
        :returns:
            Device at the given position.
        """
        return DeviceType(self._interface._call_method('getBootOrder', position))

    def attach_device(self, name: str, slot: int, device_type: DeviceType, controller_port: int, medium: typing.Optional[Medium]=None, passthrough: bool=False, non_rotational: bool=False,):
        """Attaches a device and optionally mounts a medium to the given storage
        controller (
        :param str name:
            Name of the storage controller to attach the device to.
        :param int controller_port:
            Port to attach the device to. For an IDE controller, 0 specifies
        the primary controller and 1 specifies the secondary controller.
        For a SCSI controller, this must range from 0 to 15; for a SATA controller,
        from 0 to 29; for an SAS controller, from 0 to 7.
        :param int device:
            Device slot in the given port to attach the device to. This is only
        relevant for IDE controllers, for which 0 specifies the master device and
        1 specifies the slave device. For all other controller types, this must
        be 0.
        :param DeviceType type_:
            Device type of the attached device. For media opened by
        :param Medium medium:
            Medium to mount or @c null for an empty drive.
        """
        if medium is not None:
            self._interface._call_method('attachDevice', name, controller_port, slot, type_, medium)
        else:
            self._interface._call_method('attachDeviceWithoutMedium', name, controller_port, slot, type_)

    def detach_device(self, name: str, slot: int, controller_port: int, ):
        """Detaches the device attached to a device slot of the specified bus.

        Detaching the device from the virtual machine is deferred. This means
        that the medium remains associated with the machine when this method
        returns and gets actually de-associated only after a successful
        :param str name:
            Name of the storage controller to detach the medium from.
        :param int controller_port:
            Port number to detach the medium from.
        :param int device:
            Device slot number to detach the medium from.
        """
        self._call_method('detachDevice', name, controller_port, slot)

    def set_device_options(self, name: str, slot: int, controller_port: int, passthrough=None, temporary_eject=None, non_rotational=None, auto_discard=None, hot_pluggable=None, bandwidth_group=_SENTINEL):
        if passthrough is not None:
            self._interface._call_method("passthroughDevice", name, controller_port, slot, passthrough)
        if temporary_eject is not None:
            self._interface._call_method("temporaryEjectDevice", name, controller_port, slot, temporary_eject)
        if non_rotational is not None:
            self._interface._call_method("nonRotationalDevice", name, controller_port, slot, non_rotational)
        if auto_discard is not None:
            self._interface._call_method("setAutoDiscardForDevice", name, controller_port, slot, auto_discard)
        if hot_pluggable is not None:
            self._interface._call_method("setHotPluggableForDevice", name, controller_port, slot, hot_pluggable)
        if bandwidth_group is not _SENTINEL:
            if bandwidth_group is None:
                self._interface._call_method('setNoBandwidthGroupForDevice', name, controller_port, slot)
            else:
                self._interface._call_method('setBandwidthGroupForDevice', name, controller_port, slot, bandwidth_group)

    def mount_medium(self, name: str, slot: int, controller_port: int, medium: Medium, force_mount: bool = False):
        """Mounts a medium (
        :param str name:
            Name of the storage controller to attach the medium to.
        :param int controller_port:
            Port to attach the medium to.
        :param int device:
            Device slot in the given port to attach the medium to.
        :param Medium medium:
            Medium to mount or @c null for an empty drive.
        :param bool force:
            Allows to force unmount/mount of a medium which is locked by
          the device slot in the given port to attach the medium to.
        """
        self._interface._call_method('mountMedium', name, controller_port, slot, medium, force_mount)

    def unmount_medium(self, name: str, slot: int, controller_port: int, force_unmount: bool=False):
        """Unmounts any currently mounted medium (
        :param str name:
            Name of the storage controller to unmount the medium from.
        :param int controller_port:
            Port to unmount the medium from.
        :param int device:
            Device slot in the given port to unmount the medium from.
        :param bool force:
            Allows to force unmount of a medium which is locked by
        the device slot in the given port medium is attached to.
        """
        self._interface._call_method('unmountMedium', name, controller_port, slot, force_unmount)

    def get_medium(self, name: str, slot: int, controller_port: int) -> Medium:
        """Returns the virtual medium attached to a device slot of the specified
        bus.

        Note that if the medium was indirectly attached by
        :param str name:
            Name of the storage controller the medium is attached to.
        :param int controller_port:
            Port to query.
        :param int device:
            Device slot in the given port to query.
        :rtype: Medium
        :returns:
            Attached medium object.
        """
        return Medium(self._interface._call_method('getMedium', name, controller_port, slot))

    def get_medium_attachment(self, name: str, slot: int, controller_port: int):
        """Returns a medium attachment which corresponds to the controller with
        the given name, on the given port and device slot.
        :param str name:
        :param int controller_port:
        :param int device:
        :rtype: MediumAttachment
        """
        return MediumAttachment(self._call_method('getMediumAttachment', name, controller_port, slot))

    def get_medium_attachments_of_controller(self, name):
        """Returns an array of medium attachments which are attached to the
        the controller with the given name.
        :param str name:
        :rtype: typing.List[MediumAttachment]
        """
        ret = MediumAttachment(self._call_method('getMediumAttachmentsOfController', name))
        return ret
