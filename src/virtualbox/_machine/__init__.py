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

from ._devices import MachineDevices
from ._memory import MachineMemory
from ._session import MachineSession
from ._snapshots import MachineSnapshots
from ._video import MachineVideo
from .._base import Interface


class Machine(Interface):
    """The IMachine interface represents a virtual machine, or guest, created
      in VirtualBox.

      This interface is used in two contexts. First of all, a collection of
      objects implementing this interface is stored in the
    """
    def __init__(self, _interface):
        super().__init__(_interface)

        self.devices = MachineDevices(self)
        self.memory = MachineMemory(self)
        self.session = MachineSession(self)
        self.snapshots = MachineSnapshots(self)
        self.video = MachineVideo(self)

    def acquire_lock(self, session, lock_type):
        """Locks the machine for the given session to enable the caller
        to make changes to the machine or start the VM or control
        VM execution.

        There are two ways to lock a machine for such uses:
        :param Session session:
            Session object for which the machine will be locked.
        :param LockType lock_type:
            If set to @c Write, then attempt to acquire an exclusive write lock or fail.
          If set to @c Shared, then either acquire an exclusive write lock or establish
          a link to an existing session.
        """
        self._call_method('lockMachine', session, lock_type)

    def launch(self, session, name, environment):
        """Spawns a new process that will execute the virtual machine and obtains a shared
        lock on the machine for the calling session.

        If launching the VM succeeds, the new VM process will create its own session
        and write-lock the machine for it, preventing conflicting changes from other
        processes. If the machine is already locked (because it is already running or
        because another session has a write lock), launching the VM process will therefore
        fail. Reversely, future attempts to obtain a write lock will also fail while the
        machine is running.

        The caller's session object remains separate from the session opened by the new
        VM process. It receives its own
        :param Session session:
            Client session object to which the VM process will be connected (this
          must be in "Unlocked" state).
        :param str name:
            Front-end to use for the new VM process. The following are currently supported:
        :param str environment:
            Environment to pass to the VM process.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('launchVMProcess', session, name, environment))
        return ret

    def attach_host_pci_device(self, host_address, desired_guest_address, try_to_unbind):
        """Attaches host PCI device with the given (host) PCI address to the
        PCI bus of the virtual machine. Please note, that this operation
        is two phase, as real attachment will happen when VM will start,
        and most information will be delivered as IHostPCIDevicePlugEvent
        on IVirtualBox event source.
        :param int host_address:
            Address of the host PCI device.
        :param int desired_guest_address:
            Desired position of this device on guest PCI bus.
        :param bool try_to_unbind:
            If VMM shall try to unbind existing drivers from the
        device before attaching it to the guest.
        """
        self._call_method('attachHostPCIDevice', host_address, desired_guest_address, try_to_unbind)

    def detach_host_pci_device(self, host_address):
        """Detach host PCI device from the virtual machine.
        Also HostPCIDevicePlugEvent on IVirtualBox event source
        will be delivered. As currently we don't support hot device
        unplug, IHostPCIDevicePlugEvent event is delivered immediately.
        :param int host_address:
            Address of the host PCI device.
        """
        self._call_method('detachHostPCIDevice', host_address)

    def get_network_adapter(self, slot):
        """Returns the network adapter associated with the given slot.
        Slots are numbered sequentially, starting with zero. The total
        number of adapters per machine is defined by the
        :param int slot:
        :rtype: NetworkAdapter
        """
        ret = NetworkAdapter(self._call_method('getNetworkAdapter', slot))
        return ret

    def add_storage_controller(self, name, connection_type):
        """Adds a new storage controller (SCSI, SAS or SATA controller) to the
        machine and returns it as an instance of
        :param str name:
        :param StorageBus connection_type:
        :rtype: StorageController
        """
        ret = StorageController(self._call_method('addStorageController', name, connection_type))
        return ret

    def get_storage_controller_by_name(self, name):
        """Returns a storage controller with the given name.
        :param str name:
        :rtype: StorageController
        """
        ret = StorageController(self._call_method('getStorageControllerByName', name))
        return ret

    def get_storage_controller_by_instance(self, connection_type, instance):
        """Returns a storage controller of a specific storage bus
        with the given instance number.
        :param StorageBus connection_type:
        :param int instance:
        :rtype: StorageController
        """
        ret = StorageController(self._call_method('getStorageControllerByInstance', connection_type, instance))
        return ret

    def remove_storage_controller(self, name):
        """Removes a storage controller from the machine with all devices attached to it.
        :param str name:
        """
        self._call_method('removeStorageController', name)

    def set_storage_controller_bootable(self, name, bootable):
        """Sets the bootable flag of the storage controller with the given name.
        :param str name:
        :param bool bootable:
        """
        self._call_method('setStorageControllerBootable', name, bootable)

    def add_usb_controller(self, name, type_):
        """Adds a new USB controller to the machine and returns it as an instance of
        :param str name:
        :param USBControllerType type_:
        :rtype: USBController
        """
        ret = USBController(self._call_method('addUSBController', name, type_))
        return ret

    def remove_usb_controller(self, name):
        """Removes a USB controller from the machine.
        :param str name:
        """
        self._call_method('removeUSBController', name)

    def get_usb_controller_by_name(self, name):
        """Returns a USB controller with the given type.
        :param str name:
        :rtype: USBController
        """
        ret = USBController(self._call_method('getUSBControllerByName', name))
        return ret

    def get_usb_controller_count_by_type(self, type_):
        """Returns the number of USB controllers of the given type attached to the VM.
        :param USBControllerType type_:
        :rtype: int
        """
        ret = int(self._call_method('getUSBControllerCountByType', type_))
        return ret

    def get_serial_port(self, slot):
        """Returns the serial port associated with the given slot.
        Slots are numbered sequentially, starting with zero. The total
        number of serial ports per machine is defined by the
        :param int slot:
        :rtype: SerialPort
        """
        ret = SerialPort(self._call_method('getSerialPort', slot))
        return ret

    def get_parallel_port(self, slot):
        """Returns the parallel port associated with the given slot.
        Slots are numbered sequentially, starting with zero. The total
        number of parallel ports per machine is defined by the
        :param int slot:
        :rtype: ParallelPort
        """
        ret = ParallelPort(self._call_method('getParallelPort', slot))
        return ret

    def get_extra_data_keys(self):
        """Returns an array representing the machine-specific extra data keys
            which currently have values defined.
        :rtype: typing.List[str]
        :returns:
            Array of extra data keys.
        """
        ret = str(self._call_method('getExtraDataKeys'))
        return ret

    def get_extra_data(self, key):
        """Returns associated machine-specific extra data.

        If the requested data @a key does not exist, this function will
        succeed and return an empty string in the @a value argument.
        :param str key:
            Name of the data key to get.
        :rtype: str
        :returns:
            Value of the requested data key.
        """
        ret = str(self._call_method('getExtraData', key))
        return ret

    def set_extra_data(self, key, value):
        """Sets associated machine-specific extra data.

        If you pass @c null or an empty string as a key @a value, the given
        @a key will be deleted.
        :param str key:
            Name of the data key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setExtraData', key, value)

    def get_hw_virt_ex_property(self, property_):
        """Returns the value of the specified hardware virtualization boolean property.
        :param HWVirtExPropertyType property_:
            Property type to query.
        :rtype: bool
        :returns:
            Property value.
        """
        ret = bool(self._call_method('getHWVirtExProperty', property_))
        return ret

    def set_hw_virt_ex_property(self, property_, value):
        """Sets a new value for the specified hardware virtualization boolean property.
        :param HWVirtExPropertyType property_:
            Property type to set.
        :param bool value:
            New property value.
        """
        self._call_method('setHWVirtExProperty', property_, value)

    def set_settings_file_path(self, settings_file_path):
        """Currently, it is an error to change this property on any machine.
        Later this will allow setting a new path for the settings file, with
        automatic relocation of all files (including snapshots and disk images)
        which are inside the base directory. This operation is only allowed
        when there are no pending unsaved settings.
        :param str settings_file_path:
            New settings file path, will be used to determine the new
        location for the attached media if it is in the same directory or
        below as the original settings file.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('setSettingsFilePath', settings_file_path))
        return ret

    def save_settings(self):
        """Saves any changes to machine settings made since the session
        has been opened or a new machine has been created, or since the
        last call to
        """
        self._call_method('saveSettings')

    def discard_settings(self):
        """Discards any changes to the machine settings made since the session
        has been opened or since the last call to
        """
        self._call_method('discardSettings')

    def unregister(self, cleanup_mode):
        """Unregisters a machine previously registered with
        :param CleanupMode cleanup_mode:
            How to clean up after the machine has been unregistered.
        :rtype: typing.List[Medium]
        :returns:
            List of media detached from the machine, depending on the @a cleanupMode parameter.
        """
        ret = Medium(self._call_method('unregister', cleanup_mode))
        return ret

    def delete_config(self, media):
        """Deletes the files associated with this machine from disk. If medium objects are passed
        in with the @a aMedia argument, they are closed and, if closing was successful, their
        storage files are deleted as well. For convenience, this array of media files can be
        the same as the one returned from a previous
        :param typing.List[Medium] media:
            List of media to be closed and whose storage files will be deleted.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('deleteConfig', media))
        return ret

    def export_to(self, appliance, location):
        """Exports the machine to an OVF appliance. See
        :param Appliance appliance:
            Appliance to export this machine to.
        :param str location:
            The target location.
        :rtype: VirtualSystemDescription
        :returns:
            VirtualSystemDescription object which is created for this machine.
        """
        ret = VirtualSystemDescription(self._call_method('exportTo', appliance, location))
        return ret

    def create_shared_folder(self, name, host_path, writable, automount):
        """Creates a new permanent shared folder by associating the given logical
        name with the given host path, adds it to the collection of shared
        folders and starts sharing it. Refer to the description of
        :param str name:
            Unique logical name of the shared folder.
        :param str host_path:
            Full path to the shared folder in the host file system.
        :param bool writable:
            Whether the share is writable or read-only.
        :param bool automount:
            Whether the share gets automatically mounted by the guest
          or not.
        """
        self._call_method('createSharedFolder', name, host_path, writable, automount)

    def remove_shared_folder(self, name):
        """Removes the permanent shared folder with the given name previously
        created by
        :param str name:
            Logical name of the shared folder to remove.
        """
        self._call_method('removeSharedFolder', name)

    def can_show_console_window(self):
        """Returns @c true if the VM console process can activate the
        console window and bring it to foreground on the desktop of
        the host PC.
        :rtype: bool
        :returns:
            @c true if the console window can be shown and @c false otherwise.
        """
        ret = bool(self._call_method('canShowConsoleWindow'))
        return ret

    def show_console_window(self):
        """Activates the console window and brings it to foreground on
        the desktop of the host PC. Many modern window managers on
        many platforms implement some sort of focus stealing
        prevention logic, so that it may be impossible to activate
        a window without the help of the currently active
        application. In this case, this method will return a non-zero
        identifier that represents the top-level window of the VM
        console process. The caller, if it represents a currently
        active process, is responsible to use this identifier (in a
        platform-dependent manner) to perform actual window
        activation.
        :rtype: int
        :returns:
            Platform-dependent identifier of the top-level VM console
          window, or zero if this method has performed all actions
          necessary to implement the
        """
        ret = int(self._call_method('showConsoleWindow'))
        return ret

    def get_guest_property(self, name):
        """Reads an entry from the machine's guest property store.
        :param str name:
            The name of the property to read.
        :rtype: typing.Tuple[str, int, str]
        """
        value, timestamp, flags = self._call_method('getGuestProperty', name)
        return value, timestamp, flags

    def get_guest_property_value(self, property_):
        """Reads a value from the machine's guest property store.
        :param str property_:
            The name of the property to read.
        :rtype: str
        :returns:
            The value of the property. If the property does not exist then this
          will be empty.
        """
        ret = str(self._call_method('getGuestPropertyValue', property_))
        return ret

    def get_guest_property_timestamp(self, property_):
        """Reads a property timestamp from the machine's guest property store.
        :param str property_:
            The name of the property to read.
        :rtype: int
        :returns:
            The timestamp. If the property does not exist then this will be
          empty.
        """
        ret = int(self._call_method('getGuestPropertyTimestamp', property_))
        return ret

    def set_guest_property(self, property_, value, flags):
        """Sets, changes or deletes an entry in the machine's guest property
        store.
        :param str property_:
            The name of the property to set, change or delete.
        :param str value:
            The new value of the property to set, change or delete. If the
          property does not yet exist and value is non-empty, it will be
          created. If the value is @c null or empty, the property will be
          deleted if it exists.
        :param str flags:
            Additional property parameters, passed as a comma-separated list of
          "name=value" type entries.
        """
        self._call_method('setGuestProperty', property_, value, flags)

    def set_guest_property_value(self, property_, value):
        """Sets or changes a value in the machine's guest property
        store. The flags field will be left unchanged or created empty for a
        new property.
        :param str property_:
            The name of the property to set or change.
        :param str value:
            The new value of the property to set or change. If the
          property does not yet exist and value is non-empty, it will be
          created.
        """
        self._call_method('setGuestPropertyValue', property_, value)

    def delete_guest_property(self, name):
        """Deletes an entry from the machine's guest property store.
        :param str name:
            The name of the property to delete.
        """
        self._call_method('deleteGuestProperty', name)

    def enumerate_guest_properties(self, patterns):
        """Return a list of the guest properties matching a set of patterns along
        with their values, time stamps and flags.
        :param str patterns:
            The patterns to match the properties against, separated by '|'
          characters. If this is empty or @c null, all properties will match.
        :rtype: typing.List[typing.Tuple[str, str, int, str]]
        """
        names, values, timestamps, flags = self._call_method('enumerateGuestProperties', patterns)
        return names, values, timestamps, flags

    def query_saved_guest_screen_info(self, screen_id):
        """Returns the guest dimensions from the saved state.
        :param int screen_id:
            Saved guest screen to query info from.
        :rtype: typing.Tuple[int, int, int, int, bool]
        """
        origin_x, origin_y, width, height, enabled = self._call_method('querySavedGuestScreenInfo', screen_id)
        return origin_x, origin_y, width, height, enabled

    def read_saved_thumbnail_to_array(self, screen_id, bitmap_format):
        """Thumbnail is retrieved to an array of bytes in the requested format.
        :param int screen_id:
            Saved guest screen to read from.
        :param BitmapFormat bitmap_format:
            The requested format.
        :rtype: typing.Tuple[typing.List[bytes], int, int]
        """
        data, width, height = self._call_method('readSavedThumbnailToArray', screen_id, bitmap_format)
        return data, width, height

    def query_saved_screenshot_info(self, screen_id):
        """Returns available formats and size of the screenshot from saved state.
        :param int screen_id:
            Saved guest screen to query info from.
        :rtype: typing.Tuple[typing.List[BitmapFormat], int, int]
        """
        bitmap_formats, width, height = self._call_method('querySavedScreenshotInfo', screen_id)
        bitmap_formats = BitmapFormat(bitmap_formats)
        return bitmap_formats, width, height

    def read_saved_screenshot_to_array(self, screen_id, bitmap_format):
        """Screenshot in requested format is retrieved to an array of bytes.
        :param int screen_id:
            Saved guest screen to read from.
        :param BitmapFormat bitmap_format:
            The requested format.
        :rtype: typing.Tuple[typing.List[bytes], int, int]
        """
        data, width, height = self._call_method('readSavedScreenshotToArray', screen_id, bitmap_format)
        return data, width, height

    def hot_plug_cpu(self, cpu):
        """Plugs a CPU into the machine.
        :param int cpu:
            The CPU id to insert.
        """
        self._call_method('hotPlugCPU', cpu)

    def hot_unplug_cpu(self, cpu):
        """Removes a CPU from the machine.
        :param int cpu:
            The CPU id to remove.
        """
        self._call_method('hotUnplugCPU', cpu)

    def get_cpu_status(self, cpu):
        """Returns the current status of the given CPU.
        :param int cpu:
            The CPU id to check for.
        :rtype: bool
        :returns:
            Status of the CPU.
        """
        ret = bool(self._call_method('getCPUStatus', cpu))
        return ret

    def get_effective_paravirt_provider(self):
        """Returns the effective paravirtualization provider for this VM.
        :rtype: ParavirtProvider
        :returns:
            The effective paravirtualization provider for this VM.
        """
        ret = ParavirtProvider(self._call_method('getEffectiveParavirtProvider'))
        return ret

    def query_log_filename(self, idx):
        """Queries for the VM log file name of an given index. Returns an empty
        string if a log file with that index doesn't exists.
        :param int idx:
            Which log file name to query. 0=current log file.
        :rtype: str
        :returns:
            On return the full path to the log file or an empty string on error.
        """
        ret = str(self._call_method('queryLogFilename', idx))
        return ret

    def read_log(self, idx, offset, size):
        """Reads the VM log file. The chunk size is limited, so even if you
        ask for a big piece there might be less data returned.
        :param int idx:
            Which log file to read. 0=current log file.
        :param int offset:
            Offset in the log file.
        :param int size:
            Chunk size to read in the log file.
        :rtype: typing.List[bytes]
        :returns:
            Data read from the log file. A data size of 0 means end of file
          if the requested chunk size was not 0. This is the unprocessed
          file data, i.e. the line ending style depends on the platform of
          the system the server is running on.
        """
        ret = bytes(self._call_method('readLog', idx, offset, size))
        return ret

    def clone_to(self, target, mode, options):
        """Creates a clone of this machine, either as a full clone (which means
        creating independent copies of the hard disk media, save states and so
        on), or as a linked clone (which uses its own differencing media,
        sharing the parent media with the source machine).

        The target machine object must have been created previously with
        :param Machine target:
            Target machine object.
        :param CloneMode mode:
            Which states should be cloned.
        :param typing.List[CloneOptions] options:
            Options for the cloning operation.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('cloneTo', target, mode, options))
        return ret

    def move_to(self, folder, type_):
        """Move machine on to new place/folder
        :param str folder:
            Target folder where machine is moved.
        :param str type_:
            Type of moving.
          Possible values:
          basic - Only the files which belong solely to this machine
                  are moved from the original machine's folder to
                  a new folder.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('moveTo', folder, type_))
        return ret

    def save_state(self):
        """Saves the current execution state of a running virtual machine
        and stops its execution.

        After this operation completes, the machine will go to the
        Saved state. Next time it is powered up, this state will
        be restored and the machine will continue its execution from
        the place where it was saved.

        This operation differs from taking a snapshot to the effect
        that it doesn't create new differencing media. Also, once
        the machine is powered up from the state saved using this method,
        the saved state is deleted, so it will be impossible to return
        to this state later.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('saveState'))
        return ret

    def adopt_saved_state(self, saved_state_file):
        """Associates the given saved state file to the virtual machine.

        On success, the machine will go to the Saved state. Next time it is
        powered up, it will be restored from the adopted saved state and
        continue execution from the place where the saved state file was
        created.

        The specified saved state file path may be absolute or relative to the
        folder the VM normally saves the state to (usually,
        :param str saved_state_file:
            Path to the saved state file to adopt.
        """
        self._call_method('adoptSavedState', saved_state_file)

    def discard_saved_state(self, f_remove_file):
        """Forcibly resets the machine to "Powered Off" state if it is
        currently in the "Saved" state (previously created by
        :param bool f_remove_file:
            Whether to also remove the saved state file.
        """
        self._call_method('discardSavedState', f_remove_file)

    def apply_defaults(self, flags):
        """Applies the defaults for the configured guest OS type. This is
        primarily for getting sane settings straight after creating a
        new VM, but it can also be applied later.
        :param str flags:
            Additional flags, to be defined later.
        """
        self._call_method('applyDefaults', flags)

    @property
    def parent(self):
        """Associated parent object.
        :rtype: VirtualBox
        """
        return VirtualBox(self._get_property('parent'))

    @property
    def icon(self):
        """Overridden VM Icon details.
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('icon'))

    @property
    def accessible(self):
        """Whether this virtual machine is currently accessible or not.

        A machine is always deemed accessible unless it is registered
        :rtype: bool
        """
        return self._get_property('accessible')

    @property
    def access_error(self):
        """Error information describing the reason of machine
        inaccessibility.

        Reading this property is only valid after the last call to
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('accessError'))

    @property
    def name(self):
        """Name of the virtual machine.

        Besides being used for human-readable identification purposes
        everywhere in VirtualBox, the virtual machine name is also used
        as a name of the machine's settings file and as a name of the
        subdirectory this settings file resides in. Thus, every time you
        change the value of this property, the settings file will be
        renamed once you call
        :rtype: str
        """
        return self._get_property('name')

    @property
    def description(self):
        """Description of the virtual machine.

        The description attribute can contain any text and is
        typically used to describe the hardware and software
        configuration of the virtual machine in detail (i.e. network
        settings, versions of the installed software and so on).
        :rtype: str
        """
        return self._get_property('description')

    @property
    def id_(self):
        """UUID of the virtual machine.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def groups(self):
        """Array of machine group names of which this machine is a member.
        :rtype: typing.List[str]
        """
        return list(self._get_property('groups'))

    @property
    def os_type_id(self):
        """User-defined identifier of the Guest OS type.
        You may use
        :rtype: str
        """
        return self._get_property('OSTypeId')

    @property
    def hardware_version(self):
        """Hardware version identifier. Internal use only for now.
        :rtype: str
        """
        return self._get_property('hardwareVersion')

    @property
    def hardware_uuid(self):
        """The UUID presented to the guest via memory tables, hardware and guest
        properties. For most VMs this is the same as the @a id, but for VMs
        which have been cloned or teleported it may be the same as the source
        VM. The latter is because the guest shouldn't notice that it was
        cloned or teleported.
        :rtype: str
        """
        return self._get_property('hardwareUUID')

    @property
    def bios_settings(self):
        """Object containing all BIOS settings.
        :rtype: BIOSSettings
        """
        return BIOSSettings(self._get_property('BIOSSettings'))

    @property
    def firmware_type(self):
        """Type of firmware (such as legacy BIOS or EFI), used for initial
        bootstrap in this VM.
        :rtype: FirmwareType
        """
        return FirmwareType(self._get_property('firmwareType'))

    @property
    def pointing_hid_type(self):
        """Type of pointing HID (such as mouse or tablet) used in this VM.
        The default is typically "PS2Mouse" but can vary depending on the
        requirements of the guest operating system.
        :rtype: PointingHIDType
        """
        return PointingHIDType(self._get_property('pointingHIDType'))

    @property
    def keyboard_hid_type(self):
        """Type of keyboard HID used in this VM.
        The default is typically "PS2Keyboard" but can vary depending on the
        requirements of the guest operating system.
        :rtype: KeyboardHIDType
        """
        return KeyboardHIDType(self._get_property('keyboardHIDType'))

    @property
    def hpet_enabled(self):
        """This attribute controls if High Precision Event Timer (HPET) is
        enabled in this VM. Use this property if you want to provide guests
        with additional time source, or if guest requires HPET to function correctly.
        Default is false.
        :rtype: bool
        """
        return self._get_property('HPETEnabled')

    @property
    def chipset_type(self):
        """Chipset type used in this VM.
        :rtype: ChipsetType
        """
        return ChipsetType(self._get_property('chipsetType'))

    @property
    def snapshot_folder(self):
        """Full path to the directory used to store snapshot data
        (differencing media and saved state files) of this machine.

        The initial value of this property is
        :rtype: str
        """
        return self._get_property('snapshotFolder')

    @property
    def vrde_server(self):
        """VirtualBox Remote Desktop Extension (VRDE) server object.
        :rtype: VRDEServer
        """
        return VRDEServer(self._get_property('VRDEServer'))

    @property
    def emulated_usb_card_reader_enabled(self):
        """None
        :rtype: bool
        """
        return self._get_property('emulatedUSBCardReaderEnabled')

    @property
    def medium_attachments(self):
        """Array of media attached to this machine.
        :rtype: typing.List[MediumAttachment]
        """
        return [MediumAttachment(obj) for obj in self._get_property('mediumAttachments')]

    @property
    def usb_controllers(self):
        """Array of USB controllers attached to this machine.
        :rtype: typing.List[USBController]
        """
        return [USBController(obj) for obj in self._get_property('USBControllers')]

    @property
    def usb_device_filters(self):
        """Associated USB device filters object.
        :rtype: USBDeviceFilters
        """
        return USBDeviceFilters(self._get_property('USBDeviceFilters'))

    @property
    def audio_adapter(self):
        """Associated audio adapter, always present.
        :rtype: AudioAdapter
        """
        return AudioAdapter(self._get_property('audioAdapter'))

    @property
    def storage_controllers(self):
        """Array of storage controllers attached to this machine.
        :rtype: typing.List[StorageController]
        """
        return [StorageController(obj) for obj in self._get_property('storageControllers')]

    @property
    def settings_file_path(self):
        """Full name of the file containing machine settings data.
        :rtype: str
        """
        return self._get_property('settingsFilePath')

    @property
    def settings_aux_file_path(self):
        """Full name of the file containing auxiliary machine settings data.
        :rtype: str
        """
        return self._get_property('settingsAuxFilePath')

    @property
    def settings_modified(self):
        """Whether the settings of this machine have been modified
        (but neither yet saved nor discarded).
        :rtype: bool
        """
        return self._get_property('settingsModified')

    @property
    def session_state(self):
        """Current session state for this machine.
        :rtype: SessionState
        """
        return SessionState(self._get_property('sessionState'))

    @property
    def session_name(self):
        """Name of the session. If
        :rtype: str
        """
        return self._get_property('sessionName')

    @property
    def session_pid(self):
        """Identifier of the session process. This attribute contains the
        platform-dependent identifier of the process whose session was
        used with
        :rtype: int
        """
        return self._get_property('sessionPID')

    @property
    def state(self):
        """Current execution state of this machine.
        :rtype: MachineState
        """
        return MachineState(self._get_property('state'))

    @property
    def last_state_change(self):
        """Time stamp of the last execution state change,
        in milliseconds since 1970-01-01 UTC.
        :rtype: int
        """
        return self._get_property('lastStateChange')

    @property
    def state_file_path(self):
        """Full path to the file that stores the execution state of
        the machine when it is in the
        :rtype: str
        """
        return self._get_property('stateFilePath')

    @property
    def log_folder(self):
        """Full path to the folder that stores a set of rotated log files
        recorded during machine execution. The most recent log file is
        named
        :rtype: str
        """
        return self._get_property('logFolder')

    @property
    def snapshot_count(self):
        """Number of snapshots taken on this machine. Zero means the
        machine doesn't have any snapshots.
        :rtype: int
        """
        return self._get_property('snapshotCount')

    @property
    def current_state_modified(self):
        """Returns @c true if the current state of the machine is not
        identical to the state stored in the current snapshot.

        The current state is identical to the current snapshot only
        directly after one of the following calls are made:
        :rtype: bool
        """
        return self._get_property('currentStateModified')

    @property
    def shared_folders(self):
        """Collection of shared folders for this machine (permanent shared
        folders). These folders are shared automatically at machine startup
        and available only to the guest OS installed within this machine.

        New shared folders are added to the collection using
        :rtype: typing.List[SharedFolder]
        """
        return [SharedFolder(obj) for obj in self._get_property('sharedFolders')]

    @property
    def clipboard_mode(self):
        """Synchronization mode between the host OS clipboard
        and the guest OS clipboard.
        :rtype: ClipboardMode
        """
        return ClipboardMode(self._get_property('clipboardMode'))

    @property
    def drag_and_drop_mode(self):
        """Sets or retrieves the current drag'n drop mode.
        :rtype: DnDMode
        """
        return DnDMode(self._get_property('dnDMode'))

    @property
    def teleporter_enabled(self):
        """When set to @a true, the virtual machine becomes a target teleporter
        the next time it is powered on. This can only set to @a true when the
        VM is in the @a PoweredOff or @a Aborted state.
        :rtype: bool
        """
        return self._get_property('teleporterEnabled')

    @property
    def teleporter_port(self):
        """The TCP port the target teleporter will listen for incoming
        teleportations on.

        0 means the port is automatically selected upon power on. The actual
        value can be read from this property while the machine is waiting for
        incoming teleportations.
        :rtype: int
        """
        return self._get_property('teleporterPort')

    @property
    def teleporter_address(self):
        """The address the target teleporter will listen on. If set to an empty
        string, it will listen on all addresses.
        :rtype: str
        """
        return self._get_property('teleporterAddress')

    @property
    def teleporter_password(self):
        """The password to check for on the target teleporter. This is just a
        very basic measure to prevent simple hacks and operators accidentally
        beaming a virtual machine to the wrong place.

        Note that you SET a plain text password while reading back a HASHED
        password. Setting a hashed password is currently not supported.
        :rtype: str
        """
        return self._get_property('teleporterPassword')

    @property
    def paravirt_provider(self):
        """The paravirtualized guest interface provider.
        :rtype: ParavirtProvider
        """
        return ParavirtProvider(self._get_property('paravirtProvider'))

    @property
    def fault_tolerance_state(self):
        """Fault tolerance state; disabled, source or target.
        This property can be changed at any time. If you change it for a running
        VM, then the fault tolerance address and port must be set beforehand.
        :rtype: FaultToleranceState
        """
        return FaultToleranceState(self._get_property('faultToleranceState'))

    @property
    def fault_tolerance_port(self):
        """The TCP port the fault tolerance source or target will use for
        communication.
        :rtype: int
        """
        return self._get_property('faultTolerancePort')

    @property
    def fault_tolerance_address(self):
        """The address the fault tolerance source or target.
        :rtype: str
        """
        return self._get_property('faultToleranceAddress')

    @property
    def fault_tolerance_password(self):
        """The password to check for on the standby VM. This is just a
        very basic measure to prevent simple hacks and operators accidentally
        choosing the wrong standby VM.
        :rtype: str
        """
        return self._get_property('faultTolerancePassword')

    @property
    def fault_tolerance_sync_interval(self):
        """The interval in ms used for syncing the state between source and target.
        :rtype: int
        """
        return self._get_property('faultToleranceSyncInterval')

    @property
    def rtc_use_utc(self):
        """When set to @a true, the RTC device of the virtual machine will run
        in UTC time, otherwise in local time. Especially Unix guests prefer
        the time in UTC.
        :rtype: bool
        """
        return self._get_property('RTCUseUTC')

    @property
    def io_cache_enabled(self):
        """When set to @a true, the builtin I/O cache of the virtual machine
        will be enabled.
        :rtype: bool
        """
        return self._get_property('IOCacheEnabled')

    @property
    def io_cache_size(self):
        """Maximum size of the I/O cache in MB.
        :rtype: int
        """
        return self._get_property('IOCacheSize')

    @property
    def pci_device_assignments(self):
        """Array of PCI devices assigned to this machine, to get list of all
        PCI devices attached to the machine use
        :rtype: typing.List[PCIDeviceAttachment]
        """
        return [PCIDeviceAttachment(obj) for obj in self._get_property('PCIDeviceAssignments')]

    @property
    def bandwidth_control(self):
        """Bandwidth control manager.
        :rtype: BandwidthControl
        """
        return BandwidthControl(self._get_property('bandwidthControl'))

    @property
    def tracing_enabled(self):
        """Enables the tracing facility in the VMM (including PDM devices +
        drivers). The VMM will consume about 0.5MB of more memory when
        enabled and there may be some extra overhead from tracepoints that are
        always enabled.
        :rtype: bool
        """
        return self._get_property('tracingEnabled')

    @property
    def tracing_config(self):
        """Tracepoint configuration to apply at startup when
        :rtype: str
        """
        return self._get_property('tracingConfig')

    @property
    def allow_tracing_to_access_vm(self):
        """Enables tracepoints in PDM devices and drivers to use the VMCPU or VM
        structures when firing off trace points. This is especially useful
        with DTrace tracepoints, as it allows you to use the VMCPU or VM
        pointer to obtain useful information such as guest register state.

        This is disabled by default because devices and drivers normally has no
        business accessing the VMCPU or VM structures, and are therefore unable
        to get any pointers to these.
        :rtype: bool
        """
        return self._get_property('allowTracingToAccessVM')

    @property
    def autostart_enabled(self):
        """Enables autostart of the VM during system boot.
        :rtype: bool
        """
        return self._get_property('autostartEnabled')

    @property
    def autostart_delay(self):
        """Number of seconds to wait until the VM should be started during system boot.
        :rtype: int
        """
        return self._get_property('autostartDelay')

    @property
    def autostop_type(self):
        """Action type to do when the system is shutting down.
        :rtype: AutostopType
        """
        return AutostopType(self._get_property('autostopType'))

    @property
    def default_frontend(self):
        """Selects which VM frontend should be used by default when launching
        this VM through the
        :rtype: str
        """
        return self._get_property('defaultFrontend')

    @property
    def usb_proxy_available(self):
        """Returns whether there is an USB proxy available.
        :rtype: bool
        """
        return self._get_property('USBProxyAvailable')

    @property
    def vm_process_priority(self):
        """Sets the priority of the VM process. It is a VM setting which can
        be changed both before starting the VM and at runtime. The valid
        values are system specific, and if a value is specified which does
        not get recognized, then it will be remembered (useful for preparing
        VM configs for other host OSes), with a successful result.

        The default value is the empty string, which selects the default
        process priority.
        :rtype: str
        """
        return self._get_property('VMProcessPriority')

    @property
    def paravirt_debug(self):
        """Debug parameters for the paravirtualized guest interface provider.
        :rtype: str
        """
        return self._get_property('paravirtDebug')

    @property
    def cpu_profile(self):
        """Experimental feature to select the guest CPU profile.  The default
        is "host", which indicates the host CPU.  All other names are subject
        to change.

        The profiles are found in src/VBox/VMM/VMMR3/cpus/.
        :rtype: str
        """
        return self._get_property('CPUProfile')
