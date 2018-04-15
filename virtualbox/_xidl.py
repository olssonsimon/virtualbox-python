# Copyright 2018 Seth Michael Larson (sethmichaellarson@protonmail.com)
# Copyright 2013 Michael Dorman (mjdorma@gmail.com)
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum
from ._base import Interface
class SettingsVersion(enum.Enum):
    """
      Settings version of VirtualBox settings files. This is written to
      the "version" attribute of the root "VirtualBox" element in the settings
      file XML and indicates which VirtualBox version wrote the file.
    
     .. describe:: NULL Null value, indicates invalid version.
     .. describe:: V1_0 Legacy settings version, not currently supported.
     .. describe:: V1_1 Legacy settings version, not currently supported.
     .. describe:: V1_2 Legacy settings version, not currently supported.
     .. describe:: V1_3PRE Legacy settings version, not currently supported.
     .. describe:: V1_3 Settings version "1.3", written by VirtualBox 2.0.12.
     .. describe:: V1_4 Intermediate settings version, understood by VirtualBox 2.1.x.
     .. describe:: V1_5 Intermediate settings version, understood by VirtualBox 2.1.x.
     .. describe:: V1_6 Settings version "1.6", written by VirtualBox 2.1.4 (at least).
     .. describe:: V1_7 Settings version "1.7", written by VirtualBox 2.2.x and 3.0.x.
     .. describe:: V1_8 Intermediate settings version "1.8", understood by VirtualBox 3.1.x.
     .. describe:: V1_9 Settings version "1.9", written by VirtualBox 3.1.x.
     .. describe:: V1_10 Settings version "1.10", written by VirtualBox 3.2.x.
     .. describe:: V1_11 Settings version "1.11", written by VirtualBox 4.0.x.
     .. describe:: V1_12 Settings version "1.12", written by VirtualBox 4.1.x.
     .. describe:: V1_13 Settings version "1.13", written by VirtualBox 4.2.x.
     .. describe:: V1_14 Settings version "1.14", written by VirtualBox 4.3.x.
     .. describe:: V1_15 Settings version "1.15", written by VirtualBox 5.0.x.
     .. describe:: V1_16 Settings version "1.16", written by VirtualBox 5.1.x.
     .. describe:: V1_17 Settings version "1.17", written by VirtualBox 6.0.x.
     .. describe:: FUTURE Settings version greater than "1.15", written by a future VirtualBox version.
    """
    NULL = 0
    V1_0 = 1
    V1_1 = 2
    V1_2 = 3
    V1_3PRE = 4
    V1_3 = 5
    V1_4 = 6
    V1_5 = 7
    V1_6 = 8
    V1_7 = 9
    V1_8 = 10
    V1_9 = 11
    V1_10 = 12
    V1_11 = 13
    V1_12 = 14
    V1_13 = 15
    V1_14 = 16
    V1_15 = 17
    V1_16 = 18
    V1_17 = 19
    FUTURE = 99999

class AccessMode(enum.Enum):
    """
      Access mode for opening files.
    
    """
    READ_ONLY = 1
    READ_WRITE = 2

class MachineState(enum.Enum):
    """
      Virtual machine execution state.

      This enumeration represents possible values of the 
     .. describe:: NULL Null value (never used by the API).
     .. describe:: POWERED_OFF 
        The machine is not running and has no saved execution state; it has
        either never been started or been shut down successfully.
      
     .. describe:: SAVED 
        The machine is not currently running, but the execution state of the machine
        has been saved to an external file when it was running, from where
        it can be resumed.
      
     .. describe:: TELEPORTED 
        The machine was teleported to a different host (or process) and then
        powered off. Take care when powering it on again may corrupt resources
        it shares with the teleportation target (e.g. disk and network).
      
     .. describe:: ABORTED 
        The process running the machine has terminated abnormally. This may
        indicate a crash of the VM process in host execution context, or
        the VM process has been terminated externally.
      
     .. describe:: RUNNING 
        The machine is currently being executed.
        
     .. describe:: PAUSED 
        Execution of the machine has been paused.
        
     .. describe:: STUCK 
        Execution of the machine has reached the "Guru Meditation"
        condition. This indicates a severe error in the hypervisor itself.
        
     .. describe:: TELEPORTING 
        The machine is about to be teleported to a different host or process.
        It is possible to pause a machine in this state, but it will go to the
        @c TeleportingPausedVM state and it will not be
        possible to resume it again unless the teleportation fails.
      
     .. describe:: LIVE_SNAPSHOTTING 
        A live snapshot is being taken. The machine is running normally, but
        some of the runtime configuration options are inaccessible. Also, if
        paused while in this state it will transition to
        @c OnlineSnapshotting and it will not be resume the
        execution until the snapshot operation has completed.
      
     .. describe:: STARTING 
        Machine is being started after powering it on from a
        zero execution state.
      
     .. describe:: STOPPING 
        Machine is being normally stopped powering it off, or after the guest OS
        has initiated a shutdown sequence.
      
     .. describe:: SAVING 
        Machine is saving its execution state to a file.
      
     .. describe:: RESTORING 
        Execution state of the machine is being restored from a file
        after powering it on from the saved execution state.
      
     .. describe:: TELEPORTING_PAUSED_VM 
        The machine is being teleported to another host or process, but it is
        not running. This is the paused variant of the
        @c Teleporting state.
      
     .. describe:: TELEPORTING_IN 
        Teleporting the machine state in from another host or process.
      
     .. describe:: FAULT_TOLERANT_SYNCING 
        The machine is being synced with a fault tolerant VM running elsewhere.
      
     .. describe:: DELETING_SNAPSHOT_ONLINE 
        Like @c DeletingSnapshot, but the merging of media is ongoing in
        the background while the machine is running.
      
     .. describe:: DELETING_SNAPSHOT_PAUSED 
        Like @c DeletingSnapshotOnline, but the machine was paused when the
        merging of differencing media was started.
      
     .. describe:: ONLINE_SNAPSHOTTING 
        Like @c LiveSnapshotting, but the machine was paused when the
        merging of differencing media was started.
      
     .. describe:: RESTORING_SNAPSHOT 
        A machine snapshot is being restored; this typically does not take long.
      
     .. describe:: DELETING_SNAPSHOT 
        A machine snapshot is being deleted; this can take a long time since this
        may require merging differencing media. This value indicates that the
        machine is not running while the snapshot is being deleted.
      
     .. describe:: SETTING_UP 
        Lengthy setup operation is in progress.
      
     .. describe:: SNAPSHOTTING 
        Taking an (offline) snapshot.
      
     .. describe:: FIRST_ONLINE 
        Pseudo-state: first online state (for use in relational expressions).
      
     .. describe:: LAST_ONLINE 
        Pseudo-state: last online state (for use in relational expressions).
      
     .. describe:: FIRST_TRANSIENT 
        Pseudo-state: first transient state (for use in relational expressions).
      
     .. describe:: LAST_TRANSIENT 
        Pseudo-state: last transient state (for use in relational expressions).
      
    """
    NULL = 0
    POWERED_OFF = 1
    SAVED = 2
    TELEPORTED = 3
    ABORTED = 4
    RUNNING = 5
    PAUSED = 6
    STUCK = 7
    TELEPORTING = 8
    LIVE_SNAPSHOTTING = 9
    STARTING = 10
    STOPPING = 11
    SAVING = 12
    RESTORING = 13
    TELEPORTING_PAUSED_VM = 14
    TELEPORTING_IN = 15
    FAULT_TOLERANT_SYNCING = 16
    DELETING_SNAPSHOT_ONLINE = 17
    DELETING_SNAPSHOT_PAUSED = 18
    ONLINE_SNAPSHOTTING = 19
    RESTORING_SNAPSHOT = 20
    DELETING_SNAPSHOT = 21
    SETTING_UP = 22
    SNAPSHOTTING = 23
    FIRST_ONLINE = 5
    LAST_ONLINE = 19
    FIRST_TRANSIENT = 8
    LAST_TRANSIENT = 23

class SessionState(enum.Enum):
    """
      Session state. This enumeration represents possible values of
      
     .. describe:: NULL Null value (never used by the API).
     .. describe:: UNLOCKED 
        In 
     .. describe:: LOCKED 
        In 
     .. describe:: SPAWNING 
        A new process is being spawned for the machine as a result of
        
     .. describe:: UNLOCKING 
        The session is being unlocked.
      
    """
    NULL = 0
    UNLOCKED = 1
    LOCKED = 2
    SPAWNING = 3
    UNLOCKING = 4

class CPUPropertyType(enum.Enum):
    """
      Virtual CPU property type. This enumeration represents possible values of the
      IMachine get- and setCPUProperty methods.
    
     .. describe:: NULL Null value (never used by the API).
     .. describe:: PAE 
        This setting determines whether VirtualBox will expose the Physical Address
        Extension (PAE) feature of the host CPU to the guest. Note that in case PAE
        is not available, it will not be reported.
      
     .. describe:: LONG_MODE 
        This setting determines whether VirtualBox will advertise long mode
        (i.e. 64-bit guest support) and let the guest enter it.
      
     .. describe:: TRIPLE_FAULT_RESET 
        This setting determines whether a triple fault within a guest will
        trigger an internal error condition and stop the VM (default) or reset
        the virtual CPU/VM and continue execution.
      
     .. describe:: APIC 
        This setting determines whether an APIC is part of the virtual CPU.
        This feature can only be turned off when the X2APIC feature is off.
      
     .. describe:: X2_APIC 
        This setting determines whether an x2APIC is part of the virtual CPU.
        Since this feature implies that the APIC feature is present, it
        automatically enables the APIC feature when set.
      
     .. describe:: IBPB_ON_VM_EXIT 
        If set, force an indirect branch prediction barrier on VM exits if the
        host CPU supports it.  This setting will significantly slow down workloads
        causing many VM exits, so it is only recommended for situation where there
        is a real need to be paranoid.
      
     .. describe:: IBPB_ON_VM_ENTRY 
        If set, force an indirect branch prediction barrier on VM entry if the
        host CPU supports it.  This setting will significantly slow down workloads
        causing many VM exits, so it is only recommended for situation where there
        is a real need to be paranoid.
      
     .. describe:: HARDWARE_VIRT 
        Enabled the hardware virtualization (AMD-V/VT-x) feature on the guest CPU.
        This requires hardware virtualization on the host CPU.
      
     .. describe:: SPEC_CTRL 
        If set, the speculation control CPUID bits and MSRs, when available on the
        host, are exposed to the guest. Depending on the host CPU and operating
        system, this may significantly slow down workloads causing many VM exits.
      
     .. describe:: SPEC_CTRL_BY_HOST 
        If set, the speculation controls are managed by the host. This is intended
        for guests which do not set the speculation controls themselves.
      
    """
    NULL = 0
    PAE = 1
    LONG_MODE = 2
    TRIPLE_FAULT_RESET = 3
    APIC = 4
    X2_APIC = 5
    IBPB_ON_VM_EXIT = 6
    IBPB_ON_VM_ENTRY = 7
    HARDWARE_VIRT = 8
    SPEC_CTRL = 9
    SPEC_CTRL_BY_HOST = 10

class HWVirtExPropertyType(enum.Enum):
    """
      Hardware virtualization property type. This enumeration represents possible values
      for the 
     .. describe:: NULL Null value (never used by the API).
     .. describe:: ENABLED 
        Whether hardware virtualization (VT-x/AMD-V) is enabled at all. If
        such extensions are not available, they will not be used.
      
     .. describe:: VPID 
        Whether VT-x VPID is enabled. If this extension is not available, it will not be used.
      
     .. describe:: NESTED_PAGING 
        Whether Nested Paging is enabled. If this extension is not available, it will not be used.
      
     .. describe:: UNRESTRICTED_EXECUTION 
        Whether VT-x unrestricted execution is enabled. If this feature is not available, it will not be used.
      
     .. describe:: LARGE_PAGES 
        Whether large page allocation is enabled; requires nested paging and a 64-bit host.
      
     .. describe:: FORCE 
        Whether the VM should fail to start if hardware virtualization (VT-x/AMD-V) cannot be used. If
        not set, there will be an automatic fallback to software virtualization.
      
    """
    NULL = 0
    ENABLED = 1
    VPID = 2
    NESTED_PAGING = 3
    UNRESTRICTED_EXECUTION = 4
    LARGE_PAGES = 5
    FORCE = 6

class ParavirtProvider(enum.Enum):
    """
      The paravirtualized guest interface provider. This enumeration represents possible
      values for the 
     .. describe:: NONE No provider is used.
     .. describe:: DEFAULT A default provider is automatically chosen according to the guest OS type.
     .. describe:: LEGACY Used for VMs which didn't used to have any provider settings. Usually
        interpreted as @c None for most VMs.
     .. describe:: MINIMAL A minimal set of features to expose to the paravirtualized guest.
     .. describe:: HYPER_V Microsoft Hyper-V.
     .. describe:: KVM Linux KVM.
    """
    NONE = 0
    DEFAULT = 1
    LEGACY = 2
    MINIMAL = 3
    HYPER_V = 4
    KVM = 5

class FaultToleranceState(enum.Enum):
    """
      Used with 
     .. describe:: INACTIVE No fault tolerance enabled.
     .. describe:: MASTER Fault tolerant master VM.
     .. describe:: STANDBY Fault tolerant standby VM.
    """
    INACTIVE = 1
    MASTER = 2
    STANDBY = 3

class LockType(enum.Enum):
    """
      Used with 
     .. describe:: NULL Placeholder value, do not use when obtaining a lock.
     .. describe:: SHARED Request only a shared lock for remote-controlling the machine.
        Such a lock allows changing certain VM settings which can be safely
        modified for a running VM.
     .. describe:: WRITE Lock the machine for writing. This requests an exclusive lock, i.e.
        there cannot be any other API client holding any type of lock for this
        VM concurrently. Remember that a VM process counts as an API client
        which implicitly holds the equivalent of a shared lock during the
        entire VM runtime.
     .. describe:: VM Lock the machine for writing, and create objects necessary for
        running a VM in this process.
    """
    NULL = 0
    SHARED = 1
    WRITE = 2
    VM = 3

class SessionType(enum.Enum):
    """
      Session type. This enumeration represents possible values of the
      
     .. describe:: NULL Null value (never used by the API).
     .. describe:: WRITE_LOCK 
        Session has acquired an exclusive write lock on a machine
        using 
     .. describe:: REMOTE 
        Session has launched a VM process using
        
     .. describe:: SHARED 
        Session has obtained a link to another session using
        
    """
    NULL = 0
    WRITE_LOCK = 1
    REMOTE = 2
    SHARED = 3

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

class DeviceActivity(enum.Enum):
    """
      Device activity for 
    """
    NULL = 0
    IDLE = 1
    READING = 2
    WRITING = 3

class ClipboardMode(enum.Enum):
    """
      Host-Guest clipboard interchange mode.
    
    """
    DISABLED = 0
    HOST_TO_GUEST = 1
    GUEST_TO_HOST = 2
    BIDIRECTIONAL = 3

class DnDMode(enum.Enum):
    """
      Drag and drop interchange mode.
    
    """
    DISABLED = 0
    HOST_TO_GUEST = 1
    GUEST_TO_HOST = 2
    BIDIRECTIONAL = 3

class Scope(enum.Enum):
    """
      Scope of the operation.

      A generic enumeration used in various methods to define the action or
      argument scope.
    
    """
    GLOBAL = 0
    MACHINE = 1
    SESSION = 2

class BIOSBootMenuMode(enum.Enum):
    """
      BIOS boot menu mode.
    
    """
    DISABLED = 0
    MENU_ONLY = 1
    MESSAGE_AND_MENU = 2

class APICMode(enum.Enum):
    """
      BIOS APIC initialization mode. If the hardware does not support the
      mode then the code falls back to a lower mode.
    
    """
    DISABLED = 0
    APIC = 1
    X2_APIC = 2

class ProcessorFeature(enum.Enum):
    """
      CPU features.
    
    """
    HARDWARE_VIRT_EX = 0
    PAE = 1
    LONG_MODE = 2
    NESTED_PAGING = 3

class FirmwareType(enum.Enum):
    """
      Firmware type.
    
     .. describe:: BIOS BIOS Firmware.
     .. describe:: EFI EFI Firmware, bitness detected basing on OS type.
     .. describe:: EFI32 EFI firmware, 32-bit.
     .. describe:: EFI64 EFI firmware, 64-bit.
     .. describe:: EFIDUAL EFI firmware, combined 32 and 64-bit.
    """
    BIOS = 1
    EFI = 2
    EFI32 = 3
    EFI64 = 4
    EFIDUAL = 5

class PointingHIDType(enum.Enum):
    """
      Type of pointing device used in a virtual machine.
    
     .. describe:: NONE No mouse.
     .. describe:: PS2_MOUSE PS/2 auxiliary device, a.k.a. mouse.
     .. describe:: USB_MOUSE USB mouse (relative pointer).
     .. describe:: USB_TABLET 
        USB tablet (absolute pointer).  Also enables a relative USB mouse in
        addition.
      
     .. describe:: COMBO_MOUSE 
        Combined device, working as PS/2 or USB mouse, depending on guest
        behavior.  Using this device can have negative performance implications.
      
     .. describe:: USB_MULTI_TOUCH 
        USB multi-touch device.  Also enables the USB tablet and mouse devices.
      
    """
    NONE = 1
    PS2_MOUSE = 2
    USB_MOUSE = 3
    USB_TABLET = 4
    COMBO_MOUSE = 5
    USB_MULTI_TOUCH = 6

class KeyboardHIDType(enum.Enum):
    """
      Type of keyboard device used in a virtual machine.
    
     .. describe:: NONE No keyboard.
     .. describe:: PS2_KEYBOARD PS/2 keyboard.
     .. describe:: USB_KEYBOARD USB keyboard.
     .. describe:: COMBO_KEYBOARD Combined device, working as PS/2 or USB keyboard, depending on guest behavior.
      Using of such device can have negative performance implications.
    """
    NONE = 1
    PS2_KEYBOARD = 2
    USB_KEYBOARD = 3
    COMBO_KEYBOARD = 4

class BitmapFormat(enum.Enum):
    """
      Format of a bitmap. Generic values for formats used by
      the source bitmap, the screen shot or image update APIs.
    
     .. describe:: OPAQUE 
        Unknown buffer format (the user may not assume any particular format of
        the buffer).
      
     .. describe:: BGR 
        Generic BGR format without alpha channel.
        Pixel layout depends on the number of bits per pixel:
        
     .. describe:: BGR0 
        4 bytes per pixel: B, G, R, 0.
      
     .. describe:: BGRA 
        4 bytes per pixel: B, G, R, A.
      
     .. describe:: RGBA 
        4 bytes per pixel: R, G, B, A.
      
     .. describe:: PNG 
        PNG image.
      
     .. describe:: JPEG 
        JPEG image.
      
    """
    OPAQUE = 0
    BGR = 542263106
    BGR0 = 810698562
    BGRA = 1095911234
    RGBA = 1094862674
    PNG = 541544016
    JPEG = 1195724874

class VirtualBoxErrorInfo(Interface):
    """The IVirtualBoxErrorInfo interface represents extended error information.

      Extended error information can be set by VirtualBox components after
      unsuccessful or partially successful method invocation. This information
      can be retrieved by the calling party as an IVirtualBoxErrorInfo object
      and then shown to the client in addition to the plain 32-bit result code.

      In MS COM, this interface extends the IErrorInfo interface,
      in XPCOM, it extends the nsIException interface. In both cases,
      it provides a set of common attributes to retrieve error
      information.

      Sometimes invocation of some component's method may involve methods of
      other components that may also fail (independently of this method's
      failure), or a series of non-fatal errors may precede a fatal error that
      causes method failure. In cases like that, it may be desirable to preserve
      information about all errors happened during method invocation and deliver
      it to the caller. The
    """
    @property
    def result_code(self):
        """Result code of the error.
        Usually, it will be the same as the result code returned
        by the method that provided this error information, but not
        always. For example, on Win32, CoCreateInstance() will most
        likely return E_NOINTERFACE upon unsuccessful component
        instantiation attempt, but not the value the component factory
        returned. Value is typed 'long', not 'result',
        to make interface usable from scripting languages.
        :rtype: int
        """
        return self._get_property('resultCode')

    @property
    def result_detail(self):
        """Optional result data of this error. This will vary depending on the
        actual error usage. By default this attribute is not being used.
        :rtype: int
        """
        return self._get_property('resultDetail')

    @property
    def interface_id(self):
        """UUID of the interface that defined the error.
        :rtype: str
        """
        return self._get_property('interfaceID')

    @property
    def component(self):
        """Name of the component that generated the error.
        :rtype: str
        """
        return self._get_property('component')

    @property
    def text(self):
        """Text description of the error.
        :rtype: str
        """
        return self._get_property('text')

    @property
    def next_(self):
        """Next error object if there is any, or @c null otherwise.
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('next'))


class NATNetwork(Interface):
    def add_local_mapping(self, hostid, offset):
        """None
        :param str hostid:
        :param int offset:
        """
        self._call_method('addLocalMapping', hostid, offset)

    def add_port_forward_rule(self, is_ipv6, rule_name, proto, host_ip, host_port, guest_ip, guest_port):
        """None
        :param bool is_ipv6:
        :param str rule_name:
        :param NATProtocol proto:
            Protocol handled with the rule.
        :param str host_ip:
            IP of the host interface to which the rule should apply.
        An empty ip address is acceptable, in which case the NAT engine
        binds the handling socket to any interface.
        :param int host_port:
            The port number to listen on.
        :param str guest_ip:
            The IP address of the guest which the NAT engine will forward
        matching packets to. An empty IP address is not acceptable.
        :param int guest_port:
            The port number to forward.
        """
        self._call_method('addPortForwardRule', is_ipv6, rule_name, proto, host_ip, host_port, guest_ip, guest_port)

    def remove_port_forward_rule(self, is_ipv6, rule_name):
        """None
        :param bool is_ipv6:
        :param str rule_name:
        """
        self._call_method('removePortForwardRule', is_ipv6, rule_name)

    def start(self, trunk_type):
        """None
        :param str trunk_type:
            Type of internal network trunk.
        """
        self._call_method('start', trunk_type)

    def stop(self):
        """None
        """
        self._call_method('stop')

    @property
    def network_name(self):
        """TBD: the idea, technically we can start any number of the NAT networks,
        but we should expect that at some point we will get collisions because of
        port-forwanding rules. so perhaps we should support only single instance of NAT
        network.
        :rtype: str
        """
        return self._get_property('networkName')

    @property
    def enabled(self):
        """None
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def network(self):
        """This is CIDR IPv4 string. Specifying it user defines IPv4 addresses
        of gateway (low address + 1) and DHCP server (= low address + 2).
        Note: If there are defined IPv4 port-forward rules update of network
        will be ignored (because new assignment could break existing rules).
        :rtype: str
        """
        return self._get_property('network')

    @property
    def gateway(self):
        """This attribute is read-only. It's recalculated on changing
        network attribute (low address of network + 1).
        :rtype: str
        """
        return self._get_property('gateway')

    @property
    def ipv6_enabled(self):
        """This attribute define whether gateway will support IPv6 or not.
        :rtype: bool
        """
        return self._get_property('IPv6Enabled')

    @property
    def ipv6_prefix(self):
        """This a CIDR IPv6 defining prefix for link-local addresses
        autoconfiguration within network. Note: ignored if attribute
        IPv6Enabled is false.
        :rtype: str
        """
        return self._get_property('IPv6Prefix')

    @property
    def advertise_default_ipv6_route_enabled(self):
        """None
        :rtype: bool
        """
        return self._get_property('advertiseDefaultIPv6RouteEnabled')

    @property
    def need_dhcp_server(self):
        """None
        :rtype: bool
        """
        return self._get_property('needDhcpServer')

    @property
    def event_source(self):
        """None
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def port_forward_rules_ipv4(self):
        """Array of NAT port-forwarding rules in string representation,
      in the following format:
      "name:protocolid:[host ip]:host port:[guest ip]:guest port".
        :rtype: typing.List[str]
        """
        return list(self._get_property('portForwardRules4'))

    @property
    def local_mappings(self):
        """Array of mappings (address,offset),e.g. ("127.0.1.1=4") maps 127.0.1.1 to networkid + 4.
        :rtype: typing.List[str]
        """
        return list(self._get_property('localMappings'))

    @property
    def loopback_ipv6(self):
        """Offset in ipv6 network from network id for address mapped into loopback6 interface of the host.
        :rtype: int
        """
        return self._get_property('loopbackIp6')

    @property
    def port_forward_rules_ipv6(self):
        """Array of NAT port-forwarding rules in string representation, in the
      following format: "name:protocolid:[host ip]:host port:[guest ip]:guest port".
        :rtype: typing.List[str]
        """
        return list(self._get_property('portForwardRules6'))


class DHCPOpt(enum.Enum):
    """
    """
    SUBNET_MASK = 1
    TIME_OFFSET = 2
    ROUTER = 3
    TIME_SERVER = 4
    NAME_SERVER = 5
    DOMAIN_NAME_SERVER = 6
    LOG_SERVER = 7
    COOKIE = 8
    LPR_SERVER = 9
    IMPRESS_SERVER = 10
    RESOURSE_LOCATION_SERVER = 11
    HOST_NAME = 12
    BOOT_FILE_SIZE = 13
    MERIT_DUMP_FILE = 14
    DOMAIN_NAME = 15
    SWAP_SERVER = 16
    ROOT_PATH = 17
    EXTENSION_PATH = 18
    IP_FORWARDING_ENABLE_DISABLE = 19
    NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE = 20
    POLICY_FILTER = 21
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE = 22
    DEFAULT_IP_TIME2_LIVE = 23
    PATH_MTU_AGING_TIMEOUT = 24
    IP_LAYER_PARAMETERS_PER_INTERFACE = 25
    INTERFACE_MTU = 26
    ALL_SUBNETS_ARE_LOCAL = 27
    BROADCAST_ADDRESS = 28
    PERFORM_MASK_DISCOVERY = 29
    MASK_SUPPLIER = 30
    PERFORM_ROUTE_DISCOVERY = 31
    ROUTER_SOLICITATION_ADDRESS = 32
    STATIC_ROUTE = 33
    TRAILER_ENCAPSULATION = 34
    ARP_CACHE_TIMEOUT = 35
    ETHERNET_ENCAPSULATION = 36
    TCP_DEFAULT_TTL = 37
    TCP_KEEP_ALIVE_INTERVAL = 38
    TCP_KEEP_ALIVE_GARBAGE = 39
    NETWORK_INFORMATION_SERVICE_DOMAIN = 40
    NETWORK_INFORMATION_SERVICE_SERVERS = 41
    NETWORK_TIME_PROTOCOL_SERVERS = 42
    VENDOR_SPECIFIC_INFORMATION = 43
    OPTION_44 = 44
    OPTION_45 = 45
    OPTION_46 = 46
    OPTION_47 = 47
    OPTION_48 = 48
    OPTION_49 = 49
    IP_ADDRESS_LEASE_TIME = 51
    OPTION_64 = 64
    OPTION_65 = 65
    TFTP_SERVER_NAME = 66
    BOOTFILE_NAME = 67
    OPTION_68 = 68
    OPTION_69 = 69
    OPTION_70 = 70
    OPTION_71 = 71
    OPTION_72 = 72
    OPTION_73 = 73
    OPTION_74 = 74
    OPTION_75 = 75
    OPTION_119 = 119

class DHCPOptEncoding(enum.Enum):
    """
    """
    LEGACY = 0
    HEX = 1

class DHCPServer(Interface):
    """The IDHCPServer interface represents the VirtualBox DHCP server configuration.

      To enumerate all the DHCP servers on the host, use the
    """
    def add_global_option(self, option, value):
        """None
        :param DHCPOpt option:
        :param str value:
        """
        self._call_method('addGlobalOption', option, value)

    def add_vm_slot_option(self, vmname, slot, option, value):
        """None
        :param str vmname:
        :param int slot:
        :param DHCPOpt option:
        :param str value:
        """
        self._call_method('addVmSlotOption', vmname, slot, option, value)

    def remove_vm_slot_options(self, vmname, slot):
        """None
        :param str vmname:
        :param int slot:
        """
        self._call_method('removeVmSlotOptions', vmname, slot)

    def get_vm_slot_options(self, vmname, slot):
        """None
        :param str vmname:
        :param int slot:
        :rtype: typing.List[str]
        """
        ret = self._call_method('getVmSlotOptions', vmname, slot)
        return ret

    def get_mac_options(self, mac):
        """None
        :param str mac:
        :rtype: typing.List[str]
        """
        ret = self._call_method('getMacOptions', mac)
        return ret

    def set_configuration(self, ip_address, network_mask, from_ip_address, to_ip_address):
        """None
        :param str ip_address:
            server IP address
        :param str network_mask:
            server network mask
        :param str from_ip_address:
            server From IP address for address range
        :param str to_ip_address:
            server To IP address for address range
        """
        self._call_method('setConfiguration', ip_address, network_mask, from_ip_address, to_ip_address)

    def start(self, network_name, trunk_name, trunk_type):
        """None
        :param str network_name:
            Name of internal network DHCP server should attach to.
        :param str trunk_name:
            Name of internal network trunk.
        :param str trunk_type:
            Type of internal network trunk.
        """
        self._call_method('start', network_name, trunk_name, trunk_type)

    def stop(self):
        """None
        """
        self._call_method('stop')

    @property
    def event_source(self):
        """None
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def enabled(self):
        """specifies if the DHCP server is enabled
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def ip_address(self):
        """specifies server IP
        :rtype: str
        """
        return self._get_property('IPAddress')

    @property
    def network_mask(self):
        """specifies server network mask
        :rtype: str
        """
        return self._get_property('networkMask')

    @property
    def network_name(self):
        """specifies internal network name the server is used for
        :rtype: str
        """
        return self._get_property('networkName')

    @property
    def lower_ip(self):
        """specifies from IP address in server address range
        :rtype: str
        """
        return self._get_property('lowerIP')

    @property
    def upper_ip(self):
        """specifies to IP address in server address range
        :rtype: str
        """
        return self._get_property('upperIP')

    @property
    def global_options(self):
        """None
        :rtype: typing.List[str]
        """
        return list(self._get_property('globalOptions'))

    @property
    def vm_configs(self):
        """None
        :rtype: typing.List[str]
        """
        return list(self._get_property('vmConfigs'))


class VirtualBox(Interface):
    """The IVirtualBox interface represents the main interface exposed by the
      product that provides virtual machine management.

      An instance of IVirtualBox is required for the product to do anything
      useful. Even though the interface does not expose this, internally,
      IVirtualBox is implemented as a singleton and actually lives in the
      process of the VirtualBox server (VBoxSVC.exe). This makes sure that
      IVirtualBox can track the state of all virtual machines on a particular
      host, regardless of which frontend started them.

      To enumerate all the virtual machines on the host, use the
    """
    def compose_machine_filename(self, name, group, create_flags, base_folder):
        """None
        :param str name:
            Suggested machine name.
        :param str group:
            Machine group name for the new machine or machine group. It is
        used to determine the right subdirectory.
        :param str create_flags:
            Machine creation flags, see
        :param str base_folder:
            Base machine folder (optional).
        :rtype: str
        :returns:
            Fully qualified path where the machine would be created.
        """
        ret = self._call_method('composeMachineFilename', name, group, create_flags, base_folder)
        return ret

    def create_machine(self, settings_file, name, groups, os_type_id, flags):
        """None
        :param str settings_file:
            Fully qualified path where the settings file should be created,
          empty string or @c null for a default folder and file based on the
          @a name argument and the primary group.
        (see
        :param str name:
            Machine name.
        :param typing.List[str] groups:
            Array of group names. @c null or an empty array have the same
          meaning as an array with just the empty string or
        :param str os_type_id:
            Guest OS Type ID.
        :param str flags:
            Additional property parameters, passed as a comma-separated list of
          "name=value" type entries. The following ones are recognized:
        :rtype: Machine
        :returns:
            Created machine object.
        """
        ret = self._call_method('createMachine', settings_file, name, groups, os_type_id, flags)
        return ret

    def open_machine(self, settings_file):
        """None
        :param str settings_file:
            Name of the machine settings file.
        :rtype: Machine
        :returns:
            Opened machine object.
        """
        ret = self._call_method('openMachine', settings_file)
        return ret

    def register_machine(self, machine):
        """None
        :param Machine machine:
        """
        self._call_method('registerMachine', machine)

    def find_machine(self, name_or_id):
        """None
        :param str name_or_id:
            What to search for. This can either be the UUID or the name of a virtual machine.
        :rtype: Machine
        :returns:
            Machine object, if found.
        """
        ret = self._call_method('findMachine', name_or_id)
        return ret

    def get_machines_by_groups(self, groups):
        """None
        :param typing.List[str] groups:
            What groups to match. The usual group list rules apply, i.e.
        passing an empty list will match VMs in the toplevel group, likewise
        the empty string.
        :rtype: typing.List[Machine]
        :returns:
            All machines which matched.
        """
        ret = self._call_method('getMachinesByGroups', groups)
        return ret

    def get_machine_states(self, machines):
        """None
        :param typing.List[Machine] machines:
            Array with the machine references.
        :rtype: typing.List[MachineState]
        :returns:
            Machine states, corresponding to the machines.
        """
        ret = self._call_method('getMachineStates', machines)
        return ret

    def create_appliance(self):
        """None
        :rtype: Appliance
        :returns:
            New appliance.
        """
        ret = self._call_method('createAppliance')
        return ret

    def create_unattended_installer(self):
        """None
        :rtype: Unattended
        :returns:
            New unattended object.
        """
        ret = self._call_method('createUnattendedInstaller')
        return ret

    def create_medium(self, format_, location, access_mode, a_device_type_type):
        """None
        :param str format_:
            Identifier of the storage format to use for the new medium.
        :param str location:
            Location of the storage unit for the new medium.
        :param AccessMode access_mode:
            Whether to open the image in read/write or read-only mode. For
        a "DVD" device type, this is ignored and read-only mode is always assumed.
        :param DeviceType a_device_type_type:
            Must be one of "HardDisk", "DVD" or "Floppy".
        :rtype: Medium
        :returns:
            Created medium object.
        """
        ret = self._call_method('createMedium', format_, location, access_mode, a_device_type_type)
        return ret

    def open_medium(self, location, device_type, access_mode, force_new_uuid):
        """None
        :param str location:
            Location of the storage unit that contains medium data in one of
          the supported storage formats.
        :param DeviceType device_type:
            Must be one of "HardDisk", "DVD" or "Floppy".
        :param AccessMode access_mode:
            Whether to open the image in read/write or read-only mode. For
        a "DVD" device type, this is ignored and read-only mode is always assumed.
        :param bool force_new_uuid:
            Allows the caller to request a completely new medium UUID for
           the image which is to be opened. Useful if one intends to open an exact
           copy of a previously opened image, as this would normally fail due to
           the duplicate UUID.
        :rtype: Medium
        :returns:
            Opened medium object.
        """
        ret = self._call_method('openMedium', location, device_type, access_mode, force_new_uuid)
        return ret

    def get_guest_os_type(self, id_):
        """None
        :param str id_:
            Guest OS type ID string.
        :rtype: GuestOSType
        :returns:
            Guest OS type object.
        """
        ret = self._call_method('getGuestOSType', id_)
        return ret

    def create_shared_folder(self, name, host_path, writable, automount):
        """None
        :param str name:
            Unique logical name of the shared folder.
        :param str host_path:
            Full path to the shared folder in the host file system.
        :param bool writable:
            Whether the share is writable or readonly
        :param bool automount:
            Whether the share gets automatically mounted by the guest
          or not.
        """
        self._call_method('createSharedFolder', name, host_path, writable, automount)

    def remove_shared_folder(self, name):
        """None
        :param str name:
            Logical name of the shared folder to remove.
        """
        self._call_method('removeSharedFolder', name)

    def get_extra_data_keys(self):
        """None
        :rtype: typing.List[str]
        :returns:
            Array of extra data keys.
        """
        ret = self._call_method('getExtraDataKeys')
        return ret

    def get_extra_data(self, key):
        """None
        :param str key:
            Name of the data key to get.
        :rtype: str
        :returns:
            Value of the requested data key.
        """
        ret = self._call_method('getExtraData', key)
        return ret

    def set_extra_data(self, key, value):
        """None
        :param str key:
            Name of the data key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setExtraData', key, value)

    def set_settings_secret(self, password):
        """None
        :param str password:
            The cipher key.
        """
        self._call_method('setSettingsSecret', password)

    def create_dhcp_server(self, name):
        """None
        :param str name:
            server name
        :rtype: DHCPServer
        :returns:
            DHCP server settings
        """
        ret = self._call_method('createDHCPServer', name)
        return ret

    def find_dhcp_server_by_network_name(self, name):
        """None
        :param str name:
            server name
        :rtype: DHCPServer
        :returns:
            DHCP server settings
        """
        ret = self._call_method('findDHCPServerByNetworkName', name)
        return ret

    def remove_dhcp_server(self, server):
        """None
        :param DHCPServer server:
            DHCP server settings to be removed
        """
        self._call_method('removeDHCPServer', server)

    def create_nat_network(self, network_name):
        """None
        :param str network_name:
        :rtype: NATNetwork
        """
        ret = self._call_method('createNATNetwork', network_name)
        return ret

    def find_nat_network_by_name(self, network_name):
        """None
        :param str network_name:
        :rtype: NATNetwork
        """
        ret = self._call_method('findNATNetworkByName', network_name)
        return ret

    def remove_nat_network(self, network):
        """None
        :param NATNetwork network:
        """
        self._call_method('removeNATNetwork', network)

    def check_firmware_present(self, firmware_type, version):
        """None
        :param FirmwareType firmware_type:
            Type of firmware to check.
        :param str version:
            Expected version number, usually empty string (presently ignored).
        :rtype: typing.Tuple[bool, str, str]
        """
        result, url, file_ = self._call_method('checkFirmwarePresent', firmware_type, version)
        return result, url, file_

    @property
    def version(self):
        """A string representing the version number of the product. The
        format is 3 integer numbers divided by dots (e.g. 1.0.1). The
        last number represents the build number and will frequently change.

        This may be followed by a _ALPHA[0-9]*, _BETA[0-9]* or _RC[0-9]* tag
        in prerelease builds. Non-Oracle builds may (/shall) also have a
        publisher tag, at the end. The publisher tag starts with an underscore
        just like the prerelease build type tag.
        :rtype: str
        """
        return self._get_property('version')

    @property
    def version_normalized(self):
        """A string representing the version number of the product,
        without the publisher information (but still with other tags).
        See
        :rtype: str
        """
        return self._get_property('versionNormalized')

    @property
    def revision(self):
        """The internal build revision number of the product.
        :rtype: int
        """
        return self._get_property('revision')

    @property
    def package_type(self):
        """A string representing the package type of this product. The
        format is OS_ARCH_DIST where OS is either WINDOWS, LINUX,
        SOLARIS, DARWIN. ARCH is either 32BITS or 64BITS. DIST
        is either GENERIC, UBUNTU_606, UBUNTU_710, or something like
        this.
        :rtype: str
        """
        return self._get_property('packageType')

    @property
    def api_version(self):
        """A string representing the VirtualBox API version number. The format is
        2 integer numbers divided by an underscore (e.g. 1_0). After the
        first public release of packages with a particular API version the
        API will not be changed in an incompatible way. Note that this
        guarantee does not apply to development builds, and also there is no
        guarantee that this version is identical to the first two integer
        numbers of the package version.
        :rtype: str
        """
        return self._get_property('APIVersion')

    @property
    def api_revision(self):
        """To be defined exactly, but we need something that the Validation Kit
        can use to figure which methods and attributes can safely be used on a
        continuously changing trunk (and occasional branch).
        :rtype: int
        """
        return self._get_property('APIRevision')

    @property
    def home_folder(self):
        """Full path to the directory where the global settings file,
        :rtype: str
        """
        return self._get_property('homeFolder')

    @property
    def settings_file_path(self):
        """Full name of the global settings file.
        The value of this property corresponds to the value of
        :rtype: str
        """
        return self._get_property('settingsFilePath')

    @property
    def host(self):
        """Associated host object.
        :rtype: Host
        """
        return Host(self._get_property('host'))

    @property
    def system_properties(self):
        """Associated system information object.
        :rtype: SystemProperties
        """
        return SystemProperties(self._get_property('systemProperties'))

    @property
    def machines(self):
        """Array of machine objects registered within this VirtualBox instance.
        :rtype: typing.List[Machine]
        """
        return [Machine(obj) for obj in self._get_property('machines')]

    @property
    def machine_groups(self):
        """Array of all machine group names which are used by the machines which
        are accessible. Each group is only listed once, however they are listed
        in no particular order and there is no guarantee that there are no gaps
        in the group hierarchy (i.e.
        :rtype: typing.List[str]
        """
        return list(self._get_property('machineGroups'))

    @property
    def hard_disks(self):
        """Array of medium objects known to this VirtualBox installation.

        This array contains only base media. All differencing
        media of the given base medium can be enumerated using
        :rtype: typing.List[Medium]
        """
        return [Medium(obj) for obj in self._get_property('hardDisks')]

    @property
    def dvd_images(self):
        """Array of CD/DVD image objects currently in use by this VirtualBox instance.
        :rtype: typing.List[Medium]
        """
        return [Medium(obj) for obj in self._get_property('DVDImages')]

    @property
    def floppy_images(self):
        """Array of floppy image objects currently in use by this VirtualBox instance.
        :rtype: typing.List[Medium]
        """
        return [Medium(obj) for obj in self._get_property('floppyImages')]

    @property
    def progress_operations(self):
        """None
        :rtype: typing.List[Progress]
        """
        return [Progress(obj) for obj in self._get_property('progressOperations')]

    @property
    def guest_os_types(self):
        """None
        :rtype: typing.List[GuestOSType]
        """
        return [GuestOSType(obj) for obj in self._get_property('guestOSTypes')]

    @property
    def shared_folders(self):
        """Collection of global shared folders. Global shared folders are
        available to all virtual machines.

        New shared folders are added to the collection using
        :rtype: typing.List[SharedFolder]
        """
        return [SharedFolder(obj) for obj in self._get_property('sharedFolders')]

    @property
    def performance_collector(self):
        """Associated performance collector object.
        :rtype: PerformanceCollector
        """
        return PerformanceCollector(self._get_property('performanceCollector'))

    @property
    def dhcp_servers(self):
        """DHCP servers.
        :rtype: typing.List[DHCPServer]
        """
        return [DHCPServer(obj) for obj in self._get_property('DHCPServers')]

    @property
    def nat_networks(self):
        """None
        :rtype: typing.List[NATNetwork]
        """
        return [NATNetwork(obj) for obj in self._get_property('NATNetworks')]

    @property
    def event_source(self):
        """Event source for VirtualBox events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def extension_pack_manager(self):
        """The extension pack manager.
        :rtype: ExtPackManager
        """
        return ExtPackManager(self._get_property('extensionPackManager'))

    @property
    def internal_networks(self):
        """Names of all internal networks.
        :rtype: typing.List[str]
        """
        return list(self._get_property('internalNetworks'))

    @property
    def generic_network_drivers(self):
        """Names of all generic network drivers.
        :rtype: typing.List[str]
        """
        return list(self._get_property('genericNetworkDrivers'))


class VFSType(enum.Enum):
    """
      Virtual file systems supported by VFSExplorer.
    
    """
    FILE = 1
    CLOUD = 2
    S3 = 3
    WEB_DAV = 4

class VFSExplorer(Interface):
    """The VFSExplorer interface unifies access to different file system
      types. This includes local file systems as well remote file systems like
      S3. For a list of supported types see
    """
    def update(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('update')
        return ret

    def cd(self, dir_):
        """None
        :param str dir_:
            The name of the directory to go in.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('cd', dir_)
        return ret

    def cd_up(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('cdUp')
        return ret

    def entry_list(self):
        """None
        :rtype: typing.List[typing.Tuple[str, int, int, int]]
        """
        names, types, sizes, modes = self._call_method('entryList')
        return names, types, sizes, modes

    def exists(self, names):
        """None
        :param typing.List[str] names:
            The names to check.
        :rtype: typing.List[str]
        :returns:
            The names which exist.
        """
        ret = self._call_method('exists', names)
        return ret

    def remove(self, names):
        """None
        :param typing.List[str] names:
            The names to remove.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('remove', names)
        return ret

    @property
    def path(self):
        """Returns the current path in the virtual file system.
        :rtype: str
        """
        return self._get_property('path')

    @property
    def type_(self):
        """Returns the file system type which is currently in use.
        :rtype: VFSType
        """
        return VFSType(self._get_property('type'))


class ImportOptions(enum.Enum):
    """
    Import options, used with 
     .. describe:: KEEP_ALL_MA_CS Don't generate new MAC addresses of the attached network adapters.
     .. describe:: KEEP_NATMA_CS Don't generate new MAC addresses of the attached network adapters when they are using NAT.
     .. describe:: IMPORT_TO_VDI Import all disks to VDI format
    """
    KEEP_ALL_MA_CS = 1
    KEEP_NATMA_CS = 2
    IMPORT_TO_VDI = 3

class ExportOptions(enum.Enum):
    """
    Export options, used with 
     .. describe:: CREATE_MANIFEST Write the optional manifest file (.mf) which is used for integrity
      checks prior import.
     .. describe:: EXPORT_DVD_IMAGES Export DVD images. Default is not to export them as it is rarely
      needed for typical VMs.
     .. describe:: STRIP_ALL_MA_CS Do not export any MAC address information. Default is to keep them
      to avoid losing information which can cause trouble after import, at the
      price of risking duplicate MAC addresses, if the import options are used
      to keep them.
     .. describe:: STRIP_ALL_NON_NATMA_CS Do not export any MAC address information, except for adapters
      using NAT. Default is to keep them to avoid losing information which can
      cause trouble after import, at the price of risking duplicate MAC
      addresses, if the import options are used to keep them.
    """
    CREATE_MANIFEST = 1
    EXPORT_DVD_IMAGES = 2
    STRIP_ALL_MA_CS = 3
    STRIP_ALL_NON_NATMA_CS = 4

class CertificateVersion(enum.Enum):
    """
      X.509 certificate version numbers.
    
    """
    V1 = 1
    V2 = 2
    V3 = 3
    UNKNOWN = 99

class Certificate(Interface):
    """X.509 certificate details.
    """
    def is_currently_expired(self):
        """None
        :rtype: bool
        """
        ret = self._call_method('isCurrentlyExpired')
        return ret

    def query_info(self, what):
        """None
        :param int what:
        :rtype: str
        """
        ret = self._call_method('queryInfo', what)
        return ret

    @property
    def version_number(self):
        """Certificate version number.
        :rtype: CertificateVersion
        """
        return CertificateVersion(self._get_property('versionNumber'))

    @property
    def serial_number(self):
        """Certificate serial number.
        :rtype: str
        """
        return self._get_property('serialNumber')

    @property
    def signature_algorithm_oid(self):
        """The dotted OID of the signature algorithm.
        :rtype: str
        """
        return self._get_property('signatureAlgorithmOID')

    @property
    def signature_algorithm_name(self):
        """The signature algorithm name if known (if known).
        :rtype: str
        """
        return self._get_property('signatureAlgorithmName')

    @property
    def issuer_name(self):
        """Issuer name.  Each member of the array is on the format
      COMPONENT=NAME, e.g. "C=DE", "ST=Example", "L=For Instance", "O=Beispiel GmbH",
      "CN=beispiel.example.org".
        :rtype: typing.List[str]
        """
        return list(self._get_property('issuerName'))

    @property
    def subject_name(self):
        """Subject name.  Same format as issuerName.
        :rtype: typing.List[str]
        """
        return list(self._get_property('subjectName'))

    @property
    def friendly_name(self):
        """Friendly subject name or similar.
        :rtype: str
        """
        return self._get_property('friendlyName')

    @property
    def validity_period_not_before(self):
        """Certificate not valid before ISO time stamp.
        :rtype: str
        """
        return self._get_property('validityPeriodNotBefore')

    @property
    def validity_period_not_after(self):
        """Certificate not valid after ISO time stamp.
        :rtype: str
        """
        return self._get_property('validityPeriodNotAfter')

    @property
    def public_key_algorithm_oid(self):
        """The dotted OID of the public key algorithm.
        :rtype: str
        """
        return self._get_property('publicKeyAlgorithmOID')

    @property
    def public_key_algorithm(self):
        """The public key algorithm name (if known).
        :rtype: str
        """
        return self._get_property('publicKeyAlgorithm')

    @property
    def subject_public_key(self):
        """The raw public key bytes.
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('subjectPublicKey'))

    @property
    def issuer_unique_identifier(self):
        """Unique identifier of the issuer (empty string if not present).
        :rtype: str
        """
        return self._get_property('issuerUniqueIdentifier')

    @property
    def subject_unique_identifier(self):
        """Unique identifier of this certificate (empty string if not present).
        :rtype: str
        """
        return self._get_property('subjectUniqueIdentifier')

    @property
    def certificate_authority(self):
        """Whether this certificate is a certificate authority.  Will return E_FAIL
      if this attribute is not present.
        :rtype: bool
        """
        return self._get_property('certificateAuthority')

    @property
    def key_usage(self):
        """Key usage mask.  Will return 0 if not present.
        :rtype: int
        """
        return self._get_property('keyUsage')

    @property
    def extended_key_usage(self):
        """Array of dotted extended key usage OIDs.  Empty array if not present.
        :rtype: typing.List[str]
        """
        return list(self._get_property('extendedKeyUsage'))

    @property
    def raw_cert_data(self):
        """The raw certificate bytes.
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('rawCertData'))

    @property
    def self_signed(self):
        """Set if self signed certificate.
        :rtype: bool
        """
        return self._get_property('selfSigned')

    @property
    def trusted(self):
        """Set if the certificate is trusted (by the parent object).
        :rtype: bool
        """
        return self._get_property('trusted')

    @property
    def expired(self):
        """Set if the certificate has expired (relevant to the parent object)/
        :rtype: bool
        """
        return self._get_property('expired')


class Appliance(Interface):
    """Represents a platform-independent appliance in OVF format. An instance of this is returned
        by
    """
    def read(self, file_):
        """None
        :param str file_:
            Name of appliance file to open (either with an
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('read', file_)
        return ret

    def interpret(self):
        """None
        """
        self._call_method('interpret')

    def import_machines(self, options):
        """None
        :param typing.List[mportOptions] options:
            Options for the importing operation.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('importMachines', options)
        return ret

    def create_vfs_explorer(self, uri):
        """None
        :param str uri:
            The URI describing the file system to use.
        :rtype: VFSExplorer
        """
        ret = self._call_method('createVFSExplorer', uri)
        return ret

    def write(self, format_, options, path):
        """None
        :param str format_:
            Output format, as a string. Currently supported formats are "ovf-0.9", "ovf-1.0",
            "ovf-2.0" and "opc-1.0"; future versions of VirtualBox may support additional formats.
            The "opc-1.0" format is for creating tarballs for the Oracle Public Cloud.
        :param typing.List[ExportOptions] options:
            Options for the exporting operation.
        :param str path:
            Name of appliance file to create.  There are certain restrictions with regard
              to the file name suffix.  If the format parameter is "opc-1.0" a
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('write', format_, options, path)
        return ret

    def get_warnings(self):
        """None
        :rtype: typing.List[str]
        """
        ret = self._call_method('getWarnings')
        return ret

    def get_password_ids(self):
        """None
        :rtype: typing.List[str]
        :returns:
            The list of password identifiers required for export on success.
        """
        ret = self._call_method('getPasswordIds')
        return ret

    def get_medium_ids_for_password_id(self, password_id):
        """None
        :param str password_id:
            The password identifier to get the medium identifiers for.
        :rtype: typing.List[str]
        :returns:
            The list of medium identifiers returned on success.
        """
        ret = self._call_method('getMediumIdsForPasswordId', password_id)
        return ret

    def add_passwords(self, identifiers, passwords):
        """None
        :param typing.List[str] identifiers:
            List of identifiers.
        :param typing.List[str] passwords:
            List of matching passwords.
        """
        self._call_method('addPasswords', identifiers, passwords)

    @property
    def path(self):
        """Path to the main file of the OVF appliance, which is either the
        :rtype: str
        """
        return self._get_property('path')

    @property
    def disks(self):
        """Array of virtual disk definitions. One such description exists for each
        disk definition in the OVF; each string array item represents one such piece of
        disk information, with the information fields separated by tab (\\t) characters.

        The caller should be prepared for additional fields being appended to
        this string in future versions of VirtualBox and therefore check for
        the number of tabs in the strings returned.

        In the current version, the following eight fields are returned per string
        in the array:
        :rtype: typing.List[str]
        """
        return list(self._get_property('disks'))

    @property
    def virtual_system_descriptions(self):
        """Array of virtual system descriptions. One such description is created
      for each virtual system (machine) found in the OVF.
      This array is empty until either
        :rtype: typing.List[VirtualSystemDescription]
        """
        return [VirtualSystemDescription(obj) for obj in self._get_property('virtualSystemDescriptions')]

    @property
    def machines(self):
        """Contains the UUIDs of the machines created from the information in this appliances. This is only
        relevant for the import case, and will only contain data after a call to
        :rtype: typing.List[str]
        """
        return list(self._get_property('machines'))

    @property
    def certificate(self):
        """The X.509 signing certificate, if the imported OVF was signed, @c null
        if not signed.  This is available after calling
        :rtype: Certificate
        """
        return Certificate(self._get_property('certificate'))


class VirtualSystemDescriptionType(enum.Enum):
    """Used with 
     .. describe:: SETTINGS_FILE Not used/implemented right now, will be added later in 4.1.x.
    """
    IGNORE = 1
    OS = 2
    NAME = 3
    PRODUCT = 4
    VENDOR = 5
    VERSION = 6
    PRODUCT_URL = 7
    VENDOR_URL = 8
    DESCRIPTION = 9
    LICENSE = 10
    MISCELLANEOUS = 11
    CPU = 12
    MEMORY = 13
    HARD_DISK_CONTROLLER_IDE = 14
    HARD_DISK_CONTROLLER_SATA = 15
    HARD_DISK_CONTROLLER_SCSI = 16
    HARD_DISK_CONTROLLER_SAS = 17
    HARD_DISK_IMAGE = 18
    FLOPPY = 19
    CDROM = 20
    NETWORK_ADAPTER = 21
    USB_CONTROLLER = 22
    SOUND_CARD = 23
    SETTINGS_FILE = 24

class VirtualSystemDescriptionValueType(enum.Enum):
    """Used with 
    """
    REFERENCE = 1
    ORIGINAL = 2
    AUTO = 3
    EXTRA_CONFIG = 4

class VirtualSystemDescription(Interface):
    """Represents one virtual system (machine) in an appliance. This interface is used in
      the
    """
    def get_description(self):
        """None
        :rtype: typing.List[typing.Tuple[VirtualSystemDescriptionType, str, str, str, str]]
        """
        types, refs, ovf_values, virtualbox_values, extra_config_values = self._call_method('getDescription')
        types = VirtualSystemDescriptionType(types)
        return types, refs, ovf_values, virtualbox_values, extra_config_values

    def get_description_by_type(self, type_):
        """None
        :param VirtualSystemDescriptionType type_:
        :rtype: typing.List[typing.Tuple[VirtualSystemDescriptionType, str, str, str, str]]
        """
        types, refs, ovf_values, virtualbox_values, extra_config_values = self._call_method('getDescriptionByType', type_)
        types = VirtualSystemDescriptionType(types)
        return types, refs, ovf_values, virtualbox_values, extra_config_values

    def get_values_by_type(self, type_, which):
        """None
        :param VirtualSystemDescriptionType type_:
        :param VirtualSystemDescriptionValueType which:
        :rtype: typing.List[str]
        """
        ret = self._call_method('getValuesByType', type_, which)
        return ret

    def set_final_values(self, enabled, virtualbox_values, extra_config_values):
        """None
        :param typing.List[bool] enabled:
        :param typing.List[str] virtualbox_values:
        :param typing.List[str] extra_config_values:
        """
        self._call_method('setFinalValues', enabled, virtualbox_values, extra_config_values)

    def add_description(self, type_, virtualbox_value, extra_config_value):
        """None
        :param VirtualSystemDescriptionType type_:
        :param str virtualbox_value:
        :param str extra_config_value:
        """
        self._call_method('addDescription', type_, virtualbox_value, extra_config_value)

    @property
    def count(self):
        """Return the number of virtual system description entries.
        :rtype: int
        """
        return self._get_property('count')


class Unattended(Interface):
    """The IUnattended interface represents the pipeline for preparing
      the Guest OS for fully automated install.

      The typical workflow is:
    """
    def detect_iso_os(self):
        """None
        """
        self._call_method('detectIsoOS')

    def prepare(self):
        """None
        """
        self._call_method('prepare')

    def construct_media(self):
        """None
        """
        self._call_method('constructMedia')

    def reconfigure_vm(self):
        """None
        """
        self._call_method('reconfigureVM')

    def done(self):
        """None
        """
        self._call_method('done')

    @property
    def iso_path(self):
        """Guest operating system ISO image
        :rtype: str
        """
        return self._get_property('isoPath')

    @property
    def machine(self):
        """The associated machine object.

        This must be set before
        :rtype: Machine
        """
        return Machine(self._get_property('machine'))

    @property
    def user(self):
        """Assign an user login name.
        :rtype: str
        """
        return self._get_property('user')

    @property
    def password(self):
        """Assign a password to the user. The password is the same for both
        normal user and for Administrator / 'root' accounts.
        :rtype: str
        """
        return self._get_property('password')

    @property
    def full_user_name(self):
        """The full name of the user.  This is optional and defaults to
        :rtype: str
        """
        return self._get_property('fullUserName')

    @property
    def product_key(self):
        """Any key which is used as authorization of access to install genuine OS
        :rtype: str
        """
        return self._get_property('productKey')

    @property
    def additions_iso_path(self):
        """Guest Additions ISO image path.  This defaults to
        :rtype: str
        """
        return self._get_property('additionsIsoPath')

    @property
    def install_guest_additions(self):
        """Indicates whether the guest additions should be installed or not.

        Setting this to false does not affect additions shipped with the linux
        distribution, only the installation of additions pointed to by
        :rtype: bool
        """
        return self._get_property('installGuestAdditions')

    @property
    def validation_kit_iso_path(self):
        """VirtualBox ValidationKit ISO image path.  This is used when
        :rtype: str
        """
        return self._get_property('validationKitIsoPath')

    @property
    def install_test_exec_service(self):
        """Indicates whether the test execution service (TXS) from the VBox
        ValidationKit should be installed.

        The TXS binary will be taken from the ISO indicated by
        :rtype: bool
        """
        return self._get_property('installTestExecService')

    @property
    def time_zone(self):
        """The guest time zone specifier.

        This is unfortunately guest OS specific.

        Windows XP and earlier takes the index number from this table:
        https://support.microsoft.com/en-gb/help/973627/microsoft-time-zone-index-values

        Windows Vista and later takes the time zone string from this table:
        https://technet.microsoft.com/en-us/library/cc749073(v=ws.10).aspx

        Linux usually takes the TZ string from this table:
        https://en.wikipedia.org/wiki/List_of_tz_database_time_zones

        The default is currently UTC/GMT, but this may change to be same as
        the host later.

        TODO: Investigate automatic mapping between linux and the two windows
              time zone formats.
        TODO: Take default from host (this requires mapping).
        :rtype: str
        """
        return self._get_property('timeZone')

    @property
    def locale(self):
        """The 5 letter locale identifier, no codesets or such.

        The format is two lower case language letters (ISO 639-1), underscore ('_'),
        and two upper case country letters (ISO 3166-1 alpha-2).  For instance
        'en_US', 'de_DE', or 'ny_NO'.

        The default is taken from the host if possible, with 'en_US' as fallback.
        :rtype: str
        """
        return self._get_property('locale')

    @property
    def language(self):
        """This is more or less a Windows specific setting for choosing the UI language
        setting of the installer.

        The value should be from the list availble via
        :rtype: str
        """
        return self._get_property('language')

    @property
    def country(self):
        """The 2 upper case letter country identifier, ISO 3166-1 alpha-2.

        This is used for mirrors and such.

        The default is taken from the host when possible, falling back on
        :rtype: str
        """
        return self._get_property('country')

    @property
    def proxy(self):
        """Proxy incantation to pass on to the guest OS installer.

        This is important to get right if the guest OS installer is of the type
        that goes online to fetch the packages (e.g. debian-*-netinst.iso) or
        to fetch updates during the install process.

        Format: [schema=]schema://[login@password:]proxy[:port][;...]

        The default is taken from the host proxy configuration (once implemented).
        :rtype: str
        """
        return self._get_property('proxy')

    @property
    def package_selection_adjustments(self):
        """Guest OS specific package selection adjustments.

        This is a semicolon separated list of keywords, and later maybe guest OS
        package specifiers.  Currently the 'minimal' is the only recognized value,
        and this only works with a selection of linux installers.
        :rtype: str
        """
        return self._get_property('packageSelectionAdjustments')

    @property
    def hostname(self):
        """The fully qualified guest hostname.

        This defaults to machine-name + ".myguest.virtualbox.org", though it may
        change to the host domain name later.
        :rtype: str
        """
        return self._get_property('hostname')

    @property
    def auxiliary_base_path(self):
        """The path + basename for auxiliary files generated by the unattended
        installation.  This defaults to the VM folder + Unattended + VM UUID.

        The files which gets generated depends on the OS being installed.  When
        installing Windows there is currently only a auxiliaryBasePath + "floppy.img"
        being created.  But for linux, a "cdrom.viso" and one or more configuration
        files are generate generated.
        :rtype: str
        """
        return self._get_property('auxiliaryBasePath')

    @property
    def image_index(self):
        """The image index on installation CD/DVD used to install.

        Used only with Windows installation CD/DVD:
        https://technet.microsoft.com/en-us/library/cc766022%28v=ws.10%29.aspx
        :rtype: int
        """
        return self._get_property('imageIndex')

    @property
    def script_template_path(self):
        """The unattended installation script template file.

        The template default is based on the guest OS type and is determined by the
        internal installer when when
        :rtype: str
        """
        return self._get_property('scriptTemplatePath')

    @property
    def post_install_script_template_path(self):
        """The post installation (shell/batch) script template file.

        The template default is based on the guest OS type and is determined by the
        internal installer when when
        :rtype: str
        """
        return self._get_property('postInstallScriptTemplatePath')

    @property
    def post_install_command(self):
        """Custom post installation command.

        Exactly what is expected as input here depends on the guest OS installer
        and the post installation script template (see
        :rtype: str
        """
        return self._get_property('postInstallCommand')

    @property
    def extra_install_kernel_parameters(self):
        """Extra kernel arguments passed to the install kernel of some guests.

        This is currently only picked up by linux guests.  The exact parameters
        are specific to the guest OS being installed of course.

        After
        :rtype: str
        """
        return self._get_property('extraInstallKernelParameters')

    @property
    def detected_os_type_id(self):
        """The detected OS type ID (
        :rtype: str
        """
        return self._get_property('detectedOSTypeId')

    @property
    def detected_os_version(self):
        """The detected OS version string.

        Set by
        :rtype: str
        """
        return self._get_property('detectedOSVersion')

    @property
    def detected_os_flavor(self):
        """The detected OS flavor (e.g. server, desktop, etc)

        Set by
        :rtype: str
        """
        return self._get_property('detectedOSFlavor')

    @property
    def detected_os_languages(self):
        """The space separated list of (Windows) installation UI languages we detected (lang.ini).

        The language specifier format is specific to the guest OS.  They are
        used to set
        :rtype: str
        """
        return self._get_property('detectedOSLanguages')

    @property
    def detected_os_hints(self):
        """Space separated list of other stuff detected about the OS and the
        installation ISO.

        Set by
        :rtype: str
        """
        return self._get_property('detectedOSHints')


class InternalMachineControl(Interface):
    def update_state(self, state):
        """None
        :param MachineState state:
        """
        self._call_method('updateState', state)

    def begin_power_up(self, progress):
        """None
        :param Progress progress:
        """
        self._call_method('beginPowerUp', progress)

    def end_power_up(self, result):
        """None
        :param int result:
        """
        self._call_method('endPowerUp', result)

    def begin_powering_down(self):
        """None
        :rtype: Progress
        :returns:
            Progress object created by VBoxSVC to wait until
          the VM is powered down.
        """
        ret = self._call_method('beginPoweringDown')
        return ret

    def end_powering_down(self, result, err_msg):
        """None
        :param int result:
            @c S_OK to indicate success.
        :param str err_msg:
            @c human readable error message in case of failure.
        """
        self._call_method('endPoweringDown', result, err_msg)

    def run_usb_device_filters(self, device):
        """None
        :param USBDevice device:
        :rtype: typing.Tuple[bool, int]
        """
        matched, masked_interfaces = self._call_method('runUSBDeviceFilters', device)
        return matched, masked_interfaces

    def capture_usb_device(self, id_, capture_filename):
        """None
        :param str id_:
        :param str capture_filename:
        """
        self._call_method('captureUSBDevice', id_, capture_filename)

    def detach_usb_device(self, id_, done):
        """None
        :param str id_:
        :param bool done:
        """
        self._call_method('detachUSBDevice', id_, done)

    def auto_capture_usb_devices(self):
        """None
        """
        self._call_method('autoCaptureUSBDevices')

    def detach_all_usb_devices(self, done):
        """None
        :param bool done:
        """
        self._call_method('detachAllUSBDevices', done)

    def on_session_end(self, session):
        """None
        :param Session session:
            Session that is being closed
        :rtype: Progress
        :returns:
            Used to wait until the corresponding machine is actually
          dissociated from the given session on the server.
          Returned only when this session is a direct one.
        """
        ret = self._call_method('onSessionEnd', session)
        return ret

    def finish_online_merge_medium(self):
        """None
        """
        self._call_method('finishOnlineMergeMedium')

    def pull_guest_properties(self):
        """None
        :rtype: typing.List[typing.Tuple[str, str, int, str]]
        """
        names, values, timestamps, flags = self._call_method('pullGuestProperties')
        return names, values, timestamps, flags

    def push_guest_property(self, name, value, timestamp, flags):
        """None
        :param str name:
            The name of the property to be updated.
        :param str value:
            The value of the property.
        :param int timestamp:
            The timestamp of the property.
        :param str flags:
            The flags of the property.
        """
        self._call_method('pushGuestProperty', name, value, timestamp, flags)

    def lock_media(self):
        """None
        """
        self._call_method('lockMedia')

    def unlock_media(self):
        """None
        """
        self._call_method('unlockMedia')

    def eject_medium(self, attachment):
        """None
        :param MediumAttachment attachment:
            The medium attachment where the eject happened.
        :rtype: MediumAttachment
        :returns:
            A new reference to the medium attachment, as the config change can
          result in the creation of a new instance.
        """
        ret = self._call_method('ejectMedium', attachment)
        return ret

    def report_vm_statistics(self, valid_stats, cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total, vm_net_rx, vm_net_tx):
        """None
        :param int valid_stats:
            Mask defining which parameters are valid. For example: 0x11 means
          that cpuIdle and XXX are valid. Other parameters should be ignored.
        :param int cpu_user:
            Percentage of processor time spent in user mode as seen by the guest.
        :param int cpu_kernel:
            Percentage of processor time spent in kernel mode as seen by the guest.
        :param int cpu_idle:
            Percentage of processor time spent idling as seen by the guest.
        :param int mem_total:
            Total amount of physical guest RAM.
        :param int mem_free:
            Free amount of physical guest RAM.
        :param int mem_balloon:
            Amount of ballooned physical guest RAM.
        :param int mem_shared:
            Amount of shared physical guest RAM.
        :param int mem_cache:
            Total amount of guest (disk) cache memory.
        :param int paged_total:
            Total amount of space in the page file.
        :param int mem_alloc_total:
            Total amount of memory allocated by the hypervisor.
        :param int mem_free_total:
            Total amount of free memory available in the hypervisor.
        :param int mem_balloon_total:
            Total amount of memory ballooned by the hypervisor.
        :param int mem_shared_total:
            Total amount of shared memory in the hypervisor.
        :param int vm_net_rx:
            Network receive rate for VM.
        :param int vm_net_tx:
            Network transmit rate for VM.
        """
        self._call_method('reportVmStatistics', valid_stats, cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total, vm_net_rx, vm_net_tx)

    def authenticate_external(self, auth_params):
        """None
        :param typing.List[str] auth_params:
            The auth parameters, credentials, etc.
        :rtype: str
        :returns:
            The authentification result.
        """
        ret = self._call_method('authenticateExternal', auth_params)
        return ret


class BIOSSettings(Interface):
    """The IBIOSSettings interface represents BIOS settings of the virtual
        machine. This is used only in the
    """
    @property
    def logo_fade_in(self):
        """Fade in flag for BIOS logo animation.
        :rtype: bool
        """
        return self._get_property('logoFadeIn')

    @property
    def logo_fade_out(self):
        """Fade out flag for BIOS logo animation.
        :rtype: bool
        """
        return self._get_property('logoFadeOut')

    @property
    def logo_display_time(self):
        """BIOS logo display time in milliseconds (0 = default).
        :rtype: int
        """
        return self._get_property('logoDisplayTime')

    @property
    def logo_image_path(self):
        """Local file system path for external BIOS splash image. Empty string
        means the default image is shown on boot.
        :rtype: str
        """
        return self._get_property('logoImagePath')

    @property
    def boot_menu_mode(self):
        """Mode of the BIOS boot device menu.
        :rtype: BIOSBootMenuMode
        """
        return BIOSBootMenuMode(self._get_property('bootMenuMode'))

    @property
    def acpi_enabled(self):
        """ACPI support flag.
        :rtype: bool
        """
        return self._get_property('ACPIEnabled')

    @property
    def ioapic_enabled(self):
        """I/O-APIC support flag. If set, VirtualBox will provide an I/O-APIC
        and support IRQs above 15.
        :rtype: bool
        """
        return self._get_property('IOAPICEnabled')

    @property
    def apic_mode(self):
        """APIC mode to set up by the firmware.
        :rtype: APICMode
        """
        return APICMode(self._get_property('APICMode'))

    @property
    def time_offset(self):
        """Offset in milliseconds from the host system time. This allows for
        guests running with a different system date/time than the host.
        It is equivalent to setting the system date/time in the BIOS except
        it is not an absolute value but a relative one. Guest Additions
        time synchronization honors this offset.
        :rtype: int
        """
        return self._get_property('timeOffset')

    @property
    def pxe_debug_enabled(self):
        """PXE debug logging flag. If set, VirtualBox will write extensive
        PXE trace information to the release log.
        :rtype: bool
        """
        return self._get_property('PXEDebugEnabled')

    @property
    def non_volatile_storage_file(self):
        """The location of the file storing the non-volatile memory content when
        the VM is powered off.  The file does not always exist.

        This feature will be realized after VirtualBox v4.3.0.
        :rtype: str
        """
        return self._get_property('nonVolatileStorageFile')


class PCIAddress(Interface):
    """Address on the PCI bus.
    """
    def as_long(self):
        """None
        :rtype: int
        """
        ret = self._call_method('asLong')
        return ret

    def from_long(self, number):
        """None
        :param int number:
        """
        self._call_method('fromLong', number)

    @property
    def bus(self):
        """Bus number.
        :rtype: int
        """
        return self._get_property('bus')

    @property
    def device(self):
        """Device number.
        :rtype: int
        """
        return self._get_property('device')

    @property
    def dev_function(self):
        """Device function number.
        :rtype: int
        """
        return self._get_property('devFunction')


class PCIDeviceAttachment(Interface):
    """Information about PCI attachments.
    """
    @property
    def name(self):
        """Device name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def is_physical_device(self):
        """If this is physical or virtual device.
        :rtype: bool
        """
        return self._get_property('isPhysicalDevice')

    @property
    def host_address(self):
        """Address of device on the host, applicable only to host devices.
        :rtype: int
        """
        return self._get_property('hostAddress')

    @property
    def guest_address(self):
        """Address of device in the guest.
        :rtype: int
        """
        return self._get_property('guestAddress')


class GraphicsControllerType(enum.Enum):
    """Graphics controller type, used with 
     .. describe:: NULL Reserved value, invalid.
     .. describe:: VIRTUALBOX_VGA Default VirtualBox VGA device.
     .. describe:: VMSVGA VMware SVGA II device.
    """
    NULL = 0
    VIRTUALBOX_VGA = 1
    VMSVGA = 2

class CleanupMode(enum.Enum):
    """Cleanup mode, used with 
     .. describe:: UNREGISTER_ONLY Unregister only the machine, but neither delete snapshots nor detach media.
     .. describe:: DETACH_ALL_RETURN_NONE Delete all snapshots and detach all media but return none; this will keep all media registered.
     .. describe:: DETACH_ALL_RETURN_HARD_DISKS_ONLY Delete all snapshots, detach all media and return hard disks for closing, but not removable media.
     .. describe:: FULL Delete all snapshots, detach all media and return all media for closing.
    """
    UNREGISTER_ONLY = 1
    DETACH_ALL_RETURN_NONE = 2
    DETACH_ALL_RETURN_HARD_DISKS_ONLY = 3
    FULL = 4

class CloneMode(enum.Enum):
    """
    Clone mode, used with 
     .. describe:: MACHINE_STATE Clone the state of the selected machine.
     .. describe:: MACHINE_AND_CHILD_STATES Clone the state of the selected machine and its child snapshots if present.
     .. describe:: ALL_STATES Clone all states (including all snapshots) of the machine, regardless of the machine object used.
    """
    MACHINE_STATE = 1
    MACHINE_AND_CHILD_STATES = 2
    ALL_STATES = 3

class CloneOptions(enum.Enum):
    """
    Clone options, used with 
     .. describe:: LINK Create a clone VM where all virtual disks are linked to the original VM.
     .. describe:: KEEP_ALL_MA_CS Don't generate new MAC addresses of the attached network adapters.
     .. describe:: KEEP_NATMA_CS Don't generate new MAC addresses of the attached network adapters when they are using NAT.
     .. describe:: KEEP_DISK_NAMES Don't change the disk names.
    """
    LINK = 1
    KEEP_ALL_MA_CS = 2
    KEEP_NATMA_CS = 3
    KEEP_DISK_NAMES = 4

class AutostopType(enum.Enum):
    """
    Autostop types, used with 
     .. describe:: DISABLED Stopping the VM during system shutdown is disabled.
     .. describe:: SAVE_STATE The state of the VM will be saved when the system shuts down.
     .. describe:: POWER_OFF The VM is powered off when the system shuts down.
     .. describe:: ACPI_SHUTDOWN An ACPI shutdown event is generated.
    """
    DISABLED = 1
    SAVE_STATE = 2
    POWER_OFF = 3
    ACPI_SHUTDOWN = 4

class _Machine(Interface):
    """The IMachine interface represents a virtual machine, or guest, created
      in VirtualBox.

      This interface is used in two contexts. First of all, a collection of
      objects implementing this interface is stored in the
    """
    def lock_machine(self, session, lock_type):
        """None
        :param Session session:
            Session object for which the machine will be locked.
        :param LockType lock_type:
            If set to @c Write, then attempt to acquire an exclusive write lock or fail.
          If set to @c Shared, then either acquire an exclusive write lock or establish
          a link to an existing session.
        """
        self._call_method('lockMachine', session, lock_type)

    def launch_vm_process(self, session, name, environment):
        """None
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
        ret = self._call_method('launchVMProcess', session, name, environment)
        return ret

    def set_boot_order(self, position, device):
        """None
        :param int position:
            Position in the boot order (@c 1 to the total number of
          devices the machine can boot from, as returned by
        :param DeviceType device:
            The type of the device used to boot at the given position.
        """
        self._call_method('setBootOrder', position, device)

    def get_boot_order(self, position):
        """None
        :param int position:
            Position in the boot order (@c 1 to the total number of
          devices the machine can boot from, as returned by
        :rtype: DeviceType
        :returns:
            Device at the given position.
        """
        ret = self._call_method('getBootOrder', position)
        return ret

    def attach_device(self, name, controller_port, device, type_, medium):
        """None
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
        self._call_method('attachDevice', name, controller_port, device, type_, medium)

    def attach_device_without_medium(self, name, controller_port, device, type_):
        """None
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
        """
        self._call_method('attachDeviceWithoutMedium', name, controller_port, device, type_)

    def detach_device(self, name, controller_port, device):
        """None
        :param str name:
            Name of the storage controller to detach the medium from.
        :param int controller_port:
            Port number to detach the medium from.
        :param int device:
            Device slot number to detach the medium from.
        """
        self._call_method('detachDevice', name, controller_port, device)

    def passthrough_device(self, name, controller_port, device, passthrough):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        :param bool passthrough:
            New value for the passthrough setting.
        """
        self._call_method('passthroughDevice', name, controller_port, device, passthrough)

    def temporary_eject_device(self, name, controller_port, device, temporary_eject):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        :param bool temporary_eject:
            New value for the eject behavior.
        """
        self._call_method('temporaryEjectDevice', name, controller_port, device, temporary_eject)

    def non_rotational_device(self, name, controller_port, device, non_rotational):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        :param bool non_rotational:
            New value for the non-rotational device flag.
        """
        self._call_method('nonRotationalDevice', name, controller_port, device, non_rotational)

    def set_auto_discard_for_device(self, name, controller_port, device, discard):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        :param bool discard:
            New value for the discard device flag.
        """
        self._call_method('setAutoDiscardForDevice', name, controller_port, device, discard)

    def set_hot_pluggable_for_device(self, name, controller_port, device, hot_pluggable):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        :param bool hot_pluggable:
            New value for the hot-pluggable device flag.
        """
        self._call_method('setHotPluggableForDevice', name, controller_port, device, hot_pluggable)

    def set_bandwidth_group_for_device(self, name, controller_port, device, bandwidth_group):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        :param BandwidthGroup bandwidth_group:
            New value for the bandwidth group or @c null for no group.
        """
        self._call_method('setBandwidthGroupForDevice', name, controller_port, device, bandwidth_group)

    def set_no_bandwidth_group_for_device(self, name, controller_port, device):
        """None
        :param str name:
            Name of the storage controller.
        :param int controller_port:
            Storage controller port.
        :param int device:
            Device slot in the given port.
        """
        self._call_method('setNoBandwidthGroupForDevice', name, controller_port, device)

    def unmount_medium(self, name, controller_port, device, force):
        """None
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
        self._call_method('unmountMedium', name, controller_port, device, force)

    def mount_medium(self, name, controller_port, device, medium, force):
        """None
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
        self._call_method('mountMedium', name, controller_port, device, medium, force)

    def get_medium(self, name, controller_port, device):
        """None
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
        ret = self._call_method('getMedium', name, controller_port, device)
        return ret

    def get_medium_attachments_of_controller(self, name):
        """None
        :param str name:
        :rtype: typing.List[MediumAttachment]
        """
        ret = self._call_method('getMediumAttachmentsOfController', name)
        return ret

    def get_medium_attachment(self, name, controller_port, device):
        """None
        :param str name:
        :param int controller_port:
        :param int device:
        :rtype: MediumAttachment
        """
        ret = self._call_method('getMediumAttachment', name, controller_port, device)
        return ret

    def attach_host_pci_device(self, host_address, desired_guest_address, try_to_unbind):
        """None
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
        """None
        :param int host_address:
            Address of the host PCI device.
        """
        self._call_method('detachHostPCIDevice', host_address)

    def get_network_adapter(self, slot):
        """None
        :param int slot:
        :rtype: NetworkAdapter
        """
        ret = self._call_method('getNetworkAdapter', slot)
        return ret

    def add_storage_controller(self, name, connection_type):
        """None
        :param str name:
        :param StorageBus connection_type:
        :rtype: StorageController
        """
        ret = self._call_method('addStorageController', name, connection_type)
        return ret

    def get_storage_controller_by_name(self, name):
        """None
        :param str name:
        :rtype: StorageController
        """
        ret = self._call_method('getStorageControllerByName', name)
        return ret

    def get_storage_controller_by_instance(self, connection_type, instance):
        """None
        :param StorageBus connection_type:
        :param int instance:
        :rtype: StorageController
        """
        ret = self._call_method('getStorageControllerByInstance', connection_type, instance)
        return ret

    def remove_storage_controller(self, name):
        """None
        :param str name:
        """
        self._call_method('removeStorageController', name)

    def set_storage_controller_bootable(self, name, bootable):
        """None
        :param str name:
        :param bool bootable:
        """
        self._call_method('setStorageControllerBootable', name, bootable)

    def add_usb_controller(self, name, type_):
        """None
        :param str name:
        :param USBControllerType type_:
        :rtype: USBController
        """
        ret = self._call_method('addUSBController', name, type_)
        return ret

    def remove_usb_controller(self, name):
        """None
        :param str name:
        """
        self._call_method('removeUSBController', name)

    def get_usb_controller_by_name(self, name):
        """None
        :param str name:
        :rtype: USBController
        """
        ret = self._call_method('getUSBControllerByName', name)
        return ret

    def get_usb_controller_count_by_type(self, type_):
        """None
        :param USBControllerType type_:
        :rtype: int
        """
        ret = self._call_method('getUSBControllerCountByType', type_)
        return ret

    def get_serial_port(self, slot):
        """None
        :param int slot:
        :rtype: SerialPort
        """
        ret = self._call_method('getSerialPort', slot)
        return ret

    def get_parallel_port(self, slot):
        """None
        :param int slot:
        :rtype: ParallelPort
        """
        ret = self._call_method('getParallelPort', slot)
        return ret

    def get_extra_data_keys(self):
        """None
        :rtype: typing.List[str]
        :returns:
            Array of extra data keys.
        """
        ret = self._call_method('getExtraDataKeys')
        return ret

    def get_extra_data(self, key):
        """None
        :param str key:
            Name of the data key to get.
        :rtype: str
        :returns:
            Value of the requested data key.
        """
        ret = self._call_method('getExtraData', key)
        return ret

    def set_extra_data(self, key, value):
        """None
        :param str key:
            Name of the data key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setExtraData', key, value)

    def get_cpu_property(self, property_):
        """None
        :param CPUPropertyType property_:
            Property type to query.
        :rtype: bool
        :returns:
            Property value.
        """
        ret = self._call_method('getCPUProperty', property_)
        return ret

    def set_cpu_property(self, property_, value):
        """None
        :param CPUPropertyType property_:
            Property type to query.
        :param bool value:
            Property value.
        """
        self._call_method('setCPUProperty', property_, value)

    def get_cpuid_leaf_by_ordinal(self, ordinal):
        """None
        :param int ordinal:
            The ordinal number of the leaf to get.
        :rtype: typing.Tuple[int, int, int, int, int, int]
        """
        idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx = self._call_method('getCPUIDLeafByOrdinal', ordinal)
        return idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx

    def get_cpuid_leaf(self, idx, idx_sub):
        """None
        :param int idx:
            CPUID leaf index.
        :param int idx_sub:
            CPUID leaf sub-index (ECX).  Set to 0xffffffff (or 0) if not applicable.
        :rtype: typing.Tuple[int, int, int, int]
        """
        val_eax, val_ebx, val_ecx, val_edx = self._call_method('getCPUIDLeaf', idx, idx_sub)
        return val_eax, val_ebx, val_ecx, val_edx

    def set_cpuid_leaf(self, idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx):
        """None
        :param int idx:
            CPUID leaf index.
        :param int idx_sub:
            CPUID leaf sub-index (ECX).  Set to 0xffffffff (or 0) if not applicable.
          The 0xffffffff causes it to remove all other subleaves before adding one
          with sub-index 0.
        :param int val_eax:
            CPUID leaf value for register eax.
        :param int val_ebx:
            CPUID leaf value for register ebx.
        :param int val_ecx:
            CPUID leaf value for register ecx.
        :param int val_edx:
            CPUID leaf value for register edx.
        """
        self._call_method('setCPUIDLeaf', idx, idx_sub, val_eax, val_ebx, val_ecx, val_edx)

    def remove_cpuid_leaf(self, idx, idx_sub):
        """None
        :param int idx:
            CPUID leaf index.
        :param int idx_sub:
            CPUID leaf sub-index (ECX).  Set to 0xffffffff (or 0) if not applicable.
          The 0xffffffff value works like a wildcard.
        """
        self._call_method('removeCPUIDLeaf', idx, idx_sub)

    def remove_all_cpuid_leaves(self):
        """None
        """
        self._call_method('removeAllCPUIDLeaves')

    def get_hw_virt_ex_property(self, property_):
        """None
        :param HWVirtExPropertyType property_:
            Property type to query.
        :rtype: bool
        :returns:
            Property value.
        """
        ret = self._call_method('getHWVirtExProperty', property_)
        return ret

    def set_hw_virt_ex_property(self, property_, value):
        """None
        :param HWVirtExPropertyType property_:
            Property type to set.
        :param bool value:
            New property value.
        """
        self._call_method('setHWVirtExProperty', property_, value)

    def set_settings_file_path(self, settings_file_path):
        """None
        :param str settings_file_path:
            New settings file path, will be used to determine the new
        location for the attached media if it is in the same directory or
        below as the original settings file.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('setSettingsFilePath', settings_file_path)
        return ret

    def save_settings(self):
        """None
        """
        self._call_method('saveSettings')

    def discard_settings(self):
        """None
        """
        self._call_method('discardSettings')

    def unregister(self, cleanup_mode):
        """None
        :param CleanupMode cleanup_mode:
            How to clean up after the machine has been unregistered.
        :rtype: typing.List[Medium]
        :returns:
            List of media detached from the machine, depending on the @a cleanupMode parameter.
        """
        ret = self._call_method('unregister', cleanup_mode)
        return ret

    def delete_config(self, media):
        """None
        :param typing.List[Medium] media:
            List of media to be closed and whose storage files will be deleted.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('deleteConfig', media)
        return ret

    def export_to(self, appliance, location):
        """None
        :param Appliance appliance:
            Appliance to export this machine to.
        :param str location:
            The target location.
        :rtype: VirtualSystemDescription
        :returns:
            VirtualSystemDescription object which is created for this machine.
        """
        ret = self._call_method('exportTo', appliance, location)
        return ret

    def find_snapshot(self, name_or_id):
        """None
        :param str name_or_id:
            What to search for. Name or UUID of the snapshot to find
        :rtype: Snapshot
        :returns:
            Snapshot object with the given name.
        """
        ret = self._call_method('findSnapshot', name_or_id)
        return ret

    def create_shared_folder(self, name, host_path, writable, automount):
        """None
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
        """None
        :param str name:
            Logical name of the shared folder to remove.
        """
        self._call_method('removeSharedFolder', name)

    def can_show_console_window(self):
        """None
        :rtype: bool
        :returns:
            @c true if the console window can be shown and @c false otherwise.
        """
        ret = self._call_method('canShowConsoleWindow')
        return ret

    def show_console_window(self):
        """None
        :rtype: int
        :returns:
            Platform-dependent identifier of the top-level VM console
          window, or zero if this method has performed all actions
          necessary to implement the
        """
        ret = self._call_method('showConsoleWindow')
        return ret

    def get_guest_property(self, name):
        """None
        :param str name:
            The name of the property to read.
        :rtype: typing.Tuple[str, int, str]
        """
        value, timestamp, flags = self._call_method('getGuestProperty', name)
        return value, timestamp, flags

    def get_guest_property_value(self, property_):
        """None
        :param str property_:
            The name of the property to read.
        :rtype: str
        :returns:
            The value of the property. If the property does not exist then this
          will be empty.
        """
        ret = self._call_method('getGuestPropertyValue', property_)
        return ret

    def get_guest_property_timestamp(self, property_):
        """None
        :param str property_:
            The name of the property to read.
        :rtype: int
        :returns:
            The timestamp. If the property does not exist then this will be
          empty.
        """
        ret = self._call_method('getGuestPropertyTimestamp', property_)
        return ret

    def set_guest_property(self, property_, value, flags):
        """None
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
        """None
        :param str property_:
            The name of the property to set or change.
        :param str value:
            The new value of the property to set or change. If the
          property does not yet exist and value is non-empty, it will be
          created.
        """
        self._call_method('setGuestPropertyValue', property_, value)

    def delete_guest_property(self, name):
        """None
        :param str name:
            The name of the property to delete.
        """
        self._call_method('deleteGuestProperty', name)

    def enumerate_guest_properties(self, patterns):
        """None
        :param str patterns:
            The patterns to match the properties against, separated by '|'
          characters. If this is empty or @c null, all properties will match.
        :rtype: typing.List[typing.Tuple[str, str, int, str]]
        """
        names, values, timestamps, flags = self._call_method('enumerateGuestProperties', patterns)
        return names, values, timestamps, flags

    def query_saved_guest_screen_info(self, screen_id):
        """None
        :param int screen_id:
            Saved guest screen to query info from.
        :rtype: typing.Tuple[int, int, int, int, bool]
        """
        origin_x, origin_y, width, height, enabled = self._call_method('querySavedGuestScreenInfo', screen_id)
        return origin_x, origin_y, width, height, enabled

    def read_saved_thumbnail_to_array(self, screen_id, bitmap_format):
        """None
        :param int screen_id:
            Saved guest screen to read from.
        :param BitmapFormat bitmap_format:
            The requested format.
        :rtype: typing.Tuple[typing.List[bytes], int, int]
        """
        data, width, height = self._call_method('readSavedThumbnailToArray', screen_id, bitmap_format)
        return data, width, height

    def query_saved_screenshot_info(self, screen_id):
        """None
        :param int screen_id:
            Saved guest screen to query info from.
        :rtype: typing.Tuple[typing.List[BitmapFormat], int, int]
        """
        bitmap_formats, width, height = self._call_method('querySavedScreenshotInfo', screen_id)
        bitmap_formats = BitmapFormat(bitmap_formats)
        return bitmap_formats, width, height

    def read_saved_screenshot_to_array(self, screen_id, bitmap_format):
        """None
        :param int screen_id:
            Saved guest screen to read from.
        :param BitmapFormat bitmap_format:
            The requested format.
        :rtype: typing.Tuple[typing.List[bytes], int, int]
        """
        data, width, height = self._call_method('readSavedScreenshotToArray', screen_id, bitmap_format)
        return data, width, height

    def hot_plug_cpu(self, cpu):
        """None
        :param int cpu:
            The CPU id to insert.
        """
        self._call_method('hotPlugCPU', cpu)

    def hot_unplug_cpu(self, cpu):
        """None
        :param int cpu:
            The CPU id to remove.
        """
        self._call_method('hotUnplugCPU', cpu)

    def get_cpu_status(self, cpu):
        """None
        :param int cpu:
            The CPU id to check for.
        :rtype: bool
        :returns:
            Status of the CPU.
        """
        ret = self._call_method('getCPUStatus', cpu)
        return ret

    def get_effective_paravirt_provider(self):
        """None
        :rtype: ParavirtProvider
        :returns:
            The effective paravirtualization provider for this VM.
        """
        ret = self._call_method('getEffectiveParavirtProvider')
        return ret

    def query_log_filename(self, idx):
        """None
        :param int idx:
            Which log file name to query. 0=current log file.
        :rtype: str
        :returns:
            On return the full path to the log file or an empty string on error.
        """
        ret = self._call_method('queryLogFilename', idx)
        return ret

    def read_log(self, idx, offset, size):
        """None
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
        ret = self._call_method('readLog', idx, offset, size)
        return ret

    def clone_to(self, target, mode, options):
        """None
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
        ret = self._call_method('cloneTo', target, mode, options)
        return ret

    def move_to(self, folder, type_):
        """None
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
        ret = self._call_method('moveTo', folder, type_)
        return ret

    def save_state(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('saveState')
        return ret

    def adopt_saved_state(self, saved_state_file):
        """None
        :param str saved_state_file:
            Path to the saved state file to adopt.
        """
        self._call_method('adoptSavedState', saved_state_file)

    def discard_saved_state(self, f_remove_file):
        """None
        :param bool f_remove_file:
            Whether to also remove the saved state file.
        """
        self._call_method('discardSavedState', f_remove_file)

    def take_snapshot(self, name, description, pause):
        """None
        :param str name:
            Short name for the snapshot.
        :param str description:
            Optional description of the snapshot.
        :param bool pause:
            Whether the VM should be paused while taking the snapshot. Only
          relevant when the VM is running, and distinguishes between online
          (@c true) and live (@c false) snapshots. When the VM is not running
          the result is always an offline snapshot.
        :rtype: typing.Tuple[Progress, str]
        """
        progress, id_ = self._call_method('takeSnapshot', name, description, pause)
        progress = Progress(progress)
        return progress, id_

    def delete_snapshot(self, id_):
        """None
        :param str id_:
            UUID of the snapshot to delete.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('deleteSnapshot', id_)
        return ret

    def delete_snapshot_and_all_children(self, id_):
        """None
        :param str id_:
            UUID of the snapshot to delete, including all its children.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('deleteSnapshotAndAllChildren', id_)
        return ret

    def delete_snapshot_range(self, start_id, end_id):
        """None
        :param str start_id:
            UUID of the first snapshot to delete.
        :param str end_id:
            UUID of the last snapshot to delete.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('deleteSnapshotRange', start_id, end_id)
        return ret

    def restore_snapshot(self, snapshot):
        """None
        :param Snapshot snapshot:
            The snapshot to restore the VM state from.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('restoreSnapshot', snapshot)
        return ret

    def apply_defaults(self, flags):
        """None
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
    def cpu_count(self):
        """Number of virtual CPUs in the VM.
        :rtype: int
        """
        return self._get_property('CPUCount')

    @property
    def cpu_hot_plug_enabled(self):
        """This setting determines whether VirtualBox allows CPU
        hotplugging for this machine.
        :rtype: bool
        """
        return self._get_property('CPUHotPlugEnabled')

    @property
    def cpu_execution_cap(self):
        """Means to limit the number of CPU cycles a guest can use. The unit
        is percentage of host CPU cycles per second. The valid range
        is 1 - 100. 100 (the default) implies no limit.
        :rtype: int
        """
        return self._get_property('CPUExecutionCap')

    @property
    def cpuid_portability_level(self):
        """Virtual CPUID portability level, the higher number the fewer newer
        or vendor specific CPU feature is reported to the guest (via the CPUID
        instruction).  The default level of zero (0) means that all virtualized
        feautres supported by the host is pass thru to the guest.  While the
        three (3) is currently the level supressing the most features.

        Exactly which of the CPUID features are left out by the VMM at which
        level is subject to change with each major version.
        :rtype: int
        """
        return self._get_property('CPUIDPortabilityLevel')

    @property
    def memory_size(self):
        """System memory size in megabytes.
        :rtype: int
        """
        return self._get_property('memorySize')

    @property
    def memory_balloon_size(self):
        """Memory balloon size in megabytes.
        :rtype: int
        """
        return self._get_property('memoryBalloonSize')

    @property
    def page_fusion_enabled(self):
        """This setting determines whether VirtualBox allows page
        fusion for this machine (64-bit hosts only).
        :rtype: bool
        """
        return self._get_property('pageFusionEnabled')

    @property
    def graphics_controller_type(self):
        """Graphics controller type.
        :rtype: GraphicsControllerType
        """
        return GraphicsControllerType(self._get_property('graphicsControllerType'))

    @property
    def vram_size(self):
        """Video memory size in megabytes.
        :rtype: int
        """
        return self._get_property('VRAMSize')

    @property
    def accelerate_3d_enabled(self):
        """This setting determines whether VirtualBox allows this machine to make
        use of the 3D graphics support available on the host.
        :rtype: bool
        """
        return self._get_property('accelerate3DEnabled')

    @property
    def accelerate_2d_video_enabled(self):
        """This setting determines whether VirtualBox allows this machine to make
        use of the 2D video acceleration support available on the host.
        :rtype: bool
        """
        return self._get_property('accelerate2DVideoEnabled')

    @property
    def monitor_count(self):
        """Number of virtual monitors.
        :rtype: int
        """
        return self._get_property('monitorCount')

    @property
    def video_capture_enabled(self):
        """This setting determines whether VirtualBox uses video capturing to
        record a VM session.
        :rtype: bool
        """
        return self._get_property('videoCaptureEnabled')

    @property
    def video_capture_screens(self):
        """This setting determines for which screens video capturing is
        enabled.
        :rtype: typing.List[bool]
        """
        return list(self._get_property('videoCaptureScreens'))

    @property
    def video_capture_file(self):
        """This setting determines the filename VirtualBox uses to save
        the recorded content. This setting cannot be changed while video
        capturing is enabled.
        :rtype: str
        """
        return self._get_property('videoCaptureFile')

    @property
    def video_capture_width(self):
        """This setting determines the horizontal resolution of the recorded
        video. This setting cannot be changed while video capturing is
        enabled.
        :rtype: int
        """
        return self._get_property('videoCaptureWidth')

    @property
    def video_capture_height(self):
        """This setting determines the vertical resolution of the recorded
        video. This setting cannot be changed while video capturing is
        enabled.
        :rtype: int
        """
        return self._get_property('videoCaptureHeight')

    @property
    def video_capture_rate(self):
        """This setting determines the bitrate in kilobits per second.
        Increasing this value makes the video look better for the
        cost of an increased file size. This setting cannot be changed
        while video capturing is enabled.
        :rtype: int
        """
        return self._get_property('videoCaptureRate')

    @property
    def video_capture_fps(self):
        """This setting determines the maximum number of frames per second.
        Frames with a higher frequency will be skipped. Reducing this
        value increases the number of skipped frames and reduces the
        file size. This setting cannot be changed while video capturing
        is enabled.
        :rtype: int
        """
        return self._get_property('videoCaptureFPS')

    @property
    def video_capture_max_time(self):
        """This setting determines the maximum amount of time in milliseconds
        the video capture will work for. The capture stops as the defined time
        interval  has elapsed. If this value is zero the capturing will not be
        limited by time. This setting cannot be changed while video capturing is
        enabled.
        :rtype: int
        """
        return self._get_property('videoCaptureMaxTime')

    @property
    def video_capture_max_file_size(self):
        """This setting determines the maximal number of captured video file
        size in MB. The capture stops as the captured video file size
        has reached the defined. If this value is zero the capturing
        will not be limited by file size. This setting cannot be changed
        while video capturing is enabled.
        :rtype: int
        """
        return self._get_property('videoCaptureMaxFileSize')

    @property
    def video_capture_options(self):
        """This setting contains any additional video capture options
        required in comma-separated key=value format. This setting
        cannot be changed while video capturing is enabled.

        The following keys and their corresponding values are available:
        :rtype: str
        """
        return self._get_property('videoCaptureOptions')

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
    def current_snapshot(self):
        """Current snapshot of this machine. This is @c null if the machine
        currently has no snapshots. If it is not @c null, then it was
        set by one of
        :rtype: Snapshot
        """
        return Snapshot(self._get_property('currentSnapshot'))

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

class Machine(_Machine):
    pass

class EmulatedUSB(Interface):
    """Manages emulated USB devices.
    """
    def webcam_attach(self, path, settings):
        """None
        :param str path:
            The host path of the capture device to use.
        :param str settings:
            Optional settings.
        """
        self._call_method('webcamAttach', path, settings)

    def webcam_detach(self, path):
        """None
        :param str path:
            The host path of the capture device to detach.
        """
        self._call_method('webcamDetach', path)

    @property
    def webcams(self):
        """Lists attached virtual webcams.
        :rtype: typing.List[str]
        """
        return list(self._get_property('webcams'))


class VRDEServerInfo(Interface):
    """Contains information about the remote desktop (VRDE) server capabilities and status.
      This is used in the
    """
    @property
    def active(self):
        """Whether the remote desktop connection is active.
        :rtype: bool
        """
        return self._get_property('active')

    @property
    def port(self):
        """VRDE server port number. If this property is equal to
        :rtype: int
        """
        return self._get_property('port')

    @property
    def number_of_clients(self):
        """How many times a client connected.
        :rtype: int
        """
        return self._get_property('numberOfClients')

    @property
    def begin_time(self):
        """When the last connection was established, in milliseconds since 1970-01-01 UTC.
        :rtype: int
        """
        return self._get_property('beginTime')

    @property
    def end_time(self):
        """When the last connection was terminated or the current time, if
        connection is still active, in milliseconds since 1970-01-01 UTC.
        :rtype: int
        """
        return self._get_property('endTime')

    @property
    def bytes_sent(self):
        """How many bytes were sent in last or current, if still active, connection.
        :rtype: int
        """
        return self._get_property('bytesSent')

    @property
    def bytes_sent_total(self):
        """How many bytes were sent in all connections.
        :rtype: int
        """
        return self._get_property('bytesSentTotal')

    @property
    def bytes_received(self):
        """How many bytes were received in last or current, if still active, connection.
        :rtype: int
        """
        return self._get_property('bytesReceived')

    @property
    def bytes_received_total(self):
        """How many bytes were received in all connections.
        :rtype: int
        """
        return self._get_property('bytesReceivedTotal')

    @property
    def user(self):
        """Login user name supplied by the client.
        :rtype: str
        """
        return self._get_property('user')

    @property
    def domain(self):
        """Login domain name supplied by the client.
        :rtype: str
        """
        return self._get_property('domain')

    @property
    def client_name(self):
        """The client name supplied by the client.
        :rtype: str
        """
        return self._get_property('clientName')

    @property
    def client_ip(self):
        """The IP address of the client.
        :rtype: str
        """
        return self._get_property('clientIP')

    @property
    def client_version(self):
        """The client software version number.
        :rtype: int
        """
        return self._get_property('clientVersion')

    @property
    def encryption_style(self):
        """Public key exchange method used when connection was established.
        Values: 0 - RDP4 public key exchange scheme.
        1 - X509 certificates were sent to client.
        :rtype: int
        """
        return self._get_property('encryptionStyle')


class Console(Interface):
    """The IConsole interface represents an interface to control virtual
      machine execution.

      A console object gets created when a machine has been locked for a
      particular session (client process) using
    """
    def power_up(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('powerUp')
        return ret

    def power_up_paused(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('powerUpPaused')
        return ret

    def power_down(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('powerDown')
        return ret

    def reset(self):
        """None
        """
        self._call_method('reset')

    def pause(self):
        """None
        """
        self._call_method('pause')

    def resume(self):
        """None
        """
        self._call_method('resume')

    def power_button(self):
        """None
        """
        self._call_method('powerButton')

    def sleep_button(self):
        """None
        """
        self._call_method('sleepButton')

    def get_power_button_handled(self):
        """None
        :rtype: bool
        """
        ret = self._call_method('getPowerButtonHandled')
        return ret

    def get_guest_entered_acpi_mode(self):
        """None
        :rtype: bool
        """
        ret = self._call_method('getGuestEnteredACPIMode')
        return ret

    def get_device_activity(self, type_):
        """None
        :param typing.List[DeviceType] type_:
        :rtype: typing.List[DeviceActivity]
        """
        ret = self._call_method('getDeviceActivity', type_)
        return ret

    def attach_usb_device(self, id_, capture_filename):
        """None
        :param str id_:
            UUID of the host USB device to attach.
        :param str capture_filename:
            Filename to capture the USB traffic to.
        """
        self._call_method('attachUSBDevice', id_, capture_filename)

    def detach_usb_device(self, id_):
        """None
        :param str id_:
            UUID of the USB device to detach.
        :rtype: USBDevice
        :returns:
            Detached USB device.
        """
        ret = self._call_method('detachUSBDevice', id_)
        return ret

    def find_usb_device_by_address(self, name):
        """None
        :param str name:
            Address of the USB device (as assigned by the host) to
          search for.
        :rtype: USBDevice
        :returns:
            Found USB device object.
        """
        ret = self._call_method('findUSBDeviceByAddress', name)
        return ret

    def find_usb_device_by_id(self, id_):
        """None
        :param str id_:
            UUID of the USB device to search for.
        :rtype: USBDevice
        :returns:
            Found USB device object.
        """
        ret = self._call_method('findUSBDeviceById', id_)
        return ret

    def create_shared_folder(self, name, host_path, writable, automount):
        """None
        :param str name:
            Unique logical name of the shared folder.
        :param str host_path:
            Full path to the shared folder in the host file system.
        :param bool writable:
            Whether the share is writable or readonly
        :param bool automount:
            Whether the share gets automatically mounted by the guest
          or not.
        """
        self._call_method('createSharedFolder', name, host_path, writable, automount)

    def remove_shared_folder(self, name):
        """None
        :param str name:
            Logical name of the shared folder to remove.
        """
        self._call_method('removeSharedFolder', name)

    def teleport(self, hostname, tcpport, password, max_downtime):
        """None
        :param str hostname:
            The name or IP of the host to teleport to.
        :param int tcpport:
            The TCP port to connect to (1..65535).
        :param str password:
            The password.
        :param int max_downtime:
            The maximum allowed downtime given as milliseconds. 0 is not a valid
          value. Recommended value: 250 ms.

          The higher the value is, the greater the chance for a successful
          teleportation. A small value may easily result in the teleportation
          process taking hours and eventually fail.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('teleport', hostname, tcpport, password, max_downtime)
        return ret

    def add_disk_encryption_password(self, id_, password, clear_on_suspend):
        """None
        :param str id_:
            The identifier used for the password. Must match the identifier
          used when the encrypted medium was created.
        :param str password:
            The password.
        :param bool clear_on_suspend:
            Flag whether to clear the password on VM suspend (due to a suspending host
          for example). The password must be supplied again before the VM can resume.
        """
        self._call_method('addDiskEncryptionPassword', id_, password, clear_on_suspend)

    def add_disk_encryption_passwords(self, ids, passwords, clear_on_suspend):
        """None
        :param typing.List[str] ids:
            List of identifiers for the passwords. Must match the identifier
          used when the encrypted medium was created.
        :param typing.List[str] passwords:
            List of passwords.
        :param bool clear_on_suspend:
            Flag whether to clear the given passwords on VM suspend (due to a suspending host
          for example). The passwords must be supplied again before the VM can resume.
        """
        self._call_method('addDiskEncryptionPasswords', ids, passwords, clear_on_suspend)

    def remove_disk_encryption_password(self, id_):
        """None
        :param str id_:
            The identifier used for the password. Must match the identifier
          used when the encrypted medium was created.
        """
        self._call_method('removeDiskEncryptionPassword', id_)

    def clear_all_disk_encryption_passwords(self):
        """None
        """
        self._call_method('clearAllDiskEncryptionPasswords')

    @property
    def machine(self):
        """Machine object for this console session.
        :rtype: Machine
        """
        return Machine(self._get_property('machine'))

    @property
    def state(self):
        """Current execution state of the machine.
        :rtype: MachineState
        """
        return MachineState(self._get_property('state'))

    @property
    def guest(self):
        """Guest object.
        :rtype: Guest
        """
        return Guest(self._get_property('guest'))

    @property
    def keyboard(self):
        """Virtual keyboard object.
        :rtype: Keyboard
        """
        return Keyboard(self._get_property('keyboard'))

    @property
    def mouse(self):
        """Virtual mouse object.
        :rtype: Mouse
        """
        return Mouse(self._get_property('mouse'))

    @property
    def display(self):
        """Virtual display object.
        :rtype: Display
        """
        return Display(self._get_property('display'))

    @property
    def debugger(self):
        """Debugging interface.
        :rtype: MachineDebugger
        """
        return MachineDebugger(self._get_property('debugger'))

    @property
    def usb_devices(self):
        """Collection of USB devices currently attached to the virtual
        USB controller.
        :rtype: typing.List[USBDevice]
        """
        return [USBDevice(obj) for obj in self._get_property('USBDevices')]

    @property
    def remote_usb_devices(self):
        """List of USB devices currently attached to the remote VRDE client.
        Once a new device is physically attached to the remote host computer,
        it appears in this list and remains there until detached.
        :rtype: typing.List[HostUSBDevice]
        """
        return [HostUSBDevice(obj) for obj in self._get_property('remoteUSBDevices')]

    @property
    def shared_folders(self):
        """Collection of shared folders for the current session. These folders
        are called transient shared folders because they are available to the
        guest OS running inside the associated virtual machine only for the
        duration of the session (as opposed to
        :rtype: typing.List[SharedFolder]
        """
        return [SharedFolder(obj) for obj in self._get_property('sharedFolders')]

    @property
    def vrde_server_info(self):
        """Interface that provides information on Remote Desktop Extension (VRDE) connection.
        :rtype: VRDEServerInfo
        """
        return VRDEServerInfo(self._get_property('VRDEServerInfo'))

    @property
    def event_source(self):
        """Event source for console events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def attached_pci_devices(self):
        """Array of PCI devices attached to this machine.
        :rtype: typing.List[PCIDeviceAttachment]
        """
        return [PCIDeviceAttachment(obj) for obj in self._get_property('attachedPCIDevices')]

    @property
    def use_host_clipboard(self):
        """Whether the guest clipboard should be connected to the host one or
        whether it should only be allowed access to the VRDE clipboard. This
        setting may not affect existing guest clipboard connections which
        are already connected to the host clipboard.
        :rtype: bool
        """
        return self._get_property('useHostClipboard')

    @property
    def emulated_usb(self):
        """Interface that manages emulated USB devices.
        :rtype: EmulatedUSB
        """
        return EmulatedUSB(self._get_property('emulatedUSB'))


class HostNetworkInterfaceMediumType(enum.Enum):
    """
      Type of encapsulation. Ethernet encapsulation includes both wired and
      wireless Ethernet connections.
      
     .. describe:: UNKNOWN 
        The type of interface cannot be determined.
      
     .. describe:: ETHERNET 
        Ethernet frame encapsulation.
      
     .. describe:: PPP 
        Point-to-point protocol encapsulation.
      
     .. describe:: SLIP 
        Serial line IP encapsulation.
      
    """
    UNKNOWN = 0
    ETHERNET = 1
    PPP = 2
    SLIP = 3

class HostNetworkInterfaceStatus(enum.Enum):
    """
      Current status of the interface.
      
     .. describe:: UNKNOWN 
        The state of interface cannot be determined.
      
     .. describe:: UP 
        The interface is fully operational.
      
     .. describe:: DOWN 
        The interface is not functioning.
      
    """
    UNKNOWN = 0
    UP = 1
    DOWN = 2

class HostNetworkInterfaceType(enum.Enum):
    """
      Network interface type.
    
    """
    BRIDGED = 1
    HOST_ONLY = 2

class HostNetworkInterface(Interface):
    """Represents one of host's network interfaces. IP V6 address and network
      mask are strings of 32 hexadecimal digits grouped by four. Groups are
      separated by colons.
      For example, fe80:0000:0000:0000:021e:c2ff:fed2:b030.
    """
    def enable_static_ip_config(self, ip_address, network_mask):
        """None
        :param str ip_address:
            IP address.
        :param str network_mask:
            network mask.
        """
        self._call_method('enableStaticIPConfig', ip_address, network_mask)

    def enable_static_ip_config_v6(self, ipv6_address, ipv6_network_mask_prefix_length):
        """None
        :param str ipv6_address:
            IP address.
        :param int ipv6_network_mask_prefix_length:
            network mask.
        """
        self._call_method('enableStaticIPConfigV6', ipv6_address, ipv6_network_mask_prefix_length)

    def enable_dynamic_ip_config(self):
        """None
        """
        self._call_method('enableDynamicIPConfig')

    def dhcp_rediscover(self):
        """None
        """
        self._call_method('DHCPRediscover')

    @property
    def name(self):
        """Returns the host network interface name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def short_name(self):
        """Returns the host network interface short name.
        :rtype: str
        """
        return self._get_property('shortName')

    @property
    def id_(self):
        """Returns the interface UUID.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def network_name(self):
        """Returns the name of a virtual network the interface gets attached to.
        :rtype: str
        """
        return self._get_property('networkName')

    @property
    def dhcp_enabled(self):
        """Specifies whether the DHCP is enabled for the interface.
        :rtype: bool
        """
        return self._get_property('DHCPEnabled')

    @property
    def ip_address(self):
        """Returns the IP V4 address of the interface.
        :rtype: str
        """
        return self._get_property('IPAddress')

    @property
    def network_mask(self):
        """Returns the network mask of the interface.
        :rtype: str
        """
        return self._get_property('networkMask')

    @property
    def ipv6_supported(self):
        """Specifies whether the IP V6 is supported/enabled for the interface.
        :rtype: bool
        """
        return self._get_property('IPV6Supported')

    @property
    def ipv6_address(self):
        """Returns the IP V6 address of the interface.
        :rtype: str
        """
        return self._get_property('IPV6Address')

    @property
    def ipv6_network_mask_prefix_length(self):
        """Returns the length IP V6 network mask prefix of the interface.
        :rtype: int
        """
        return self._get_property('IPV6NetworkMaskPrefixLength')

    @property
    def hardware_address(self):
        """Returns the hardware address. For Ethernet it is MAC address.
        :rtype: str
        """
        return self._get_property('hardwareAddress')

    @property
    def medium_type(self):
        """Type of protocol encapsulation used.
        :rtype: HostNetworkInterfaceMediumType
        """
        return HostNetworkInterfaceMediumType(self._get_property('mediumType'))

    @property
    def status(self):
        """Status of the interface.
        :rtype: HostNetworkInterfaceStatus
        """
        return HostNetworkInterfaceStatus(self._get_property('status'))

    @property
    def interface_type(self):
        """specifies the host interface type.
        :rtype: HostNetworkInterfaceType
        """
        return HostNetworkInterfaceType(self._get_property('interfaceType'))

    @property
    def wireless(self):
        """Specifies whether the interface is wireless.
        :rtype: bool
        """
        return self._get_property('wireless')


class HostVideoInputDevice(Interface):
    """Represents one of host's video capture devices, for example a webcam.
    """
    @property
    def name(self):
        """User friendly name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def path(self):
        """The host path of the device.
        :rtype: str
        """
        return self._get_property('path')

    @property
    def alias(self):
        """An alias which can be used for IConsole::webcamAttach
        :rtype: str
        """
        return self._get_property('alias')


class Host(Interface):
    """The IHost interface represents the physical machine that this VirtualBox
      installation runs on.

      An object implementing this interface is returned by the
    """
    def get_processor_speed(self, cpu_id):
        """None
        :param int cpu_id:
            Identifier of the CPU.
        :rtype: int
        :returns:
            Speed value. 0 is returned if value is not known or @a cpuId is
          invalid.
        """
        ret = self._call_method('getProcessorSpeed', cpu_id)
        return ret

    def get_processor_feature(self, feature):
        """None
        :param ProcessorFeature feature:
            CPU Feature identifier.
        :rtype: bool
        :returns:
            Feature is supported or not.
        """
        ret = self._call_method('getProcessorFeature', feature)
        return ret

    def get_processor_description(self, cpu_id):
        """None
        :param int cpu_id:
            Identifier of the CPU.
        :rtype: str
        :returns:
            Model string. An empty string is returned if value is not known or
          @a cpuId is invalid.
        """
        ret = self._call_method('getProcessorDescription', cpu_id)
        return ret

    def get_processor_cpuid_leaf(self, cpu_id, leaf, sub_leaf):
        """None
        :param int cpu_id:
            Identifier of the CPU. The CPU most be online.
        :param int leaf:
            CPUID leaf index (eax).
        :param int sub_leaf:
            CPUID leaf sub index (ecx). This currently only applies to cache
          information on Intel CPUs. Use 0 if retrieving values for
        :rtype: typing.Tuple[int, int, int, int]
        """
        val_eax, val_ebx, val_ecx, val_edx = self._call_method('getProcessorCPUIDLeaf', cpu_id, leaf, sub_leaf)
        return val_eax, val_ebx, val_ecx, val_edx

    def create_host_only_network_interface(self):
        """None
        :rtype: typing.Tuple[Progress, HostNetworkInterface]
        """
        progress, host_interface = self._call_method('createHostOnlyNetworkInterface')
        progress = Progress(progress)
        host_interface = HostNetworkInterface(host_interface)
        return progress, host_interface

    def remove_host_only_network_interface(self, id_):
        """None
        :param str id_:
            Adapter GUID.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('removeHostOnlyNetworkInterface', id_)
        return ret

    def create_usb_device_filter(self, name):
        """None
        :param str name:
            Filter name. See
        :rtype: HostUSBDeviceFilter
        :returns:
            Created filter object.
        """
        ret = self._call_method('createUSBDeviceFilter', name)
        return ret

    def insert_usb_device_filter(self, position, filter_):
        """None
        :param int position:
            Position to insert the filter to.
        :param HostUSBDeviceFilter filter_:
            USB device filter to insert.
        """
        self._call_method('insertUSBDeviceFilter', position, filter_)

    def remove_usb_device_filter(self, position):
        """None
        :param int position:
            Position to remove the filter from.
        """
        self._call_method('removeUSBDeviceFilter', position)

    def find_host_dvd_drive(self, name):
        """None
        :param str name:
            Name of the host drive to search for
        :rtype: Medium
        :returns:
            Found host drive object
        """
        ret = self._call_method('findHostDVDDrive', name)
        return ret

    def find_host_floppy_drive(self, name):
        """None
        :param str name:
            Name of the host floppy drive to search for
        :rtype: Medium
        :returns:
            Found host floppy drive object
        """
        ret = self._call_method('findHostFloppyDrive', name)
        return ret

    def find_host_network_interface_by_name(self, name):
        """None
        :param str name:
            Name of the host network interface to search for.
        :rtype: HostNetworkInterface
        :returns:
            Found host network interface object.
        """
        ret = self._call_method('findHostNetworkInterfaceByName', name)
        return ret

    def find_host_network_interface_by_id(self, id_):
        """None
        :param str id_:
            GUID of the host network interface to search for.
        :rtype: HostNetworkInterface
        :returns:
            Found host network interface object.
        """
        ret = self._call_method('findHostNetworkInterfaceById', id_)
        return ret

    def find_host_network_interfaces_of_type(self, type_):
        """None
        :param HostNetworkInterfaceType type_:
            type of the host network interfaces to search for.
        :rtype: typing.List[HostNetworkInterface]
        :returns:
            Found host network interface objects.
        """
        ret = self._call_method('findHostNetworkInterfacesOfType', type_)
        return ret

    def find_usb_device_by_id(self, id_):
        """None
        :param str id_:
            UUID of the USB device to search for.
        :rtype: HostUSBDevice
        :returns:
            Found USB device object.
        """
        ret = self._call_method('findUSBDeviceById', id_)
        return ret

    def find_usb_device_by_address(self, name):
        """None
        :param str name:
            Address of the USB device (as assigned by the host) to
          search for.
        :rtype: HostUSBDevice
        :returns:
            Found USB device object.
        """
        ret = self._call_method('findUSBDeviceByAddress', name)
        return ret

    def generate_mac_address(self):
        """None
        :rtype: str
        :returns:
            New Ethernet MAC address.
        """
        ret = self._call_method('generateMACAddress')
        return ret

    def add_usb_device_source(self, backend, id_, address, property_names, property_values):
        """None
        :param str backend:
            The backend to use as the new device source.
        :param str id_:
            Unique ID to identify the source.
        :param str address:
            Address to use, the format is dependent on the backend.
          For USB/IP backends for example the notation is host[:port].
        :param typing.List[str] property_names:
            Array of property names for more detailed configuration. Not used at the moment.
        :param typing.List[str] property_values:
            Array of property values for more detailed configuration. Not used at the moment.
        """
        self._call_method('addUSBDeviceSource', backend, id_, address, property_names, property_values)

    def remove_usb_device_source(self, id_):
        """None
        :param str id_:
            The identifier used when the source was added.
        """
        self._call_method('removeUSBDeviceSource', id_)

    @property
    def dvd_drives(self):
        """List of DVD drives available on the host.
        :rtype: typing.List[Medium]
        """
        return [Medium(obj) for obj in self._get_property('DVDDrives')]

    @property
    def floppy_drives(self):
        """List of floppy drives available on the host.
        :rtype: typing.List[Medium]
        """
        return [Medium(obj) for obj in self._get_property('floppyDrives')]

    @property
    def usb_devices(self):
        """List of USB devices currently attached to the host.
        Once a new device is physically attached to the host computer,
        it appears in this list and remains there until detached.
        :rtype: typing.List[HostUSBDevice]
        """
        return [HostUSBDevice(obj) for obj in self._get_property('USBDevices')]

    @property
    def usb_device_filters(self):
        """List of USB device filters in action.
        When a new device is physically attached to the host computer,
        filters from this list are applied to it (in order they are stored
        in the list). The first matched filter will determine the
        :rtype: typing.List[HostUSBDeviceFilter]
        """
        return [HostUSBDeviceFilter(obj) for obj in self._get_property('USBDeviceFilters')]

    @property
    def network_interfaces(self):
        """List of host network interfaces currently defined on the host.
        :rtype: typing.List[HostNetworkInterface]
        """
        return [HostNetworkInterface(obj) for obj in self._get_property('networkInterfaces')]

    @property
    def name_servers(self):
        """The list of nameservers registered in host's name resolving system.
        :rtype: typing.List[str]
        """
        return list(self._get_property('nameServers'))

    @property
    def domain_name(self):
        """Domain name used for name resolving.
        :rtype: str
        """
        return self._get_property('domainName')

    @property
    def search_strings(self):
        """Search string registered for name resolving.
        :rtype: typing.List[str]
        """
        return list(self._get_property('searchStrings'))

    @property
    def processor_count(self):
        """Number of (logical) CPUs installed in the host system.
        :rtype: int
        """
        return self._get_property('processorCount')

    @property
    def processor_online_count(self):
        """Number of (logical) CPUs online in the host system.
        :rtype: int
        """
        return self._get_property('processorOnlineCount')

    @property
    def processor_core_count(self):
        """Number of physical processor cores installed in the host system.
        :rtype: int
        """
        return self._get_property('processorCoreCount')

    @property
    def processor_online_core_count(self):
        """Number of physical processor cores online in the host system.
        :rtype: int
        """
        return self._get_property('processorOnlineCoreCount')

    @property
    def memory_size(self):
        """Amount of system memory in megabytes installed in the host system.
        :rtype: int
        """
        return self._get_property('memorySize')

    @property
    def memory_available(self):
        """Available system memory in the host system.
        :rtype: int
        """
        return self._get_property('memoryAvailable')

    @property
    def operating_system(self):
        """Name of the host system's operating system.
        :rtype: str
        """
        return self._get_property('operatingSystem')

    @property
    def os_version(self):
        """Host operating system's version string.
        :rtype: str
        """
        return self._get_property('OSVersion')

    @property
    def utc_time(self):
        """Returns the current host time in milliseconds since 1970-01-01 UTC.
        :rtype: int
        """
        return self._get_property('UTCTime')

    @property
    def acceleration_3d_available(self):
        """Returns @c true when the host supports 3D hardware acceleration.
        :rtype: bool
        """
        return self._get_property('acceleration3DAvailable')

    @property
    def video_input_devices(self):
        """List of currently available host video capture devices.
        :rtype: typing.List[HostVideoInputDevice]
        """
        return [HostVideoInputDevice(obj) for obj in self._get_property('videoInputDevices')]


class SystemProperties(Interface):
    """The ISystemProperties interface represents global properties of the given
      VirtualBox installation.

      These properties define limits and default values for various attributes
      and parameters. Most of the properties are read-only, but some can be
      changed by a user.
    """
    def get_max_network_adapters(self, chipset):
        """None
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :rtype: int
        :returns:
            The maximum total number of network adapters allowed.
        """
        ret = self._call_method('getMaxNetworkAdapters', chipset)
        return ret

    def get_max_network_adapters_of_type(self, chipset, type_):
        """None
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :param NetworkAttachmentType type_:
            Type of attachment.
        :rtype: int
        :returns:
            The maximum number of network adapters allowed for
          particular chipset and attachment type.
        """
        ret = self._call_method('getMaxNetworkAdaptersOfType', chipset, type_)
        return ret

    def get_max_devices_per_port_for_storage_bus(self, bus):
        """None
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The maximum number of devices which can be attached to the port for the given
        storage bus.
        """
        ret = self._call_method('getMaxDevicesPerPortForStorageBus', bus)
        return ret

    def get_min_port_count_for_storage_bus(self, bus):
        """None
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The minimum number of ports for the given storage bus.
        """
        ret = self._call_method('getMinPortCountForStorageBus', bus)
        return ret

    def get_max_port_count_for_storage_bus(self, bus):
        """None
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The maximum number of ports for the given storage bus.
        """
        ret = self._call_method('getMaxPortCountForStorageBus', bus)
        return ret

    def get_max_instances_of_storage_bus(self, chipset, bus):
        """None
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The maximum number of instances for the given storage bus.
        """
        ret = self._call_method('getMaxInstancesOfStorageBus', chipset, bus)
        return ret

    def get_device_types_for_storage_bus(self, bus):
        """None
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: typing.List[DeviceType]
        :returns:
            The list of all supported device types for the given storage bus.
        """
        ret = self._call_method('getDeviceTypesForStorageBus', bus)
        return ret

    def get_default_io_cache_setting_for_storage_controller(self, controller_type):
        """None
        :param StorageControllerType controller_type:
            The storage controller type to get the setting for.
        :rtype: bool
        :returns:
            Returned flag indicating the default value
        """
        ret = self._call_method('getDefaultIoCacheSettingForStorageController', controller_type)
        return ret

    def get_storage_controller_hotplug_capable(self, controller_type):
        """None
        :param StorageControllerType controller_type:
            The storage controller to check the setting for.
        :rtype: bool
        :returns:
            Returned flag indicating whether the controller is hotplug capable
        """
        ret = self._call_method('getStorageControllerHotplugCapable', controller_type)
        return ret

    def get_max_instances_of_usb_controller_type(self, chipset, type_):
        """None
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :param USBControllerType type_:
            The USB controller type to get the value for.
        :rtype: int
        :returns:
            The maximum number of instances for the given USB controller type.
        """
        ret = self._call_method('getMaxInstancesOfUSBControllerType', chipset, type_)
        return ret

    @property
    def min_guest_ram(self):
        """Minimum guest system memory in Megabytes.
        :rtype: int
        """
        return self._get_property('minGuestRAM')

    @property
    def max_guest_ram(self):
        """Maximum guest system memory in Megabytes.
        :rtype: int
        """
        return self._get_property('maxGuestRAM')

    @property
    def min_guest_vram(self):
        """Minimum guest video memory in Megabytes.
        :rtype: int
        """
        return self._get_property('minGuestVRAM')

    @property
    def max_guest_vram(self):
        """Maximum guest video memory in Megabytes.
        :rtype: int
        """
        return self._get_property('maxGuestVRAM')

    @property
    def min_guest_cpu_count(self):
        """Minimum CPU count.
        :rtype: int
        """
        return self._get_property('minGuestCPUCount')

    @property
    def max_guest_cpu_count(self):
        """Maximum CPU count.
        :rtype: int
        """
        return self._get_property('maxGuestCPUCount')

    @property
    def max_guest_monitors(self):
        """Maximum of monitors which could be connected.
        :rtype: int
        """
        return self._get_property('maxGuestMonitors')

    @property
    def info_vd_size(self):
        """Maximum size of a virtual disk image in bytes. Informational value,
      does not reflect the limits of any virtual disk image format.
        :rtype: int
        """
        return self._get_property('infoVDSize')

    @property
    def serial_port_count(self):
        """Maximum number of serial ports associated with every
        :rtype: int
        """
        return self._get_property('serialPortCount')

    @property
    def parallel_port_count(self):
        """Maximum number of parallel ports associated with every
        :rtype: int
        """
        return self._get_property('parallelPortCount')

    @property
    def max_boot_position(self):
        """Maximum device position in the boot order. This value corresponds
        to the total number of devices a machine can boot from, to make it
        possible to include all possible devices to the boot list.
        :rtype: int
        """
        return self._get_property('maxBootPosition')

    @property
    def raw_mode_supported(self):
        """Indicates whether VirtualBox was built with raw-mode support.

        When this reads as False, the
        :rtype: bool
        """
        return self._get_property('rawModeSupported')

    @property
    def exclusive_hw_virt(self):
        """Exclusive use of hardware virtualization by VirtualBox. When enabled,
        VirtualBox assumes it can obtain full and exclusive access to the VT-x
        or AMD-V feature of the host. To share hardware virtualization with
        other hypervisors, this property must be disabled.
        :rtype: bool
        """
        return self._get_property('exclusiveHwVirt')

    @property
    def default_machine_folder(self):
        """Full path to the default directory used to create new or open
        existing machines when a machine settings file name contains no
        path.

        Starting with VirtualBox 4.0, by default, this attribute contains
        the full path of folder named "VirtualBox VMs" in the user's
        home directory, which depends on the host platform.

        When setting this attribute, a full path must be specified.
        Setting this property to @c null or an empty string or the
        special value "Machines" (for compatibility reasons) will restore
        that default value.

        If the folder specified herein does not exist, it will be created
        automatically as needed.
        :rtype: str
        """
        return self._get_property('defaultMachineFolder')

    @property
    def logging_level(self):
        """Specifies the logging level in current use by VirtualBox.
        :rtype: str
        """
        return self._get_property('loggingLevel')

    @property
    def medium_formats(self):
        """List of all medium storage formats supported by this VirtualBox
        installation.

        Keep in mind that the medium format identifier
        (
        :rtype: typing.List[MediumFormat]
        """
        return [MediumFormat(obj) for obj in self._get_property('mediumFormats')]

    @property
    def default_hard_disk_format(self):
        """Identifier of the default medium format used by VirtualBox.

        The medium format set by this attribute is used by VirtualBox
        when the medium format was not specified explicitly. One example is
        :rtype: str
        """
        return self._get_property('defaultHardDiskFormat')

    @property
    def free_disk_space_warning(self):
        """Issue a warning if the free disk space is below (or in some disk
      intensive operation is expected to go below) the given size in
      bytes.
        :rtype: int
        """
        return self._get_property('freeDiskSpaceWarning')

    @property
    def free_disk_space_percent_warning(self):
        """Issue a warning if the free disk space is below (or in some disk
      intensive operation is expected to go below) the given percentage.
        :rtype: int
        """
        return self._get_property('freeDiskSpacePercentWarning')

    @property
    def free_disk_space_error(self):
        """Issue an error if the free disk space is below (or in some disk
      intensive operation is expected to go below) the given size in
      bytes.
        :rtype: int
        """
        return self._get_property('freeDiskSpaceError')

    @property
    def free_disk_space_percent_error(self):
        """Issue an error if the free disk space is below (or in some disk
      intensive operation is expected to go below) the given percentage.
        :rtype: int
        """
        return self._get_property('freeDiskSpacePercentError')

    @property
    def vrde_auth_library(self):
        """Library that provides authentication for Remote Desktop clients. The library
        is used if a virtual machine's authentication type is set to "external"
        in the VM RemoteDisplay configuration.

        The system library extension (".DLL" or ".so") must be omitted.
        A full path can be specified; if not, then the library must reside on the
        system's default library path.

        The default value of this property is
        :rtype: str
        """
        return self._get_property('VRDEAuthLibrary')

    @property
    def web_service_auth_library(self):
        """Library that provides authentication for webservice clients. The library
        is used if a virtual machine's authentication type is set to "external"
        in the VM RemoteDisplay configuration and will be called from
        within the
        :rtype: str
        """
        return self._get_property('webServiceAuthLibrary')

    @property
    def default_vrde_ext_pack(self):
        """The name of the extension pack providing the default VRDE.

        This attribute is for choosing between multiple extension packs
        providing VRDE. If only one is installed, it will automatically be the
        default one. The attribute value can be empty if no VRDE extension
        pack is installed.

        For details about VirtualBox Remote Desktop Extension and how to
        implement one, please refer to the VirtualBox SDK.
        :rtype: str
        """
        return self._get_property('defaultVRDEExtPack')

    @property
    def log_history_count(self):
        """This value specifies how many old release log files are kept.
        :rtype: int
        """
        return self._get_property('logHistoryCount')

    @property
    def default_audio_driver(self):
        """This value hold the default audio driver for the current
      system.
        :rtype: AudioDriverType
        """
        return AudioDriverType(self._get_property('defaultAudioDriver'))

    @property
    def autostart_database_path(self):
        """The path to the autostart database. Depending on the host this might
        be a filesystem path or something else.
        :rtype: str
        """
        return self._get_property('autostartDatabasePath')

    @property
    def default_additions_iso(self):
        """The path to the default Guest Additions ISO image. Can be empty if
        the location is not known in this installation.
        :rtype: str
        """
        return self._get_property('defaultAdditionsISO')

    @property
    def default_frontend(self):
        """Selects which VM frontend should be used by default when launching
        a VM through the
        :rtype: str
        """
        return self._get_property('defaultFrontend')

    @property
    def screen_shot_formats(self):
        """Supported bitmap formats which can be used with takeScreenShot
        and takeScreenShotToArray methods.
        :rtype: typing.List[BitmapFormat]
        """
        return [BitmapFormat(obj) for obj in self._get_property('screenShotFormats')]


class GuestOSType(Interface):
    @property
    def family_id(self):
        """Guest OS family identifier string.
        :rtype: str
        """
        return self._get_property('familyId')

    @property
    def family_description(self):
        """Human readable description of the guest OS family.
        :rtype: str
        """
        return self._get_property('familyDescription')

    @property
    def id_(self):
        """Guest OS identifier string.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def description(self):
        """Human readable description of the guest OS.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def is64_bit(self):
        """Returns @c true if the given OS is 64-bit
        :rtype: bool
        """
        return self._get_property('is64Bit')

    @property
    def recommended_ioapic(self):
        """Returns @c true if I/O-APIC recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedIOAPIC')

    @property
    def recommended_virt_ex(self):
        """Returns @c true if VT-x or AMD-V recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedVirtEx')

    @property
    def recommended_ram(self):
        """Recommended RAM size in Megabytes.
        :rtype: int
        """
        return self._get_property('recommendedRAM')

    @property
    def recommended_vram(self):
        """Recommended video RAM size in Megabytes.
        :rtype: int
        """
        return self._get_property('recommendedVRAM')

    @property
    def recommended_2d_video_acceleration(self):
        """Returns @c true if 2D video acceleration is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommended2DVideoAcceleration')

    @property
    def recommended_3d_acceleration(self):
        """Returns @c true if 3D acceleration is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommended3DAcceleration')

    @property
    def recommended_hdd(self):
        """Recommended hard disk size in bytes.
        :rtype: int
        """
        return self._get_property('recommendedHDD')

    @property
    def adapter_type(self):
        """Returns recommended network adapter for this OS type.
        :rtype: NetworkAdapterType
        """
        return NetworkAdapterType(self._get_property('adapterType'))

    @property
    def recommended_pae(self):
        """Returns @c true if using PAE is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedPAE')

    @property
    def recommended_dvd_storage_controller(self):
        """Recommended storage controller type for DVD/CD drives.
        :rtype: StorageControllerType
        """
        return StorageControllerType(self._get_property('recommendedDVDStorageController'))

    @property
    def recommended_dvd_storage_bus(self):
        """Recommended storage bus type for DVD/CD drives.
        :rtype: StorageBus
        """
        return StorageBus(self._get_property('recommendedDVDStorageBus'))

    @property
    def recommended_hd_storage_controller(self):
        """Recommended storage controller type for HD drives.
        :rtype: StorageControllerType
        """
        return StorageControllerType(self._get_property('recommendedHDStorageController'))

    @property
    def recommended_hd_storage_bus(self):
        """Recommended storage bus type for HD drives.
        :rtype: StorageBus
        """
        return StorageBus(self._get_property('recommendedHDStorageBus'))

    @property
    def recommended_firmware(self):
        """Recommended firmware type.
        :rtype: FirmwareType
        """
        return FirmwareType(self._get_property('recommendedFirmware'))

    @property
    def recommended_usb_hid(self):
        """Returns @c true if using USB Human Interface Devices, such as keyboard and mouse recommended.
        :rtype: bool
        """
        return self._get_property('recommendedUSBHID')

    @property
    def recommended_hpet(self):
        """Returns @c true if using HPET is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedHPET')

    @property
    def recommended_usb_tablet(self):
        """Returns @c true if using a USB Tablet is recommended.
        :rtype: bool
        """
        return self._get_property('recommendedUSBTablet')

    @property
    def recommended_rtc_use_utc(self):
        """Returns @c true if the RTC of this VM should be set to UTC
        :rtype: bool
        """
        return self._get_property('recommendedRTCUseUTC')

    @property
    def recommended_chipset(self):
        """Recommended chipset type.
        :rtype: ChipsetType
        """
        return ChipsetType(self._get_property('recommendedChipset'))

    @property
    def recommended_audio_controller(self):
        """Recommended audio controller type.
        :rtype: AudioControllerType
        """
        return AudioControllerType(self._get_property('recommendedAudioController'))

    @property
    def recommended_audio_codec(self):
        """Recommended audio codec type.
        :rtype: AudioCodecType
        """
        return AudioCodecType(self._get_property('recommendedAudioCodec'))

    @property
    def recommended_floppy(self):
        """Returns @c true a floppy drive is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedFloppy')

    @property
    def recommended_usb(self):
        """Returns @c true a USB controller is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedUSB')

    @property
    def recommended_usb3(self):
        """Returns @c true an xHCI (USB 3) controller is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedUSB3')

    @property
    def recommended_tf_reset(self):
        """Returns @c true if using VCPU reset on triple fault is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedTFReset')

    @property
    def recommended_x2_apic(self):
        """Returns @c true if X2APIC is recommended for this OS type.
        :rtype: bool
        """
        return self._get_property('recommendedX2APIC')


class AdditionsFacilityType(enum.Enum):
    """
      Guest Additions facility IDs.
    
     .. describe:: NONE No/invalid facility.
     .. describe:: VIRTUALBOX_GUEST_DRIVER VirtualBox base driver (VBoxGuest).
     .. describe:: AUTO_LOGON Auto-logon modules (VBoxGINA, VBoxCredProv, pam_vbox).
     .. describe:: VIRTUALBOX_SERVICE VirtualBox system service (VBoxService).
     .. describe:: VIRTUALBOX_TRAY_CLIENT VirtualBox desktop integration (VBoxTray on Windows, VBoxClient on non-Windows).
     .. describe:: SEAMLESS Seamless guest desktop integration.
     .. describe:: GRAPHICS Guest graphics mode. If not enabled, seamless rendering will not work, resize hints
        are not immediately acted on and guest display resizes are probably not initiated by
        the guest additions.
      
     .. describe:: MONITOR_ATTACH Guest supports monitor hotplug.
      
     .. describe:: ALL All facilities selected.
    """
    NONE = 0
    VIRTUALBOX_GUEST_DRIVER = 20
    AUTO_LOGON = 90
    VIRTUALBOX_SERVICE = 100
    VIRTUALBOX_TRAY_CLIENT = 101
    SEAMLESS = 1000
    GRAPHICS = 1100
    MONITOR_ATTACH = 1101
    ALL = 2147483646

class AdditionsFacilityClass(enum.Enum):
    """
      Guest Additions facility classes.
    
     .. describe:: NONE No/invalid class.
     .. describe:: DRIVER Driver.
     .. describe:: SERVICE System service.
     .. describe:: PROGRAM Program.
     .. describe:: FEATURE Feature.
     .. describe:: THIRD_PARTY Third party.
     .. describe:: ALL All facility classes selected.
    """
    NONE = 0
    DRIVER = 10
    SERVICE = 30
    PROGRAM = 50
    FEATURE = 100
    THIRD_PARTY = 999
    ALL = 2147483646

class AdditionsFacilityStatus(enum.Enum):
    """
      Guest Additions facility states.
    
     .. describe:: INACTIVE Facility is not active.
     .. describe:: PAUSED Facility has been paused.
     .. describe:: PRE_INIT Facility is preparing to initialize.
     .. describe:: INIT Facility is initializing.
     .. describe:: ACTIVE Facility is up and running.
     .. describe:: TERMINATING Facility is shutting down.
     .. describe:: TERMINATED Facility successfully shut down.
     .. describe:: FAILED Facility failed to start.
     .. describe:: UNKNOWN Facility status is unknown.
    """
    INACTIVE = 0
    PAUSED = 1
    PRE_INIT = 20
    INIT = 30
    ACTIVE = 50
    TERMINATING = 100
    TERMINATED = 101
    FAILED = 800
    UNKNOWN = 999

class AdditionsFacility(Interface):
    """Structure representing a Guest Additions facility.
    """
    @property
    def class_type(self):
        """The class this facility is part of.
        :rtype: AdditionsFacilityClass
        """
        return AdditionsFacilityClass(self._get_property('classType'))

    @property
    def last_updated(self):
        """Time stamp of the last status update,
        in milliseconds since 1970-01-01 UTC.
        :rtype: int
        """
        return self._get_property('lastUpdated')

    @property
    def name(self):
        """The facility's friendly name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def status(self):
        """The current status.
        :rtype: AdditionsFacilityStatus
        """
        return AdditionsFacilityStatus(self._get_property('status'))

    @property
    def type_(self):
        """The facility's type ID.
        :rtype: AdditionsFacilityType
        """
        return AdditionsFacilityType(self._get_property('type'))


class AdditionsRunLevelType(enum.Enum):
    """
      Guest Additions run level type.
    
     .. describe:: NONE Guest Additions are not loaded.
     .. describe:: SYSTEM Guest drivers are loaded.
     .. describe:: USERLAND Common components (such as application services) are loaded.
     .. describe:: DESKTOP Per-user desktop components are loaded.
    """
    NONE = 0
    SYSTEM = 1
    USERLAND = 2
    DESKTOP = 3

class AdditionsUpdateFlag(enum.Enum):
    """
      Guest Additions update flags.
    
     .. describe:: NONE No flag set.
     .. describe:: WAIT_FOR_UPDATE_START_ONLY Starts the regular updating process and waits until the
        actual Guest Additions update inside the guest was started.
        This can be necessary due to needed interaction with the guest
        OS during the installation phase.
    """
    NONE = 0
    WAIT_FOR_UPDATE_START_ONLY = 1

class GuestSessionStatus(enum.Enum):
    """
      Guest session status. This enumeration represents possible values of
      the 
     .. describe:: UNDEFINED Guest session is in an undefined state.
     .. describe:: STARTING Guest session is being started.
     .. describe:: STARTED Guest session has been started.
     .. describe:: TERMINATING Guest session is being terminated.
     .. describe:: TERMINATED Guest session terminated normally.
     .. describe:: TIMED_OUT_KILLED Guest session timed out and was killed.
     .. describe:: TIMED_OUT_ABNORMALLY Guest session timed out and was not killed successfully.
     .. describe:: DOWN Service/OS is stopping, guest session was killed.
     .. describe:: ERROR Something went wrong.
    """
    UNDEFINED = 0
    STARTING = 10
    STARTED = 100
    TERMINATING = 480
    TERMINATED = 500
    TIMED_OUT_KILLED = 512
    TIMED_OUT_ABNORMALLY = 513
    DOWN = 600
    ERROR = 800

class GuestSessionWaitForFlag(enum.Enum):
    """
      Guest session waiting flags. Multiple flags can be combined.
    
     .. describe:: NONE No waiting flags specified. Do not use this.
     .. describe:: START Wait for the guest session being started.
     .. describe:: TERMINATE Wait for the guest session being terminated.
     .. describe:: STATUS Wait for the next guest session status change.
    """
    NONE = 0
    START = 1
    TERMINATE = 2
    STATUS = 4

class GuestSessionWaitResult(enum.Enum):
    """
      Guest session waiting results. Depending on the session waiting flags (for
      more information see 
     .. describe:: NONE No result was returned. Not being used.
     .. describe:: START The guest session has been started.
     .. describe:: TERMINATE The guest session has been terminated.
     .. describe:: STATUS 
        The guest session has changed its status. The status then can
        be retrieved via 
     .. describe:: ERROR Error while executing the process.
     .. describe:: TIMEOUT 
        The waiting operation timed out. This also will happen
        when no event has been occurred matching the
        current waiting flags in a 
     .. describe:: WAIT_FLAG_NOT_SUPPORTED 
        A waiting flag specified in the 
    """
    NONE = 0
    START = 1
    TERMINATE = 2
    STATUS = 3
    ERROR = 4
    TIMEOUT = 5
    WAIT_FLAG_NOT_SUPPORTED = 6

class GuestUserState(enum.Enum):
    """
      State a guest user has been changed to.
    
     .. describe:: UNKNOWN Unknown state. Not being used.
     .. describe:: LOGGED_IN A guest user has been successfully logged into
        the guest OS.
        
     .. describe:: LOGGED_OUT A guest user has been successfully logged out
        of the guest OS.
        
     .. describe:: LOCKED A guest user has locked its account. This might
        include running a password-protected screensaver
        in the guest.
        
     .. describe:: UNLOCKED A guest user has unlocked its account.
        
     .. describe:: DISABLED A guest user has been disabled by the guest OS.
        
     .. describe:: IDLE 
        A guest user currently is not using the guest OS.
        
     .. describe:: IN_USE A guest user continued using the guest OS after
        being idle.
     .. describe:: CREATED A guest user has been successfully created.
        
     .. describe:: DELETED A guest user has been successfully deleted.
        
     .. describe:: SESSION_CHANGED To guest OS has changed the session of a user.
        
     .. describe:: CREDENTIALS_CHANGED To guest OS has changed the authentication
        credentials of a user. This might include changed passwords
        and authentication types.
        
     .. describe:: ROLE_CHANGED To guest OS has changed the role of a user permanently,
        e.g. granting / denying administrative rights.
        
     .. describe:: GROUP_ADDED To guest OS has added a user to a specific
        user group.
        
     .. describe:: GROUP_REMOVED To guest OS has removed a user from a specific
        user group.
        
     .. describe:: ELEVATED To guest OS temporarily has elevated a user
        to perform a certain task.
        
    """
    UNKNOWN = 0
    LOGGED_IN = 1
    LOGGED_OUT = 2
    LOCKED = 3
    UNLOCKED = 4
    DISABLED = 5
    IDLE = 6
    IN_USE = 7
    CREATED = 8
    DELETED = 9
    SESSION_CHANGED = 10
    CREDENTIALS_CHANGED = 11
    ROLE_CHANGED = 12
    GROUP_ADDED = 13
    GROUP_REMOVED = 14
    ELEVATED = 15

class FileSeekOrigin(enum.Enum):
    """
      What a file seek (
     .. describe:: BEGIN Seek from the beginning of the file.
     .. describe:: CURRENT Seek from the current file position.
     .. describe:: END Seek relative to the end of the file.  To seek to the position two
        bytes from the end of the file, specify -2 as the seek offset.
    """
    BEGIN = 0
    CURRENT = 1
    END = 2

class ProcessInputFlag(enum.Enum):
    """
      Guest process input flags.
    
     .. describe:: NONE No flag set.
     .. describe:: END_OF_FILE End of file (input) reached.
    """
    NONE = 0
    END_OF_FILE = 1

class ProcessOutputFlag(enum.Enum):
    """
      Guest process output flags for specifying which
      type of output to retrieve.
    
     .. describe:: NONE No flags set. Get output from stdout.
     .. describe:: STDERR Get output from stderr.
    """
    NONE = 0
    STDERR = 1

class ProcessWaitForFlag(enum.Enum):
    """
      Process waiting flags. Multiple flags can be combined.
    
     .. describe:: NONE No waiting flags specified. Do not use this.
     .. describe:: START Wait for the process being started.
     .. describe:: TERMINATE Wait for the process being terminated.
     .. describe:: STDIN Wait for stdin becoming available.
     .. describe:: STDOUT Wait for data becoming available on stdout.
     .. describe:: STDERR Wait for data becoming available on stderr.
    """
    NONE = 0
    START = 1
    TERMINATE = 2
    STDIN = 4
    STDOUT = 8
    STDERR = 16

class ProcessWaitResult(enum.Enum):
    """
      Process waiting results. Depending on the process waiting flags (for
      more information see 
     .. describe:: NONE No result was returned. Not being used.
     .. describe:: START The process has been started.
     .. describe:: TERMINATE The process has been terminated.
     .. describe:: STATUS 
        The process has changed its status. The status then can
        be retrieved via 
     .. describe:: ERROR Error while executing the process.
     .. describe:: TIMEOUT 
        The waiting operation timed out. Also use if the guest process has
        timed out in the guest side (kill attempted).
      
     .. describe:: STDIN The process signalled that stdin became available for writing.
     .. describe:: STDOUT Data on stdout became available for reading.
     .. describe:: STDERR Data on stderr became available for reading.
     .. describe:: WAIT_FLAG_NOT_SUPPORTED 
        A waiting flag specified in the 
    """
    NONE = 0
    START = 1
    TERMINATE = 2
    STATUS = 3
    ERROR = 4
    TIMEOUT = 5
    STDIN = 6
    STDOUT = 7
    STDERR = 8
    WAIT_FLAG_NOT_SUPPORTED = 9

class FileCopyFlag(enum.Enum):
    """
      File copying flags.
      
     .. describe:: NONE No flag set.
     .. describe:: NO_REPLACE 
        Do not replace the destination file if it exists.
        
     .. describe:: FOLLOW_LINKS 
        Follow symbolic links.
        
     .. describe:: UPDATE 
        Only copy when the source file is newer than the destination file
        or when the destination file is missing.
        
    """
    NONE = 0
    NO_REPLACE = 1
    FOLLOW_LINKS = 2
    UPDATE = 4

class FsObjMoveFlag(enum.Enum):
    """
      File moving flags.
    
     .. describe:: NONE No flag set.
     .. describe:: REPLACE 
        Replace the destination file, symlink, etc if it exists, however this
        does not allow replacing any directories.
      
     .. describe:: FOLLOW_LINKS 
        Follow symbolic links in the final components or not (only applied to
        the given source and target paths, not to anything else).
      
     .. describe:: ALLOW_DIRECTORY_MOVES 
        Allow moving directories accross file system boundraries. Because it
        is could be a big undertaking, we require extra assurance that we
        should do it when requested.
      
    """
    NONE = 0
    REPLACE = 1
    FOLLOW_LINKS = 2
    ALLOW_DIRECTORY_MOVES = 4

class DirectoryCreateFlag(enum.Enum):
    """
      Directory creation flags.
    
     .. describe:: NONE No flag set.
     .. describe:: PARENTS No error if existing, make parent directories as needed.
    """
    NONE = 0
    PARENTS = 1

class DirectoryCopyFlag(enum.Enum):
    """
      Directory copying flags.
      
     .. describe:: NONE No flag set.
     .. describe:: COPY_INTO_EXISTING Allow copying into an existing destination directory.
    """
    NONE = 0
    COPY_INTO_EXISTING = 1

class DirectoryRemoveRecFlag(enum.Enum):
    """
      Directory recursive removement flags.
      
     .. describe:: NONE No flag set.
     .. describe:: CONTENT_AND_DIR Delete the content of the directory and the directory itself.
     .. describe:: CONTENT_ONLY Only delete the content of the directory, omit the directory it self.
    """
    NONE = 0
    CONTENT_AND_DIR = 1
    CONTENT_ONLY = 2

class FsObjRenameFlag(enum.Enum):
    """
      Flags for use when renaming file system objects (files, directories,
      symlink, etc), see 
     .. describe:: NO_REPLACE Do not replace any destination object.
     .. describe:: REPLACE This will attempt to replace any destination object other except
        directories. (The default is to fail if the destination exists.)
    """
    NO_REPLACE = 0
    REPLACE = 1

class ProcessCreateFlag(enum.Enum):
    """
      Guest process execution flags.
      
     .. describe:: NONE No flag set.
     .. describe:: WAIT_FOR_PROCESS_START_ONLY Only use the specified timeout value to wait for starting the guest process - the guest
        process itself then uses an infinite timeout.
     .. describe:: IGNORE_ORPHANED_PROCESSES Do not report an error when executed processes are still alive when VBoxService or the guest OS is shutting down.
     .. describe:: HIDDEN Do not show the started process according to the guest OS guidelines.
     .. describe:: PROFILE Utilize the user's profile data when exeuting a process. Only available for Windows guests at the moment.
     .. describe:: WAIT_FOR_STDOUT The guest process waits until all data from stdout is read out.
     .. describe:: WAIT_FOR_STDERR The guest process waits until all data from stderr is read out.
     .. describe:: EXPAND_ARGUMENTS Expands environment variables in process arguments.
        
     .. describe:: UNQUOTED_ARGUMENTS Work around for Windows and OS/2 applications not following normal
        argument quoting and escaping rules. The arguments are passed to the
        application without any extra quoting, just a single space between each.
        
    """
    NONE = 0
    WAIT_FOR_PROCESS_START_ONLY = 1
    IGNORE_ORPHANED_PROCESSES = 2
    HIDDEN = 4
    PROFILE = 8
    WAIT_FOR_STDOUT = 16
    WAIT_FOR_STDERR = 32
    EXPAND_ARGUMENTS = 64
    UNQUOTED_ARGUMENTS = 128

class ProcessPriority(enum.Enum):
    """
      Process priorities.
    
     .. describe:: INVALID Invalid priority, do not use.
     .. describe:: DEFAULT Default process priority determined by the OS.
    """
    INVALID = 0
    DEFAULT = 1

class SymlinkType(enum.Enum):
    """
      Symbolic link types.  This is significant when creating links on the
      Windows platform, ignored elsewhere.
    
     .. describe:: UNKNOWN It is not known what is being targeted.
     .. describe:: DIRECTORY The link targets a directory.
     .. describe:: FILE The link targets a file (or whatever else except directories).
    """
    UNKNOWN = 0
    DIRECTORY = 1
    FILE = 2

class SymlinkReadFlag(enum.Enum):
    """
      Symbolic link reading flags.
    
     .. describe:: NONE No flags set.
     .. describe:: NO_SYMLINKS Don't allow symbolic links as part of the path.
    """
    NONE = 0
    NO_SYMLINKS = 1

class ProcessStatus(enum.Enum):
    """
      Process execution statuses.
    
     .. describe:: UNDEFINED Process is in an undefined state.
     .. describe:: STARTING Process is being started.
     .. describe:: STARTED Process has been started.
     .. describe:: PAUSED Process has been paused.
     .. describe:: TERMINATING Process is being terminated.
     .. describe:: TERMINATED_NORMALLY Process terminated normally.
     .. describe:: TERMINATED_SIGNAL Process terminated via signal.
     .. describe:: TERMINATED_ABNORMALLY Process terminated abnormally.
     .. describe:: TIMED_OUT_KILLED Process timed out and was killed.
     .. describe:: TIMED_OUT_ABNORMALLY Process timed out and was not killed successfully.
     .. describe:: DOWN Service/OS is stopping, process was killed.
     .. describe:: ERROR Something went wrong.
    """
    UNDEFINED = 0
    STARTING = 10
    STARTED = 100
    PAUSED = 110
    TERMINATING = 480
    TERMINATED_NORMALLY = 500
    TERMINATED_SIGNAL = 510
    TERMINATED_ABNORMALLY = 511
    TIMED_OUT_KILLED = 512
    TIMED_OUT_ABNORMALLY = 513
    DOWN = 600
    ERROR = 800

class ProcessInputStatus(enum.Enum):
    """
      Process input statuses.
    
     .. describe:: UNDEFINED Undefined state.
     .. describe:: BROKEN Input pipe is broken.
     .. describe:: AVAILABLE Input pipe became available for writing.
     .. describe:: WRITTEN Data has been successfully written.
     .. describe:: OVERFLOW Too much input data supplied, data overflow.
    """
    UNDEFINED = 0
    BROKEN = 1
    AVAILABLE = 10
    WRITTEN = 50
    OVERFLOW = 100

class PathStyle(enum.Enum):
    """
      The path style of a system.
      (Values matches the RTPATH_STR_F_STYLE_XXX defines in iprt/path.h!)
    
     .. describe:: DOS DOS-style paths with forward and backward slashes, drive
      letters and UNC.  Known from DOS, OS/2 and Windows.
     .. describe:: UNIX UNIX-style paths with forward slashes only.
     .. describe:: UNKNOWN 
        The path style is not known, most likely because the guest additions
        aren't active yet.
      
    """
    DOS = 1
    UNIX = 2
    UNKNOWN = 8

class FileAccessMode(enum.Enum):
    """
      File open access mode for use with 
     .. describe:: READ_ONLY Open the file only with read access.
     .. describe:: WRITE_ONLY Open the file only with write access.
     .. describe:: READ_WRITE Open the file with both read and write access.
     .. describe:: APPEND_ONLY Open the file for appending only, no read or seek access.
        
     .. describe:: APPEND_READ Open the file for appending and read.  Writes always goes to the
        end of the file while reads are done at the current or specified file
        position.
        
    """
    READ_ONLY = 1
    WRITE_ONLY = 2
    READ_WRITE = 3
    APPEND_ONLY = 4
    APPEND_READ = 5

class FileOpenAction(enum.Enum):
    """
      What action 
     .. describe:: OPEN_EXISTING Opens an existing file, fails if no file exists. (Was "oe".)
     .. describe:: OPEN_OR_CREATE Opens an existing file, creates a new one if no file exists. (Was "oc".)
     .. describe:: CREATE_NEW Creates a new file is no file exists, fails if there is a file there already. (Was "ce".)
     .. describe:: CREATE_OR_REPLACE 
        Creates a new file, replace any existing file. (Was "ca".)
        
     .. describe:: OPEN_EXISTING_TRUNCATED Opens and truncate an existing file, fails if no file exists. (Was "ot".)
     .. describe:: APPEND_OR_CREATE Opens an existing file and places the file pointer at the end of
        the file, creates the file if it does not exist.  This action implies
        write access. (Was "oa".)
        
    """
    OPEN_EXISTING = 1
    OPEN_OR_CREATE = 2
    CREATE_NEW = 3
    CREATE_OR_REPLACE = 4
    OPEN_EXISTING_TRUNCATED = 5
    APPEND_OR_CREATE = 99

class FileSharingMode(enum.Enum):
    """
      File sharing mode for 
     .. describe:: READ Only share read access to the file.
     .. describe:: WRITE Only share write access to the file.
     .. describe:: READ_WRITE Share both read and write access to the file, but deny deletion.
     .. describe:: DELETE Only share delete access, denying read and write.
     .. describe:: READ_DELETE Share read and delete access to the file, denying writing.
     .. describe:: WRITE_DELETE Share write and delete access to the file, denying reading.
     .. describe:: ALL Share all access, i.e. read, write and delete, to the file.
    """
    READ = 1
    WRITE = 2
    READ_WRITE = 3
    DELETE = 4
    READ_DELETE = 5
    WRITE_DELETE = 6
    ALL = 7

class FileOpenExFlag(enum.Enum):
    """
      Open flags for 
     .. describe:: NONE No flag set.
    """
    NONE = 0

class FileStatus(enum.Enum):
    """
      File statuses.
    
     .. describe:: UNDEFINED File is in an undefined state.
     .. describe:: OPENING Guest file is opening.
     .. describe:: OPEN Guest file has been successfully opened.
     .. describe:: CLOSING Guest file closing.
     .. describe:: CLOSED Guest file has been closed.
     .. describe:: DOWN Service/OS is stopping, guest file was closed.
     .. describe:: ERROR Something went wrong.
    """
    UNDEFINED = 0
    OPENING = 10
    OPEN = 100
    CLOSING = 150
    CLOSED = 200
    DOWN = 600
    ERROR = 800

class FsObjType(enum.Enum):
    """
      File system object (file) types.
    
     .. describe:: UNKNOWN Used either if the object has type that is not in this enum, or
        if the type has not yet been determined or set.
     .. describe:: FIFO FIFO or named pipe, depending on the platform/terminology.
     .. describe:: DEV_CHAR Character device.
     .. describe:: DIRECTORY Directory.
     .. describe:: DEV_BLOCK Block device.
     .. describe:: FILE Regular file.
     .. describe:: SYMLINK Symbolic link.
     .. describe:: SOCKET Socket.
     .. describe:: WHITE_OUT A white-out file.  Found in union mounts where it is used for
        hiding files after deletion, I think. 
    """
    UNKNOWN = 1
    FIFO = 2
    DEV_CHAR = 3
    DIRECTORY = 4
    DEV_BLOCK = 5
    FILE = 6
    SYMLINK = 7
    SOCKET = 8
    WHITE_OUT = 9

class DnDAction(enum.Enum):
    """
      Possible actions of a drag'n drop operation.
    
     .. describe:: IGNORE Do nothing.
     .. describe:: COPY Copy the item to the target.
     .. describe:: MOVE Move the item to the target.
     .. describe:: LINK Link the item from within the target.
    """
    IGNORE = 0
    COPY = 1
    MOVE = 2
    LINK = 3

class DirectoryOpenFlag(enum.Enum):
    """
      Directory open flags.
    
     .. describe:: NONE No flag set.
     .. describe:: NO_SYMLINKS Don't allow symbolic links as part of the path.
    """
    NONE = 0
    NO_SYMLINKS = 1

class DnDBase(Interface):
    """Base abstract interface for drag'n drop.
    """
    def is_format_supported(self, format_):
        """None
        :param str format_:
            Format to check for.
        :rtype: bool
        :returns:
            Returns @c true if the specified format is supported, @c false if not.
        """
        ret = self._call_method('isFormatSupported', format_)
        return ret

    def add_formats(self, formats):
        """None
        :param typing.List[str] formats:
            Collection of formats to add.
        """
        self._call_method('addFormats', formats)

    def remove_formats(self, formats):
        """None
        :param typing.List[str] formats:
            Collection of formats to remove.
        """
        self._call_method('removeFormats', formats)

    @property
    def formats(self):
        """Returns all supported drag'n drop formats.
        :rtype: typing.List[str]
        """
        return list(self._get_property('formats'))

    @property
    def protocol_version(self):
        """Returns the protocol version which is used to communicate
       with the guest.
        :rtype: int
        """
        return self._get_property('protocolVersion')


class DnDSource(DnDBase):
    """Abstract interface for handling drag'n drop sources.
    """
    def drag_is_pending(self, screen_id):
        """None
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        :rtype: typing.Tuple[DnDAction, typing.List[str], typing.List[DnDAction]]
        """
        default_action, formats, allowed_actions = self._call_method('dragIsPending', screen_id)
        default_action = DnDAction(default_action)
        allowed_actions = DnDAction(allowed_actions)
        return default_action, formats, allowed_actions

    def drop(self, format_, action):
        """None
        :param str format_:
            The mime type the data must be in.
        :param DnDAction action:
            The action to use.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('drop', format_, action)
        return ret

    def receive_data(self):
        """None
        :rtype: typing.List[bytes]
        :returns:
            The actual data.
        """
        ret = self._call_method('receiveData')
        return ret


class GuestDnDSource(DnDSource):
    """Implementation of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class DnDTarget(DnDBase):
    """Abstract interface for handling drag'n drop targets.
    """
    def enter(self, screen_id, y, x, default_action, allowed_actions, formats):
        """None
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        :param int y:
            Y-position of the event.
        :param int x:
            X-position of the event.
        :param DnDAction default_action:
            The default action to use.
        :param typing.List[DnDAction] allowed_actions:
            The actions which are allowed.
        :param typing.List[str] formats:
            The supported MIME types.
        :rtype: DnDAction
        :returns:
            The resulting action of this event.
        """
        ret = self._call_method('enter', screen_id, y, x, default_action, allowed_actions, formats)
        return ret

    def move(self, screen_id, x, y, default_action, allowed_actions, formats):
        """None
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        :param int x:
            X-position of the event.
        :param int y:
            Y-position of the event.
        :param DnDAction default_action:
            The default action to use.
        :param typing.List[DnDAction] allowed_actions:
            The actions which are allowed.
        :param typing.List[str] formats:
            The supported MIME types.
        :rtype: DnDAction
        :returns:
            The resulting action of this event.
        """
        ret = self._call_method('move', screen_id, x, y, default_action, allowed_actions, formats)
        return ret

    def leave(self, screen_id):
        """None
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        """
        self._call_method('leave', screen_id)

    def drop(self, screen_id, x, y, default_action, allowed_actions, formats):
        """None
        :param int screen_id:
            The screen ID where the Drag and Drop event occurred.
        :param int x:
            X-position of the event.
        :param int y:
            Y-position of the event.
        :param DnDAction default_action:
            The default action to use.
        :param typing.List[DnDAction] allowed_actions:
            The actions which are allowed.
        :param typing.List[str] formats:
            The supported MIME types.
        :rtype: typing.Tuple[DnDAction, str]
        """
        result_action, format_ = self._call_method('drop', screen_id, x, y, default_action, allowed_actions, formats)
        result_action = DnDAction(result_action)
        return result_action, format_

    def send_data(self, screen_id, format_, data):
        """None
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        :param str format_:
            The MIME type the data is in.
        :param typing.List[bytes] data:
            The actual data.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('sendData', screen_id, format_, data)
        return ret

    def cancel(self):
        """None
        :rtype: bool
        :returns:
            Whether the target has vetoed cancelling the operation.
        """
        ret = self._call_method('cancel')
        return ret


class GuestDnDTarget(DnDTarget):
    """Implementation of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class GuestSession(Interface):
    """A guest session represents one impersonated user account in the guest, so
      every operation will use the same credentials specified when creating
      the session object via
    """
    def close(self):
        """None
        """
        self._call_method('close')

    def directory_copy(self, source, destination, flags):
        """None
        :param str source:
            The path to the directory to copy (in the guest).  Guest path style.
        :param str destination:
            The path to the target directory (in the guest).  Unless the
        :param typing.List[DirectoryCopyFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('directoryCopy', source, destination, flags)
        return ret

    def directory_copy_from_guest(self, source, destination, flags):
        """None
        :param str source:
            Path to the directory on the guest side that should be copied to
          the host. Guest path style.
        :param str destination:
            Where to put the directory on the host.  Unless the
        :param typing.List[DirectoryCopyFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('directoryCopyFromGuest', source, destination, flags)
        return ret

    def directory_copy_to_guest(self, source, destination, flags):
        """None
        :param str source:
            Path to the directory on the host side that should be copied to
          the guest.  Host path style.
        :param str destination:
            Where to put the file in the guest. Unless the
        :param typing.List[DirectoryCopyFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('directoryCopyToGuest', source, destination, flags)
        return ret

    def directory_create(self, path, mode, flags):
        """None
        :param str path:
            Path to the directory directory to be created. Guest path style.
        :param int mode:
            The UNIX-style access mode mask to create the directory with.
          Whether/how all three access groups and associated access rights are
          realized is guest OS dependent.  The API does the best it can on each
          OS.
        :param typing.List[DirectoryCreateFlag] flags:
            Zero or more
        """
        self._call_method('directoryCreate', path, mode, flags)

    def directory_create_temp(self, template_name, mode, path, secure):
        """None
        :param str template_name:
            Template for the name of the directory to create. This must
          contain at least one 'X' character. The first group of consecutive
          'X' characters in the template will be replaced by a random
          alphanumeric string to produce a unique name.
        :param int mode:
            The UNIX-style access mode mask to create the directory with.
          Whether/how all three access groups and associated access rights are
          realized is guest OS dependent.  The API does the best it can on each
          OS.

          This parameter is ignore if the @a secure parameter is set to @c true.
        :param str path:
            The path to the directory in which the temporary directory should
          be created. Guest path style.
        :param bool secure:
            Whether to fail if the directory can not be securely created.
          Currently this means that another unprivileged user cannot
          manipulate the path specified or remove the temporary directory
          after it has been created. Also causes the mode specified to be
          ignored. May not be supported on all guest types.
        :rtype: str
        :returns:
            On success this will contain the full path to the created
          directory. Guest path style.
        """
        ret = self._call_method('directoryCreateTemp', template_name, mode, path, secure)
        return ret

    def directory_exists(self, path, follow_symlinks):
        """None
        :param str path:
            Path to the directory to check if exists. Guest path style.
        :param bool follow_symlinks:
            If @c true, symbolic links in the final component will be followed
          and the existance of the symlink target made the question for this method.
          If @c false, a symbolic link in the final component will make the
          method return @c false (because a symlink isn't a directory).
        :rtype: bool
        :returns:
            Returns @c true if the directory exists, @c false if not.
        """
        ret = self._call_method('directoryExists', path, follow_symlinks)
        return ret

    def directory_open(self, path, filter_, flags):
        """None
        :param str path:
            Path to the directory to open. Guest path style.
        :param str filter_:
            Optional directory listing filter to apply.  This uses the DOS/NT
          style wildcard characters '?' and '*'.
        :param typing.List[DirectoryOpenFlag] flags:
            Zero or more
        :rtype: GuestDirectory
        """
        ret = self._call_method('directoryOpen', path, filter_, flags)
        return ret

    def directory_remove(self, path):
        """None
        :param str path:
            Path to the directory that should be removed. Guest path style.
        """
        self._call_method('directoryRemove', path)

    def directory_remove_recursive(self, path, flags):
        """None
        :param str path:
            Path of the directory that is to be removed recursively. Guest
          path style.
        :param typing.List[DirectoryRemoveRecFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation completion. This is not implemented
          yet and therefore this method call will block until deletion is completed.
        """
        ret = self._call_method('directoryRemoveRecursive', path, flags)
        return ret

    def environment_schedule_set(self, name, value):
        """None
        :param str name:
            Name of the environment variable to set.  This cannot be empty
          nor can it contain any equal signs.
        :param str value:
            Value to set the session environment variable to.
        """
        self._call_method('environmentScheduleSet', name, value)

    def environment_schedule_unset(self, name):
        """None
        :param str name:
            Name of the environment variable to unset.  This cannot be empty
          nor can it contain any equal signs.
        """
        self._call_method('environmentScheduleUnset', name)

    def environment_get_base_variable(self, name):
        """None
        :param str name:
            Name of the environment variable to   get.This cannot be empty
          nor can it contain any equal signs.
        :rtype: str
        :returns:
            The value of the variable.  Empty if not found.  To deal with
          variables that may have empty values, use
        """
        ret = self._call_method('environmentGetBaseVariable', name)
        return ret

    def environment_does_base_variable_exist(self, name):
        """None
        :param str name:
            Name of the environment variable to look for.  This cannot be
          empty nor can it contain any equal signs.
        :rtype: bool
        :returns:
            TRUE if the variable exists, FALSE if not.
        """
        ret = self._call_method('environmentDoesBaseVariableExist', name)
        return ret

    def file_copy(self, source, destination, flags):
        """None
        :param str source:
            The path to the file to copy (in the guest).  Guest path style.
        :param str destination:
            The path to the target file (in the guest).  This cannot be a
          directory.  Guest path style.
        :param typing.List[FileCopyFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('fileCopy', source, destination, flags)
        return ret

    def file_copy_from_guest(self, source, destination, flags):
        """None
        :param str source:
            Path to the file on the guest side that should be copied to the
          host.  Guest path style.
        :param str destination:
            Where to put the file on the host (file, not directory). Host
          path style.
        :param typing.List[FileCopyFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('fileCopyFromGuest', source, destination, flags)
        return ret

    def file_copy_to_guest(self, source, destination, flags):
        """None
        :param str source:
            Path to the file on the host side that should be copied to the
          guest.  Host path style.
        :param str destination:
            Where to put the file in the guest (file, not directory).  Guest
          style path.
        :param typing.List[FileCopyFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('fileCopyToGuest', source, destination, flags)
        return ret

    def file_create_temp(self, template_name, mode, path, secure):
        """None
        :param str template_name:
            Template for the name of the file to create. This must contain
          at least one 'X' character. The first group of consecutive 'X'
          characters in the template will be replaced by a random
          alphanumeric string to produce a unique name.
        :param int mode:
            The UNIX-style access mode mask to create the file with.
          Whether/how all three access groups and associated access rights are
          realized is guest OS dependent.  The API does the best it can on each
          OS.

          This parameter is ignore if the @a secure parameter is set to @c true.
        :param str path:
            The path to the directory in which the temporary file should be
          created.
        :param bool secure:
            Whether to fail if the file can not be securely created.
          Currently this means that another unprivileged user cannot
          manipulate the path specified or remove the temporary file after
          it has been created. Also causes the mode specified to be ignored.
          May not be supported on all guest types.
        :rtype: GuestFile
        :returns:
            On success this will contain an open file object for the new
          temporary file.
        """
        ret = self._call_method('fileCreateTemp', template_name, mode, path, secure)
        return ret

    def file_exists(self, path, follow_symlinks):
        """None
        :param str path:
            Path to the alleged regular file.  Guest path style.
        :param bool follow_symlinks:
            If @c true, symbolic links in the final component will be followed
          and the existance of the symlink target made the question for this method.
          If @c false, a symbolic link in the final component will make the
          method return @c false (because a symlink isn't a regular file).
        :rtype: bool
        :returns:
            Returns @c true if the file exists, @c false if not.  @c false is
          also return if this @a path does not point to a file object.
        """
        ret = self._call_method('fileExists', path, follow_symlinks)
        return ret

    def file_open(self, path, access_mode, open_action, creation_mode):
        """None
        :param str path:
            Path to file to open.  Guest path style.
        :param FileAccessMode access_mode:
            The file access mode (read, write and/or append).
          See
        :param FileOpenAction open_action:
            What action to take depending on whether the file exists or not.
          See
        :param int creation_mode:
            The UNIX-style access mode mask to create the file with if @a openAction
          requested the file to be created (otherwise ignored).  Whether/how all
          three access groups and associated access rights are realized is guest
          OS dependent.  The API does the best it can on each OS.
        :rtype: GuestFile
        """
        ret = self._call_method('fileOpen', path, access_mode, open_action, creation_mode)
        return ret

    def file_open_ex(self, path, access_mode, open_action, sharing_mode, creation_mode, flags):
        """None
        :param str path:
            Path to file to open.  Guest path style.
        :param FileAccessMode access_mode:
            The file access mode (read, write and/or append).
          See
        :param FileOpenAction open_action:
            What action to take depending on whether the file exists or not.
          See
        :param FileSharingMode sharing_mode:
            The file sharing mode in the guest. This parameter is currently
          ignore for all guest OSes.  It will in the future be implemented for
          Windows, OS/2 and maybe Solaris guests only, the others will ignore it.
          Use
        :param int creation_mode:
            The UNIX-style access mode mask to create the file with if @a openAction
          requested the file to be created (otherwise ignored).  Whether/how all
          three access groups and associated access rights are realized is guest
          OS dependent.  The API does the best it can on each OS.
        :param typing.List[FileOpenExFlag] flags:
            Zero or more
        :rtype: GuestFile
        """
        ret = self._call_method('fileOpenEx', path, access_mode, open_action, sharing_mode, creation_mode, flags)
        return ret

    def file_query_size(self, path, follow_symlinks):
        """None
        :param str path:
            Path to the file which size is requested.  Guest path style.
        :param bool follow_symlinks:
            It @c true, symbolic links in the final path component will be
           followed to their target, and the size of the target is returned.
           If @c false, symbolic links in the final path component will make
           the method call fail (symblink is not a regular file).
        :rtype: int
        :returns:
            Queried file size.
        """
        ret = self._call_method('fileQuerySize', path, follow_symlinks)
        return ret

    def fs_obj_exists(self, path, follow_symlinks):
        """None
        :param str path:
            Path to the file system object to check the existance of.  Guest
          path style.
        :param bool follow_symlinks:
            If @c true, symbolic links in the final component will be followed
           and the method will instead check if the target exists.
           If @c false, symbolic links in the final component will satisfy the
           method and it will return @c true in @a exists.
        :rtype: bool
        :returns:
            Returns @c true if the file exists, @c false if not.
        """
        ret = self._call_method('fsObjExists', path, follow_symlinks)
        return ret

    def fs_obj_query_info(self, path, follow_symlinks):
        """None
        :param str path:
            Path to the file system object to gather information about.
          Guest path style.
        :param bool follow_symlinks:
            Information about symbolic links is returned if @c false.  Otherwise,
           symbolic links are followed and the returned information concerns
           itself with the symlink target if @c true.
        :rtype: GuestFsObjInfo
        """
        ret = self._call_method('fsObjQueryInfo', path, follow_symlinks)
        return ret

    def fs_obj_remove(self, path):
        """None
        :param str path:
            Path to the file system object to remove.  Guest style path.
        """
        self._call_method('fsObjRemove', path)

    def fs_obj_rename(self, old_path, new_path, flags):
        """None
        :param str old_path:
            The current path to the object.  Guest path style.
        :param str new_path:
            The new path to the object.  Guest path style.
        :param typing.List[FsObjRenameFlag] flags:
            Zero or more
        """
        self._call_method('fsObjRename', old_path, new_path, flags)

    def fs_obj_move(self, source, destination, flags):
        """None
        :param str source:
            Path to the file to move.  Guest path style.
        :param str destination:
            Where to move the file to (file, not directory).  Guest path
          style.
        :param typing.List[FsObjMoveFlag] flags:
            Zero or more
        :rtype: Progress
        :returns:
            Progress object to track the operation to completion.
        """
        ret = self._call_method('fsObjMove', source, destination, flags)
        return ret

    def fs_obj_set_acl(self, path, follow_symlinks, acl, mode):
        """None
        :param str path:
            Full path of the file system object which ACL to set
        :param bool follow_symlinks:
            If @c true symbolic links in the final component will be followed,
          otherwise, if @c false, the method will work directly on a symbolic
          link in the final component.
        :param str acl:
            The ACL specification string. To-be-defined.
        :param int mode:
            UNIX-style mode mask to use if @a acl is empty. As mention in
        """
        self._call_method('fsObjSetACL', path, follow_symlinks, acl, mode)

    def process_create(self, executable, arguments, environment_changes, flags, timeout_ms):
        """None
        :param str executable:
            Full path to the file to execute in the guest.  The file has to
          exists in the guest VM with executable right to the session user in
          order to succeed.  If empty/null, the first entry in the
          @a arguments array will be used instead (i.e. argv[0]).
        :param typing.List[str] arguments:
            Array of arguments passed to the new process.
        :param typing.List[str] environment_changes:
            Set of environment changes to complement
        :param typing.List[ProcessCreateFlag] flags:
            Process creation flags;
          see
        :param int timeout_ms:
            Timeout (in ms) for limiting the guest process' running time.
          Pass 0 for an infinite timeout. On timeout the guest process will be
          killed and its status will be put to an appropriate value. See
        :rtype: GuestProcess
        :returns:
            Guest process object of the newly created process.
        """
        ret = self._call_method('processCreate', executable, arguments, environment_changes, flags, timeout_ms)
        return ret

    def process_create_ex(self, executable, arguments, environment_changes, flags, timeout_ms, priority, affinity):
        """None
        :param str executable:
            Full path to the file to execute in the guest.  The file has to
          exists in the guest VM with executable right to the session user in
          order to succeed.  If empty/null, the first entry in the
          @a arguments array will be used instead (i.e. argv[0]).
        :param typing.List[str] arguments:
            Array of arguments passed to the new process.
        :param typing.List[str] environment_changes:
            Set of environment changes to complement
        :param typing.List[ProcessCreateFlag] flags:
            Process creation flags, see
        :param int timeout_ms:
            Timeout (in ms) for limiting the guest process' running time.
          Pass 0 for an infinite timeout. On timeout the guest process will be
          killed and its status will be put to an appropriate value. See
        :param ProcessPriority priority:
            Process priority to use for execution, see
        :param int affinity:
            Processor affinity to set for the new process.  This is a list of
          guest CPU numbers the process is allowed to run on.
        :rtype: GuestProcess
        :returns:
            Guest process object of the newly created process.
        """
        ret = self._call_method('processCreateEx', executable, arguments, environment_changes, flags, timeout_ms, priority, affinity)
        return ret

    def process_get(self, pid):
        """None
        :param int pid:
            Process ID (PID) to get guest process for.
        :rtype: GuestProcess
        :returns:
            Guest process of specified process ID (PID).
        """
        ret = self._call_method('processGet', pid)
        return ret

    def symlink_create(self, symlink, target, type_):
        """None
        :param str symlink:
            Path to the symbolic link that should be created.  Guest path
          style.
        :param str target:
            The path to the symbolic link target.  If not an absolute, this will
          be relative to the @a symlink location at access time.  Guest path
          style.
        :param SymlinkType type_:
            The symbolic link type (mainly for Windows). See
        """
        self._call_method('symlinkCreate', symlink, target, type_)

    def symlink_exists(self, symlink):
        """None
        :param str symlink:
            Path to the alleged symbolic link.  Guest path style.
        :rtype: bool
        :returns:
            Returns @c true if the symbolic link exists.  Returns @c false if it
          does not exist, if the file system object identified by the path is
          not a symbolic link, or if the object type is inaccessible to the
          user, or if the @a symlink argument is empty.
        """
        ret = self._call_method('symlinkExists', symlink)
        return ret

    def symlink_read(self, symlink, flags):
        """None
        :param str symlink:
            Path to the symbolic link to read.
        :param typing.List[SymlinkReadFlag] flags:
            Zero or more
        :rtype: str
        :returns:
            Target value of the symbolic link.  Guest path style.
        """
        ret = self._call_method('symlinkRead', symlink, flags)
        return ret

    def wait_for(self, wait_for, timeout_ms):
        """None
        :param int wait_for:
            Specifies what to wait for;
          see
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: GuestSessionWaitResult
        :returns:
            The overall wait result;
          see
        """
        ret = self._call_method('waitFor', wait_for, timeout_ms)
        return ret

    def wait_for_array(self, wait_for, timeout_ms):
        """None
        :param typing.List[GuestSessionWaitForFlag] wait_for:
            Specifies what to wait for;
          see
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: GuestSessionWaitResult
        :returns:
            The overall wait result;
          see
        """
        ret = self._call_method('waitForArray', wait_for, timeout_ms)
        return ret

    @property
    def user(self):
        """Returns the user name used by this session to impersonate
        users in the guest.
        :rtype: str
        """
        return self._get_property('user')

    @property
    def domain(self):
        """Returns the domain name used by this session to impersonate
        users in the guest.
        :rtype: str
        """
        return self._get_property('domain')

    @property
    def name(self):
        """Returns the session's friendly name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def id_(self):
        """Returns the internal session ID.
        :rtype: int
        """
        return self._get_property('id')

    @property
    def timeout(self):
        """
        :rtype: int
        """
        return self._get_property('timeout')

    @property
    def protocol_version(self):
        """Returns the protocol version which is used by this session to
        communicate with the guest.
        :rtype: int
        """
        return self._get_property('protocolVersion')

    @property
    def status(self):
        """Returns the current session status.
        :rtype: GuestSessionStatus
        """
        return GuestSessionStatus(self._get_property('status'))

    @property
    def environment_changes(self):
        """The set of scheduled environment changes to the base environment of the
        session.  They are in putenv format, i.e. "VAR=VALUE" for setting and
        "VAR" for unsetting.  One entry per variable (change).  The changes are
        applied when creating new guest processes.

        This is writable, so to undo all the scheduled changes, assign it an
        empty array.
        :rtype: typing.List[str]
        """
        return list(self._get_property('environmentChanges'))

    @property
    def environment_base(self):
        """The base environment of the session.  They are on the "VAR=VALUE" form,
        one array entry per variable.
        :rtype: typing.List[str]
        """
        return list(self._get_property('environmentBase'))

    @property
    def processes(self):
        """Returns all current guest processes.
        :rtype: typing.List[GuestProcess]
        """
        return [GuestProcess(obj) for obj in self._get_property('processes')]

    @property
    def path_style(self):
        """The style of paths used by the guest.  Handy for giving the right kind
        of path specifications to
        :rtype: PathStyle
        """
        return PathStyle(self._get_property('pathStyle'))

    @property
    def current_directory(self):
        """Gets or sets the current directory of the session.  Guest path style.
        :rtype: str
        """
        return self._get_property('currentDirectory')

    @property
    def user_home(self):
        """Returns the user's home / profile directory.  Guest path style.
        :rtype: str
        """
        return self._get_property('userHome')

    @property
    def user_documents(self):
        """Returns the user's documents directory.  Guest path style.
        :rtype: str
        """
        return self._get_property('userDocuments')

    @property
    def directories(self):
        """Returns all currently opened guest directories.
        :rtype: typing.List[GuestDirectory]
        """
        return [GuestDirectory(obj) for obj in self._get_property('directories')]

    @property
    def files(self):
        """Returns all currently opened guest files.
        :rtype: typing.List[GuestFile]
        """
        return [GuestFile(obj) for obj in self._get_property('files')]

    @property
    def event_source(self):
        """Event source for guest session events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))


class Process(Interface):
    """Abstract parent interface for processes handled by VirtualBox.
    """
    def wait_for(self, wait_for, timeout_ms):
        """None
        :param int wait_for:
            Specifies what to wait for;
          see
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: ProcessWaitResult
        :returns:
            The overall wait result;
          see
        """
        ret = self._call_method('waitFor', wait_for, timeout_ms)
        return ret

    def wait_for_array(self, wait_for, timeout_ms):
        """None
        :param typing.List[ProcessWaitForFlag] wait_for:
            Specifies what to wait for;
          see
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: ProcessWaitResult
        :returns:
            The overall wait result;
          see
        """
        ret = self._call_method('waitForArray', wait_for, timeout_ms)
        return ret

    def read(self, handle, to_read, timeout_ms):
        """None
        :param int handle:
            Handle to read from. Usually 0 is stdin.
        :param int to_read:
            Number of bytes to read.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: typing.List[bytes]
        :returns:
            Array of data read.
        """
        ret = self._call_method('read', handle, to_read, timeout_ms)
        return ret

    def write(self, handle, flags, data, timeout_ms):
        """None
        :param int handle:
            Handle to write to. Usually 0 is stdin, 1 is stdout and 2 is stderr.
        :param int flags:
            A combination of
        :param typing.List[bytes] data:
            Array of bytes to write. The size of the array also specifies
          how much to write.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: int
        :returns:
            How much bytes were written.
        """
        ret = self._call_method('write', handle, flags, data, timeout_ms)
        return ret

    def write_array(self, handle, flags, data, timeout_ms):
        """None
        :param int handle:
            Handle to write to. Usually 0 is stdin, 1 is stdout and 2 is stderr.
        :param typing.List[ProcessInputFlag] flags:
            A combination of
        :param typing.List[bytes] data:
            Array of bytes to write. The size of the array also specifies
          how much to write.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: int
        :returns:
            How much bytes were written.
        """
        ret = self._call_method('writeArray', handle, flags, data, timeout_ms)
        return ret

    def terminate(self):
        """None
        """
        self._call_method('terminate')

    @property
    def arguments(self):
        """The arguments this process is using for execution.
        :rtype: typing.List[str]
        """
        return list(self._get_property('arguments'))

    @property
    def environment(self):
        """The initial process environment.  Not yet implemented.
        :rtype: typing.List[str]
        """
        return list(self._get_property('environment'))

    @property
    def event_source(self):
        """Event source for process events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def executable_path(self):
        """Full path of the actual executable image.
        :rtype: str
        """
        return self._get_property('executablePath')

    @property
    def exit_code(self):
        """The exit code. Only available when the process has been
        terminated normally.
        :rtype: int
        """
        return self._get_property('exitCode')

    @property
    def name(self):
        """The friendly name of this process.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def pid(self):
        """The process ID (PID).
        :rtype: int
        """
        return self._get_property('PID')

    @property
    def status(self):
        """The current process status; see
        :rtype: ProcessStatus
        """
        return ProcessStatus(self._get_property('status'))


class GuestProcess(Process):
    """Implementation of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class Directory(Interface):
    """Abstract parent interface for directories handled by VirtualBox.
    """
    def close(self):
        """None
        """
        self._call_method('close')

    def read(self):
        """None
        :rtype: FsObjInfo
        :returns:
            Object information of the current directory entry read. Also see
        """
        ret = self._call_method('read')
        return ret

    @property
    def directory_name(self):
        """The path specified when opening the directory.
        :rtype: str
        """
        return self._get_property('directoryName')

    @property
    def filter_(self):
        """Directory listing filter to (specified when opening the directory).
        :rtype: str
        """
        return self._get_property('filter')


class GuestDirectory(Directory):
    """Implementation of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class File(Interface):
    """Abstract parent interface for files handled by VirtualBox.
    """
    def close(self):
        """None
        """
        self._call_method('close')

    def query_info(self):
        """None
        :rtype: FsObjInfo
        :returns:
            Object information of this file. Also see
        """
        ret = self._call_method('queryInfo')
        return ret

    def query_size(self):
        """None
        :rtype: int
        :returns:
            Queried file size.
        """
        ret = self._call_method('querySize')
        return ret

    def read(self, to_read, timeout_ms):
        """None
        :param int to_read:
            Number of bytes to read.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: typing.List[bytes]
        :returns:
            Array of data read.
        """
        ret = self._call_method('read', to_read, timeout_ms)
        return ret

    def read_at(self, offset, to_read, timeout_ms):
        """None
        :param int offset:
            Offset in bytes to start reading.
        :param int to_read:
            Number of bytes to read.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: typing.List[bytes]
        :returns:
            Array of data read.
        """
        ret = self._call_method('readAt', offset, to_read, timeout_ms)
        return ret

    def seek(self, offset, whence):
        """None
        :param int offset:
            Offset to seek relative to the position specified by @a whence.
        :param FileSeekOrigin whence:
            One of the
        :rtype: int
        :returns:
            The new file offset after the seek operation.
        """
        ret = self._call_method('seek', offset, whence)
        return ret

    def set_acl(self, acl, mode):
        """None
        :param str acl:
            The ACL specification string. To-be-defined.
        :param int mode:
            UNIX-style mode mask to use if @a acl is empty. As mention in
        """
        self._call_method('setACL', acl, mode)

    def set_size(self, size):
        """None
        :param int size:
            The new file size.
        """
        self._call_method('setSize', size)

    def write(self, data, timeout_ms):
        """None
        :param typing.List[bytes] data:
            Array of bytes to write. The size of the array also specifies
          how much to write.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: int
        :returns:
            How much bytes were written.
        """
        ret = self._call_method('write', data, timeout_ms)
        return ret

    def write_at(self, offset, data, timeout_ms):
        """None
        :param int offset:
            Offset in bytes to start writing.
        :param typing.List[bytes] data:
            Array of bytes to write. The size of the array also specifies
          how much to write.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: int
        :returns:
            How much bytes were written.
        """
        ret = self._call_method('writeAt', offset, data, timeout_ms)
        return ret

    @property
    def event_source(self):
        """Event source for file events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def id_(self):
        """The ID VirtualBox internally assigned to the open file.
        :rtype: int
        """
        return self._get_property('id')

    @property
    def initial_size(self):
        """The initial size in bytes when opened.
        :rtype: int
        """
        return self._get_property('initialSize')

    @property
    def offset(self):
        """The current file position.

        The file current position always applies to the
        :rtype: int
        """
        return self._get_property('offset')

    @property
    def status(self):
        """Current file status.
        :rtype: FileStatus
        """
        return FileStatus(self._get_property('status'))

    @property
    def file_name(self):
        """Full path of the actual file name of this file.
        :rtype: str
        """
        return self._get_property('fileName')

    @property
    def creation_mode(self):
        """The UNIX-style creation mode specified when opening the file.
        :rtype: int
        """
        return self._get_property('creationMode')

    @property
    def open_action(self):
        """The opening action specified when opening the file.
        :rtype: FileOpenAction
        """
        return FileOpenAction(self._get_property('openAction'))

    @property
    def access_mode(self):
        """The file access mode.
        :rtype: FileAccessMode
        """
        return FileAccessMode(self._get_property('accessMode'))


class GuestFile(File):
    """Implementation of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class FsObjInfo(Interface):
    """Abstract parent interface for VirtualBox file system object information.
      This can be information about a file or a directory, for example.
    """
    @property
    def access_time(self):
        """Time of last access (st_atime).
        :rtype: int
        """
        return self._get_property('accessTime')

    @property
    def allocated_size(self):
        """Disk allocation size (st_blocks * DEV_BSIZE).
        :rtype: int
        """
        return self._get_property('allocatedSize')

    @property
    def birth_time(self):
        """Time of file birth (st_birthtime).
        :rtype: int
        """
        return self._get_property('birthTime')

    @property
    def change_time(self):
        """Time of last status change (st_ctime).
        :rtype: int
        """
        return self._get_property('changeTime')

    @property
    def device_number(self):
        """The device number of a character or block device type object (st_rdev).
        :rtype: int
        """
        return self._get_property('deviceNumber')

    @property
    def file_attributes(self):
        """File attributes. Not implemented yet.
        :rtype: str
        """
        return self._get_property('fileAttributes')

    @property
    def generation_id(self):
        """The current generation number (st_gen).
        :rtype: int
        """
        return self._get_property('generationId')

    @property
    def gid(self):
        """The group the filesystem object is assigned (st_gid).
        :rtype: int
        """
        return self._get_property('GID')

    @property
    def group_name(self):
        """The group name.
        :rtype: str
        """
        return self._get_property('groupName')

    @property
    def hard_links(self):
        """Number of hard links to this filesystem object (st_nlink).
        :rtype: int
        """
        return self._get_property('hardLinks')

    @property
    def modification_time(self):
        """Time of last data modification (st_mtime).
        :rtype: int
        """
        return self._get_property('modificationTime')

    @property
    def name(self):
        """The object's name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def node_id(self):
        """The unique identifier (within the filesystem) of this filesystem object (st_ino).
        :rtype: int
        """
        return self._get_property('nodeId')

    @property
    def node_id_device(self):
        """The device number of the device which this filesystem object resides on (st_dev).
        :rtype: int
        """
        return self._get_property('nodeIdDevice')

    @property
    def object_size(self):
        """The logical size (st_size). For normal files this is the size of the file.
        For symbolic links, this is the length of the path name contained in the
        symbolic link. For other objects this fields needs to be specified.
        :rtype: int
        """
        return self._get_property('objectSize')

    @property
    def type_(self):
        """The object type. See
        :rtype: FsObjType
        """
        return FsObjType(self._get_property('type'))

    @property
    def uid(self):
        """The user owning the filesystem object (st_uid).
        :rtype: int
        """
        return self._get_property('UID')

    @property
    def user_flags(self):
        """User flags (st_flags).
        :rtype: int
        """
        return self._get_property('userFlags')

    @property
    def user_name(self):
        """The user name.
        :rtype: str
        """
        return self._get_property('userName')


class GuestFsObjInfo(FsObjInfo):
    """Represents the guest implementation of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class Guest(Interface):
    """The IGuest interface represents information about the operating system
      running inside the virtual machine. Used in
    """
    def internal_get_statistics(self):
        """None
        :rtype: typing.Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int]
        """
        cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total = self._call_method('internalGetStatistics')
        return cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total

    def get_facility_status(self, facility):
        """None
        :param AdditionsFacilityType facility:
            Facility to check status for.
        :rtype: typing.Tuple[AdditionsFacilityStatus, int]
        """
        status, timestamp = self._call_method('getFacilityStatus', facility)
        status = AdditionsFacilityStatus(status)
        return status, timestamp

    def get_additions_status(self, level):
        """None
        :param AdditionsRunLevelType level:
            Status level to check
        :rtype: bool
        :returns:
            Flag whether the status level has been reached or not
        """
        ret = self._call_method('getAdditionsStatus', level)
        return ret

    def set_credentials(self, user_name, password, domain, allow_interactive_logon):
        """None
        :param str user_name:
            User name string, can be empty
        :param str password:
            Password string, can be empty
        :param str domain:
            Domain name (guest logon scheme specific), can be empty
        :param bool allow_interactive_logon:
            Flag whether the guest should alternatively allow the user to
          interactively specify different credentials. This flag might
          not be supported by all versions of the Additions.
        """
        self._call_method('setCredentials', user_name, password, domain, allow_interactive_logon)

    def create_session(self, user, password, domain, session_name):
        """None
        :param str user:
            User name this session will be using to control the guest; has to exist
          and have the appropriate rights to execute programs in the VM. Must not
          be empty.
        :param str password:
            Password of the user account to be used. Empty passwords are allowed.
        :param str domain:
            Domain name of the user account to be used if the guest is part of
          a domain. Optional. This feature is not implemented yet.
        :param str session_name:
            The session's friendly name. Optional, can be empty.
        :rtype: GuestSession
        :returns:
            The newly created session object.
        """
        ret = self._call_method('createSession', user, password, domain, session_name)
        return ret

    def find_session(self, session_name):
        """None
        :param str session_name:
            The session's friendly name to find. Wildcards like ? and * are allowed.
        :rtype: typing.List[GuestSession]
        :returns:
            Array with all guest sessions found matching the name specified.
        """
        ret = self._call_method('findSession', session_name)
        return ret

    def update_guest_additions(self, source, arguments, flags):
        """None
        :param str source:
            Path to the Guest Additions .ISO file to use for the update.
        :param typing.List[str] arguments:
            Optional command line arguments to use for the Guest Additions
          installer. Useful for retrofitting features which weren't installed
          before in the guest.
        :param typing.List[AdditionsUpdateFlag] flags:
            
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('updateGuestAdditions', source, arguments, flags)
        return ret

    @property
    def os_type_id(self):
        """Identifier of the Guest OS type as reported by the Guest
        Additions.
        You may use
        :rtype: str
        """
        return self._get_property('OSTypeId')

    @property
    def additions_run_level(self):
        """Current run level of the installed Guest Additions.
        :rtype: AdditionsRunLevelType
        """
        return AdditionsRunLevelType(self._get_property('additionsRunLevel'))

    @property
    def additions_version(self):
        """Version of the installed Guest Additions in the same format as
        :rtype: str
        """
        return self._get_property('additionsVersion')

    @property
    def additions_revision(self):
        """The internal build revision number of the installed Guest Additions.

        See also
        :rtype: int
        """
        return self._get_property('additionsRevision')

    @property
    def drag_and_drop_source(self):
        """Retrieves the drag'n drop source implementation for the guest side, that
        is, handling and retrieving drag'n drop data from the guest.
        :rtype: GuestDnDSource
        """
        return GuestDnDSource(self._get_property('dnDSource'))

    @property
    def drag_and_drop_target(self):
        """Retrieves the drag'n drop source implementation for the host side. This
        will allow the host to handle and initiate a drag'n drop operation to copy
        data from the host to the guest.
        :rtype: GuestDnDTarget
        """
        return GuestDnDTarget(self._get_property('dnDTarget'))

    @property
    def event_source(self):
        """Event source for guest events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

    @property
    def facilities(self):
        """Returns a collection of current known facilities. Only returns facilities where
        a status is known, e.g. facilities with an unknown status will not be returned.
        :rtype: typing.List[AdditionsFacility]
        """
        return [AdditionsFacility(obj) for obj in self._get_property('facilities')]

    @property
    def sessions(self):
        """Returns a collection of all opened guest sessions.
        :rtype: typing.List[GuestSession]
        """
        return [GuestSession(obj) for obj in self._get_property('sessions')]

    @property
    def memory_balloon_size(self):
        """Guest system memory balloon size in megabytes (transient property).
        :rtype: int
        """
        return self._get_property('memoryBalloonSize')

    @property
    def statistics_update_interval(self):
        """Interval to update guest statistics in seconds.
        :rtype: int
        """
        return self._get_property('statisticsUpdateInterval')


class Progress(Interface):
    """The IProgress interface is used to track and control
        asynchronous tasks within VirtualBox.

        An instance of this is returned every time VirtualBox starts
        an asynchronous task (in other words, a separate thread) which
        continues to run after a method call returns. For example,
    """
    def set_current_operation_progress(self, percent):
        """None
        :param int percent:
        """
        self._call_method('setCurrentOperationProgress', percent)

    def set_next_operation(self, next_operation_description, next_operations_weight):
        """None
        :param str next_operation_description:
        :param int next_operations_weight:
        """
        self._call_method('setNextOperation', next_operation_description, next_operations_weight)

    def wait_for_completion(self, timeout):
        """None
        :param int timeout:
            Maximum time in milliseconds to wait or -1 to wait indefinitely.
        """
        self._call_method('waitForCompletion', timeout)

    def wait_for_operation_completion(self, operation, timeout):
        """None
        :param int operation:
            Number of the operation to wait for.
          Must be less than
        :param int timeout:
            Maximum time in milliseconds to wait or -1 to wait indefinitely.
        """
        self._call_method('waitForOperationCompletion', operation, timeout)

    def wait_for_async_progress_completion(self, p_progress_async):
        """None
        :param Progress p_progress_async:
            The progress object of the asynchrony process.
        """
        self._call_method('waitForAsyncProgressCompletion', p_progress_async)

    def cancel(self):
        """None
        """
        self._call_method('cancel')

    @property
    def id_(self):
        """ID of the task.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def description(self):
        """Description of the task.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def initiator(self):
        """Initiator of the task.
        :rtype: Interface
        """
        return Interface(self._get_property('initiator'))

    @property
    def cancelable(self):
        """Whether the task can be interrupted.
        :rtype: bool
        """
        return self._get_property('cancelable')

    @property
    def percent(self):
        """Current progress value of the task as a whole, in percent.
        This value depends on how many operations are already complete.
        Returns 100 if
        :rtype: int
        """
        return self._get_property('percent')

    @property
    def time_remaining(self):
        """Estimated remaining time until the task completes, in
            seconds. Returns 0 once the task has completed; returns -1
            if the remaining time cannot be computed, in particular if
            the current progress is 0.

            Even if a value is returned, the estimate will be unreliable
            for low progress values. It will become more reliable as the
            task progresses; it is not recommended to display an ETA
            before at least 20% of a task have completed.
        :rtype: int
        """
        return self._get_property('timeRemaining')

    @property
    def completed(self):
        """Whether the task has been completed.
        :rtype: bool
        """
        return self._get_property('completed')

    @property
    def canceled(self):
        """Whether the task has been canceled.
        :rtype: bool
        """
        return self._get_property('canceled')

    @property
    def result_code(self):
        """Result code of the progress task.
        Valid only if
        :rtype: int
        """
        return self._get_property('resultCode')

    @property
    def error_info(self):
        """Extended information about the unsuccessful result of the
        progress operation. May be @c null if no extended information
        is available.
        Valid only if
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('errorInfo'))

    @property
    def operation_count(self):
        """Number of sub-operations this task is divided into.
          Every task consists of at least one suboperation.
        :rtype: int
        """
        return self._get_property('operationCount')

    @property
    def operation(self):
        """Number of the sub-operation being currently executed.
        :rtype: int
        """
        return self._get_property('operation')

    @property
    def operation_description(self):
        """Description of the sub-operation being currently executed.
        :rtype: str
        """
        return self._get_property('operationDescription')

    @property
    def operation_percent(self):
        """Progress value of the current sub-operation only, in percent.
        :rtype: int
        """
        return self._get_property('operationPercent')

    @property
    def operation_weight(self):
        """Weight value of the current sub-operation only.
        :rtype: int
        """
        return self._get_property('operationWeight')

    @property
    def timeout(self):
        """When non-zero, this specifies the number of milliseconds after which
          the operation will automatically be canceled. This can only be set on
          cancelable objects.
        :rtype: int
        """
        return self._get_property('timeout')

    @property
    def event_source(self):
        """None
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))


class Snapshot(Interface):
    """The ISnapshot interface represents a snapshot of the virtual
      machine.

      Together with the differencing media that are created
      when a snapshot is taken, a machine can be brought back to
      the exact state it was in when the snapshot was taken.

      The ISnapshot interface has no methods, only attributes; snapshots
      are controlled through methods of the
    """
    def get_children_count(self):
        """None
        :rtype: int
        :returns:
            
        """
        ret = self._call_method('getChildrenCount')
        return ret

    @property
    def id_(self):
        """UUID of the snapshot.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def name(self):
        """Short name of the snapshot.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def description(self):
        """Optional description of the snapshot.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def time_stamp(self):
        """Time stamp of the snapshot, in milliseconds since 1970-01-01 UTC.
        :rtype: int
        """
        return self._get_property('timeStamp')

    @property
    def online(self):
        """@c true if this snapshot is an online snapshot and @c false otherwise.

          When this attribute is @c true, the
        :rtype: bool
        """
        return self._get_property('online')

    @property
    def machine(self):
        """Virtual machine this snapshot is taken on. This object
        stores all settings the machine had when taking this snapshot.
        :rtype: Machine
        """
        return Machine(self._get_property('machine'))

    @property
    def parent(self):
        """Parent snapshot (a snapshot this one is based on), or
        @c null if the snapshot has no parent (i.e. is the first snapshot).
        :rtype: Snapshot
        """
        return Snapshot(self._get_property('parent'))

    @property
    def children(self):
        """Child snapshots (all snapshots having this one as a parent).
        By inspecting this attribute starting with a machine's root snapshot
        (which can be obtained by calling
        :rtype: typing.List[Snapshot]
        """
        return [Snapshot(obj) for obj in self._get_property('children')]


class MediumState(enum.Enum):
    """
      Virtual medium state.
      
     .. describe:: NOT_CREATED 
        Associated medium storage does not exist (either was not created yet or
        was deleted).
      
     .. describe:: CREATED 
        Associated storage exists and accessible; this gets set if the
        accessibility check performed by 
     .. describe:: LOCKED_READ 
        Medium is locked for reading (see 
     .. describe:: LOCKED_WRITE 
        Medium is locked for writing (see 
     .. describe:: INACCESSIBLE 
        Medium accessibility check (see 
     .. describe:: CREATING 
        Associated medium storage is being created.
      
     .. describe:: DELETING 
        Associated medium storage is being deleted.
      
    """
    NOT_CREATED = 0
    CREATED = 1
    LOCKED_READ = 2
    LOCKED_WRITE = 3
    INACCESSIBLE = 4
    CREATING = 5
    DELETING = 6

class MediumType(enum.Enum):
    """
      Virtual medium type. For each 
     .. describe:: NORMAL 
        Normal medium (attached directly or indirectly, preserved
        when taking snapshots).
      
     .. describe:: IMMUTABLE 
        Immutable medium (attached indirectly, changes are wiped out
        the next time the virtual machine is started).
      
     .. describe:: WRITETHROUGH 
        Write through medium (attached directly, ignored when
        taking snapshots).
      
     .. describe:: SHAREABLE 
        Allow using this medium concurrently by several machines.
        
     .. describe:: READONLY 
        A readonly medium, which can of course be used by several machines.
        
     .. describe:: MULTI_ATTACH 
        A medium which is indirectly attached, so that one base medium can
        be used for several VMs which have their own differencing medium to
        store their modifications. In some sense a variant of Immutable
        with unset AutoReset flag in each differencing medium.
        
    """
    NORMAL = 0
    IMMUTABLE = 1
    WRITETHROUGH = 2
    SHAREABLE = 3
    READONLY = 4
    MULTI_ATTACH = 5

class MediumVariant(enum.Enum):
    """
      Virtual medium image variant. More than one flag may be set.
      
     .. describe:: STANDARD 
        No particular variant requested, results in using the backend default.
      
     .. describe:: VMDK_SPLIT2_G 
        VMDK image split in chunks of less than 2GByte.
      
     .. describe:: VMDK_RAW_DISK 
        VMDK image representing a raw disk.
      
     .. describe:: VMDK_STREAM_OPTIMIZED 
        VMDK streamOptimized image. Special import/export format which is
        read-only/append-only.
      
     .. describe:: VMDK_ESX 
        VMDK format variant used on ESX products.
      
     .. describe:: VDI_ZERO_EXPAND 
        Fill new blocks with zeroes while expanding image file.
      
     .. describe:: FIXED 
        Fixed image. Only allowed for base images.
      
     .. describe:: DIFF 
        Differencing image. Only allowed for child images.
      
     .. describe:: NO_CREATE_DIR 
        Special flag which suppresses automatic creation of the subdirectory.
        Only used when passing the medium variant as an input parameter.
      
    """
    STANDARD = 0
    VMDK_SPLIT2_G = 1
    VMDK_RAW_DISK = 2
    VMDK_STREAM_OPTIMIZED = 4
    VMDK_ESX = 8
    VDI_ZERO_EXPAND = 256
    FIXED = 65536
    DIFF = 131072
    NO_CREATE_DIR = 1073741824

class MediumAttachment(Interface):
    """The IMediumAttachment interface links storage media to virtual machines.
      For each medium (
    """
    @property
    def medium(self):
        """Medium object associated with this attachment; it
        can be @c null for removable devices.
        :rtype: Medium
        """
        return Medium(self._get_property('medium'))

    @property
    def controller(self):
        """Name of the storage controller of this attachment; this
        refers to one of the controllers in
        :rtype: str
        """
        return self._get_property('controller')

    @property
    def port(self):
        """Port number of this attachment.
        See
        :rtype: int
        """
        return self._get_property('port')

    @property
    def device(self):
        """Device slot number of this attachment.
        See
        :rtype: int
        """
        return self._get_property('device')

    @property
    def type_(self):
        """Device type of this attachment.
        :rtype: DeviceType
        """
        return DeviceType(self._get_property('type'))

    @property
    def passthrough(self):
        """Pass I/O requests through to a device on the host.
        :rtype: bool
        """
        return self._get_property('passthrough')

    @property
    def temporary_eject(self):
        """Whether guest-triggered eject results in unmounting the medium.
        :rtype: bool
        """
        return self._get_property('temporaryEject')

    @property
    def is_ejected(self):
        """Signals that the removable medium has been ejected. This is not
        necessarily equivalent to having a @c null medium association.
        :rtype: bool
        """
        return self._get_property('isEjected')

    @property
    def non_rotational(self):
        """Whether the associated medium is non-rotational.
        :rtype: bool
        """
        return self._get_property('nonRotational')

    @property
    def discard(self):
        """Whether the associated medium supports discarding unused blocks.
        :rtype: bool
        """
        return self._get_property('discard')

    @property
    def hot_pluggable(self):
        """Whether this attachment is hot pluggable or not.
        :rtype: bool
        """
        return self._get_property('hotPluggable')

    @property
    def bandwidth_group(self):
        """The bandwidth group this medium attachment is assigned to.
        :rtype: BandwidthGroup
        """
        return BandwidthGroup(self._get_property('bandwidthGroup'))


class Medium(Interface):
    """The IMedium interface represents virtual storage for a machine's
      hard disks, CD/DVD or floppy drives. It will typically represent
      a disk image on the host, for example a VDI or VMDK file representing
      a virtual hard disk, or an ISO or RAW file representing virtual
      removable media, but can also point to a network location (e.g.
      for iSCSI targets).

      Instances of IMedium are connected to virtual machines by way of medium
      attachments, which link the storage medium to a particular device slot
      of a storage controller of the virtual machine.
      In the VirtualBox API, virtual storage is therefore always represented
      by the following chain of object links:
    """
    def set_ids(self, set_image_id, image_id, set_parent_id, parent_id):
        """None
        :param bool set_image_id:
            Select whether a new image UUID is set or not.
        :param str image_id:
            New UUID for the image. If an empty string is passed, then a new
          UUID is automatically created, provided that @a setImageId is @c true.
          Specifying a zero UUID is not allowed.
        :param bool set_parent_id:
            Select whether a new parent UUID is set or not.
        :param str parent_id:
            New parent UUID for the image. If an empty string is passed, then a
          new UUID is automatically created, provided @a setParentId is
          @c true. A zero UUID is valid.
        """
        self._call_method('setIds', set_image_id, image_id, set_parent_id, parent_id)

    def refresh_state(self):
        """None
        :rtype: MediumState
        :returns:
            New medium state.
        """
        ret = self._call_method('refreshState')
        return ret

    def get_snapshot_ids(self, machine_id):
        """None
        :param str machine_id:
            UUID of the machine to query.
        :rtype: typing.List[str]
        :returns:
            Array of snapshot UUIDs of the given machine using this medium.
        """
        ret = self._call_method('getSnapshotIds', machine_id)
        return ret

    def lock_read(self):
        """None
        :rtype: Token
        :returns:
            Token object, when this is released (reference count reaches 0) then
          the lock count is decreased. The lock is released when the lock count
          reaches 0.
        """
        ret = self._call_method('lockRead')
        return ret

    def lock_write(self):
        """None
        :rtype: Token
        :returns:
            Token object, when this is released (reference count reaches 0) then
          the lock is released.
        """
        ret = self._call_method('lockWrite')
        return ret

    def close(self):
        """None
        """
        self._call_method('close')

    def get_property(self, name):
        """None
        :param str name:
            Name of the property to get.
        :rtype: str
        :returns:
            Current property value.
        """
        ret = self._call_method('getProperty', name)
        return ret

    def set_property(self, name, value):
        """None
        :param str name:
            Name of the property to set.
        :param str value:
            Property value to set.
        """
        self._call_method('setProperty', name, value)

    def get_properties(self, names):
        """None
        :param str names:
            Names of properties to get.
        :rtype: typing.List[typing.Tuple[str, str]]
        """
        return_values, return_names = self._call_method('getProperties', names)
        return return_values, return_names

    def set_properties(self, names, values):
        """None
        :param typing.List[str] names:
            Names of properties to set.
        :param typing.List[str] values:
            Values of properties to set.
        """
        self._call_method('setProperties', names, values)

    def create_base_storage(self, logical_size, variant):
        """None
        :param int logical_size:
            Maximum logical size of the medium in bytes.
        :param typing.List[MediumVariant] variant:
            Exact image variant which should be created (as a combination of
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('createBaseStorage', logical_size, variant)
        return ret

    def delete_storage(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('deleteStorage')
        return ret

    def create_diff_storage(self, target, variant):
        """None
        :param Medium target:
            Target medium.
        :param typing.List[MediumVariant] variant:
            Exact image variant which should be created (as a combination of
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('createDiffStorage', target, variant)
        return ret

    def merge_to(self, target):
        """None
        :param Medium target:
            Target medium.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('mergeTo', target)
        return ret

    def clone_to(self, target, variant, parent):
        """None
        :param Medium target:
            Target medium.
        :param typing.List[MediumVariant] variant:
            Exact image variant which should be created (as a combination of
        :param Medium parent:
            Parent of the cloned medium.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('cloneTo', target, variant, parent)
        return ret

    def clone_to_base(self, target, variant):
        """None
        :param Medium target:
            Target medium.
        :param typing.List[MediumVariant] variant:
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('cloneToBase', target, variant)
        return ret

    def set_location(self, location):
        """None
        :param str location:
            New location.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('setLocation', location)
        return ret

    def compact(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('compact')
        return ret

    def resize(self, logical_size):
        """None
        :param int logical_size:
            New nominal capacity of the medium in bytes.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('resize', logical_size)
        return ret

    def reset(self):
        """None
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('reset')
        return ret

    def change_encryption(self, current_password, cipher, new_password, new_password_id):
        """None
        :param str current_password:
            The current password the medium is protected with. Use an empty string to indicate
          that the medium isn't encrypted.
        :param str cipher:
            The cipher to use for encryption. An empty string indicates no encryption for the
          result.
        :param str new_password:
            The new password the medium should be protected with. An empty password and password ID
          will result in the medium being encrypted with the current password.
        :param str new_password_id:
            The ID of the new password when unlocking the medium.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = self._call_method('changeEncryption', current_password, cipher, new_password, new_password_id)
        return ret

    def get_encryption_settings(self):
        """None
        :rtype: typing.Tuple[str, str]
        """
        password_id, cipher = self._call_method('getEncryptionSettings')
        return password_id, cipher

    def check_encryption_password(self, password):
        """None
        :param str password:
            The password to check.
        """
        self._call_method('checkEncryptionPassword', password)

    @property
    def id_(self):
        """UUID of the medium. For a newly created medium, this value is a randomly
        generated UUID.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def description(self):
        """Optional description of the medium. For a newly created medium the value
        of this attribute is an empty string.

        Medium types that don't support this attribute will return E_NOTIMPL in
        attempt to get or set this attribute's value.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def state(self):
        """Returns the current medium state, which is the last state set by
        the accessibility check performed by
        :rtype: MediumState
        """
        return MediumState(self._get_property('state'))

    @property
    def variant(self):
        """Returns the storage format variant information for this medium
        as an array of the flags described at
        :rtype: typing.List[MediumVariant]
        """
        return [MediumVariant(obj) for obj in self._get_property('variant')]

    @property
    def location(self):
        """Location of the storage unit holding medium data.

        The format of the location string is medium type specific. For medium
        types using regular files in a host's file system, the location
        string is the full file name.
        :rtype: str
        """
        return self._get_property('location')

    @property
    def name(self):
        """Name of the storage unit holding medium data.

        The returned string is a short version of the
        :rtype: str
        """
        return self._get_property('name')

    @property
    def device_type(self):
        """Kind of device (DVD/Floppy/HardDisk) which is applicable to this
        medium.
        :rtype: DeviceType
        """
        return DeviceType(self._get_property('deviceType'))

    @property
    def host_drive(self):
        """True if this corresponds to a drive on the host.
        :rtype: bool
        """
        return self._get_property('hostDrive')

    @property
    def size(self):
        """Physical size of the storage unit used to hold medium data (in bytes).
        :rtype: int
        """
        return self._get_property('size')

    @property
    def format_(self):
        """Storage format of this medium.

        The value of this attribute is a string that specifies a backend used
        to store medium data. The storage format is defined when you create a
        new medium or automatically detected when you open an existing medium,
        and cannot be changed later.

        The list of all storage formats supported by this VirtualBox
        installation can be obtained using
        :rtype: str
        """
        return self._get_property('format')

    @property
    def medium_format(self):
        """Storage medium format object corresponding to this medium.

        The value of this attribute is a reference to the medium format object
        that specifies the backend properties used to store medium data. The
        storage format is defined when you create a new medium or automatically
        detected when you open an existing medium, and cannot be changed later.
        :rtype: MediumFormat
        """
        return MediumFormat(self._get_property('mediumFormat'))

    @property
    def type_(self):
        """Type (role) of this medium.

        The following constraints apply when changing the value of this
        attribute:
        :rtype: MediumType
        """
        return MediumType(self._get_property('type'))

    @property
    def allowed_types(self):
        """Returns which medium types can selected for this medium.
        :rtype: typing.List[MediumType]
        """
        return [MediumType(obj) for obj in self._get_property('allowedTypes')]

    @property
    def parent(self):
        """Parent of this medium (the medium this medium is directly based
        on).

        Only differencing media have parents. For base (non-differencing)
        media, @c null is returned.
        :rtype: Medium
        """
        return Medium(self._get_property('parent'))

    @property
    def children(self):
        """Children of this medium (all differencing media directly based
        on this medium). A @c null array is returned if this medium
        does not have any children.
        :rtype: typing.List[Medium]
        """
        return [Medium(obj) for obj in self._get_property('children')]

    @property
    def base(self):
        """Base medium of this medium.

        If this is a differencing medium, its base medium is the medium
        the given medium branch starts from. For all other types of media, this
        property returns the medium object itself (i.e. the same object this
        property is read on).
        :rtype: Medium
        """
        return Medium(self._get_property('base'))

    @property
    def read_only(self):
        """Returns @c true if this medium is read-only and @c false otherwise.

        A medium is considered to be read-only when its contents cannot be
        modified without breaking the integrity of other parties that depend on
        this medium such as its child media or snapshots of virtual machines
        where this medium is attached to these machines. If there are no
        children and no such snapshots then there is no dependency and the
        medium is not read-only.

        The value of this attribute can be used to determine the kind of the
        attachment that will take place when attaching this medium to a
        virtual machine. If the value is @c false then the medium will
        be attached directly. If the value is @c true then the medium
        will be attached indirectly by creating a new differencing child
        medium for that. See the interface description for more information.

        Note that all
        :rtype: bool
        """
        return self._get_property('readOnly')

    @property
    def logical_size(self):
        """Logical size of this medium (in bytes), as reported to the
        guest OS running inside the virtual machine this medium is
        attached to. The logical size is defined when the medium is created
        and cannot be changed later.
        :rtype: int
        """
        return self._get_property('logicalSize')

    @property
    def auto_reset(self):
        """Whether this differencing medium will be automatically reset each
        time a virtual machine it is attached to is powered up. This
        attribute is automatically set to @c true for the last
        differencing image of an "immutable" medium (see
        :rtype: bool
        """
        return self._get_property('autoReset')

    @property
    def last_access_error(self):
        """Text message that represents the result of the last accessibility
        check performed by
        :rtype: str
        """
        return self._get_property('lastAccessError')

    @property
    def machine_ids(self):
        """Array of UUIDs of all machines this medium is attached to.

        A @c null array is returned if this medium is not attached to any
        machine or to any machine's snapshot.
        :rtype: typing.List[str]
        """
        return list(self._get_property('machineIds'))


class DataType(enum.Enum):
    """
    """
    INT32 = 0
    INT8 = 1
    STRING = 2

class DataFlags(enum.Enum):
    """
    """
    NONE = 0
    MANDATORY = 1
    EXPERT = 2
    ARRAY = 4
    FLAG_MASK = 7

class MediumFormatCapabilities(enum.Enum):
    """
      Medium format capability flags.
    
     .. describe:: UUID 
        Supports UUIDs as expected by VirtualBox code.
      
     .. describe:: CREATE_FIXED 
        Supports creating fixed size images, allocating all space instantly.
      
     .. describe:: CREATE_DYNAMIC 
        Supports creating dynamically growing images, allocating space on
        demand.
      
     .. describe:: CREATE_SPLIT2_G 
        Supports creating images split in chunks of a bit less than 2 GBytes.
      
     .. describe:: DIFFERENCING 
        Supports being used as a format for differencing media (see 
     .. describe:: ASYNCHRONOUS 
        Supports asynchronous I/O operations for at least some configurations.
      
     .. describe:: FILE 
        The format backend operates on files (the 
     .. describe:: PROPERTIES 
        The format backend uses the property interface to configure the storage
        location and properties (the 
     .. describe:: TCP_NETWORKING 
        The format backend uses the TCP networking interface for network access.
      
     .. describe:: VFS 
        The format backend supports virtual filesystem functionality.
      
     .. describe:: DISCARD 
        The format backend supports discarding blocks.
      
     .. describe:: PREFERRED 
        Indicates that this is a frequently used format backend.
      
    """
    UUID = 1
    CREATE_FIXED = 2
    CREATE_DYNAMIC = 4
    CREATE_SPLIT2_G = 8
    DIFFERENCING = 16
    ASYNCHRONOUS = 32
    FILE = 64
    PROPERTIES = 128
    TCP_NETWORKING = 256
    VFS = 512
    DISCARD = 1024
    PREFERRED = 2048
    CAPABILITY_MASK = 4095

class MediumFormat(Interface):
    """The IMediumFormat interface represents a medium format.

        Each medium format has an associated backend which is used to handle
        media stored in this format. This interface provides information
        about the properties of the associated backend.

        Each medium format is identified by a string represented by the
    """
    def describe_file_extensions(self):
        """None
        :rtype: typing.List[typing.Tuple[str, DeviceType]]
        """
        extensions, types = self._call_method('describeFileExtensions')
        types = DeviceType(types)
        return extensions, types

    def describe_properties(self):
        """None
        :rtype: typing.List[typing.Tuple[str, str, DataType, int, str]]
        """
        names, descriptions, types, flags, defaults = self._call_method('describeProperties')
        types = DataType(types)
        return names, descriptions, types, flags, defaults

    @property
    def id_(self):
        """Identifier of this format.

        The format identifier is a non-@c null non-empty ASCII string. Note that
        this string is case-insensitive. This means that, for example, all of
        the following strings:
        :rtype: str
        """
        return self._get_property('id')

    @property
    def name(self):
        """Human readable description of this format.

        Mainly for use in file open dialogs.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def capabilities(self):
        """Capabilities of the format as an array of the flags.

        For the meaning of individual capability flags see
        :rtype: typing.List[MediumFormatCapabilities]
        """
        return [MediumFormatCapabilities(obj) for obj in self._get_property('capabilities')]


class Token(Interface):
    """The IToken interface represents a token passed to an API client, which
      triggers cleanup actions when it is explicitly released by calling the
    """
    def abandon(self):
        """None
        """
        self._call_method('abandon')

    def dummy(self):
        """None
        """
        self._call_method('dummy')


class KeyboardLED(enum.Enum):
    """
      Keyboard LED indicators.
    
    """
    NUM_LOCK = 1
    CAPS_LOCK = 2
    SCROLL_LOCK = 4

class Keyboard(Interface):
    """The IKeyboard interface represents the virtual machine's keyboard. Used
      in
    """
    def put_scancode(self, scancode):
        """None
        :param int scancode:
        """
        self._call_method('putScancode', scancode)

    def put_scancodes(self, scancodes):
        """None
        :param int scancodes:
        :rtype: int
        """
        ret = self._call_method('putScancodes', scancodes)
        return ret

    def put_cad(self):
        """None
        """
        self._call_method('putCAD')

    def release_keys(self):
        """None
        """
        self._call_method('releaseKeys')

    @property
    def keyboard_le_ds(self):
        """Current status of the guest keyboard LEDs.
        :rtype: typing.List[KeyboardLED]
        """
        return [KeyboardLED(obj) for obj in self._get_property('keyboardLEDs')]

    @property
    def event_source(self):
        """Event source for keyboard events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))


class MouseButtonState(enum.Enum):
    """
      Mouse button state.
    
    """
    LEFT_BUTTON = 1
    RIGHT_BUTTON = 2
    MIDDLE_BUTTON = 4
    WHEEL_UP = 8
    WHEEL_DOWN = 16
    X_BUTTON1 = 32
    X_BUTTON2 = 64
    MOUSE_STATE_MASK = 127

class TouchContactState(enum.Enum):
    """
      Touch event contact state.
    
     .. describe:: NONE The touch has finished.
     .. describe:: IN_CONTACT Whether the touch is really touching the device.
     .. describe:: IN_RANGE 
        Whether the touch is close enough to the device to be detected.
      
    """
    NONE = 0
    IN_CONTACT = 1
    IN_RANGE = 2
    CONTACT_STATE_MASK = 3

class MousePointerShape(Interface):
    """The guest mouse pointer description.
    """
    @property
    def visible(self):
        """Flag whether the pointer is visible.
        :rtype: bool
        """
        return self._get_property('visible')

    @property
    def alpha(self):
        """Flag whether the pointer has an alpha channel.
        :rtype: bool
        """
        return self._get_property('alpha')

    @property
    def hot_x(self):
        """The pointer hot spot X coordinate.
        :rtype: int
        """
        return self._get_property('hotX')

    @property
    def hot_y(self):
        """The pointer hot spot Y coordinate.
        :rtype: int
        """
        return self._get_property('hotY')

    @property
    def width(self):
        """Width of the pointer shape in pixels.
        :rtype: int
        """
        return self._get_property('width')

    @property
    def height(self):
        """Height of the pointer shape in pixels.
        :rtype: int
        """
        return self._get_property('height')

    @property
    def shape(self):
        """Shape bitmaps.

        The @a shape buffer contains a 1bpp (bits per pixel) AND mask
        followed by a 32bpp XOR (color) mask.

        For pointers without alpha channel the XOR mask pixels are
        32 bit values: (lsb)BGR0(msb). For pointers with alpha channel
        the XOR mask consists of (lsb)BGRA(msb) 32 bit values.

        An AND mask is provided for pointers with alpha channel, so if the
        client does not support alpha, the pointer could be
        displayed as a normal color pointer.

        The AND mask is a 1bpp bitmap with byte aligned scanlines. The
        size of the AND mask therefore is
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('shape'))


class Mouse(Interface):
    """The IMouse interface represents the virtual machine's mouse. Used in
    """
    def put_mouse_event(self, dx, dy, dz, dw, button_state):
        """None
        :param int dx:
            Amount of pixels the mouse should move to the right.
          Negative values move the mouse to the left.
        :param int dy:
            Amount of pixels the mouse should move downwards.
          Negative values move the mouse upwards.
        :param int dz:
            Amount of mouse wheel moves.
          Positive values describe clockwise wheel rotations,
          negative values describe counterclockwise rotations.
        :param int dw:
            Amount of horizontal mouse wheel moves.
          Positive values describe a movement to the left,
          negative values describe a movement to the right.
        :param int button_state:
            The current state of mouse buttons. Every bit represents
          a mouse button as follows:
        """
        self._call_method('putMouseEvent', dx, dy, dz, dw, button_state)

    def put_mouse_event_absolute(self, x, y, dz, dw, button_state):
        """None
        :param int x:
            X coordinate of the pointer in pixels, starting from @c 1.
        :param int y:
            Y coordinate of the pointer in pixels, starting from @c 1.
        :param int dz:
            Amount of mouse wheel moves.
          Positive values describe clockwise wheel rotations,
          negative values describe counterclockwise rotations.
        :param int dw:
            Amount of horizontal mouse wheel moves.
          Positive values describe a movement to the left,
          negative values describe a movement to the right.
        :param int button_state:
            The current state of mouse buttons. Every bit represents
          a mouse button as follows:
        """
        self._call_method('putMouseEventAbsolute', x, y, dz, dw, button_state)

    def put_event_multi_touch(self, count, contacts, scan_time):
        """None
        :param int count:
            Number of contacts in the event.
        :param int contacts:
            Each array element contains packed information about one contact.
          Bits 0..15: X coordinate in pixels.
          Bits 16..31: Y coordinate in pixels.
          Bits 32..39: contact identifier.
          Bit 40: "in contact" flag, which indicates that there is a contact with the touch surface.
          Bit 41: "in range" flag, the contact is close enough to the touch surface.
          All other bits are reserved for future use and must be set to 0.
        :param int scan_time:
            Timestamp of the event in milliseconds. Only relative time between events is important.
        """
        self._call_method('putEventMultiTouch', count, contacts, scan_time)

    def put_event_multi_touch_string(self, count, contacts, scan_time):
        """None
        :param int count:
            
        :param str contacts:
            Contains information about all contacts:
          "id1,x1,y1,inContact1,inRange1;...;idN,xN,yN,inContactN,inRangeN".
          For example for two contacts: "0,10,20,1,1;1,30,40,1,1"
        :param int scan_time:
            
        """
        self._call_method('putEventMultiTouchString', count, contacts, scan_time)

    @property
    def absolute_supported(self):
        """Whether the guest OS supports absolute mouse pointer positioning
        or not.
        :rtype: bool
        """
        return self._get_property('absoluteSupported')

    @property
    def relative_supported(self):
        """Whether the guest OS supports relative mouse pointer positioning
        or not.
        :rtype: bool
        """
        return self._get_property('relativeSupported')

    @property
    def multi_touch_supported(self):
        """Whether the guest OS has enabled the multi-touch reporting device.
        :rtype: bool
        """
        return self._get_property('multiTouchSupported')

    @property
    def needs_host_cursor(self):
        """Whether the guest OS can currently switch to drawing it's own mouse
        cursor on demand.
        :rtype: bool
        """
        return self._get_property('needsHostCursor')

    @property
    def pointer_shape(self):
        """The current mouse pointer used by the guest.
        :rtype: MousePointerShape
        """
        return MousePointerShape(self._get_property('pointerShape'))

    @property
    def event_source(self):
        """Event source for mouse events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))


class DisplaySourceBitmap(Interface):
    def query_bitmap_info(self):
        """None
        :rtype: typing.Tuple[bytes, int, int, int, int, BitmapFormat]
        """
        address, width, height, bits_per_pixel, bytes_per_line, bitmap_format = self._call_method('queryBitmapInfo')
        bitmap_format = BitmapFormat(bitmap_format)
        return address, width, height, bits_per_pixel, bytes_per_line, bitmap_format

    @property
    def screen_id(self):
        """None
        :rtype: int
        """
        return self._get_property('screenId')


class FramebufferCapabilities(enum.Enum):
    """
      Framebuffer capability flags.
    
     .. describe:: UPDATE_IMAGE 
        Requires NotifyUpdateImage. NotifyUpdate must not be called.
      
     .. describe:: VHWA 
        Supports VHWA interface. If set, then IFramebuffer::processVHWACommand can be called.
      
     .. describe:: VISIBLE_REGION 
        Supports visible region. If set, then IFramebuffer::setVisibleRegion can be called.
      
    """
    UPDATE_IMAGE = 1
    VHWA = 2
    VISIBLE_REGION = 4

class Framebuffer(Interface):
    def notify_update(self, x, y, width, height):
        """None
        :param int x:
        :param int y:
        :param int width:
        :param int height:
        """
        self._call_method('notifyUpdate', x, y, width, height)

    def notify_update_image(self, x, y, width, height, image):
        """None
        :param int x:
        :param int y:
        :param int width:
        :param int height:
        :param typing.List[bytes] image:
            Array with 32BPP image data.
        """
        self._call_method('notifyUpdateImage', x, y, width, height, image)

    def notify_change(self, screen_id, x_origin, y_origin, width, height):
        """None
        :param int screen_id:
            Logical guest screen number.
        :param int x_origin:
            Location of the screen in the guest.
        :param int y_origin:
            Location of the screen in the guest.
        :param int width:
            Width of the guest display, in pixels.
        :param int height:
            Height of the guest display, in pixels.
        """
        self._call_method('notifyChange', screen_id, x_origin, y_origin, width, height)

    def video_mode_supported(self, width, height, bpp):
        """None
        :param int width:
        :param int height:
        :param int bpp:
        :rtype: bool
        """
        ret = self._call_method('videoModeSupported', width, height, bpp)
        return ret

    def get_visible_region(self, rectangles, count):
        """None
        :param bytes rectangles:
            Pointer to the @c RTRECT array to receive region data.
        :param int count:
            Number of @c RTRECT elements in the @a rectangles array.
        :rtype: int
        :returns:
            Number of elements copied to the @a rectangles array.
        """
        ret = self._call_method('getVisibleRegion', rectangles, count)
        return ret

    def set_visible_region(self, rectangles, count):
        """None
        :param bytes rectangles:
            Pointer to the @c RTRECT array.
        :param int count:
            Number of @c RTRECT elements in the @a rectangles array.
        """
        self._call_method('setVisibleRegion', rectangles, count)

    def process_vhwa_command(self, command):
        """None
        :param bytes command:
            Pointer to VBOXVHWACMD containing the command to execute.
        """
        self._call_method('processVHWACommand', command)

    def notify_3d_event(self, type_, data):
        """None
        :param int type_:
            event type. Currently only VBOX3D_NOTIFY_EVENT_TYPE_VISIBLE_3DDATA is supported.
        :param typing.List[bytes] data:
            event-specific data, depends on the supplied event type
        """
        self._call_method('notify3DEvent', type_, data)

    @property
    def width(self):
        """Frame buffer width, in pixels.
        :rtype: int
        """
        return self._get_property('width')

    @property
    def height(self):
        """Frame buffer height, in pixels.
        :rtype: int
        """
        return self._get_property('height')

    @property
    def bits_per_pixel(self):
        """Color depth, in bits per pixel.
        :rtype: int
        """
        return self._get_property('bitsPerPixel')

    @property
    def bytes_per_line(self):
        """Scan line size, in bytes.
        :rtype: int
        """
        return self._get_property('bytesPerLine')

    @property
    def pixel_format(self):
        """Frame buffer pixel format. It's one of the values defined by
        :rtype: BitmapFormat
        """
        return BitmapFormat(self._get_property('pixelFormat'))

    @property
    def height_reduction(self):
        """Hint from the frame buffer about how much of the standard
        screen height it wants to use for itself. This information is
        exposed to the guest through the VESA BIOS and VMMDev interface
        so that it can use it for determining its video mode table. It
        is not guaranteed that the guest respects the value.
        :rtype: int
        """
        return self._get_property('heightReduction')

    @property
    def overlay(self):
        """An alpha-blended overlay which is superposed over the frame buffer.
        The initial purpose is to allow the display of icons providing
        information about the VM state, including disk activity, in front
        ends which do not have other means of doing that. The overlay is
        designed to controlled exclusively by IDisplay. It has no locking
        of its own, and any changes made to it are not guaranteed to be
        visible until the affected portion of IFramebuffer is updated. The
        overlay can be created lazily the first time it is requested. This
        attribute can also return @c null to signal that the overlay is not
        implemented.
        :rtype: FramebufferOverlay
        """
        return FramebufferOverlay(self._get_property('overlay'))

    @property
    def win_id(self):
        """Platform-dependent identifier of the window where context of this
        frame buffer is drawn, or zero if there's no such window.
        :rtype: int
        """
        return self._get_property('winId')

    @property
    def capabilities(self):
        """Capabilities of the framebuffer instance.

        For the meaning of individual capability flags see
        :rtype: typing.List[FramebufferCapabilities]
        """
        return [FramebufferCapabilities(obj) for obj in self._get_property('capabilities')]


class FramebufferOverlay(Framebuffer):
    """The IFramebufferOverlay interface represents an alpha blended overlay
      for displaying status icons above an IFramebuffer. It is always created
      not visible, so that it must be explicitly shown. It only covers a
      portion of the IFramebuffer, determined by its width, height and
      co-ordinates. It is always in packed pixel little-endian 32bit ARGB (in
      that order) format, and may be written to directly. Do re-read the
      width though, after setting it, as it may be adjusted (increased) to
      make it more suitable for the front end.
    """
    def move(self, x, y):
        """None
        :param int x:
        :param int y:
        """
        self._call_method('move', x, y)

    @property
    def x(self):
        """X position of the overlay, relative to the frame buffer.
        :rtype: int
        """
        return self._get_property('x')

    @property
    def y(self):
        """Y position of the overlay, relative to the frame buffer.
        :rtype: int
        """
        return self._get_property('y')

    @property
    def visible(self):
        """Whether the overlay is currently visible.
        :rtype: bool
        """
        return self._get_property('visible')

    @property
    def alpha(self):
        """The global alpha value for the overlay. This may or may not be
        supported by a given front end.
        :rtype: int
        """
        return self._get_property('alpha')


class GuestMonitorStatus(enum.Enum):
    """
      The current status of the guest display.
    
     .. describe:: DISABLED 
        The guest monitor is disabled in the guest.
      
     .. describe:: ENABLED 
        The guest monitor is enabled in the guest.
      
     .. describe:: BLANK 
        The guest monitor is enabled in the guest but should display nothing.
      
    """
    DISABLED = 0
    ENABLED = 1
    BLANK = 2

class ScreenLayoutMode(enum.Enum):
    """
      How IDisplay::setScreenLayout method should work.
    
     .. describe:: APPLY 
        If the guest is already at desired mode then the API might avoid setting the mode.
      
     .. describe:: RESET 
        Always set the new mode even if the guest is already at desired mode.
      
     .. describe:: ATTACH 
        Attach new screens and always set the new mode for existing screens.
      
    """
    APPLY = 0
    RESET = 1
    ATTACH = 2

class GuestScreenInfo(Interface):
    @property
    def screen_id(self):
        """None
        :rtype: int
        """
        return self._get_property('screenId')

    @property
    def guest_monitor_status(self):
        """None
        :rtype: GuestMonitorStatus
        """
        return GuestMonitorStatus(self._get_property('guestMonitorStatus'))

    @property
    def primary(self):
        """None
        :rtype: bool
        """
        return self._get_property('primary')

    @property
    def origin(self):
        """None
        :rtype: bool
        """
        return self._get_property('origin')

    @property
    def origin_x(self):
        """None
        :rtype: int
        """
        return self._get_property('originX')

    @property
    def origin_y(self):
        """None
        :rtype: int
        """
        return self._get_property('originY')

    @property
    def width(self):
        """None
        :rtype: int
        """
        return self._get_property('width')

    @property
    def height(self):
        """None
        :rtype: int
        """
        return self._get_property('height')

    @property
    def bits_per_pixel(self):
        """None
        :rtype: int
        """
        return self._get_property('bitsPerPixel')

    @property
    def extended_info(self):
        """None
        :rtype: str
        """
        return self._get_property('extendedInfo')


class Display(Interface):
    """The IDisplay interface represents the virtual machine's display.

      The object implementing this interface is contained in each
    """
    def get_screen_resolution(self, screen_id):
        """None
        :param int screen_id:
        :rtype: typing.Tuple[int, int, int, int, int, GuestMonitorStatus]
        """
        width, height, bits_per_pixel, x_origin, y_origin, guest_monitor_status = self._call_method('getScreenResolution', screen_id)
        guest_monitor_status = GuestMonitorStatus(guest_monitor_status)
        return width, height, bits_per_pixel, x_origin, y_origin, guest_monitor_status

    def attach_framebuffer(self, screen_id, framebuffer):
        """None
        :param int screen_id:
        :param Framebuffer framebuffer:
        :rtype: str
        """
        ret = self._call_method('attachFramebuffer', screen_id, framebuffer)
        return ret

    def detach_framebuffer(self, screen_id, id_):
        """None
        :param int screen_id:
        :param str id_:
        """
        self._call_method('detachFramebuffer', screen_id, id_)

    def query_framebuffer(self, screen_id):
        """None
        :param int screen_id:
        :rtype: Framebuffer
        """
        ret = self._call_method('queryFramebuffer', screen_id)
        return ret

    def set_video_mode_hint(self, display, enabled, change_origin, origin_x, origin_y, width, height, bits_per_pixel):
        """None
        :param int display:
            The number of the guest display to send the hint to.
        :param bool enabled:
            @c True, if this guest screen is enabled,
          @c False otherwise.
        :param bool change_origin:
            @c True, if the origin of the guest screen should be changed,
          @c False otherwise.
        :param int origin_x:
            The X origin of the guest screen.
        :param int origin_y:
            The Y origin of the guest screen.
        :param int width:
            The width of the guest screen.
        :param int height:
            The height of the guest screen.
        :param int bits_per_pixel:
            The number of bits per pixel of the guest screen.
        """
        self._call_method('setVideoModeHint', display, enabled, change_origin, origin_x, origin_y, width, height, bits_per_pixel)

    def set_seamless_mode(self, enabled):
        """None
        :param bool enabled:
        """
        self._call_method('setSeamlessMode', enabled)

    def take_screen_shot(self, screen_id, address, width, height, bitmap_format):
        """None
        :param int screen_id:
        :param bytes address:
        :param int width:
        :param int height:
        :param BitmapFormat bitmap_format:
        """
        self._call_method('takeScreenShot', screen_id, address, width, height, bitmap_format)

    def take_screen_shot_to_array(self, screen_id, width, height, bitmap_format):
        """None
        :param int screen_id:
            The guest monitor to take screenshot from.
        :param int width:
            Desired image width.
        :param int height:
            Desired image height.
        :param BitmapFormat bitmap_format:
            The requested format.
        :rtype: typing.List[bytes]
        :returns:
            Array with resulting screen data.
        """
        ret = self._call_method('takeScreenShotToArray', screen_id, width, height, bitmap_format)
        return ret

    def draw_to_screen(self, screen_id, address, x, y, width, height):
        """None
        :param int screen_id:
            Monitor to take the screenshot from.
        :param bytes address:
            Address to store the screenshot to
        :param int x:
            Relative to the screen top left corner.
        :param int y:
            Relative to the screen top left corner.
        :param int width:
            Desired image width.
        :param int height:
            Desired image height.
        """
        self._call_method('drawToScreen', screen_id, address, x, y, width, height)

    def invalidate_and_update(self):
        """None
        """
        self._call_method('invalidateAndUpdate')

    def invalidate_and_update_screen(self, screen_id):
        """None
        :param int screen_id:
            The guest screen to redraw.
        """
        self._call_method('invalidateAndUpdateScreen', screen_id)

    def complete_vhwa_command(self, command):
        """None
        :param bytes command:
            Pointer to VBOXVHWACMD containing the completed command.
        """
        self._call_method('completeVHWACommand', command)

    def viewport_changed(self, screen_id, x, y, width, height):
        """None
        :param int screen_id:
            Monitor to take the screenshot from.
        :param int x:
            Framebuffer x offset.
        :param int y:
            Framebuffer y offset.
        :param int width:
            Viewport width.
        :param int height:
            Viewport height.
        """
        self._call_method('viewportChanged', screen_id, x, y, width, height)

    def query_source_bitmap(self, screen_id):
        """None
        :param int screen_id:
        :rtype: DisplaySourceBitmap
        """
        ret = self._call_method('querySourceBitmap', screen_id)
        return ret

    def notify_scale_factor_change(self, screen_id, u32_scale_factor_w_multiplied, u32_scale_factor_h_multiplied):
        """None
        :param int screen_id:
        :param int u32_scale_factor_w_multiplied:
        :param int u32_scale_factor_h_multiplied:
        """
        self._call_method('notifyScaleFactorChange', screen_id, u32_scale_factor_w_multiplied, u32_scale_factor_h_multiplied)

    def notify_hi_dpi_output_policy_change(self, f_unscaled_hi_dpi):
        """None
        :param bool f_unscaled_hi_dpi:
        """
        self._call_method('notifyHiDPIOutputPolicyChange', f_unscaled_hi_dpi)

    def set_screen_layout(self, screen_layout_mode, guest_screen_info):
        """None
        :param ScreenLayoutMode screen_layout_mode:
        :param typing.List[GuestScreenInfo] guest_screen_info:
        """
        self._call_method('setScreenLayout', screen_layout_mode, guest_screen_info)

    def detach_screens(self, screen_ids):
        """None
        :param int screen_ids:
        """
        self._call_method('detachScreens', screen_ids)

    @property
    def guest_screen_layout(self):
        """Layout of the guest screens.
        :rtype: typing.List[GuestScreenInfo]
        """
        return [GuestScreenInfo(obj) for obj in self._get_property('guestScreenLayout')]


class NetworkAttachmentType(enum.Enum):
    """
      Network attachment type.
    
     .. describe:: NULL Null value, also means "not attached".
    """
    NULL = 0
    NAT = 1
    BRIDGED = 2
    INTERNAL = 3
    HOST_ONLY = 4
    GENERIC = 5
    NAT_NETWORK = 6

class NetworkAdapterType(enum.Enum):
    """
      Network adapter type.
    
     .. describe:: NULL Null value (never used by the API).
     .. describe:: AM79_C970_A AMD PCNet-PCI II network card (Am79C970A).
     .. describe:: AM79_C973 AMD PCNet-FAST III network card (Am79C973).
     .. describe:: I82540_EM Intel PRO/1000 MT Desktop network card (82540EM).
     .. describe:: I82543_GC Intel PRO/1000 T Server network card (82543GC).
     .. describe:: I82545_EM Intel PRO/1000 MT Server network card (82545EM).
     .. describe:: VIRTIO Virtio network device.
    """
    NULL = 0
    AM79_C970_A = 1
    AM79_C973 = 2
    I82540_EM = 3
    I82543_GC = 4
    I82545_EM = 5
    VIRTIO = 6

class NetworkAdapterPromiscModePolicy(enum.Enum):
    """
      The promiscuous mode policy of an interface.
    
     .. describe:: DENY Deny promiscuous mode requests.
     .. describe:: ALLOW_NETWORK 
        Allow promiscuous mode, but restrict the scope it to the internal
        network so that it only applies to other VMs.
      
     .. describe:: ALLOW_ALL 
        Allow promiscuous mode, include unrelated traffic going over the wire
        and internally on the host.
      
    """
    DENY = 1
    ALLOW_NETWORK = 2
    ALLOW_ALL = 3

class NetworkAdapter(Interface):
    """Represents a virtual network adapter that is attached to a virtual machine.
        Each virtual machine has a fixed number of network adapter slots with one
        instance of this attached to each of them. Call
    """
    def get_property(self, key):
        """None
        :param str key:
            Name of the property to get.
        :rtype: str
        :returns:
            Current property value.
        """
        ret = self._call_method('getProperty', key)
        return ret

    def set_property(self, key, value):
        """None
        :param str key:
            Name of the property to set.
        :param str value:
            Property value to set.
        """
        self._call_method('setProperty', key, value)

    def get_properties(self, names):
        """None
        :param str names:
            Names of properties to get.
        :rtype: typing.List[typing.Tuple[str, str]]
        """
        return_values, return_names = self._call_method('getProperties', names)
        return return_values, return_names

    @property
    def adapter_type(self):
        """Type of the virtual network adapter. Depending on this value,
        VirtualBox will provide a different virtual network hardware
        to the guest.
        :rtype: NetworkAdapterType
        """
        return NetworkAdapterType(self._get_property('adapterType'))

    @property
    def slot(self):
        """Slot number this adapter is plugged into. Corresponds to
        the value you pass to
        :rtype: int
        """
        return self._get_property('slot')

    @property
    def enabled(self):
        """Flag whether the network adapter is present in the
        guest system. If disabled, the virtual guest hardware will
        not contain this network adapter. Can only be changed when
        the VM is not running.
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def mac_address(self):
        """Ethernet MAC address of the adapter, 12 hexadecimal characters. When
        setting it to @c null or an empty string for an enabled adapter,
        VirtualBox will generate a unique MAC address. Disabled adapters can
        have an empty MAC address.
        :rtype: str
        """
        return self._get_property('MACAddress')

    @property
    def attachment_type(self):
        """Sets/Gets network attachment type of this network adapter.
        :rtype: NetworkAttachmentType
        """
        return NetworkAttachmentType(self._get_property('attachmentType'))

    @property
    def bridged_interface(self):
        """Name of the network interface the VM should be bridged to.
        :rtype: str
        """
        return self._get_property('bridgedInterface')

    @property
    def host_only_interface(self):
        """Name of the host only network interface the VM is attached to.
        :rtype: str
        """
        return self._get_property('hostOnlyInterface')

    @property
    def internal_network(self):
        """Name of the internal network the VM is attached to.
        :rtype: str
        """
        return self._get_property('internalNetwork')

    @property
    def nat_network(self):
        """Name of the NAT network the VM is attached to.
        :rtype: str
        """
        return self._get_property('NATNetwork')

    @property
    def generic_driver(self):
        """Name of the driver to use for the "Generic" network attachment type.
        :rtype: str
        """
        return self._get_property('genericDriver')

    @property
    def cable_connected(self):
        """Flag whether the adapter reports the cable as connected or not.
        It can be used to report offline situations to a VM.
        :rtype: bool
        """
        return self._get_property('cableConnected')

    @property
    def line_speed(self):
        """Line speed reported by custom drivers, in units of 1 kbps.
        :rtype: int
        """
        return self._get_property('lineSpeed')

    @property
    def promisc_mode_policy(self):
        """The promiscuous mode policy of the network adapter when attached to an
        internal network, host only network or a bridge.
        :rtype: NetworkAdapterPromiscModePolicy
        """
        return NetworkAdapterPromiscModePolicy(self._get_property('promiscModePolicy'))

    @property
    def trace_enabled(self):
        """Flag whether network traffic from/to the network card should be traced.
        Can only be toggled when the VM is turned off.
        :rtype: bool
        """
        return self._get_property('traceEnabled')

    @property
    def trace_file(self):
        """Filename where a network trace will be stored. If not set, VBox-pid.pcap
        will be used.
        :rtype: str
        """
        return self._get_property('traceFile')

    @property
    def nat_engine(self):
        """Points to the NAT engine which handles the network address translation
        for this interface. This is active only when the interface actually uses
        NAT.
        :rtype: NATEngine
        """
        return NATEngine(self._get_property('NATEngine'))

    @property
    def boot_priority(self):
        """Network boot priority of the adapter. Priority 1 is highest. If not set,
        the priority is considered to be at the lowest possible setting.
        :rtype: int
        """
        return self._get_property('bootPriority')

    @property
    def bandwidth_group(self):
        """The bandwidth group this network adapter is assigned to.
        :rtype: BandwidthGroup
        """
        return BandwidthGroup(self._get_property('bandwidthGroup'))


class PortMode(enum.Enum):
    """
      The PortMode enumeration represents possible communication modes for
      the virtual serial port device.
    
     .. describe:: DISCONNECTED Virtual device is not attached to any real host device.
     .. describe:: HOST_PIPE Virtual device is attached to a host pipe.
     .. describe:: HOST_DEVICE Virtual device is attached to a host device.
     .. describe:: RAW_FILE Virtual device is attached to a raw file.
     .. describe:: TCP Virtual device is attached to a TCP socket.
    """
    DISCONNECTED = 0
    HOST_PIPE = 1
    HOST_DEVICE = 2
    RAW_FILE = 3
    TCP = 4

class SerialPort(Interface):
    """The ISerialPort interface represents the virtual serial port device.

      The virtual serial port device acts like an ordinary serial port
      inside the virtual machine. This device communicates to the real
      serial port hardware in one of two modes: host pipe or host device.

      In host pipe mode, the #path attribute specifies the path to the pipe on
      the host computer that represents a serial port. The #server attribute
      determines if this pipe is created by the virtual machine process at
      machine startup or it must already exist before starting machine
      execution.

      In host device mode, the #path attribute specifies the name of the
      serial port device on the host computer.

      There is also a third communication mode: the disconnected mode. In this
      mode, the guest OS running inside the virtual machine will be able to
      detect the serial port, but all port write operations will be discarded
      and all port read operations will return no data.
    """
    @property
    def slot(self):
        """Slot number this serial port is plugged into. Corresponds to
        the value you pass to
        :rtype: int
        """
        return self._get_property('slot')

    @property
    def enabled(self):
        """Flag whether the serial port is enabled. If disabled,
        the serial port will not be reported to the guest OS.
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def io_base(self):
        """Base I/O address of the serial port.
        :rtype: int
        """
        return self._get_property('IOBase')

    @property
    def irq(self):
        """IRQ number of the serial port.
        :rtype: int
        """
        return self._get_property('IRQ')

    @property
    def host_mode(self):
        """How is this port connected to the host.
        :rtype: PortMode
        """
        return PortMode(self._get_property('hostMode'))

    @property
    def server(self):
        """Flag whether this serial port acts as a server (creates a new pipe on
        the host) or as a client (uses the existing pipe). This attribute is
        used only when
        :rtype: bool
        """
        return self._get_property('server')

    @property
    def path(self):
        """Path to the serial port's pipe on the host when
        :rtype: str
        """
        return self._get_property('path')


class ParallelPort(Interface):
    """The IParallelPort interface represents the virtual parallel port device.

      The virtual parallel port device acts like an ordinary parallel port
      inside the virtual machine. This device communicates to the real
      parallel port hardware using the name of the parallel device on the host
      computer specified in the #path attribute.

      Each virtual parallel port device is assigned a base I/O address and an
      IRQ number that will be reported to the guest operating system and used
      to operate the given parallel port from within the virtual machine.
    """
    @property
    def slot(self):
        """Slot number this parallel port is plugged into. Corresponds to
        the value you pass to
        :rtype: int
        """
        return self._get_property('slot')

    @property
    def enabled(self):
        """Flag whether the parallel port is enabled. If disabled,
        the parallel port will not be reported to the guest OS.
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def io_base(self):
        """Base I/O address of the parallel port.
        :rtype: int
        """
        return self._get_property('IOBase')

    @property
    def irq(self):
        """IRQ number of the parallel port.
        :rtype: int
        """
        return self._get_property('IRQ')

    @property
    def path(self):
        """Host parallel device name. If this parallel port is enabled, setting a
        @c null or an empty string as this attribute's value will result in
        the parallel port behaving as if not connected to any device.
        :rtype: str
        """
        return self._get_property('path')


class MachineDebugger(Interface):
    def dump_guest_core(self, filename, compression):
        """None
        :param str filename:
            The name of the output file. The file must not exist.
        :param str compression:
            Reserved for future compression method indicator.
        """
        self._call_method('dumpGuestCore', filename, compression)

    def dump_host_process_core(self, filename, compression):
        """None
        :param str filename:
            The name of the output file. The file must not exist.
        :param str compression:
            Reserved for future compression method indicator.
        """
        self._call_method('dumpHostProcessCore', filename, compression)

    def info(self, name, args):
        """None
        :param str name:
            The name of the info item.
        :param str args:
            Arguments to the info dumper.
        :rtype: str
        :returns:
            The into string.
        """
        ret = self._call_method('info', name, args)
        return ret

    def inject_nmi(self):
        """None
        """
        self._call_method('injectNMI')

    def modify_log_groups(self, settings):
        """None
        :param str settings:
            The group settings string. See iprt/log.h for details. To target the
          release logger, prefix the string with "release:".
        """
        self._call_method('modifyLogGroups', settings)

    def modify_log_flags(self, settings):
        """None
        :param str settings:
            The flags settings string. See iprt/log.h for details. To target the
          release logger, prefix the string with "release:".
        """
        self._call_method('modifyLogFlags', settings)

    def modify_log_destinations(self, settings):
        """None
        :param str settings:
            The destination settings string. See iprt/log.h for details. To target the
          release logger, prefix the string with "release:".
        """
        self._call_method('modifyLogDestinations', settings)

    def read_physical_memory(self, address, size):
        """None
        :param int address:
            The guest physical address.
        :param int size:
            The number of bytes to read.
        :rtype: typing.List[bytes]
        :returns:
            The bytes read.
        """
        ret = self._call_method('readPhysicalMemory', address, size)
        return ret

    def write_physical_memory(self, address, size, bytes_):
        """None
        :param int address:
            The guest physical address.
        :param int size:
            The number of bytes to read.
        :param typing.List[bytes] bytes_:
            The bytes to write.
        """
        self._call_method('writePhysicalMemory', address, size, bytes_)

    def read_virtual_memory(self, cpu_id, address, size):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param int address:
            The guest virtual address.
        :param int size:
            The number of bytes to read.
        :rtype: typing.List[bytes]
        :returns:
            The bytes read.
        """
        ret = self._call_method('readVirtualMemory', cpu_id, address, size)
        return ret

    def write_virtual_memory(self, cpu_id, address, size, bytes_):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param int address:
            The guest virtual address.
        :param int size:
            The number of bytes to read.
        :param typing.List[bytes] bytes_:
            The bytes to write.
        """
        self._call_method('writeVirtualMemory', cpu_id, address, size, bytes_)

    def load_plug_in(self, name):
        """None
        :param str name:
            The plug-in name or DLL. Special name 'all' loads all installed plug-ins.
        :rtype: str
        :returns:
            The name of the loaded plug-in.
        """
        ret = self._call_method('loadPlugIn', name)
        return ret

    def unload_plug_in(self, name):
        """None
        :param str name:
            The plug-in name or DLL. Special name 'all' unloads all plug-ins.
        """
        self._call_method('unloadPlugIn', name)

    def detect_os(self):
        """None
        :rtype: str
        :returns:
            The detected OS kernel on success.
        """
        ret = self._call_method('detectOS')
        return ret

    def query_os_kernel_log(self, max_messages):
        """None
        :param int max_messages:
            Max number of messages to return, counting from the end of the
          log.  If 0, there is no limit.
        :rtype: str
        :returns:
            The kernel log.
        """
        ret = self._call_method('queryOSKernelLog', max_messages)
        return ret

    def get_register(self, cpu_id, name):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param str name:
            The register name, case is ignored.
        :rtype: str
        :returns:
            The register value. This is usually a hex value (always 0x prefixed)
          but other format may be used for floating point registers (TBD).
        """
        ret = self._call_method('getRegister', cpu_id, name)
        return ret

    def get_registers(self, cpu_id):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :rtype: typing.List[typing.Tuple[str, str]]
        """
        names, values = self._call_method('getRegisters', cpu_id)
        return names, values

    def set_register(self, cpu_id, name, value):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param str name:
            The register name, case is ignored.
        :param str value:
            The new register value. Hexadecimal, decimal and octal formattings
          are supported in addition to any special formattings returned by
          the getters.
        """
        self._call_method('setRegister', cpu_id, name, value)

    def set_registers(self, cpu_id, names, values):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param typing.List[str] names:
            Array containing the register names, case ignored.
        :param typing.List[str] values:
            Array paralell to the names holding the register values. See
        """
        self._call_method('setRegisters', cpu_id, names, values)

    def dump_guest_stack(self, cpu_id):
        """None
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :rtype: str
        :returns:
            String containing the formatted stack dump.
        """
        ret = self._call_method('dumpGuestStack', cpu_id)
        return ret

    def reset_stats(self, pattern):
        """None
        :param str pattern:
            The selection pattern. A bit similar to filename globbing.
        """
        self._call_method('resetStats', pattern)

    def dump_stats(self, pattern):
        """None
        :param str pattern:
            The selection pattern. A bit similar to filename globbing.
        """
        self._call_method('dumpStats', pattern)

    def get_stats(self, pattern, with_descriptions):
        """None
        :param str pattern:
            The selection pattern. A bit similar to filename globbing.
        :param bool with_descriptions:
            Whether to include the descriptions.
        :rtype: str
        :returns:
            The XML document containing the statistics.
        """
        ret = self._call_method('getStats', pattern, with_descriptions)
        return ret

    @property
    def single_step(self):
        """Switch for enabling single-stepping.
        :rtype: bool
        """
        return self._get_property('singleStep')

    @property
    def recompile_user(self):
        """Switch for forcing code recompilation for user mode code.
        :rtype: bool
        """
        return self._get_property('recompileUser')

    @property
    def recompile_supervisor(self):
        """Switch for forcing code recompilation for supervisor mode code.
        :rtype: bool
        """
        return self._get_property('recompileSupervisor')

    @property
    def execute_all_in_iem(self):
        """Whether to execute all the code in the instruction interpreter. This
        is mainly for testing the interpreter and not an execution mode
        intended for general consumption.
        :rtype: bool
        """
        return self._get_property('executeAllInIEM')

    @property
    def patm_enabled(self):
        """Switch for enabling and disabling the PATM component.
        :rtype: bool
        """
        return self._get_property('PATMEnabled')

    @property
    def csam_enabled(self):
        """Switch for enabling and disabling the CSAM component.
        :rtype: bool
        """
        return self._get_property('CSAMEnabled')

    @property
    def log_enabled(self):
        """Switch for enabling and disabling the debug logger.
        :rtype: bool
        """
        return self._get_property('logEnabled')

    @property
    def log_dbg_flags(self):
        """The debug logger flags.
        :rtype: str
        """
        return self._get_property('logDbgFlags')

    @property
    def log_dbg_groups(self):
        """The debug logger's group settings.
        :rtype: str
        """
        return self._get_property('logDbgGroups')

    @property
    def log_dbg_destinations(self):
        """The debug logger's destination settings.
        :rtype: str
        """
        return self._get_property('logDbgDestinations')

    @property
    def log_rel_flags(self):
        """The release logger flags.
        :rtype: str
        """
        return self._get_property('logRelFlags')

    @property
    def log_rel_groups(self):
        """The release logger's group settings.
        :rtype: str
        """
        return self._get_property('logRelGroups')

    @property
    def log_rel_destinations(self):
        """The relase logger's destination settings.
        :rtype: str
        """
        return self._get_property('logRelDestinations')

    @property
    def Hardware_virt_ex_enabled(self):
        """Flag indicating whether the VM is currently making use of CPU hardware
        virtualization extensions.
        :rtype: bool
        """
        return self._get_property('HWVirtExEnabled')

    @property
    def Hardware_virt_ex_nested_paging_enabled(self):
        """Flag indicating whether the VM is currently making use of the nested paging
        CPU hardware virtualization extension.
        :rtype: bool
        """
        return self._get_property('HWVirtExNestedPagingEnabled')

    @property
    def Hardware_virt_ex_vpid_enabled(self):
        """Flag indicating whether the VM is currently making use of the VPID
        VT-x extension.
        :rtype: bool
        """
        return self._get_property('HWVirtExVPIDEnabled')

    @property
    def Hardware_virt_ex_ux_enabled(self):
        """Flag indicating whether the VM is currently making use of the
        unrestricted execution feature of VT-x.
        :rtype: bool
        """
        return self._get_property('HWVirtExUXEnabled')

    @property
    def os_name(self):
        """Query the guest OS kernel name as detected by the DBGF.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :rtype: str
        """
        return self._get_property('OSName')

    @property
    def os_version(self):
        """Query the guest OS kernel version string as detected by the DBGF.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :rtype: str
        """
        return self._get_property('OSVersion')

    @property
    def pae_enabled(self):
        """Flag indicating whether the VM is currently making use of the Physical
        Address Extension CPU feature.
        :rtype: bool
        """
        return self._get_property('PAEEnabled')

    @property
    def virtual_time_rate(self):
        """The rate at which the virtual time runs expressed as a percentage.
        The accepted range is 2% to 20000%.
        :rtype: int
        """
        return self._get_property('virtualTimeRate')

    @property
    def vm(self):
        """Gets the user-mode VM handle, with a reference. Must be passed to
        VMR3ReleaseUVM when done. This is only for internal use while we carve
        the details of this interface.
        :rtype: int
        """
        return self._get_property('VM')

    @property
    def uptime(self):
        """VM uptime in milliseconds, i.e. time in which it could have been
        executing guest code. Excludes the time when the VM was paused.
        :rtype: int
        """
        return self._get_property('uptime')


class USBDeviceFilters(Interface):
    def create_device_filter(self, name):
        """None
        :param str name:
            Filter name. See
        :rtype: USBDeviceFilter
        :returns:
            Created filter object.
        """
        ret = self._call_method('createDeviceFilter', name)
        return ret

    def insert_device_filter(self, position, filter_):
        """None
        :param int position:
            Position to insert the filter to.
        :param USBDeviceFilter filter_:
            USB device filter to insert.
        """
        self._call_method('insertDeviceFilter', position, filter_)

    def remove_device_filter(self, position):
        """None
        :param int position:
            Position to remove the filter from.
        :rtype: USBDeviceFilter
        :returns:
            Removed USB device filter.
        """
        ret = self._call_method('removeDeviceFilter', position)
        return ret

    @property
    def device_filters(self):
        """List of USB device filters associated with the machine.

        If the machine is currently running, these filters are activated
        every time a new (supported) USB device is attached to the host
        computer that was not ignored by global filters
        (
        :rtype: typing.List[USBDeviceFilter]
        """
        return [USBDeviceFilter(obj) for obj in self._get_property('deviceFilters')]


class USBControllerType(enum.Enum):
    """
      The USB controller type. 
     .. describe:: NULL @c null value. Never used by the API.
     .. describe:: LAST Last element (invalid). Used for parameter checks.
    """
    NULL = 0
    OHCI = 1
    EHCI = 2
    XHCI = 3
    LAST = 4

class USBController(Interface):
    @property
    def name(self):
        """The USB Controller name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def type_(self):
        """The USB Controller type.
        :rtype: USBControllerType
        """
        return USBControllerType(self._get_property('type'))

    @property
    def usb_standard(self):
        """USB standard version which the controller implements.
        This is a BCD which means that the major version is in the
        high byte and minor version is in the low byte.
        :rtype: int
        """
        return self._get_property('USBStandard')


class USBConnectionSpeed(enum.Enum):
    """
      USB device/port speed state. This enumeration represents speeds at
      which a USB device can communicate with the host.

      The speed is a function of both the device itself and the port which
      it is attached to, including hubs and cables in the path.

      
     .. describe:: NULL 
        @c null value. Never returned by the API.
      
     .. describe:: LOW 
        Low speed, 1.5 Mbps.
      
     .. describe:: FULL 
        Full speed, 12 Mbps.
      
     .. describe:: HIGH 
        High speed, 480 Mbps.
      
     .. describe:: SUPER 
        SuperSpeed, 5 Gbps.
      
     .. describe:: SUPER_PLUS 
        SuperSpeedPlus, 10 Gbps.
      
    """
    NULL = 0
    LOW = 1
    FULL = 2
    HIGH = 3
    SUPER = 4
    SUPER_PLUS = 5

class USBDevice(Interface):
    """The IUSBDevice interface represents a virtual USB device attached to the
      virtual machine.

      A collection of objects implementing this interface is stored in the
    """
    @property
    def id_(self):
        """Unique USB device ID. This ID is built from #vendorId,
        #productId, #revision and #serialNumber.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def vendor_id(self):
        """Vendor ID.
        :rtype: int
        """
        return self._get_property('vendorId')

    @property
    def product_id(self):
        """Product ID.
        :rtype: int
        """
        return self._get_property('productId')

    @property
    def revision(self):
        """Product revision number. This is a packed BCD represented as
        unsigned short. The high byte is the integer part and the low
        byte is the decimal.
        :rtype: int
        """
        return self._get_property('revision')

    @property
    def manufacturer(self):
        """Manufacturer string.
        :rtype: str
        """
        return self._get_property('manufacturer')

    @property
    def product(self):
        """Product string.
        :rtype: str
        """
        return self._get_property('product')

    @property
    def serial_number(self):
        """Serial number string.
        :rtype: str
        """
        return self._get_property('serialNumber')

    @property
    def address(self):
        """Host specific address of the device.
        :rtype: str
        """
        return self._get_property('address')

    @property
    def port(self):
        """Host USB port number the device is physically
        connected to.
        :rtype: int
        """
        return self._get_property('port')

    @property
    def version(self):
        """The major USB version of the device - 1, 2 or 3.
        :rtype: int
        """
        return self._get_property('version')

    @property
    def port_version(self):
        """The major USB version of the host USB port the device is
        physically connected to - 1, 2 or 3. For devices not connected to
        anything this will have the same value as the version attribute.
        :rtype: int
        """
        return self._get_property('portVersion')

    @property
    def speed(self):
        """The speed at which the device is currently communicating.
        :rtype: USBConnectionSpeed
        """
        return USBConnectionSpeed(self._get_property('speed'))

    @property
    def remote(self):
        """Whether the device is physically connected to a remote VRDE
        client or to a local host machine.
        :rtype: bool
        """
        return self._get_property('remote')

    @property
    def device_info(self):
        """Array of device attributes as single strings.

        So far the following are used:
          0: The manufacturer string, if the device doesn't expose the ID one is taken
             from an internal database or an empty string if none is found.
          1: The product string, if the device doesn't expose the ID one is taken
             from an internal database or an empty string if none is found.
        :rtype: typing.List[str]
        """
        return list(self._get_property('deviceInfo'))

    @property
    def backend(self):
        """The backend which will be used to communicate with this device.
        :rtype: str
        """
        return self._get_property('backend')


class USBDeviceFilter(Interface):
    """The IUSBDeviceFilter interface represents an USB device filter used
      to perform actions on a group of USB devices.

      This type of filters is used by running virtual machines to
      automatically capture selected USB devices once they are physically
      attached to the host computer.

      A USB device is matched to the given device filter if and only if all
      attributes of the device match the corresponding attributes of the
      filter (that is, attributes are joined together using the logical AND
      operation). On the other hand, all together, filters in the list of
      filters carry the semantics of the logical OR operation. So if it is
      desirable to create a match like "this vendor id OR this product id",
      one needs to create two filters and specify "any match" (see below)
      for unused attributes.

      All filter attributes used for matching are strings. Each string
      is an expression representing a set of values of the corresponding
      device attribute, that will match the given filter. Currently, the
      following filtering expressions are supported:
    """
    @property
    def name(self):
        """Visible name for this filter.
        This name is used to visually distinguish one filter from another,
        so it can neither be @c null nor an empty string.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def active(self):
        """Whether this filter active or has been temporarily disabled.
        :rtype: bool
        """
        return self._get_property('active')

    @property
    def vendor_id(self):
        """
        :rtype: str
        """
        return self._get_property('vendorId')

    @property
    def product_id(self):
        """
        :rtype: str
        """
        return self._get_property('productId')

    @property
    def revision(self):
        """
        :rtype: str
        """
        return self._get_property('revision')

    @property
    def manufacturer(self):
        """
        :rtype: str
        """
        return self._get_property('manufacturer')

    @property
    def product(self):
        """
        :rtype: str
        """
        return self._get_property('product')

    @property
    def serial_number(self):
        """
        :rtype: str
        """
        return self._get_property('serialNumber')

    @property
    def port(self):
        """
        :rtype: str
        """
        return self._get_property('port')

    @property
    def remote(self):
        """
        :rtype: str
        """
        return self._get_property('remote')

    @property
    def masked_interfaces(self):
        """This is an advanced option for hiding one or more USB interfaces
        from the guest. The value is a bit mask where the bits that are set
        means the corresponding USB interface should be hidden, masked off
        if you like.
        This feature only works on Linux hosts.
        :rtype: int
        """
        return self._get_property('maskedInterfaces')


class USBDeviceState(enum.Enum):
    """
      USB device state. This enumeration represents all possible states
      of the USB device physically attached to the host computer regarding
      its state on the host computer and availability to guest computers
      (all currently running virtual machines).

      Once a supported USB device is attached to the host, global USB
      filters (
     .. describe:: NOT_SUPPORTED 
        Not supported by the VirtualBox server, not available to guests.
      
     .. describe:: UNAVAILABLE 
        Being used by the host computer exclusively,
        not available to guests.
      
     .. describe:: BUSY 
        Being used by the host computer, potentially available to guests.
      
     .. describe:: AVAILABLE 
        Not used by the host computer, available to guests (the host computer
        can also start using the device at any time).
      
     .. describe:: HELD 
        Held by the VirtualBox server (ignored by the host computer),
        available to guests.
      
     .. describe:: CAPTURED 
        Captured by one of the guest computers, not available
        to anybody else.
      
    """
    NOT_SUPPORTED = 0
    UNAVAILABLE = 1
    BUSY = 2
    AVAILABLE = 3
    HELD = 4
    CAPTURED = 5

class HostUSBDevice(USBDevice):
    """The IHostUSBDevice interface represents a physical USB device attached
      to the host computer.

      Besides properties inherited from IUSBDevice, this interface adds the
    """
    @property
    def state(self):
        """Current state of the device.
        :rtype: USBDeviceState
        """
        return USBDeviceState(self._get_property('state'))


class USBDeviceFilterAction(enum.Enum):
    """
      Actions for host USB device filters.
      
     .. describe:: NULL Null value (never used by the API).
     .. describe:: IGNORE Ignore the matched USB device.
     .. describe:: HOLD Hold the matched USB device.
    """
    NULL = 0
    IGNORE = 1
    HOLD = 2

class HostUSBDeviceFilter(USBDeviceFilter):
    """The IHostUSBDeviceFilter interface represents a global filter for a
      physical USB device used by the host computer. Used indirectly in
    """
    @property
    def action(self):
        """Action performed by the host when an attached USB device
        matches this filter.
        :rtype: USBDeviceFilterAction
        """
        return USBDeviceFilterAction(self._get_property('action'))


class USBProxyBackend(Interface):
    """The USBProxyBackend interface represents a source for USB devices available
      to the host for attaching to the VM.
    """
    @property
    def name(self):
        """The unique name of the proxy backend.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def type_(self):
        """The type of the backend.
        :rtype: str
        """
        return self._get_property('type')


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

class AudioAdapter(Interface):
    """The IAudioAdapter interface represents the virtual audio adapter of
        the virtual machine. Used in
    """
    def set_property(self, key, value):
        """None
        :param str key:
            Name of the key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setProperty', key, value)

    def get_property(self, key):
        """None
        :param str key:
            Name of the key to get.
        :rtype: str
        :returns:
            Value of the requested key.
        """
        ret = self._call_method('getProperty', key)
        return ret

    @property
    def enabled(self):
        """Flag whether the audio adapter is present in the
        guest system. If disabled, the virtual guest hardware will
        not contain any audio adapter. Can only be changed when
        the VM is not running.
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def enabled_in(self):
        """Flag whether the audio adapter is enabled for audio
        input. Only relevant if the adapter is enabled.
        :rtype: bool
        """
        return self._get_property('enabledIn')

    @property
    def enabled_out(self):
        """Flag whether the audio adapter is enabled for audio
        output. Only relevant if the adapter is enabled.
        :rtype: bool
        """
        return self._get_property('enabledOut')

    @property
    def audio_controller(self):
        """The emulated audio controller.
        :rtype: AudioControllerType
        """
        return AudioControllerType(self._get_property('audioController'))

    @property
    def audio_codec(self):
        """The exact variant of audio codec hardware presented
        to the guest.
        For HDA and SB16, only one variant is available, but for AC'97,
        there are several.
        :rtype: AudioCodecType
        """
        return AudioCodecType(self._get_property('audioCodec'))

    @property
    def audio_driver(self):
        """Audio driver the adapter is connected to. This setting
        can only be changed when the VM is not running.
        :rtype: AudioDriverType
        """
        return AudioDriverType(self._get_property('audioDriver'))

    @property
    def properties_list(self):
        """Array of names of tunable properties, which can be supported by audio driver.
        :rtype: typing.List[str]
        """
        return list(self._get_property('propertiesList'))


class AuthType(enum.Enum):
    """
      VirtualBox authentication type.
    
     .. describe:: NULL Null value, also means "no authentication".
    """
    NULL = 0
    EXTERNAL = 1
    GUEST = 2

class VRDEServer(Interface):
    def set_vrde_property(self, key, value):
        """None
        :param str key:
            Name of the key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setVRDEProperty', key, value)

    def get_vrde_property(self, key):
        """None
        :param str key:
            Name of the key to get.
        :rtype: str
        :returns:
            Value of the requested key.
        """
        ret = self._call_method('getVRDEProperty', key)
        return ret

    @property
    def enabled(self):
        """Flag if VRDE server is enabled.
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def auth_type(self):
        """VRDE authentication method.
        :rtype: AuthType
        """
        return AuthType(self._get_property('authType'))

    @property
    def auth_timeout(self):
        """Timeout for guest authentication. Milliseconds.
        :rtype: int
        """
        return self._get_property('authTimeout')

    @property
    def allow_multi_connection(self):
        """Flag whether multiple simultaneous connections to the VM are permitted.
        Note that this will be replaced by a more powerful mechanism in the future.
        :rtype: bool
        """
        return self._get_property('allowMultiConnection')

    @property
    def reuse_single_connection(self):
        """Flag whether the existing connection must be dropped and a new connection
        must be established by the VRDE server, when a new client connects in single
        connection mode.
        :rtype: bool
        """
        return self._get_property('reuseSingleConnection')

    @property
    def vrde_ext_pack(self):
        """The name of Extension Pack providing VRDE for this VM. Overrides
        :rtype: str
        """
        return self._get_property('VRDEExtPack')

    @property
    def auth_library(self):
        """Library used for authentication of RDP clients by this VM. Overrides
        :rtype: str
        """
        return self._get_property('authLibrary')

    @property
    def vrde_properties(self):
        """Array of names of properties, which are supported by this VRDE server.
        :rtype: typing.List[str]
        """
        return list(self._get_property('VRDEProperties'))


class SharedFolder(Interface):
    """The ISharedFolder interface represents a folder in the host computer's
      file system accessible from the guest OS running inside a virtual
      machine using an associated logical name.

      There are three types of shared folders:
    """
    @property
    def name(self):
        """Logical name of the shared folder.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def host_path(self):
        """Full path to the shared folder in the host file system.
        :rtype: str
        """
        return self._get_property('hostPath')

    @property
    def accessible(self):
        """Whether the folder defined by the host path is currently
        accessible or not.
        For example, the folder can be inaccessible if it is placed
        on the network share that is not available by the time
        this property is read.
        :rtype: bool
        """
        return self._get_property('accessible')

    @property
    def writable(self):
        """Whether the folder defined by the host path is writable or
        not.
        :rtype: bool
        """
        return self._get_property('writable')

    @property
    def auto_mount(self):
        """Whether the folder gets automatically mounted by the guest or not.
        :rtype: bool
        """
        return self._get_property('autoMount')

    @property
    def last_access_error(self):
        """Text message that represents the result of the last accessibility
        check.

        Accessibility checks are performed each time the
        :rtype: str
        """
        return self._get_property('lastAccessError')


class Reason(enum.Enum):
    """
      Internal event reason type.
    
     .. describe:: UNSPECIFIED Null value, means "no known reason".
     .. describe:: HOST_SUSPEND Host is being suspended (power management event).
     .. describe:: HOST_RESUME Host is being resumed (power management event).
     .. describe:: HOST_BATTERY_LOW Host is running low on battery (power management event).
     .. describe:: SNAPSHOT A snapshot of the VM is being taken.
    """
    UNSPECIFIED = 0
    HOST_SUSPEND = 1
    HOST_RESUME = 2
    HOST_BATTERY_LOW = 3
    SNAPSHOT = 4

class InternalSessionControl(Interface):
    def assign_remote_machine(self, machine, console):
        """None
        :param Machine machine:
        :param Console console:
        """
        self._call_method('assignRemoteMachine', machine, console)

    def update_machine_state(self, machine_state):
        """None
        :param MachineState machine_state:
        """
        self._call_method('updateMachineState', machine_state)

    def uninitialize(self):
        """None
        """
        self._call_method('uninitialize')

    def on_network_adapter_change(self, network_adapter, change_adapter):
        """None
        :param NetworkAdapter network_adapter:
        :param bool change_adapter:
        """
        self._call_method('onNetworkAdapterChange', network_adapter, change_adapter)

    def on_audio_adapter_change(self, audio_adapter):
        """None
        :param AudioAdapter audio_adapter:
        """
        self._call_method('onAudioAdapterChange', audio_adapter)

    def on_serial_port_change(self, serial_port):
        """None
        :param SerialPort serial_port:
        """
        self._call_method('onSerialPortChange', serial_port)

    def on_parallel_port_change(self, parallel_port):
        """None
        :param ParallelPort parallel_port:
        """
        self._call_method('onParallelPortChange', parallel_port)

    def on_storage_controller_change(self):
        """None
        """
        self._call_method('onStorageControllerChange')

    def on_medium_change(self, medium_attachment, force):
        """None
        :param MediumAttachment medium_attachment:
            The medium attachment which changed.
        :param bool force:
            If the medium change was forced.
        """
        self._call_method('onMediumChange', medium_attachment, force)

    def on_storage_device_change(self, medium_attachment, remove, silent):
        """None
        :param MediumAttachment medium_attachment:
            The medium attachment which changed.
        :param bool remove:
            TRUE if the device is removed, FALSE if it was added.
        :param bool silent:
            TRUE if the device is is silently reconfigured without
          notifying the guest about it.
        """
        self._call_method('onStorageDeviceChange', medium_attachment, remove, silent)

    def on_clipboard_mode_change(self, clipboard_mode):
        """None
        :param ClipboardMode clipboard_mode:
            The new shared clipboard mode.
        """
        self._call_method('onClipboardModeChange', clipboard_mode)

    def on_drag_and_drop_mode_change(self, dnd_mode):
        """None
        :param DnDMode dnd_mode:
            The new mode for drag'n drop.
        """
        self._call_method('onDnDModeChange', dnd_mode)

    def on_cpu_change(self, cpu, add):
        """None
        :param int cpu:
            The CPU which changed
        :param bool add:
            Flag whether the CPU was added or removed
        """
        self._call_method('onCPUChange', cpu, add)

    def on_cpu_execution_cap_change(self, execution_cap):
        """None
        :param int execution_cap:
            The new CPU execution cap value. (1-100)
        """
        self._call_method('onCPUExecutionCapChange', execution_cap)

    def on_vrde_server_change(self, restart):
        """None
        :param bool restart:
            Flag whether the server must be restarted
        """
        self._call_method('onVRDEServerChange', restart)

    def on_video_capture_change(self):
        """None
        """
        self._call_method('onVideoCaptureChange')

    def on_usb_controller_change(self):
        """None
        """
        self._call_method('onUSBControllerChange')

    def on_shared_folder_change(self, global_):
        """None
        :param bool global_:
        """
        self._call_method('onSharedFolderChange', global_)

    def on_usb_device_attach(self, device, error, masked_interfaces, capture_filename):
        """None
        :param USBDevice device:
        :param VirtualBoxErrorInfo error:
        :param int masked_interfaces:
        :param str capture_filename:
        """
        self._call_method('onUSBDeviceAttach', device, error, masked_interfaces, capture_filename)

    def on_usb_device_detach(self, id_, error):
        """None
        :param str id_:
        :param VirtualBoxErrorInfo error:
        """
        self._call_method('onUSBDeviceDetach', id_, error)

    def on_show_window(self, check):
        """None
        :param bool check:
        :rtype: typing.Tuple[bool, int]
        """
        can_show, win_id = self._call_method('onShowWindow', check)
        return can_show, win_id

    def on_bandwidth_group_change(self, bandwidth_group):
        """None
        :param BandwidthGroup bandwidth_group:
            The bandwidth group which changed.
        """
        self._call_method('onBandwidthGroupChange', bandwidth_group)

    def access_guest_property(self, name, value, flags, access_mode):
        """None
        :param str name:
        :param str value:
        :param str flags:
        :param int access_mode:
            0 = get, 1 = set, 2 = delete.
        :rtype: typing.Tuple[str, int, str]
        """
        ret_value, ret_timestamp, ret_flags = self._call_method('accessGuestProperty', name, value, flags, access_mode)
        return ret_value, ret_timestamp, ret_flags

    def enumerate_guest_properties(self, patterns):
        """None
        :param str patterns:
            The patterns to match the properties against as a comma-separated
          string. If this is empty, all properties currently set will be
          returned.
        :rtype: typing.List[typing.Tuple[str, str, int, str]]
        """
        keys, values, timestamps, flags = self._call_method('enumerateGuestProperties', patterns)
        return keys, values, timestamps, flags

    def online_merge_medium(self, medium_attachment, source_idx, target_idx, progress):
        """None
        :param MediumAttachment medium_attachment:
            The medium attachment to identify the medium chain.
        :param int source_idx:
            The index of the source image in the chain.
        Redundant, but drastically reduces IPC.
        :param int target_idx:
            The index of the target image in the chain.
        Redundant, but drastically reduces IPC.
        :param Progress progress:
            Progress object for this operation.
        """
        self._call_method('onlineMergeMedium', medium_attachment, source_idx, target_idx, progress)

    def reconfigure_medium_attachments(self, attachments):
        """None
        :param typing.List[MediumAttachment] attachments:
            Array containing the medium attachments which need to be
          reconfigured.
        """
        self._call_method('reconfigureMediumAttachments', attachments)

    def enable_vmm_statistics(self, enable):
        """None
        :param bool enable:
            True enables statistics collection.
        """
        self._call_method('enableVMMStatistics', enable)

    def pause_with_reason(self, reason):
        """None
        :param Reason reason:
            Specify the best matching reason code please.
        """
        self._call_method('pauseWithReason', reason)

    def resume_with_reason(self, reason):
        """None
        :param Reason reason:
            Specify the best matching reason code please.
        """
        self._call_method('resumeWithReason', reason)

    def save_state_with_reason(self, reason, progress, snapshot, state_file_path, pause_vm):
        """None
        :param Reason reason:
            Specify the best matching reason code please.
        :param Progress progress:
            Progress object to track the operation completion.
        :param Snapshot snapshot:
            Snapshot object for which this save state operation is executed.
        :param str state_file_path:
            File path the VM process must save the execution state to.
        :param bool pause_vm:
            The VM should be paused before saving state. It is automatically
        unpaused on error in the "vanilla save state" case.
        :rtype: bool
        :returns:
            Returns if the VM was left in paused state, which is necessary
        in many situations (snapshots, teleportation).
        """
        ret = self._call_method('saveStateWithReason', reason, progress, snapshot, state_file_path, pause_vm)
        return ret

    def cancel_save_state_with_reason(self):
        """None
        """
        self._call_method('cancelSaveStateWithReason')

    @property
    def pid(self):
        """PID of the process that has created this Session object.
        :rtype: int
        """
        return self._get_property('PID')

    @property
    def remote_console(self):
        """Returns the console object suitable for remote control.
        :rtype: Console
        """
        return Console(self._get_property('remoteConsole'))

    @property
    def nominal_state(self):
        """Returns suitable machine state for the VM execution state. Useful
        for choosing a sensible machine state after a complex operation which
        failed or otherwise resulted in an unclear situation.
        :rtype: MachineState
        """
        return MachineState(self._get_property('nominalState'))


class Session(Interface):
    """The ISession interface represents a client process and allows for locking
      virtual machines (represented by IMachine objects) to prevent conflicting
      changes to the machine.

      Any caller wishing to manipulate a virtual machine needs to create a session
      object first, which lives in its own process space. Such session objects are
      then associated with
    """
    def unlock_machine(self):
        """None
        """
        self._call_method('unlockMachine')

    @property
    def state(self):
        """Current state of this session.
        :rtype: SessionState
        """
        return SessionState(self._get_property('state'))

    @property
    def type_(self):
        """Type of this session. The value of this attribute is valid only
        if the session currently has a machine locked (i.e. its
        :rtype: SessionType
        """
        return SessionType(self._get_property('type'))

    @property
    def name(self):
        """Name of this session. Important only for VM sessions, otherwise it
        it will be remembered, but not used for anything significant (and can
        be left at the empty string which is the default). The value can only
        be changed when the session state is SessionState_Unlocked. Make sure
        that you use a descriptive name which does not conflict with the VM
        process session names: "GUI/Qt", "GUI/SDL" and "headless".
        :rtype: str
        """
        return self._get_property('name')

    @property
    def machine(self):
        """Machine object associated with this session.
        :rtype: Machine
        """
        return Machine(self._get_property('machine'))

    @property
    def console(self):
        """Console object associated with this session. Only sessions
      which locked the machine for a VM process have a non-null console.
        :rtype: Console
        """
        return Console(self._get_property('console'))


class StorageBus(enum.Enum):
    """
      The bus type of the storage controller (IDE, SATA, SCSI, SAS or Floppy);
      see 
     .. describe:: NULL @c null value. Never used by the API.
    """
    NULL = 0
    IDE = 1
    SATA = 2
    SCSI = 3
    FLOPPY = 4
    SAS = 5
    USB = 6
    PC_IE = 7

class StorageControllerType(enum.Enum):
    """
      The exact variant of storage controller hardware presented
      to the guest; see 
     .. describe:: NULL @c null value. Never used by the API.
     .. describe:: LSI_LOGIC A SCSI controller of the LsiLogic variant.
     .. describe:: BUS_LOGIC A SCSI controller of the BusLogic variant.
     .. describe:: INTEL_AHCI An Intel AHCI SATA controller; this is the only variant for SATA.
     .. describe:: PIIX3 An IDE controller of the PIIX3 variant.
     .. describe:: PIIX4 An IDE controller of the PIIX4 variant.
     .. describe:: ICH6 An IDE controller of the ICH6 variant.
     .. describe:: I82078 A floppy disk controller; this is the only variant for floppy drives.
     .. describe:: LSI_LOGIC_SAS A variant of the LsiLogic controller using SAS.
     .. describe:: USB Special USB based storage controller.
     .. describe:: NV_ME An NVMe storage controller.
    """
    NULL = 0
    LSI_LOGIC = 1
    BUS_LOGIC = 2
    INTEL_AHCI = 3
    PIIX3 = 4
    PIIX4 = 5
    ICH6 = 6
    I82078 = 7
    LSI_LOGIC_SAS = 8
    USB = 9
    NV_ME = 10

class ChipsetType(enum.Enum):
    """
      Type of emulated chipset (mostly southbridge).
    
     .. describe:: NULL @c null value. Never used by the API.
     .. describe:: PIIX3 A PIIX3 (PCI IDE ISA Xcelerator) chipset.
     .. describe:: ICH9 A ICH9 (I/O Controller Hub) chipset.
    """
    NULL = 0
    PIIX3 = 1
    ICH9 = 2

class StorageController(Interface):
    """Represents a storage controller that is attached to a virtual machine
        (
    """
    @property
    def name(self):
        """Name of the storage controller, as originally specified with
        :rtype: str
        """
        return self._get_property('name')

    @property
    def max_devices_per_port_count(self):
        """Maximum number of devices which can be attached to one port.
        :rtype: int
        """
        return self._get_property('maxDevicesPerPortCount')

    @property
    def min_port_count(self):
        """Minimum number of ports that
        :rtype: int
        """
        return self._get_property('minPortCount')

    @property
    def max_port_count(self):
        """Maximum number of ports that
        :rtype: int
        """
        return self._get_property('maxPortCount')

    @property
    def instance(self):
        """The instance number of the device in the running VM.
        :rtype: int
        """
        return self._get_property('instance')

    @property
    def port_count(self):
        """The number of currently usable ports on the controller.
        The minimum and maximum number of ports for one controller are
        stored in
        :rtype: int
        """
        return self._get_property('portCount')

    @property
    def bus(self):
        """The bus type of the storage controller (IDE, SATA, SCSI, SAS or Floppy).
        :rtype: StorageBus
        """
        return StorageBus(self._get_property('bus'))

    @property
    def controller_type(self):
        """The exact variant of storage controller hardware presented
        to the guest.
        Depending on this value, VirtualBox will provide a different
        virtual storage controller hardware to the guest.
        For SATA, SAS and floppy controllers, only one variant is
        available, but for IDE and SCSI, there are several.

        For SCSI controllers, the default type is LsiLogic.
        :rtype: StorageControllerType
        """
        return StorageControllerType(self._get_property('controllerType'))

    @property
    def use_host_io_cache(self):
        """If true, the storage controller emulation will use a dedicated I/O thread, enable the host I/O
        caches and use synchronous file APIs on the host. This was the only option in the API before
        VirtualBox 3.2 and is still the default for IDE controllers.

        If false, the host I/O cache will be disabled for image files attached to this storage controller.
        Instead, the storage controller emulation will use asynchronous I/O APIs on the host. This makes
        it possible to turn off the host I/O caches because the emulation can handle unaligned access to
        the file. This should be used on OS X and Linux hosts if a high I/O load is expected or many
        virtual machines are running at the same time to prevent I/O cache related hangs.
        This option new with the API of VirtualBox 3.2 and is now the default for non-IDE storage controllers.
        :rtype: bool
        """
        return self._get_property('useHostIOCache')

    @property
    def bootable(self):
        """Returns whether it is possible to boot from disks attached to this controller.
        :rtype: bool
        """
        return self._get_property('bootable')


class ManagedObjectRef(Interface):
    """Managed object reference.

      Only within the webservice, a managed object reference (which is really
      an opaque number) allows a webservice client to address an object
      that lives in the address space of the webservice server.

      Behind each managed object reference, there is a COM object that lives
      in the webservice server's address space. The COM object is not freed
      until the managed object reference is released, either by an explicit
      call to
    """
    def get_interface_name(self):
        """None
        :rtype: str
        """
        ret = self._call_method('getInterfaceName')
        return ret

    def release(self):
        """None
        """
        self._call_method('release')


class WebsessionManager(Interface):
    """Websession manager. This provides essential services
      to webservice clients.
    """
    def logon(self, username, password):
        """None
        :param str username:
        :param str password:
        :rtype: VirtualBox
        """
        ret = self._call_method('logon', username, password)
        return ret

    def get_session_object(self, ref_i_virtual_box):
        """None
        :param VirtualBox ref_i_virtual_box:
        :rtype: Session
        """
        ret = self._call_method('getSessionObject', ref_i_virtual_box)
        return ret

    def logoff(self, ref_i_virtual_box):
        """None
        :param VirtualBox ref_i_virtual_box:
        """
        self._call_method('logoff', ref_i_virtual_box)


class PerformanceMetric(Interface):
    """The IPerformanceMetric interface represents parameters of the given
      performance metric.
    """
    @property
    def metric_name(self):
        """Name of the metric.
        :rtype: str
        """
        return self._get_property('metricName')

    @property
    def object_(self):
        """Object this metric belongs to.
        :rtype: Interface
        """
        return Interface(self._get_property('object'))

    @property
    def description(self):
        """Textual description of the metric.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def period(self):
        """Time interval between samples, measured in seconds.
        :rtype: int
        """
        return self._get_property('period')

    @property
    def count(self):
        """Number of recent samples retained by the performance collector for this
        metric.

        When the collected sample count exceeds this number, older samples
        are discarded.
        :rtype: int
        """
        return self._get_property('count')

    @property
    def unit(self):
        """Unit of measurement.
        :rtype: str
        """
        return self._get_property('unit')

    @property
    def minimum_value(self):
        """Minimum possible value of this metric.
        :rtype: int
        """
        return self._get_property('minimumValue')

    @property
    def maximum_value(self):
        """Maximum possible value of this metric.
        :rtype: int
        """
        return self._get_property('maximumValue')


class PerformanceCollector(Interface):
    """The IPerformanceCollector interface represents a service that collects
      and stores performance metrics data.

      Performance metrics are associated with objects of interfaces like IHost
      and IMachine. Each object has a distinct set of performance metrics. The
      set can be obtained with
    """
    def get_metrics(self, metric_names, objects):
        """None
        :param typing.List[str] metric_names:
            Metric name filter. Currently, only a comma-separated list of metrics
          is supported.
        :param typing.List[nterface] objects:
            Set of objects to return metric parameters for.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of returned metric parameters.
        """
        ret = self._call_method('getMetrics', metric_names, objects)
        return ret

    def setup_metrics(self, metric_names, objects, period, count):
        """None
        :param typing.List[str] metric_names:
            Metric name filter. Comma-separated list of metrics with wildcard
          support.
        :param typing.List[nterface] objects:
            Set of objects to setup metric parameters for.
        :param int period:
            Time interval in seconds between two consecutive samples of
          performance data.
        :param int count:
            Number of samples to retain in performance data history. Older
          samples get discarded.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of metrics that have been modified by the call to this method.
        """
        ret = self._call_method('setupMetrics', metric_names, objects, period, count)
        return ret

    def enable_metrics(self, metric_names, objects):
        """None
        :param typing.List[str] metric_names:
            Metric name filter. Comma-separated list of metrics with wildcard
          support.
        :param typing.List[nterface] objects:
            Set of objects to enable metrics for.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of metrics that have been modified by the call to this method.
        """
        ret = self._call_method('enableMetrics', metric_names, objects)
        return ret

    def disable_metrics(self, metric_names, objects):
        """None
        :param typing.List[str] metric_names:
            Metric name filter. Comma-separated list of metrics with wildcard
          support.
        :param typing.List[nterface] objects:
            Set of objects to disable metrics for.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of metrics that have been modified by the call to this method.
        """
        ret = self._call_method('disableMetrics', metric_names, objects)
        return ret

    def query_metrics_data(self, metric_names, objects):
        """None
        :param typing.List[str] metric_names:
            Metric name filter. Comma-separated list of metrics with wildcard
          support.
        :param typing.List[nterface] objects:
            Set of objects to query metrics for.
        :rtype: typing.List[typing.Tuple[int, str, nterface, str, int, int, int, int]]
        """
        return_data, return_metric_names, return_objects, return_units, return_scales, return_sequence_numbers, return_data_indices, return_data_lengths = self._call_method('queryMetricsData', metric_names, objects)
        return_objects = nterface(return_objects)
        return return_data, return_metric_names, return_objects, return_units, return_scales, return_sequence_numbers, return_data_indices, return_data_lengths

    @property
    def metric_names(self):
        """Array of unique names of metrics.

        This array represents all metrics supported by the performance
        collector. Individual objects do not necessarily support all of them.
        :rtype: typing.List[str]
        """
        return list(self._get_property('metricNames'))


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

class NATEngine(Interface):
    """Interface for managing a NAT engine which is used with a virtual machine. This
      allows for changing NAT behavior such as port-forwarding rules. This interface is
      used in the
    """
    def set_network_settings(self, mtu, sock_snd, sock_rcv, tcp_wnd_snd, tcp_wnd_rcv):
        """None
        :param int mtu:
            MTU (maximum transmission unit) of the NAT engine in bytes.
        :param int sock_snd:
            Capacity of the socket send buffer in bytes when creating a new socket.
        :param int sock_rcv:
            Capacity of the socket receive buffer in bytes when creating a new socket.
        :param int tcp_wnd_snd:
            Initial size of the NAT engine's sending TCP window in bytes when
          establishing a new TCP connection.
        :param int tcp_wnd_rcv:
            Initial size of the NAT engine's receiving TCP window in bytes when
          establishing a new TCP connection.
        """
        self._call_method('setNetworkSettings', mtu, sock_snd, sock_rcv, tcp_wnd_snd, tcp_wnd_rcv)

    def get_network_settings(self):
        """None
        :rtype: typing.Tuple[int, int, int, int, int]
        """
        mtu, sock_snd, sock_rcv, tcp_wnd_snd, tcp_wnd_rcv = self._call_method('getNetworkSettings')
        return mtu, sock_snd, sock_rcv, tcp_wnd_snd, tcp_wnd_rcv

    def add_redirect(self, name, proto, host_ip, host_port, guest_ip, guest_port):
        """None
        :param str name:
            The name of the rule. An empty name is acceptable, in which case the NAT engine
            auto-generates one using the other parameters.
        :param NATProtocol proto:
            Protocol handled with the rule.
        :param str host_ip:
            IP of the host interface to which the rule should apply. An empty ip address is
            acceptable, in which case the NAT engine binds the handling socket to any interface.
        :param int host_port:
            The port number to listen on.
        :param str guest_ip:
            The IP address of the guest which the NAT engine will forward matching packets
            to. An empty IP address is acceptable, in which case the NAT engine will forward
            packets to the first DHCP lease (x.x.x.15).
        :param int guest_port:
            The port number to forward.
        """
        self._call_method('addRedirect', name, proto, host_ip, host_port, guest_ip, guest_port)

    def remove_redirect(self, name):
        """None
        :param str name:
            The name of the rule to delete.
        """
        self._call_method('removeRedirect', name)

    @property
    def network(self):
        """The network attribute of the NAT engine (the same value is used with built-in
        DHCP server to fill corresponding fields of DHCP leases).
        :rtype: str
        """
        return self._get_property('network')

    @property
    def host_ip(self):
        """IP of host interface to bind all opened sockets to.
        :rtype: str
        """
        return self._get_property('hostIP')

    @property
    def tftp_prefix(self):
        """TFTP prefix attribute which is used with the built-in DHCP server to fill
        the corresponding fields of DHCP leases.
        :rtype: str
        """
        return self._get_property('TFTPPrefix')

    @property
    def tftp_boot_file(self):
        """TFTP boot file attribute which is used with the built-in DHCP server to fill
        the corresponding fields of DHCP leases.
        :rtype: str
        """
        return self._get_property('TFTPBootFile')

    @property
    def tftp_next_server(self):
        """TFTP server attribute which is used with the built-in DHCP server to fill
        the corresponding fields of DHCP leases.
        :rtype: str
        """
        return self._get_property('TFTPNextServer')

    @property
    def alias_mode(self):
        """None
        :rtype: int
        """
        return self._get_property('aliasMode')

    @property
    def dns_pass_domain(self):
        """Whether the DHCP server should pass the DNS domain used by the host.
        :rtype: bool
        """
        return self._get_property('DNSPassDomain')

    @property
    def dns_proxy(self):
        """Whether the DHCP server (and the DNS traffic by NAT) should pass the address
        of the DNS proxy and process traffic using DNS servers registered on the host.
        :rtype: bool
        """
        return self._get_property('DNSProxy')

    @property
    def dns_use_host_resolver(self):
        """Whether the DHCP server (and the DNS traffic by NAT) should pass the address
        of the DNS proxy and process traffic using the host resolver mechanism.
        :rtype: bool
        """
        return self._get_property('DNSUseHostResolver')

    @property
    def redirects(self):
        """Array of NAT port-forwarding rules in string representation, in the following
        format: "name,protocol id,host ip,host port,guest ip,guest port".
        :rtype: typing.List[str]
        """
        return list(self._get_property('redirects'))


class ExtPackPlugIn(Interface):
    """Interface for keeping information about a plug-in that ships with an
      extension pack.
    """
    @property
    def name(self):
        """The plug-in name.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def description(self):
        """The plug-in description.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def frontend(self):
        """The name of the frontend or component name this plug-in plugs into.
        :rtype: str
        """
        return self._get_property('frontend')

    @property
    def module_path(self):
        """The module path.
        :rtype: str
        """
        return self._get_property('modulePath')


class ExtPackBase(Interface):
    """Interface for querying information about an extension pack as well as
      accessing COM objects within it.
    """
    def query_license(self, preferred_locale, preferred_language, format_):
        """None
        :param str preferred_locale:
            The preferred license locale. Pass an empty string to get the default
          license.
        :param str preferred_language:
            The preferred license language. Pass an empty string to get the
          default language for the locale.
        :param str format_:
            The license format: html, rtf or txt. If a license is present there
          will always be an HTML of it, the rich text format (RTF) and plain
          text (txt) versions are optional. If
        :rtype: str
        :returns:
            The license text.
        """
        ret = self._call_method('queryLicense', preferred_locale, preferred_language, format_)
        return ret

    @property
    def name(self):
        """The extension pack name. This is unique.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def description(self):
        """The extension pack description.
        :rtype: str
        """
        return self._get_property('description')

    @property
    def version(self):
        """The extension pack version string. This is restricted to the dotted
        version number and optionally a build indicator. No tree revision or
        tag will be included in the string as those things are available as
        separate properties. An optional publisher tag may be present like for
        :rtype: str
        """
        return self._get_property('version')

    @property
    def revision(self):
        """The extension pack internal revision number.
        :rtype: int
        """
        return self._get_property('revision')

    @property
    def edition(self):
        """Edition indicator. This is usually empty.

        Can for instance be used to help distinguishing between two editions
        of the same extension pack where only the license, service contract or
        something differs.
        :rtype: str
        """
        return self._get_property('edition')

    @property
    def vrde_module(self):
        """The name of the VRDE module if the extension pack sports one.
        :rtype: str
        """
        return self._get_property('VRDEModule')

    @property
    def plug_ins(self):
        """Plug-ins provided by this extension pack.
        :rtype: typing.List[ExtPackPlugIn]
        """
        return [ExtPackPlugIn(obj) for obj in self._get_property('plugIns')]

    @property
    def usable(self):
        """Indicates whether the extension pack is usable or not.

        There are a number of reasons why an extension pack might be unusable,
        typical examples would be broken installation/file or that it is
        incompatible with the current VirtualBox version.
        :rtype: bool
        """
        return self._get_property('usable')

    @property
    def why_unusable(self):
        """String indicating why the extension pack is not usable. This is an
        empty string if usable and always a non-empty string if not usable.
        :rtype: str
        """
        return self._get_property('whyUnusable')

    @property
    def show_license(self):
        """Whether to show the license before installation
        :rtype: bool
        """
        return self._get_property('showLicense')

    @property
    def license_(self):
        """The default HTML license text for the extension pack. Same as
        calling
        :rtype: str
        """
        return self._get_property('license')


class ExtPack(ExtPackBase):
    """Interface for querying information about an extension pack as well as
      accessing COM objects within it.
    """
    def query_object(self, obj_uuid):
        """None
        :param str obj_uuid:
            The object ID. What exactly this is
        :rtype: nterface
        :returns:
            The queried interface.
        """
        ret = self._call_method('queryObject', obj_uuid)
        return ret


class ExtPackFile(ExtPackBase):
    """Extension pack file (aka tarball, .vbox-extpack) representation returned
      by
    """
    def install(self, replace, display_info):
        """None
        :param bool replace:
            Set this to automatically uninstall any existing extension pack with
          the same name as the one being installed.
        :param str display_info:
            Platform specific display information. Reserved for future hacks.
        :rtype: Progress
        :returns:
            Progress object for the operation.
        """
        ret = self._call_method('install', replace, display_info)
        return ret

    @property
    def file_path(self):
        """The path to the extension pack file.
        :rtype: str
        """
        return self._get_property('filePath')


class ExtPackManager(Interface):
    """Interface for managing VirtualBox Extension Packs.

      @todo Describe extension packs, how they are managed and how to create one.
    """
    def find(self, name):
        """None
        :param str name:
            The name of the extension pack to locate.
        :rtype: ExtPack
        :returns:
            The extension pack if found.
        """
        ret = self._call_method('find', name)
        return ret

    def open_ext_pack_file(self, path):
        """None
        :param str path:
            The path of the extension pack tarball. This can optionally be
        followed by a "::SHA-256=hex-digit" of the tarball.
        :rtype: ExtPackFile
        :returns:
            The interface of the extension pack file object.
        """
        ret = self._call_method('openExtPackFile', path)
        return ret

    def uninstall(self, name, forced_removal, display_info):
        """None
        :param str name:
            The name of the extension pack to uninstall.
        :param bool forced_removal:
            Forced removal of the extension pack. This means that the uninstall
          hook will not be called.
        :param str display_info:
            Platform specific display information. Reserved for future hacks.
        :rtype: Progress
        :returns:
            Progress object for the operation.
        """
        ret = self._call_method('uninstall', name, forced_removal, display_info)
        return ret

    def cleanup(self):
        """None
        """
        self._call_method('cleanup')

    def query_all_plug_ins_for_frontend(self, frontend_name):
        """None
        :param str frontend_name:
            The name of the frontend or component.
        :rtype: typing.List[str]
        :returns:
            Array containing the plug-in modules (full paths).
        """
        ret = self._call_method('queryAllPlugInsForFrontend', frontend_name)
        return ret

    def is_ext_pack_usable(self, name):
        """None
        :param str name:
            The name of the extension pack to check for.
        :rtype: bool
        :returns:
            Is the given extension pack loaded and usable.
        """
        ret = self._call_method('isExtPackUsable', name)
        return ret

    @property
    def installed_ext_packs(self):
        """List of the installed extension packs.
        :rtype: typing.List[ExtPack]
        """
        return [ExtPack(obj) for obj in self._get_property('installedExtPacks')]


class BandwidthGroupType(enum.Enum):
    """
      Type of a bandwidth control group.
    
     .. describe:: NULL 
        Null type, must be first.
      
     .. describe:: DISK 
        The bandwidth group controls disk I/O.
      
     .. describe:: NETWORK 
        The bandwidth group controls network I/O.
      
    """
    NULL = 0
    DISK = 1
    NETWORK = 2

class BandwidthGroup(Interface):
    """Represents one bandwidth group.
    """
    @property
    def name(self):
        """Name of the group.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def type_(self):
        """Type of the group.
        :rtype: BandwidthGroupType
        """
        return BandwidthGroupType(self._get_property('type'))

    @property
    def reference(self):
        """How many devices/medium attachments use this group.
        :rtype: int
        """
        return self._get_property('reference')

    @property
    def max_bytes_per_sec(self):
        """The maximum number of bytes which can be transfered by all
        entities attached to this group during one second.
        :rtype: int
        """
        return self._get_property('maxBytesPerSec')


class BandwidthControl(Interface):
    """Controls the bandwidth groups of one machine used to cap I/O done by a VM.
      This includes network and disk I/O.
    """
    def create_bandwidth_group(self, name, type_, max_bytes_per_sec):
        """None
        :param str name:
            Name of the bandwidth group.
        :param BandwidthGroupType type_:
            The type of the bandwidth group (network or disk).
        :param int max_bytes_per_sec:
            The maximum number of bytes which can be transfered by all
          entities attached to this group during one second.
        """
        self._call_method('createBandwidthGroup', name, type_, max_bytes_per_sec)

    def delete_bandwidth_group(self, name):
        """None
        :param str name:
            Name of the bandwidth group to delete.
        """
        self._call_method('deleteBandwidthGroup', name)

    def get_bandwidth_group(self, name):
        """None
        :param str name:
            Name of the bandwidth group to get.
        :rtype: BandwidthGroup
        :returns:
            Where to store the bandwidth group on success.
        """
        ret = self._call_method('getBandwidthGroup', name)
        return ret

    def get_all_bandwidth_groups(self):
        """None
        :rtype: typing.List[BandwidthGroup]
        :returns:
            The array of managed bandwidth groups.
        """
        ret = self._call_method('getAllBandwidthGroups')
        return ret

    @property
    def num_groups(self):
        """The current number of existing bandwidth groups managed.
        :rtype: int
        """
        return self._get_property('numGroups')


class VirtualBoxClient(Interface):
    """Convenience interface for client applications. Treat this as a
      singleton, i.e. never create more than one instance of this interface.

      At the moment only available for clients of the local API (not usable
      via the webservice). Once the session logic is redesigned this might
      change.

      Error information handling is a bit special with IVirtualBoxClient:
      creating an instance will always succeed. The return of the actual error
      code/information is postponed to any attribute or method call. The
      reason for this is that COM likes to mutilate the error code and lose
      the detailed error information returned by instance creation.
    """
    def check_machine_error(self, machine):
        """None
        :param Machine machine:
            The machine object to check.
        """
        self._call_method('checkMachineError', machine)

    @property
    def virtual_box(self):
        """Reference to the server-side API root object.
        :rtype: VirtualBox
        """
        return VirtualBox(self._get_property('virtualBox'))

    @property
    def session(self):
        """Create a new session object and return the reference to it.
        :rtype: Session
        """
        return Session(self._get_property('session'))

    @property
    def event_source(self):
        """Event source for VirtualBoxClient events.
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))


class VBoxEventType(enum.Enum):
    """
      Type of an event.
      See 
     .. describe:: INVALID 
        Invalid event, must be first.
      
     .. describe:: ANY 
        Wildcard for all events.
        Events of this type are never delivered, and only used in
        
     .. describe:: VETOABLE 
        Wildcard for all vetoable events. Events of this type are never delivered, and only
        used in 
     .. describe:: MACHINE_EVENT 
        Wildcard for all machine events. Events of this type are never delivered, and only used in
        
     .. describe:: SNAPSHOT_EVENT 
        Wildcard for all snapshot events. Events of this type are never delivered, and only used in
        
     .. describe:: INPUT_EVENT 
        Wildcard for all input device (keyboard, mouse) events.
        Events of this type are never delivered, and only used in
        
     .. describe:: LAST_WILDCARD 
        Last wildcard.
      
     .. describe:: ON_MACHINE_STATE_CHANGED 
        See 
     .. describe:: ON_MACHINE_DATA_CHANGED 
        See 
     .. describe:: ON_EXTRA_DATA_CHANGED 
        See 
     .. describe:: ON_EXTRA_DATA_CAN_CHANGE 
        See 
     .. describe:: ON_MEDIUM_REGISTERED 
        See 
     .. describe:: ON_MACHINE_REGISTERED 
        See 
     .. describe:: ON_SESSION_STATE_CHANGED 
        See 
     .. describe:: ON_SNAPSHOT_TAKEN 
        See 
     .. describe:: ON_SNAPSHOT_DELETED 
        See 
     .. describe:: ON_SNAPSHOT_CHANGED 
        See 
     .. describe:: ON_GUEST_PROPERTY_CHANGED 
        See 
     .. describe:: ON_MOUSE_POINTER_SHAPE_CHANGED 
        See 
     .. describe:: ON_MOUSE_CAPABILITY_CHANGED 
        See 
     .. describe:: ON_KEYBOARD_LEDS_CHANGED 
        See 
     .. describe:: ON_STATE_CHANGED 
        See 
     .. describe:: ON_ADDITIONS_STATE_CHANGED 
        See 
     .. describe:: ON_NETWORK_ADAPTER_CHANGED 
        See 
     .. describe:: ON_SERIAL_PORT_CHANGED 
        See 
     .. describe:: ON_PARALLEL_PORT_CHANGED 
        See 
     .. describe:: ON_STORAGE_CONTROLLER_CHANGED 
        See 
     .. describe:: ON_MEDIUM_CHANGED 
        See 
     .. describe:: ON_VRDE_SERVER_CHANGED 
        See 
     .. describe:: ON_USB_CONTROLLER_CHANGED 
        See 
     .. describe:: ON_USB_DEVICE_STATE_CHANGED 
        See 
     .. describe:: ON_SHARED_FOLDER_CHANGED 
        See 
     .. describe:: ON_RUNTIME_ERROR 
        See 
     .. describe:: ON_CAN_SHOW_WINDOW 
        See 
     .. describe:: ON_SHOW_WINDOW 
        See 
     .. describe:: ON_CPU_CHANGED 
        See 
     .. describe:: ON_VRDE_SERVER_INFO_CHANGED 
        See 
     .. describe:: ON_EVENT_SOURCE_CHANGED 
        See 
     .. describe:: ON_CPU_EXECUTION_CAP_CHANGED 
        See 
     .. describe:: ON_GUEST_KEYBOARD 
        See 
     .. describe:: ON_GUEST_MOUSE 
        See 
     .. describe:: ON_NAT_REDIRECT 
        See 
     .. describe:: ON_HOST_PCI_DEVICE_PLUG 
        See 
     .. describe:: ON_VIRTUALBOX_SVC_AVAILABILITY_CHANGED 
        See 
     .. describe:: ON_BANDWIDTH_GROUP_CHANGED 
        See 
     .. describe:: ON_GUEST_MONITOR_CHANGED 
        See 
     .. describe:: ON_STORAGE_DEVICE_CHANGED 
        See 
     .. describe:: ON_CLIPBOARD_MODE_CHANGED 
        See 
     .. describe:: ON_DRAG_AND_DROP_MODE_CHANGED 
        See 
     .. describe:: ON_NAT_NETWORK_CHANGED 
        See 
     .. describe:: ON_NAT_NETWORK_START_STOP 
        See 
     .. describe:: ON_NAT_NETWORK_ALTER 
        See 
     .. describe:: ON_NAT_NETWORK_CREATION_DELETION 
        See 
     .. describe:: ON_NAT_NETWORK_SETTING 
        See 
     .. describe:: ON_NAT_NETWORK_PORT_FORWARD 
        See 
     .. describe:: ON_GUEST_SESSION_STATE_CHANGED 
        See 
     .. describe:: ON_GUEST_SESSION_REGISTERED 
        See 
     .. describe:: ON_GUEST_PROCESS_REGISTERED 
        See 
     .. describe:: ON_GUEST_PROCESS_STATE_CHANGED 
        See 
     .. describe:: ON_GUEST_PROCESS_INPUT_NOTIFY 
        See 
     .. describe:: ON_GUEST_PROCESS_OUTPUT 
        See 
     .. describe:: ON_GUEST_FILE_REGISTERED 
        See 
     .. describe:: ON_GUEST_FILE_STATE_CHANGED 
        See 
     .. describe:: ON_GUEST_FILE_OFFSET_CHANGED 
        See 
     .. describe:: ON_GUEST_FILE_READ 
        See 
     .. describe:: ON_GUEST_FILE_WRITE 
        See 
     .. describe:: ON_VIDEO_CAPTURE_CHANGED 
        See 
     .. describe:: ON_GUEST_USER_STATE_CHANGED 
        See 
     .. describe:: ON_GUEST_MULTI_TOUCH 
        See 
     .. describe:: ON_HOST_NAME_RESOLUTION_CONFIGURATION_CHANGE 
        See 
     .. describe:: ON_SNAPSHOT_RESTORED 
        See 
     .. describe:: ON_MEDIUM_CONFIG_CHANGED 
        See 
     .. describe:: ON_AUDIO_ADAPTER_CHANGED 
        See 
     .. describe:: ON_PROGRESS_PERCENTAGE_CHANGED 
        See 
     .. describe:: ON_PROGRESS_TASK_COMPLETED 
        See 
     .. describe:: ON_CURSOR_POSITION_CHANGED 
        See 
     .. describe:: LAST 
        Must be last event, used for iterations and structures relying on numerical event values.
      
    """
    INVALID = 0
    ANY = 1
    VETOABLE = 2
    MACHINE_EVENT = 3
    SNAPSHOT_EVENT = 4
    INPUT_EVENT = 5
    LAST_WILDCARD = 31
    ON_MACHINE_STATE_CHANGED = 32
    ON_MACHINE_DATA_CHANGED = 33
    ON_EXTRA_DATA_CHANGED = 34
    ON_EXTRA_DATA_CAN_CHANGE = 35
    ON_MEDIUM_REGISTERED = 36
    ON_MACHINE_REGISTERED = 37
    ON_SESSION_STATE_CHANGED = 38
    ON_SNAPSHOT_TAKEN = 39
    ON_SNAPSHOT_DELETED = 40
    ON_SNAPSHOT_CHANGED = 41
    ON_GUEST_PROPERTY_CHANGED = 42
    ON_MOUSE_POINTER_SHAPE_CHANGED = 43
    ON_MOUSE_CAPABILITY_CHANGED = 44
    ON_KEYBOARD_LEDS_CHANGED = 45
    ON_STATE_CHANGED = 46
    ON_ADDITIONS_STATE_CHANGED = 47
    ON_NETWORK_ADAPTER_CHANGED = 48
    ON_SERIAL_PORT_CHANGED = 49
    ON_PARALLEL_PORT_CHANGED = 50
    ON_STORAGE_CONTROLLER_CHANGED = 51
    ON_MEDIUM_CHANGED = 52
    ON_VRDE_SERVER_CHANGED = 53
    ON_USB_CONTROLLER_CHANGED = 54
    ON_USB_DEVICE_STATE_CHANGED = 55
    ON_SHARED_FOLDER_CHANGED = 56
    ON_RUNTIME_ERROR = 57
    ON_CAN_SHOW_WINDOW = 58
    ON_SHOW_WINDOW = 59
    ON_CPU_CHANGED = 60
    ON_VRDE_SERVER_INFO_CHANGED = 61
    ON_EVENT_SOURCE_CHANGED = 62
    ON_CPU_EXECUTION_CAP_CHANGED = 63
    ON_GUEST_KEYBOARD = 64
    ON_GUEST_MOUSE = 65
    ON_NAT_REDIRECT = 66
    ON_HOST_PCI_DEVICE_PLUG = 67
    ON_VIRTUALBOX_SVC_AVAILABILITY_CHANGED = 68
    ON_BANDWIDTH_GROUP_CHANGED = 69
    ON_GUEST_MONITOR_CHANGED = 70
    ON_STORAGE_DEVICE_CHANGED = 71
    ON_CLIPBOARD_MODE_CHANGED = 72
    ON_DRAG_AND_DROP_MODE_CHANGED = 73
    ON_NAT_NETWORK_CHANGED = 74
    ON_NAT_NETWORK_START_STOP = 75
    ON_NAT_NETWORK_ALTER = 76
    ON_NAT_NETWORK_CREATION_DELETION = 77
    ON_NAT_NETWORK_SETTING = 78
    ON_NAT_NETWORK_PORT_FORWARD = 79
    ON_GUEST_SESSION_STATE_CHANGED = 80
    ON_GUEST_SESSION_REGISTERED = 81
    ON_GUEST_PROCESS_REGISTERED = 82
    ON_GUEST_PROCESS_STATE_CHANGED = 83
    ON_GUEST_PROCESS_INPUT_NOTIFY = 84
    ON_GUEST_PROCESS_OUTPUT = 85
    ON_GUEST_FILE_REGISTERED = 86
    ON_GUEST_FILE_STATE_CHANGED = 87
    ON_GUEST_FILE_OFFSET_CHANGED = 88
    ON_GUEST_FILE_READ = 89
    ON_GUEST_FILE_WRITE = 90
    ON_VIDEO_CAPTURE_CHANGED = 91
    ON_GUEST_USER_STATE_CHANGED = 92
    ON_GUEST_MULTI_TOUCH = 93
    ON_HOST_NAME_RESOLUTION_CONFIGURATION_CHANGE = 94
    ON_SNAPSHOT_RESTORED = 95
    ON_MEDIUM_CONFIG_CHANGED = 96
    ON_AUDIO_ADAPTER_CHANGED = 97
    ON_PROGRESS_PERCENTAGE_CHANGED = 98
    ON_PROGRESS_TASK_COMPLETED = 99
    ON_CURSOR_POSITION_CHANGED = 100
    LAST = 101

class EventSource(Interface):
    """Event source. Generally, any object which could generate events can be an event source,
      or aggregate one. To simplify using one-way protocols such as webservices running on top of HTTP(S),
      an event source can work with listeners in either active or passive mode. In active mode it is up to
      the IEventSource implementation to call
    """
    def create_listener(self):
        """None
        :rtype: EventListener
        """
        ret = self._call_method('createListener')
        return ret

    def create_aggregator(self, subordinates):
        """None
        :param typing.List[EventSource] subordinates:
            Subordinate event source this one aggregates.
        :rtype: EventSource
        :returns:
            Event source aggregating passed sources.
        """
        ret = self._call_method('createAggregator', subordinates)
        return ret

    def register_listener(self, listener, interesting, active):
        """None
        :param EventListener listener:
            Listener to register.
        :param typing.List[VBoxEventType] interesting:
            Event types listener is interested in. One can use wildcards like -
        :param bool active:
            Which mode this listener is operating in.
          In active mode,
        """
        self._call_method('registerListener', listener, interesting, active)

    def unregister_listener(self, listener):
        """None
        :param EventListener listener:
            Listener to unregister.
        """
        self._call_method('unregisterListener', listener)

    def fire_event(self, event, timeout):
        """None
        :param Event event:
            Event to deliver.
        :param int timeout:
            Maximum time to wait for event processing (if event is waitable), in ms;
          0 = no wait, -1 = indefinite wait.
        :rtype: bool
        :returns:
            true if an event was delivered to all targets, or is non-waitable.
        """
        ret = self._call_method('fireEvent', event, timeout)
        return ret

    def get_event(self, listener, timeout):
        """None
        :param EventListener listener:
            Which listener to get data for.
        :param int timeout:
            Maximum time to wait for events, in ms;
          0 = no wait, -1 = indefinite wait.
        :rtype: Event
        :returns:
            Event retrieved, or null if none available.
        """
        ret = self._call_method('getEvent', listener, timeout)
        return ret

    def event_processed(self, listener, event):
        """None
        :param EventListener listener:
            Which listener processed event.
        :param Event event:
            Which event.
        """
        self._call_method('eventProcessed', listener, event)


class EventListener(Interface):
    """Event listener. An event listener can work in either active or passive mode, depending on the way
      it was registered.
      See
    """
    def handle_event(self, event):
        """None
        :param Event event:
            Event available.
        """
        self._call_method('handleEvent', event)


class Event(Interface):
    """Abstract parent interface for VirtualBox events. Actual events will typically implement
      a more specific interface which derives from this (see below).
    """
    def set_processed(self):
        """None
        """
        self._call_method('setProcessed')

    def wait_processed(self, timeout):
        """None
        :param int timeout:
            Maximum time to wait for event processing, in ms;
          0 = no wait, -1 = indefinite wait.
        :rtype: bool
        :returns:
            If this event was processed before timeout.
        """
        ret = self._call_method('waitProcessed', timeout)
        return ret

    @property
    def type_(self):
        """Event type.
        :rtype: VBoxEventType
        """
        return VBoxEventType(self._get_property('type'))

    @property
    def source(self):
        """Source of this event.
        :rtype: EventSource
        """
        return EventSource(self._get_property('source'))

    @property
    def waitable(self):
        """If we can wait for this event being processed. If false,
        :rtype: bool
        """
        return self._get_property('waitable')


class ReusableEvent(Event):
    """Base abstract interface for all reusable events.
    """
    def reuse(self):
        """None
        """
        self._call_method('reuse')

    @property
    def generation(self):
        """Current generation of event, incremented on reuse.
        :rtype: int
        """
        return self._get_property('generation')


class MachineEvent(Event):
    """Base abstract interface for all machine events.
    """
    @property
    def machine_id(self):
        """ID of the machine this event relates to.
        :rtype: str
        """
        return self._get_property('machineId')


class MachineStateChangedEvent(MachineEvent):
    """Machine state change event.
    """
    @property
    def state(self):
        """New execution state.
        :rtype: MachineState
        """
        return MachineState(self._get_property('state'))


class MachineDataChangedEvent(MachineEvent):
    """Any of the settings of the given machine has changed.
    """
    @property
    def temporary(self):
        """@c true if the settings change is temporary. All permanent
        settings changes will trigger an event, and only temporary settings
        changes for running VMs will trigger an event. Note: sending events
        for temporary changes is NOT IMPLEMENTED.
        :rtype: bool
        """
        return self._get_property('temporary')


class MediumRegisteredEvent(Event):
    """The given medium was registered or unregistered
      within this VirtualBox installation.
    """
    @property
    def medium_id(self):
        """ID of the medium this event relates to.
        :rtype: str
        """
        return self._get_property('mediumId')

    @property
    def medium_type(self):
        """Type of the medium this event relates to.
        :rtype: DeviceType
        """
        return DeviceType(self._get_property('mediumType'))

    @property
    def registered(self):
        """If @c true, the medium was registered, otherwise it was
        unregistered.
        :rtype: bool
        """
        return self._get_property('registered')


class MediumConfigChangedEvent(Event):
    """The configuration of the given medium was changed (location, properties,
      child/parent or anything else).
    """
    @property
    def medium(self):
        """ID of the medium this event relates to.
        :rtype: Medium
        """
        return Medium(self._get_property('medium'))


class MachineRegisteredEvent(MachineEvent):
    """The given machine was registered or unregistered
      within this VirtualBox installation.
    """
    @property
    def registered(self):
        """If @c true, the machine was registered, otherwise it was
        unregistered.
        :rtype: bool
        """
        return self._get_property('registered')


class SessionStateChangedEvent(MachineEvent):
    """The state of the session for the given machine was changed.
    """
    @property
    def state(self):
        """New session state.
        :rtype: SessionState
        """
        return SessionState(self._get_property('state'))


class GuestPropertyChangedEvent(MachineEvent):
    """Notification when a guest property has changed.
    """
    @property
    def name(self):
        """The name of the property that has changed.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def value(self):
        """The new property value.
        :rtype: str
        """
        return self._get_property('value')

    @property
    def flags(self):
        """The new property flags.
        :rtype: str
        """
        return self._get_property('flags')


class SnapshotEvent(MachineEvent):
    """Base interface for all snapshot events.
    """
    @property
    def snapshot_id(self):
        """ID of the snapshot this event relates to.
        :rtype: str
        """
        return self._get_property('snapshotId')


class SnapshotTakenEvent(SnapshotEvent):
    """A new snapshot of the machine has been taken.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class SnapshotDeletedEvent(SnapshotEvent):
    """Snapshot of the given machine has been deleted.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class SnapshotRestoredEvent(SnapshotEvent):
    """Snapshot of the given machine has been restored.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class SnapshotChangedEvent(SnapshotEvent):
    """Snapshot properties (name and/or description) have been changed.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class MousePointerShapeChangedEvent(Event):
    """Notification when the guest mouse pointer shape has
      changed. The new shape data is given.
    """
    @property
    def visible(self):
        """Flag whether the pointer is visible.
        :rtype: bool
        """
        return self._get_property('visible')

    @property
    def alpha(self):
        """Flag whether the pointer has an alpha channel.
        :rtype: bool
        """
        return self._get_property('alpha')

    @property
    def xhot(self):
        """The pointer hot spot X coordinate.
        :rtype: int
        """
        return self._get_property('xhot')

    @property
    def yhot(self):
        """The pointer hot spot Y coordinate.
        :rtype: int
        """
        return self._get_property('yhot')

    @property
    def width(self):
        """Width of the pointer shape in pixels.
        :rtype: int
        """
        return self._get_property('width')

    @property
    def height(self):
        """Height of the pointer shape in pixels.
        :rtype: int
        """
        return self._get_property('height')

    @property
    def shape(self):
        """Shape buffer arrays.

        The @a shape buffer contains a 1-bpp (bits per pixel) AND mask
        followed by a 32-bpp XOR (color) mask.

        For pointers without alpha channel the XOR mask pixels are
        32-bit values: (lsb)BGR0(msb). For pointers with alpha channel
        the XOR mask consists of (lsb)BGRA(msb) 32-bit values.

        An AND mask is used for pointers with alpha channel, so if the
        callback does not support alpha, the pointer could be
        displayed as a normal color pointer.

        The AND mask is a 1-bpp bitmap with byte aligned scanlines. The
        size of the AND mask therefore is
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('shape'))


class MouseCapabilityChangedEvent(Event):
    """Notification when the mouse capabilities reported by the
      guest have changed. The new capabilities are passed.
    """
    @property
    def supports_absolute(self):
        """Supports absolute coordinates.
        :rtype: bool
        """
        return self._get_property('supportsAbsolute')

    @property
    def supports_relative(self):
        """Supports relative coordinates.
        :rtype: bool
        """
        return self._get_property('supportsRelative')

    @property
    def supports_multi_touch(self):
        """Supports multi-touch events coordinates.
        :rtype: bool
        """
        return self._get_property('supportsMultiTouch')

    @property
    def needs_host_cursor(self):
        """If host cursor is needed.
        :rtype: bool
        """
        return self._get_property('needsHostCursor')


class KeyboardLedsChangedEvent(Event):
    """Notification when the guest OS executes the KBD_CMD_SET_LEDS command
      to alter the state of the keyboard LEDs.
    """
    @property
    def num_lock(self):
        """NumLock status.
        :rtype: bool
        """
        return self._get_property('numLock')

    @property
    def caps_lock(self):
        """CapsLock status.
        :rtype: bool
        """
        return self._get_property('capsLock')

    @property
    def scroll_lock(self):
        """ScrollLock status.
        :rtype: bool
        """
        return self._get_property('scrollLock')


class StateChangedEvent(Event):
    """Notification when the execution state of the machine has changed.
      The new state is given.
    """
    @property
    def state(self):
        """New machine state.
        :rtype: MachineState
        """
        return MachineState(self._get_property('state'))


class AdditionsStateChangedEvent(Event):
    """Notification when a Guest Additions property changes.
      Interested callees should query IGuest attributes to
      find out what has changed.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class NetworkAdapterChangedEvent(Event):
    """Notification when a property of one of the
      virtual
    """
    @property
    def network_adapter(self):
        """Network adapter that is subject to change.
        :rtype: NetworkAdapter
        """
        return NetworkAdapter(self._get_property('networkAdapter'))


class AudioAdapterChangedEvent(Event):
    """Notification when a property of the audio adapter changes.
      Interested callees should use IAudioAdapter methods and attributes
      to find out what has changed.
    """
    @property
    def audio_adapter(self):
        """Audio adapter that is subject to change.
        :rtype: AudioAdapter
        """
        return AudioAdapter(self._get_property('audioAdapter'))


class SerialPortChangedEvent(Event):
    """Notification when a property of one of the
      virtual
    """
    @property
    def serial_port(self):
        """Serial port that is subject to change.
        :rtype: SerialPort
        """
        return SerialPort(self._get_property('serialPort'))


class ParallelPortChangedEvent(Event):
    """Notification when a property of one of the
      virtual
    """
    @property
    def parallel_port(self):
        """Parallel port that is subject to change.
        :rtype: ParallelPort
        """
        return ParallelPort(self._get_property('parallelPort'))


class StorageControllerChangedEvent(Event):
    """Notification when a
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class MediumChangedEvent(Event):
    """Notification when a
    """
    @property
    def medium_attachment(self):
        """Medium attachment that is subject to change.
        :rtype: MediumAttachment
        """
        return MediumAttachment(self._get_property('mediumAttachment'))


class ClipboardModeChangedEvent(Event):
    """Notification when the shared clipboard mode changes.
    """
    @property
    def clipboard_mode(self):
        """The new clipboard mode.
        :rtype: ClipboardMode
        """
        return ClipboardMode(self._get_property('clipboardMode'))


class DnDModeChangedEvent(Event):
    """Notification when the drag'n drop mode changes.
    """
    @property
    def dnd_mode(self):
        """The new drag'n drop mode.
        :rtype: DnDMode
        """
        return DnDMode(self._get_property('dndMode'))


class CPUChangedEvent(Event):
    """Notification when a CPU changes.
    """
    @property
    def cpu(self):
        """The CPU which changed.
        :rtype: int
        """
        return self._get_property('CPU')

    @property
    def add(self):
        """Flag whether the CPU was added or removed.
        :rtype: bool
        """
        return self._get_property('add')


class CPUExecutionCapChangedEvent(Event):
    """Notification when the CPU execution cap changes.
    """
    @property
    def execution_cap(self):
        """The new CPU execution cap value. (1-100)
        :rtype: int
        """
        return self._get_property('executionCap')


class GuestKeyboardEvent(Event):
    """Notification when guest keyboard event happens.
    """
    @property
    def scancodes(self):
        """Array of scancodes.
        :rtype: int
        """
        return list(self._get_property('scancodes'))


class GuestMouseEventMode(enum.Enum):
    """
      The mode (relative, absolute, multi-touch) of a pointer event.

      @todo A clear pattern seems to be emerging that we should usually have
      multiple input devices active for different types of reporting, so we
      should really have different event types for relative (including wheel),
      absolute (not including wheel) and multi-touch events.
    
     .. describe:: RELATIVE 
        Relative event.
      
     .. describe:: ABSOLUTE 
        Absolute event.
      
    """
    RELATIVE = 0
    ABSOLUTE = 1

class GuestMouseEvent(ReusableEvent):
    """Notification when guest mouse event happens.
    """
    @property
    def mode(self):
        """If this event is relative, absolute or multi-touch.
        :rtype: GuestMouseEventMode
        """
        return GuestMouseEventMode(self._get_property('mode'))

    @property
    def x(self):
        """New X position, or X delta.
        :rtype: int
        """
        return self._get_property('x')

    @property
    def y(self):
        """New Y position, or Y delta.
        :rtype: int
        """
        return self._get_property('y')

    @property
    def z(self):
        """Z delta.
        :rtype: int
        """
        return self._get_property('z')

    @property
    def w(self):
        """W delta.
        :rtype: int
        """
        return self._get_property('w')

    @property
    def buttons(self):
        """Button state bitmask.
        :rtype: int
        """
        return self._get_property('buttons')


class GuestMultiTouchEvent(Event):
    """Notification when guest touch screen event happens.
    """
    @property
    def contact_count(self):
        """Number of contacts in the event.
        :rtype: int
        """
        return self._get_property('contactCount')

    @property
    def x_positions(self):
        """X positions.
        :rtype: int
        """
        return list(self._get_property('xPositions'))

    @property
    def y_positions(self):
        """Y positions.
        :rtype: int
        """
        return list(self._get_property('yPositions'))

    @property
    def contact_ids(self):
        """Contact identifiers.
        :rtype: int
        """
        return list(self._get_property('contactIds'))

    @property
    def contact_flags(self):
        """Contact state.
        Bit 0: in contact.
        Bit 1: in range.
        :rtype: int
        """
        return list(self._get_property('contactFlags'))

    @property
    def scan_time(self):
        """Timestamp of the event in milliseconds. Only relative time between events is important.
        :rtype: int
        """
        return self._get_property('scanTime')


class GuestSessionEvent(Event):
    """Base abstract interface for all guest session events.
    """
    @property
    def session(self):
        """Guest session that is subject to change.
        :rtype: GuestSession
        """
        return GuestSession(self._get_property('session'))


class GuestSessionStateChangedEvent(GuestSessionEvent):
    """Notification when a guest session changed its state.
    """
    @property
    def id_(self):
        """Session ID of guest session which was changed.
        :rtype: int
        """
        return self._get_property('id')

    @property
    def status(self):
        """New session status.
        :rtype: GuestSessionStatus
        """
        return GuestSessionStatus(self._get_property('status'))

    @property
    def error(self):
        """Error information in case of new session status is indicating an error.

        The attribute
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('error'))


class GuestSessionRegisteredEvent(GuestSessionEvent):
    """Notification when a guest session was registered or unregistered.
    """
    @property
    def registered(self):
        """If @c true, the guest session was registered, otherwise it was
        unregistered.
        :rtype: bool
        """
        return self._get_property('registered')


class GuestProcessEvent(GuestSessionEvent):
    """Base abstract interface for all guest process events.
    """
    @property
    def process(self):
        """Guest process object which is related to this event.
        :rtype: GuestProcess
        """
        return GuestProcess(self._get_property('process'))

    @property
    def pid(self):
        """Guest process ID (PID).
        :rtype: int
        """
        return self._get_property('pid')


class GuestProcessRegisteredEvent(GuestProcessEvent):
    """Notification when a guest process was registered or unregistered.
    """
    @property
    def registered(self):
        """If @c true, the guest process was registered, otherwise it was
        unregistered.
        :rtype: bool
        """
        return self._get_property('registered')


class GuestProcessStateChangedEvent(GuestProcessEvent):
    """Notification when a guest process changed its state.
    """
    @property
    def status(self):
        """New guest process status.
        :rtype: ProcessStatus
        """
        return ProcessStatus(self._get_property('status'))

    @property
    def error(self):
        """Error information in case of new session status is indicating an error.

        The attribute
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('error'))


class GuestProcessIOEvent(GuestProcessEvent):
    """Base abstract interface for all guest process input/output (IO) events.
    """
    @property
    def handle(self):
        """Input/output (IO) handle involved in this event. Usually 0 is stdin,
        1 is stdout and 2 is stderr.
        :rtype: int
        """
        return self._get_property('handle')

    @property
    def processed(self):
        """Processed input or output (in bytes).
        :rtype: int
        """
        return self._get_property('processed')


class GuestProcessInputNotifyEvent(GuestProcessIOEvent):
    """Notification when a guest process' stdin became available.
    """
    @property
    def status(self):
        """Current process input status.
        :rtype: ProcessInputStatus
        """
        return ProcessInputStatus(self._get_property('status'))


class GuestProcessOutputEvent(GuestProcessIOEvent):
    """Notification when there is guest process output available for reading.
    """
    @property
    def data(self):
        """Actual output data.
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('data'))


class GuestFileEvent(GuestSessionEvent):
    """Base abstract interface for all guest file events.
    """
    @property
    def file_(self):
        """Guest file object which is related to this event.
        :rtype: GuestFile
        """
        return GuestFile(self._get_property('file'))


class GuestFileRegisteredEvent(GuestFileEvent):
    """Notification when a guest file was registered or unregistered.
    """
    @property
    def registered(self):
        """If @c true, the guest file was registered, otherwise it was
        unregistered.
        :rtype: bool
        """
        return self._get_property('registered')


class GuestFileStateChangedEvent(GuestFileEvent):
    """Notification when a guest file changed its state.
    """
    @property
    def status(self):
        """New guest file status.
        :rtype: FileStatus
        """
        return FileStatus(self._get_property('status'))

    @property
    def error(self):
        """Error information in case of new session status is indicating an error.

        The attribute
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('error'))


class GuestFileIOEvent(GuestFileEvent):
    """Base abstract interface for all guest file input/output (IO) events.
    """
    @property
    def offset(self):
        """Current offset (in bytes).
        :rtype: int
        """
        return self._get_property('offset')

    @property
    def processed(self):
        """Processed input or output (in bytes).
        :rtype: int
        """
        return self._get_property('processed')


class GuestFileOffsetChangedEvent(GuestFileIOEvent):
    """Notification when a guest file changed its current offset.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class GuestFileReadEvent(GuestFileIOEvent):
    """Notification when data has been read from a guest file.
    """
    @property
    def data(self):
        """Actual data read.
        :rtype: typing.List[bytes]
        """
        return list(self._get_property('data'))


class GuestFileWriteEvent(GuestFileIOEvent):
    """Notification when data has been written to a guest file.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class VRDEServerChangedEvent(Event):
    """Notification when a property of the
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class VRDEServerInfoChangedEvent(Event):
    """Notification when the status of the VRDE server changes. Interested callees
      should use
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class VideoCaptureChangedEvent(Event):
    """Notification when video capture settings have changed.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class USBControllerChangedEvent(Event):
    """Notification when a property of the virtual
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class USBDeviceStateChangedEvent(Event):
    """Notification when a USB device is attached to or detached from
      the virtual USB controller.

      This notification is sent as a result of the indirect
      request to attach the device because it matches one of the
      machine USB filters, or as a result of the direct request
      issued by
    """
    @property
    def device(self):
        """Device that is subject to state change.
        :rtype: USBDevice
        """
        return USBDevice(self._get_property('device'))

    @property
    def attached(self):
        """@c true if the device was attached and @c false otherwise.
        :rtype: bool
        """
        return self._get_property('attached')

    @property
    def error(self):
        """@c null on success or an error message object on failure.
        :rtype: VirtualBoxErrorInfo
        """
        return VirtualBoxErrorInfo(self._get_property('error'))


class SharedFolderChangedEvent(Event):
    """Notification when a shared folder is added or removed.
      The @a scope argument defines one of three scopes:
    """
    @property
    def scope(self):
        """Scope of the notification.
        :rtype: Scope
        """
        return Scope(self._get_property('scope'))


class RuntimeErrorEvent(Event):
    """Notification when an error happens during the virtual
      machine execution.

      There are three kinds of runtime errors:
    """
    @property
    def fatal(self):
        """Whether the error is fatal or not.
        :rtype: bool
        """
        return self._get_property('fatal')

    @property
    def id_(self):
        """Error identifier.
        :rtype: str
        """
        return self._get_property('id')

    @property
    def message(self):
        """Optional error message.
        :rtype: str
        """
        return self._get_property('message')


class EventSourceChangedEvent(Event):
    """Notification when an event source state changes (listener added or removed).
    """
    @property
    def listener(self):
        """Event listener which has changed.
        :rtype: EventListener
        """
        return EventListener(self._get_property('listener'))

    @property
    def add(self):
        """Flag whether listener was added or removed.
        :rtype: bool
        """
        return self._get_property('add')


class ExtraDataChangedEvent(Event):
    """Notification when machine specific or global extra data
      has changed.
    """
    @property
    def machine_id(self):
        """ID of the machine this event relates to.
        Null for global extra data changes.
        :rtype: str
        """
        return self._get_property('machineId')

    @property
    def key(self):
        """Extra data key that has changed.
        :rtype: str
        """
        return self._get_property('key')

    @property
    def value(self):
        """Extra data value for the given key.
        :rtype: str
        """
        return self._get_property('value')


class VetoEvent(Event):
    """Base abstract interface for veto events.
    """
    def add_veto(self, reason):
        """None
        :param str reason:
            Reason for veto, could be null or empty string.
        """
        self._call_method('addVeto', reason)

    def is_vetoed(self):
        """None
        :rtype: bool
        :returns:
            Reason for veto.
        """
        ret = self._call_method('isVetoed')
        return ret

    def get_vetos(self):
        """None
        :rtype: typing.List[str]
        :returns:
            Array of reasons for veto provided by different event handlers.
        """
        ret = self._call_method('getVetos')
        return ret

    def add_approval(self, reason):
        """None
        :param str reason:
            Reason for approval, could be null or empty string.
        """
        self._call_method('addApproval', reason)

    def is_approved(self):
        """None
        :rtype: bool
        """
        ret = self._call_method('isApproved')
        return ret

    def get_approvals(self):
        """None
        :rtype: typing.List[str]
        :returns:
            Array of reasons for approval provided by different event handlers.
        """
        ret = self._call_method('getApprovals')
        return ret


class ExtraDataCanChangeEvent(VetoEvent):
    """Notification when someone tries to change extra data for
      either the given machine or (if @c null) global extra data.
      This gives the chance to veto against changes.
    """
    @property
    def machine_id(self):
        """ID of the machine this event relates to.
        Null for global extra data changes.
        :rtype: str
        """
        return self._get_property('machineId')

    @property
    def key(self):
        """Extra data key that has changed.
        :rtype: str
        """
        return self._get_property('key')

    @property
    def value(self):
        """Extra data value for the given key.
        :rtype: str
        """
        return self._get_property('value')


class CanShowWindowEvent(VetoEvent):
    """Notification when a call to
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class ShowWindowEvent(Event):
    """Notification when a call to
    """
    @property
    def win_id(self):
        """Platform-dependent identifier of the top-level VM console
        window, or zero if this method has performed all actions
        necessary to implement the
        :rtype: int
        """
        return self._get_property('winId')


class NATRedirectEvent(MachineEvent):
    """Notification when NAT redirect rule added or removed.
    """
    @property
    def slot(self):
        """Adapter which NAT attached to.
        :rtype: int
        """
        return self._get_property('slot')

    @property
    def remove(self):
        """Whether rule remove or add.
        :rtype: bool
        """
        return self._get_property('remove')

    @property
    def name(self):
        """Name of the rule.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def proto(self):
        """Protocol (TCP or UDP) of the redirect rule.
        :rtype: NATProtocol
        """
        return NATProtocol(self._get_property('proto'))

    @property
    def host_ip(self):
        """Host ip address to bind socket on.
        :rtype: str
        """
        return self._get_property('hostIP')

    @property
    def host_port(self):
        """Host port to bind socket on.
        :rtype: int
        """
        return self._get_property('hostPort')

    @property
    def guest_ip(self):
        """Guest ip address to redirect to.
        :rtype: str
        """
        return self._get_property('guestIP')

    @property
    def guest_port(self):
        """Guest port to redirect to.
        :rtype: int
        """
        return self._get_property('guestPort')


class HostPCIDevicePlugEvent(MachineEvent):
    """Notification when host PCI device is plugged/unplugged. Plugging
      usually takes place on VM startup, unplug - when
    """
    @property
    def plugged(self):
        """If device successfully plugged or unplugged.
        :rtype: bool
        """
        return self._get_property('plugged')

    @property
    def success(self):
        """If operation was successful, if false - 'message' attribute
        may be of interest.
        :rtype: bool
        """
        return self._get_property('success')

    @property
    def attachment(self):
        """Attachment info for this device.
        :rtype: PCIDeviceAttachment
        """
        return PCIDeviceAttachment(self._get_property('attachment'))

    @property
    def message(self):
        """Optional error message.
        :rtype: str
        """
        return self._get_property('message')


class VBoxSVCAvailabilityChangedEvent(Event):
    """Notification when VBoxSVC becomes unavailable (due to a crash or similar
      unexpected circumstances) or available again.
    """
    @property
    def available(self):
        """Whether VBoxSVC is available now.
        :rtype: bool
        """
        return self._get_property('available')


class BandwidthGroupChangedEvent(Event):
    """Notification when one of the bandwidth groups changed
    """
    @property
    def bandwidth_group(self):
        """The changed bandwidth group.
        :rtype: BandwidthGroup
        """
        return BandwidthGroup(self._get_property('bandwidthGroup'))


class GuestMonitorChangedEventType(enum.Enum):
    """
      How the guest monitor has been changed.
    
     .. describe:: ENABLED 
        The guest monitor has been enabled by the guest.
      
     .. describe:: DISABLED 
        The guest monitor has been disabled by the guest.
      
     .. describe:: NEW_ORIGIN 
        The guest monitor origin has changed in the guest.
      
    """
    ENABLED = 0
    DISABLED = 1
    NEW_ORIGIN = 2

class GuestMonitorChangedEvent(Event):
    """Notification when the guest enables one of its monitors.
    """
    @property
    def change_type(self):
        """What was changed for this guest monitor.
        :rtype: GuestMonitorChangedEventType
        """
        return GuestMonitorChangedEventType(self._get_property('changeType'))

    @property
    def screen_id(self):
        """The monitor which was changed.
        :rtype: int
        """
        return self._get_property('screenId')

    @property
    def origin_x(self):
        """Physical X origin relative to the primary screen.
        Valid for Enabled and NewOrigin.
        :rtype: int
        """
        return self._get_property('originX')

    @property
    def origin_y(self):
        """Physical Y origin relative to the primary screen.
        Valid for Enabled and NewOrigin.
        :rtype: int
        """
        return self._get_property('originY')

    @property
    def width(self):
        """Width of the screen.
        Valid for Enabled.
        :rtype: int
        """
        return self._get_property('width')

    @property
    def height(self):
        """Height of the screen.
        Valid for Enabled.
        :rtype: int
        """
        return self._get_property('height')


class GuestUserStateChangedEvent(Event):
    """Notification when a guest user changed its state.
    """
    @property
    def name(self):
        """Name of the guest user whose state changed.
        :rtype: str
        """
        return self._get_property('name')

    @property
    def domain(self):
        """Name of the FQDN (fully qualified domain name) this user is bound
        to. Optional.
        :rtype: str
        """
        return self._get_property('domain')

    @property
    def state(self):
        """What was changed for this guest user. See
        :rtype: GuestUserState
        """
        return GuestUserState(self._get_property('state'))

    @property
    def state_details(self):
        """Optional state details, depending on the
        :rtype: str
        """
        return self._get_property('stateDetails')


class StorageDeviceChangedEvent(Event):
    """Notification when a
    """
    @property
    def storage_device(self):
        """Storage device that is subject to change.
        :rtype: MediumAttachment
        """
        return MediumAttachment(self._get_property('storageDevice'))

    @property
    def removed(self):
        """Flag whether the device was removed or added to the VM.
        :rtype: bool
        """
        return self._get_property('removed')

    @property
    def silent(self):
        """Flag whether the guest should be notified about the change.
        :rtype: bool
        """
        return self._get_property('silent')


class NATNetworkChangedEvent(Event):
    @property
    def network_name(self):
        """None
        :rtype: str
        """
        return self._get_property('networkName')


class NATNetworkStartStopEvent(NATNetworkChangedEvent):
    @property
    def start_event(self):
        """IsStartEvent is true when NAT network is started and false on stopping.
        :rtype: bool
        """
        return self._get_property('startEvent')


class NATNetworkAlterEvent(NATNetworkChangedEvent):
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class NATNetworkCreationDeletionEvent(NATNetworkAlterEvent):
    @property
    def creation_event(self):
        """None
        :rtype: bool
        """
        return self._get_property('creationEvent')


class NATNetworkSettingEvent(NATNetworkAlterEvent):
    @property
    def enabled(self):
        """None
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def network(self):
        """None
        :rtype: str
        """
        return self._get_property('network')

    @property
    def gateway(self):
        """None
        :rtype: str
        """
        return self._get_property('gateway')

    @property
    def advertise_default_ipv6_route_enabled(self):
        """None
        :rtype: bool
        """
        return self._get_property('advertiseDefaultIPv6RouteEnabled')

    @property
    def need_dhcp_server(self):
        """None
        :rtype: bool
        """
        return self._get_property('needDhcpServer')


class NATNetworkPortForwardEvent(NATNetworkAlterEvent):
    @property
    def create(self):
        """None
        :rtype: bool
        """
        return self._get_property('create')

    @property
    def ipv6(self):
        """None
        :rtype: bool
        """
        return self._get_property('ipv6')

    @property
    def name(self):
        """None
        :rtype: str
        """
        return self._get_property('name')

    @property
    def proto(self):
        """None
        :rtype: NATProtocol
        """
        return NATProtocol(self._get_property('proto'))

    @property
    def host_ip(self):
        """None
        :rtype: str
        """
        return self._get_property('hostIp')

    @property
    def host_port(self):
        """None
        :rtype: int
        """
        return self._get_property('hostPort')

    @property
    def guest_ip(self):
        """None
        :rtype: str
        """
        return self._get_property('guestIp')

    @property
    def guest_port(self):
        """None
        :rtype: int
        """
        return self._get_property('guestPort')


class HostNameResolutionConfigurationChangeEvent(Event):
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class ProgressEvent(Event):
    """Base abstract interface for all progress events.
    """
    @property
    def progress_id(self):
        """GUID of the progress this event relates to.
        :rtype: str
        """
        return self._get_property('progressId')


class ProgressPercentageChangedEvent(ProgressEvent):
    """Progress state change event.
    """
    @property
    def percent(self):
        """New percent
        :rtype: int
        """
        return self._get_property('percent')


class ProgressTaskCompletedEvent(ProgressEvent):
    """Progress task completion event.
    """
    @property
    def midl_does_not_like_empty_interfaces(self):
        """None
        :rtype: bool
        """
        return self._get_property('midlDoesNotLikeEmptyInterfaces')


class CursorPositionChangedEvent(Event):
    """The guest reports cursor position data.
    """
    @property
    def has_data(self):
        """Event contains valid data (alternative: notification of support)
        :rtype: bool
        """
        return self._get_property('hasData')

    @property
    def x(self):
        """Reported X position
        :rtype: int
        """
        return self._get_property('x')

    @property
    def y(self):
        """Reported Y position
        :rtype: int
        """
        return self._get_property('y')

class VirtualBoxClient(Interface):
    pass

class Session(Interface):
    pass

class VBoxSVCRegistration(Interface):
    """Implemented by the VirtualBox class factory and registered with VBoxSDS
          so it can retrieve IVirtualBox on behalf of other VBoxSVCs.
    """
    def get_virtual_box(self):
        """None
        :rtype: nterface
        :returns:
            Where to return the IUnknown interface.
        """
        ret = self._call_method('getVirtualBox')
        return ret

    def notify_clients_finished(self):
        """None
        """
        self._call_method('notifyClientsFinished')


class VirtualBoxSDS(Interface):
    """The IVirtualBoxSDS interface represents the system-wide directory service
          helper.

          It exists only on Windows host, and its purpose is to work around design
          flaws in Microsoft's (D)COM, in particular the local server instantiation
          behavior.
    """
    def register_virtualbox_svc(self, vbox_svc, pid):
        """None
        :param VBoxSVCRegistration vbox_svc:
            Interface implemented by the VirtualBox class factory.
        :param int pid:
            The process ID of the VBoxSVC instance.
        :rtype: nterface
        :returns:
            If there is already an VBoxSVC for this user, the an IUnknown
            interface to its VirtualBox object is returned here, otherwise it
            is set to NULL.
        """
        ret = self._call_method('registerVBoxSVC', vbox_svc, pid)
        return ret

    def deregister_virtualbox_svc(self, vbox_svc, pid):
        """None
        :param VBoxSVCRegistration vbox_svc:
            Same as specified during registration.
        :param int pid:
            The process ID of the VBoxSVC instance (same as during registration).
        """
        self._call_method('deregisterVBoxSVC', vbox_svc, pid)

    def notify_clients_finished(self):
        """None
        """
        self._call_method('notifyClientsFinished')


class VirtualBoxClientList(Interface):
    """The IVirtualBoxClientList interface represents a list of VirtualBox API clients.
    """
    def register_client(self, pid):
        """None
        :param int pid:
            Process ID of VirtualBox API client.
        """
        self._call_method('registerClient', pid)

    @property
    def clients(self):
        """List of registered VirtualBox API clients.
        :rtype: int
        """
        return list(self._get_property('clients'))


class VirtualBoxSDS(Interface):
    pass

class VirtualBoxClientList(Interface):
    pass


class VirtualBox(VirtualBox):
    def __init__(self, interface=None, manager=None):
        if interface is not None:
            super(VirtualBox, self).__init__(interface)
        elif manager is not None:
            self._interface = manager.get_virtualbox()._interface
        else:
            from ._base import Manager
            manager = Manager()
            self._interface = manager.get_virtualbox()._interface
