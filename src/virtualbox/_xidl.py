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
from ._base import Interface, VirtualBoxException


class ObjectNotFound(VirtualBoxException):
    """None"""
    name = 'VBOX_E_OBJECT_NOT_FOUND'
    value = 0x80BB0001

class InvalidVmState(VirtualBoxException):
    """None"""
    name = 'VBOX_E_INVALID_VM_STATE'
    value = 0x80BB0002

class VmError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_VM_ERROR'
    value = 0x80BB0003

class FileError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_FILE_ERROR'
    value = 0x80BB0004

class IprtError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_IPRT_ERROR'
    value = 0x80BB0005

class PdmError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_PDM_ERROR'
    value = 0x80BB0006

class InvalidObjectState(VirtualBoxException):
    """None"""
    name = 'VBOX_E_INVALID_OBJECT_STATE'
    value = 0x80BB0007

class HostError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_HOST_ERROR'
    value = 0x80BB0008

class NotSupported(VirtualBoxException):
    """None"""
    name = 'VBOX_E_NOT_SUPPORTED'
    value = 0x80BB0009

class XmlError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_XML_ERROR'
    value = 0x80BB000A

class InvalidSessionState(VirtualBoxException):
    """None"""
    name = 'VBOX_E_INVALID_SESSION_STATE'
    value = 0x80BB000B

class ObjectInUse(VirtualBoxException):
    """None"""
    name = 'VBOX_E_OBJECT_IN_USE'
    value = 0x80BB000C

class PasswordIncorrect(VirtualBoxException):
    """None"""
    name = 'VBOX_E_PASSWORD_INCORRECT'
    value = 0x80BB000D

class MaximumReached(VirtualBoxException):
    """None"""
    name = 'VBOX_E_MAXIMUM_REACHED'
    value = 0x80BB000E

class GstctlGuestError(VirtualBoxException):
    """None"""
    name = 'VBOX_E_GSTCTL_GUEST_ERROR'
    value = 0x80BB000F

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

class NATNetwork(Interface):
    def add_local_mapping(self, hostid, offset):
        """
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
        ret = str(self._call_method('getVmSlotOptions', vmname, slot))
        return ret

    def get_mac_options(self, mac):
        """None
        :param str mac:
        :rtype: typing.List[str]
        """
        ret = str(self._call_method('getMacOptions', mac))
        return ret

    def set_configuration(self, ip_address, network_mask, from_ip_address, to_ip_address):
        """configures the server
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
        """Starts DHCP server process.
        :param str network_name:
            Name of internal network DHCP server should attach to.
        :param str trunk_name:
            Name of internal network trunk.
        :param str trunk_type:
            Type of internal network trunk.
        """
        self._call_method('start', network_name, trunk_name, trunk_type)

    def stop(self):
        """Stops DHCP server process.
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
        """Returns a recommended full path of the settings file name for a new virtual
        machine.

        This API serves two purposes:
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
        ret = str(self._call_method('composeMachineFilename', name, group, create_flags, base_folder))
        return ret

    def create_machine(self, settings_file, name, groups, os_type_id, flags):
        """Creates a new virtual machine by creating a machine settings file at
        the given location.

        VirtualBox machine settings files use a custom XML dialect. Starting
        with VirtualBox 4.0, a ".vbox" extension is recommended, but not enforced,
        and machine files can be created at arbitrary locations.

        However, it is recommended that machines are created in the default
        machine folder (e.g. "/home/user/VirtualBox VMs/name/name.vbox"; see
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
        ret = Machine(self._call_method('createMachine', settings_file, name, groups, os_type_id, flags))
        return ret

    def open_machine(self, settings_file):
        """Opens a virtual machine from the existing settings file.
        The opened machine remains unregistered until you call
        :param str settings_file:
            Name of the machine settings file.
        :rtype: Machine
        :returns:
            Opened machine object.
        """
        ret = Machine(self._call_method('openMachine', settings_file))
        return ret

    def register_machine(self, machine):
        """Registers the machine previously created using
        :param Machine machine:
        """
        self._call_method('registerMachine', machine)

    def find_machine(self, name_or_id):
        """Attempts to find a virtual machine given its name or UUID.
        :param str name_or_id:
            What to search for. This can either be the UUID or the name of a virtual machine.
        :rtype: Machine
        :returns:
            Machine object, if found.
        """
        ret = Machine(self._call_method('findMachine', name_or_id))
        return ret

    def get_machines_by_groups(self, groups):
        """Gets all machine references which are in one of the specified groups.
        :param typing.List[str] groups:
            What groups to match. The usual group list rules apply, i.e.
        passing an empty list will match VMs in the toplevel group, likewise
        the empty string.
        :rtype: typing.List[Machine]
        :returns:
            All machines which matched.
        """
        ret = Machine(self._call_method('getMachinesByGroups', groups))
        return ret

    def get_machine_states(self, machines):
        """Gets the state of several machines in a single operation.
        :param typing.List[Machine] machines:
            Array with the machine references.
        :rtype: typing.List[MachineState]
        :returns:
            Machine states, corresponding to the machines.
        """
        ret = MachineState(self._call_method('getMachineStates', machines))
        return ret

    def create_appliance(self):
        """Creates a new appliance object, which represents an appliance in the Open Virtual Machine
        Format (OVF). This can then be used to import an OVF appliance into VirtualBox or to export
        machines as an OVF appliance; see the documentation for
        :rtype: Appliance
        :returns:
            New appliance.
        """
        ret = Appliance(self._call_method('createAppliance'))
        return ret

    def create_unattended_installer(self):
        """Creates a new
        :rtype: Unattended
        :returns:
            New unattended object.
        """
        ret = Unattended(self._call_method('createUnattendedInstaller'))
        return ret

    def create_medium(self, format_, location, access_mode, a_device_type_type):
        """Creates a new base medium object that will use the given storage
        format and location for medium data.

        The actual storage unit is not created by this method. In order to
        do it, and before you are able to attach the created medium to
        virtual machines, you must call one of the following methods to
        allocate a format-specific storage unit at the specified location:
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
        ret = Medium(self._call_method('createMedium', format_, location, access_mode, a_device_type_type))
        return ret

    def open_medium(self, location, device_type, access_mode, force_new_uuid):
        """Finds existing media or opens a medium from an existing storage location.

        Once a medium has been opened, it can be passed to other VirtualBox
        methods, in particular to
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
        ret = Medium(self._call_method('openMedium', location, device_type, access_mode, force_new_uuid))
        return ret

    def get_guest_os_type(self, id_):
        """Returns an object describing the specified guest OS type.

        The requested guest OS type is specified using a string which is a
        mnemonic identifier of the guest operating system, such as
        :param str id_:
            Guest OS type ID string.
        :rtype: GuestOSType
        :returns:
            Guest OS type object.
        """
        ret = GuestOSType(self._call_method('getGuestOSType', id_))
        return ret

    def create_shared_folder(self, name, host_path, writable, automount):
        """Creates a new global shared folder by associating the given logical
        name with the given host path, adds it to the collection of shared
        folders and starts sharing it. Refer to the description of
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
        """Removes the global shared folder with the given name previously
        created by
        :param str name:
            Logical name of the shared folder to remove.
        """
        self._call_method('removeSharedFolder', name)

    def get_extra_data_keys(self):
        """Returns an array representing the global extra data keys which currently
        have values defined.
        :rtype: typing.List[str]
        :returns:
            Array of extra data keys.
        """
        ret = str(self._call_method('getExtraDataKeys'))
        return ret

    def get_extra_data(self, key):
        """Returns associated global extra data.

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
        """Sets associated global extra data.

        If you pass @c null or empty string as a key @a value, the given @a key
        will be deleted.
        :param str key:
            Name of the data key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setExtraData', key, value)

    def set_settings_secret(self, password):
        """Unlocks the secret data by passing the unlock password to the
        server. The server will cache the password for that machine.
        :param str password:
            The cipher key.
        """
        self._call_method('setSettingsSecret', password)

    def create_dhcp_server(self, name):
        """Creates a DHCP server settings to be used for the given internal network name
        :param str name:
            server name
        :rtype: DHCPServer
        :returns:
            DHCP server settings
        """
        ret = DHCPServer(self._call_method('createDHCPServer', name))
        return ret

    def find_dhcp_server_by_network_name(self, name):
        """Searches a DHCP server settings to be used for the given internal network name
        :param str name:
            server name
        :rtype: DHCPServer
        :returns:
            DHCP server settings
        """
        ret = DHCPServer(self._call_method('findDHCPServerByNetworkName', name))
        return ret

    def remove_dhcp_server(self, server):
        """Removes the DHCP server settings
        :param DHCPServer server:
            DHCP server settings to be removed
        """
        self._call_method('removeDHCPServer', server)

    def create_nat_network(self, network_name):
        """None
        :param str network_name:
        :rtype: NATNetwork
        """
        ret = NATNetwork(self._call_method('createNATNetwork', network_name))
        return ret

    def find_nat_network_by_name(self, network_name):
        """None
        :param str network_name:
        :rtype: NATNetwork
        """
        ret = NATNetwork(self._call_method('findNATNetworkByName', network_name))
        return ret

    def remove_nat_network(self, network):
        """None
        :param NATNetwork network:
        """
        self._call_method('removeNATNetwork', network)

    def check_firmware_present(self, firmware_type, version):
        """Check if this VirtualBox installation has a firmware
        of the given type available, either system-wide or per-user.
        Optionally, this may return a hint where this firmware can be
        downloaded from.
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
        """Updates the internal list of files/directories from the
      current directory level. Use
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('update'))
        return ret

    def cd(self, dir_):
        """Change the current directory level.
        :param str dir_:
            The name of the directory to go in.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('cd', dir_))
        return ret

    def cd_up(self):
        """Go one directory upwards from the current directory level.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('cdUp'))
        return ret

    def entry_list(self):
        """Returns a list of files/directories after a call to
        :rtype: typing.List[typing.Tuple[str, int, int, int]]
        """
        names, types, sizes, modes = self._call_method('entryList')
        return names, types, sizes, modes

    def exists(self, names):
        """Checks if the given file list exists in the current directory
      level.
        :param typing.List[str] names:
            The names to check.
        :rtype: typing.List[str]
        :returns:
            The names which exist.
        """
        ret = str(self._call_method('exists', names))
        return ret

    def remove(self, names):
        """Deletes the given files in the current directory level.
        :param typing.List[str] names:
            The names to remove.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('remove', names))
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
        """Tests if the certificate has expired at the present time according to
        the X.509 validity of the certificate.
        :rtype: bool
        """
        ret = bool(self._call_method('isCurrentlyExpired'))
        return ret

    def query_info(self, what):
        """Way to extend the interface.
        :param int what:
        :rtype: str
        """
        ret = str(self._call_method('queryInfo', what))
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
        """Reads an OVF file into the appliance object.

        This method succeeds if the OVF is syntactically valid and, by itself, without errors. The
        mere fact that this method returns successfully does not mean that VirtualBox supports all
        features requested by the appliance; this can only be examined after a call to
        :param str file_:
            Name of appliance file to open (either with an
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('read', file_))
        return ret

    def interpret(self):
        """Interprets the OVF data that was read when the appliance was constructed. After
        calling this method, one can inspect the
        """
        self._call_method('interpret')

    def import_machines(self, options):
        """Imports the appliance into VirtualBox by creating instances of
        :param typing.List[mportOptions] options:
            Options for the importing operation.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('importMachines', options))
        return ret

    def create_vfs_explorer(self, uri):
        """Returns a
        :param str uri:
            The URI describing the file system to use.
        :rtype: VFSExplorer
        """
        ret = VFSExplorer(self._call_method('createVFSExplorer', uri))
        return ret

    def write(self, format_, options, path):
        """Writes the contents of the appliance exports into a new OVF file.

          Calling this method is the final step of exporting an appliance from VirtualBox;
          see
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
        ret = Progress(self._call_method('write', format_, options, path))
        return ret

    def get_warnings(self):
        """Returns textual warnings which occurred during execution of
        :rtype: typing.List[str]
        """
        ret = str(self._call_method('getWarnings'))
        return ret

    def get_password_ids(self):
        """Returns a list of password identifiers which must be supplied to import or export
        encrypted virtual machines.
        :rtype: typing.List[str]
        :returns:
            The list of password identifiers required for export on success.
        """
        ret = str(self._call_method('getPasswordIds'))
        return ret

    def get_medium_ids_for_password_id(self, password_id):
        """Returns a list of medium identifiers which use the given password identifier.
        :param str password_id:
            The password identifier to get the medium identifiers for.
        :rtype: typing.List[str]
        :returns:
            The list of medium identifiers returned on success.
        """
        ret = str(self._call_method('getMediumIdsForPasswordId', password_id))
        return ret

    def add_passwords(self, identifiers, passwords):
        """Adds a list of passwords required to import or export encrypted virtual
        machines.
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
        """Returns information about the virtual system as arrays of instruction items. In each array, the
      items with the same indices correspond and jointly represent an import instruction for VirtualBox.

      The list below identifies the value sets that are possible depending on the
        :rtype: typing.List[typing.Tuple[VirtualSystemDescriptionType, str, str, str, str]]
        """
        types, refs, ovf_values, virtualbox_values, extra_config_values = self._call_method('getDescription')
        types = VirtualSystemDescriptionType(types)
        return types, refs, ovf_values, virtualbox_values, extra_config_values

    def get_description_by_type(self, type_):
        """This is the same as
        :param VirtualSystemDescriptionType type_:
        :rtype: typing.List[typing.Tuple[VirtualSystemDescriptionType, str, str, str, str]]
        """
        types, refs, ovf_values, virtualbox_values, extra_config_values = self._call_method('getDescriptionByType', type_)
        types = VirtualSystemDescriptionType(types)
        return types, refs, ovf_values, virtualbox_values, extra_config_values

    def get_values_by_type(self, type_, which):
        """This is the same as
        :param VirtualSystemDescriptionType type_:
        :param VirtualSystemDescriptionValueType which:
        :rtype: typing.List[str]
        """
        ret = str(self._call_method('getValuesByType', type_, which))
        return ret

    def set_final_values(self, enabled, virtualbox_values, extra_config_values):
        """This method allows the appliance's user to change the configuration for the virtual
        system descriptions. For each array item returned from
        :param typing.List[bool] enabled:
        :param typing.List[str] virtualbox_values:
        :param typing.List[str] extra_config_values:
        """
        self._call_method('setFinalValues', enabled, virtualbox_values, extra_config_values)

    def add_description(self, type_, virtualbox_value, extra_config_value):
        """This method adds an additional description entry to the stack of already
      available descriptions for this virtual system. This is handy for writing
      values which aren't directly supported by VirtualBox. One example would
      be the License type of
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
        """Detects the OS on the ISO given by
        """
        self._call_method('detectIsoOS')

    def prepare(self):
        """Prepare for running the unattended process of installation.

        This will instantiate the installer based on the guest type associated
        with the machine (see
        """
        self._call_method('prepare')

    def construct_media(self):
        """Constructors the necessary ISO/VISO/Floppy images, with unattended scripts
        and all necessary bits on them.
        """
        self._call_method('constructMedia')

    def reconfigure_vm(self):
        """Reconfigures the machine to start the installation.

        This involves mounting the ISOs and floppy images created by
        """
        self._call_method('reconfigureVM')

    def done(self):
        """Done - time to start the VM.

        This deletes the internal installer instance that
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
        """Updates the VM state.
        :param MachineState state:
        """
        self._call_method('updateState', state)

    def begin_power_up(self, progress):
        """Tells VBoxSVC that
        :param Progress progress:
        """
        self._call_method('beginPowerUp', progress)

    def end_power_up(self, result):
        """Tells VBoxSVC that
        :param int result:
        """
        self._call_method('endPowerUp', result)

    def begin_powering_down(self):
        """Called by the VM process to inform the server it wants to
        stop the VM execution and power down.
        :rtype: Progress
        :returns:
            Progress object created by VBoxSVC to wait until
          the VM is powered down.
        """
        ret = Progress(self._call_method('beginPoweringDown'))
        return ret

    def end_powering_down(self, result, err_msg):
        """Called by the VM process to inform the server that powering
        down previously requested by #beginPoweringDown is either
        successfully finished or there was a failure.
        :param int result:
            @c S_OK to indicate success.
        :param str err_msg:
            @c human readable error message in case of failure.
        """
        self._call_method('endPoweringDown', result, err_msg)

    def run_usb_device_filters(self, device):
        """Asks the server to run USB devices filters of the associated
        machine against the given USB device and tell if there is
        a match.
        :param USBDevice device:
        :rtype: typing.Tuple[bool, int]
        """
        matched, masked_interfaces = self._call_method('runUSBDeviceFilters', device)
        return matched, masked_interfaces

    def capture_usb_device(self, id_, capture_filename):
        """Requests a capture of the given host USB device.
        When the request is completed, the VM process will
        get a
        :param str id_:
        :param str capture_filename:
        """
        self._call_method('captureUSBDevice', id_, capture_filename)

    def detach_usb_device(self, id_, done):
        """Notification that a VM is going to detach (@a done = @c false) or has
        already detached (@a done = @c true) the given USB device.
        When the @a done = @c true request is completed, the VM process will
        get a
        :param str id_:
        :param bool done:
        """
        self._call_method('detachUSBDevice', id_, done)

    def auto_capture_usb_devices(self):
        """Requests a capture all matching USB devices attached to the host.
        When the request is completed, the VM process will
        get a
        """
        self._call_method('autoCaptureUSBDevices')

    def detach_all_usb_devices(self, done):
        """Notification that a VM that is being powered down. The done
        parameter indicates whether which stage of the power down
        we're at. When @a done = @c false the VM is announcing its
        intentions, while when @a done = @c true the VM is reporting
        what it has done.
        :param bool done:
        """
        self._call_method('detachAllUSBDevices', done)

    def on_session_end(self, session):
        """Triggered by the given session object when the session is about
        to close normally.
        :param Session session:
            Session that is being closed
        :rtype: Progress
        :returns:
            Used to wait until the corresponding machine is actually
          dissociated from the given session on the server.
          Returned only when this session is a direct one.
        """
        ret = Progress(self._call_method('onSessionEnd', session))
        return ret

    def finish_online_merge_medium(self):
        """Gets called by
        """
        self._call_method('finishOnlineMergeMedium')

    def pull_guest_properties(self):
        """Get the list of the guest properties matching a set of patterns along
        with their values, time stamps and flags and give responsibility for
        managing properties to the console.
        :rtype: typing.List[typing.Tuple[str, str, int, str]]
        """
        names, values, timestamps, flags = self._call_method('pullGuestProperties')
        return names, values, timestamps, flags

    def push_guest_property(self, name, value, timestamp, flags):
        """Update a single guest property in IMachine.
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
        """Locks all media attached to the machine for writing and parents of
        attached differencing media (if any) for reading. This operation is
        atomic so that if it fails no media is actually locked.

        This method is intended to be called when the machine is in Starting or
        Restoring state. The locked media will be automatically unlocked when
        the machine is powered off or crashed.
        """
        self._call_method('lockMedia')

    def unlock_media(self):
        """Unlocks all media previously locked using
        """
        self._call_method('unlockMedia')

    def eject_medium(self, attachment):
        """Tells VBoxSVC that the guest has ejected the medium associated with
        the medium attachment.
        :param MediumAttachment attachment:
            The medium attachment where the eject happened.
        :rtype: MediumAttachment
        :returns:
            A new reference to the medium attachment, as the config change can
          result in the creation of a new instance.
        """
        ret = MediumAttachment(self._call_method('ejectMedium', attachment))
        return ret

    def report_vm_statistics(self, valid_stats, cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total, vm_net_rx, vm_net_tx):
        """Passes statistics collected by VM (including guest statistics) to VBoxSVC.
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
        """Verify credentials using the external auth library.
        :param typing.List[str] auth_params:
            The auth parameters, credentials, etc.
        :rtype: str
        :returns:
            The authentification result.
        """
        ret = str(self._call_method('authenticateExternal', auth_params))
        return ret


class PCIAddress(Interface):
    """Address on the PCI bus.
    """
    def as_long(self):
        """Convert PCI address into long.
        :rtype: int
        """
        ret = int(self._call_method('asLong'))
        return ret

    def from_long(self, number):
        """Make PCI address from long.
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


class EmulatedUSB(Interface):
    """Manages emulated USB devices.
    """
    def webcam_attach(self, path, settings):
        """Attaches the emulated USB webcam to the VM, which will use a host video capture device.
        :param str path:
            The host path of the capture device to use.
        :param str settings:
            Optional settings.
        """
        self._call_method('webcamAttach', path, settings)

    def webcam_detach(self, path):
        """Detaches the emulated USB webcam from the VM
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


class Console(Interface):
    """The IConsole interface represents an interface to control virtual
      machine execution.

      A console object gets created when a machine has been locked for a
      particular session (client process) using
    """
    def power_up(self):
        """Starts the virtual machine execution using the current machine
        state (that is, its current execution state, current settings and
        current storage devices).
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('powerUp'))
        return ret

    def power_up_paused(self):
        """Identical to powerUp except that the VM will enter the
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('powerUpPaused'))
        return ret

    def power_down(self):
        """Initiates the power down procedure to stop the virtual machine
        execution.

        The completion of the power down procedure is tracked using the returned
        IProgress object. After the operation is complete, the machine will go
        to the PoweredOff state.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('powerDown'))
        return ret

    def reset(self):
        """Resets the virtual machine.
        """
        self._call_method('reset')

    def pause(self):
        """Pauses the virtual machine execution.
        """
        self._call_method('pause')

    def resume(self):
        """Resumes the virtual machine execution.
        """
        self._call_method('resume')

    def power_button(self):
        """Sends the ACPI power button event to the guest.
        """
        self._call_method('powerButton')

    def sleep_button(self):
        """Sends the ACPI sleep button event to the guest.
        """
        self._call_method('sleepButton')

    def get_power_button_handled(self):
        """Checks if the last power button event was handled by guest.
        :rtype: bool
        """
        ret = bool(self._call_method('getPowerButtonHandled'))
        return ret

    def get_guest_entered_acpi_mode(self):
        """Checks if the guest entered the ACPI mode G0 (working) or
        G1 (sleeping). If this method returns @c false, the guest will
        most likely not respond to external ACPI events.
        :rtype: bool
        """
        ret = bool(self._call_method('getGuestEnteredACPIMode'))
        return ret

    def get_device_activity(self, type_):
        """Gets the current activity type of given devices or device groups.
        :param typing.List[DeviceType] type_:
        :rtype: typing.List[DeviceActivity]
        """
        ret = DeviceActivity(self._call_method('getDeviceActivity', type_))
        return ret

    def attach_usb_device(self, id_, capture_filename):
        """Attaches a host USB device with the given UUID to the
        USB controller of the virtual machine.

        The device needs to be in one of the following states:
        :param str id_:
            UUID of the host USB device to attach.
        :param str capture_filename:
            Filename to capture the USB traffic to.
        """
        self._call_method('attachUSBDevice', id_, capture_filename)

    def detach_usb_device(self, id_):
        """Detaches an USB device with the given UUID from the USB controller
        of the virtual machine.

        After this method succeeds, the VirtualBox server re-initiates
        all USB filters as if the device were just physically attached
        to the host, but filters of this machine are ignored to avoid
        a possible automatic re-attachment.
        :param str id_:
            UUID of the USB device to detach.
        :rtype: USBDevice
        :returns:
            Detached USB device.
        """
        ret = USBDevice(self._call_method('detachUSBDevice', id_))
        return ret

    def find_usb_device_by_address(self, name):
        """Searches for a USB device with the given host address.
        :param str name:
            Address of the USB device (as assigned by the host) to
          search for.
        :rtype: USBDevice
        :returns:
            Found USB device object.
        """
        ret = USBDevice(self._call_method('findUSBDeviceByAddress', name))
        return ret

    def find_usb_device_by_id(self, id_):
        """Searches for a USB device with the given UUID.
        :param str id_:
            UUID of the USB device to search for.
        :rtype: USBDevice
        :returns:
            Found USB device object.
        """
        ret = USBDevice(self._call_method('findUSBDeviceById', id_))
        return ret

    def create_shared_folder(self, name, host_path, writable, automount):
        """Creates a transient new shared folder by associating the given logical
        name with the given host path, adds it to the collection of shared
        folders and starts sharing it. Refer to the description of
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
        """Removes a transient shared folder with the given name previously
        created by
        :param str name:
            Logical name of the shared folder to remove.
        """
        self._call_method('removeSharedFolder', name)

    def teleport(self, hostname, tcpport, password, max_downtime):
        """Teleport the VM to a different host machine or process.

        @todo Explain the details.
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
        ret = Progress(self._call_method('teleport', hostname, tcpport, password, max_downtime))
        return ret

    def add_disk_encryption_password(self, id_, password, clear_on_suspend):
        """Adds a password used for hard disk encryption/decryption.
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
        """Adds a password used for hard disk encryption/decryption.
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
        """Removes a password used for hard disk encryption/decryption from
        the running VM. As soon as the medium requiring this password
        is accessed the VM is paused with an error and the password must be
        provided again.
        :param str id_:
            The identifier used for the password. Must match the identifier
          used when the encrypted medium was created.
        """
        self._call_method('removeDiskEncryptionPassword', id_)

    def clear_all_disk_encryption_passwords(self):
        """Clears all provided supplied disk encryption passwords.
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
        """sets and enables the static IP V4 configuration for the given interface.
        :param str ip_address:
            IP address.
        :param str network_mask:
            network mask.
        """
        self._call_method('enableStaticIPConfig', ip_address, network_mask)

    def enable_static_ip_config_v6(self, ipv6_address, ipv6_network_mask_prefix_length):
        """sets and enables the static IP V6 configuration for the given interface.
        :param str ipv6_address:
            IP address.
        :param int ipv6_network_mask_prefix_length:
            network mask.
        """
        self._call_method('enableStaticIPConfigV6', ipv6_address, ipv6_network_mask_prefix_length)

    def enable_dynamic_ip_config(self):
        """enables the dynamic IP configuration.
        """
        self._call_method('enableDynamicIPConfig')

    def dhcp_rediscover(self):
        """refreshes the IP configuration for DHCP-enabled interface.
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


class Host(Interface):
    """The IHost interface represents the physical machine that this VirtualBox
      installation runs on.

      An object implementing this interface is returned by the
    """
    def get_processor_speed(self, cpu_id):
        """Query the (approximate) maximum speed of a specified host CPU in
        Megahertz.
        :param int cpu_id:
            Identifier of the CPU.
        :rtype: int
        :returns:
            Speed value. 0 is returned if value is not known or @a cpuId is
          invalid.
        """
        ret = int(self._call_method('getProcessorSpeed', cpu_id))
        return ret

    def get_processor_feature(self, feature):
        """Query whether a CPU feature is supported or not.
        :param ProcessorFeature feature:
            CPU Feature identifier.
        :rtype: bool
        :returns:
            Feature is supported or not.
        """
        ret = bool(self._call_method('getProcessorFeature', feature))
        return ret

    def get_processor_description(self, cpu_id):
        """Query the model string of a specified host CPU.
        :param int cpu_id:
            Identifier of the CPU.
        :rtype: str
        :returns:
            Model string. An empty string is returned if value is not known or
          @a cpuId is invalid.
        """
        ret = str(self._call_method('getProcessorDescription', cpu_id))
        return ret

    def get_processor_cpuid_leaf(self, cpu_id, leaf, sub_leaf):
        """Returns the CPU cpuid information for the specified leaf.
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
        """Creates a new adapter for Host Only Networking.
        :rtype: typing.Tuple[Progress, HostNetworkInterface]
        """
        progress, host_interface = self._call_method('createHostOnlyNetworkInterface')
        progress = Progress(progress)
        host_interface = HostNetworkInterface(host_interface)
        return progress, host_interface

    def remove_host_only_network_interface(self, id_):
        """Removes the given Host Only Networking interface.
        :param str id_:
            Adapter GUID.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('removeHostOnlyNetworkInterface', id_))
        return ret

    def create_usb_device_filter(self, name):
        """Creates a new USB device filter. All attributes except
        the filter name are set to empty (any match),
        :param str name:
            Filter name. See
        :rtype: HostUSBDeviceFilter
        :returns:
            Created filter object.
        """
        ret = HostUSBDeviceFilter(self._call_method('createUSBDeviceFilter', name))
        return ret

    def insert_usb_device_filter(self, position, filter_):
        """Inserts the given USB device to the specified position
        in the list of filters.

        Positions are numbered starting from @c 0. If the specified
        position is equal to or greater than the number of elements in
        the list, the filter is added at the end of the collection.
        :param int position:
            Position to insert the filter to.
        :param HostUSBDeviceFilter filter_:
            USB device filter to insert.
        """
        self._call_method('insertUSBDeviceFilter', position, filter_)

    def remove_usb_device_filter(self, position):
        """Removes a USB device filter from the specified position in the
        list of filters.

        Positions are numbered starting from @c 0. Specifying a
        position equal to or greater than the number of elements in
        the list will produce an error.
        :param int position:
            Position to remove the filter from.
        """
        self._call_method('removeUSBDeviceFilter', position)

    def find_host_dvd_drive(self, name):
        """Searches for a host DVD drive with the given @c name.
        :param str name:
            Name of the host drive to search for
        :rtype: Medium
        :returns:
            Found host drive object
        """
        ret = Medium(self._call_method('findHostDVDDrive', name))
        return ret

    def find_host_floppy_drive(self, name):
        """Searches for a host floppy drive with the given @c name.
        :param str name:
            Name of the host floppy drive to search for
        :rtype: Medium
        :returns:
            Found host floppy drive object
        """
        ret = Medium(self._call_method('findHostFloppyDrive', name))
        return ret

    def find_host_network_interface_by_name(self, name):
        """Searches through all host network interfaces for an interface with
        the given @c name.
        :param str name:
            Name of the host network interface to search for.
        :rtype: HostNetworkInterface
        :returns:
            Found host network interface object.
        """
        ret = HostNetworkInterface(self._call_method('findHostNetworkInterfaceByName', name))
        return ret

    def find_host_network_interface_by_id(self, id_):
        """Searches through all host network interfaces for an interface with
        the given GUID.
        :param str id_:
            GUID of the host network interface to search for.
        :rtype: HostNetworkInterface
        :returns:
            Found host network interface object.
        """
        ret = HostNetworkInterface(self._call_method('findHostNetworkInterfaceById', id_))
        return ret

    def find_host_network_interfaces_of_type(self, type_):
        """Searches through all host network interfaces and returns a list of interfaces of the specified type
        :param HostNetworkInterfaceType type_:
            type of the host network interfaces to search for.
        :rtype: typing.List[HostNetworkInterface]
        :returns:
            Found host network interface objects.
        """
        ret = HostNetworkInterface(self._call_method('findHostNetworkInterfacesOfType', type_))
        return ret

    def find_usb_device_by_id(self, id_):
        """Searches for a USB device with the given UUID.
        :param str id_:
            UUID of the USB device to search for.
        :rtype: HostUSBDevice
        :returns:
            Found USB device object.
        """
        ret = HostUSBDevice(self._call_method('findUSBDeviceById', id_))
        return ret

    def find_usb_device_by_address(self, name):
        """Searches for a USB device with the given host address.
        :param str name:
            Address of the USB device (as assigned by the host) to
          search for.
        :rtype: HostUSBDevice
        :returns:
            Found USB device object.
        """
        ret = HostUSBDevice(self._call_method('findUSBDeviceByAddress', name))
        return ret

    def generate_mac_address(self):
        """Generates a valid Ethernet MAC address, 12 hexadecimal characters.
        :rtype: str
        :returns:
            New Ethernet MAC address.
        """
        ret = str(self._call_method('generateMACAddress'))
        return ret

    def add_usb_device_source(self, backend, id_, address, property_names, property_values):
        """Adds a new USB device source.
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
        """Removes a previously added USB device source.
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
        """Maximum total number of network adapters associated with every
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :rtype: int
        :returns:
            The maximum total number of network adapters allowed.
        """
        ret = int(self._call_method('getMaxNetworkAdapters', chipset))
        return ret

    def get_max_network_adapters_of_type(self, chipset, type_):
        """Maximum number of network adapters of a given attachment type,
        associated with every
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :param NetworkAttachmentType type_:
            Type of attachment.
        :rtype: int
        :returns:
            The maximum number of network adapters allowed for
          particular chipset and attachment type.
        """
        ret = int(self._call_method('getMaxNetworkAdaptersOfType', chipset, type_))
        return ret

    def get_max_devices_per_port_for_storage_bus(self, bus):
        """Returns the maximum number of devices which can be attached to a port
      for the given storage bus.
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The maximum number of devices which can be attached to the port for the given
        storage bus.
        """
        ret = int(self._call_method('getMaxDevicesPerPortForStorageBus', bus))
        return ret

    def get_min_port_count_for_storage_bus(self, bus):
        """Returns the minimum number of ports the given storage bus supports.
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The minimum number of ports for the given storage bus.
        """
        ret = int(self._call_method('getMinPortCountForStorageBus', bus))
        return ret

    def get_max_port_count_for_storage_bus(self, bus):
        """Returns the maximum number of ports the given storage bus supports.
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The maximum number of ports for the given storage bus.
        """
        ret = int(self._call_method('getMaxPortCountForStorageBus', bus))
        return ret

    def get_max_instances_of_storage_bus(self, chipset, bus):
        """Returns the maximum number of storage bus instances which
        can be configured for each VM. This corresponds to the number of
        storage controllers one can have. Value may depend on chipset type
        used.
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: int
        :returns:
            The maximum number of instances for the given storage bus.
        """
        ret = int(self._call_method('getMaxInstancesOfStorageBus', chipset, bus))
        return ret

    def get_device_types_for_storage_bus(self, bus):
        """Returns list of all the supported device types
        (
        :param StorageBus bus:
            The storage bus type to get the value for.
        :rtype: typing.List[DeviceType]
        :returns:
            The list of all supported device types for the given storage bus.
        """
        ret = DeviceType(self._call_method('getDeviceTypesForStorageBus', bus))
        return ret

    def get_default_io_cache_setting_for_storage_controller(self, controller_type):
        """Returns the default I/O cache setting for the
        given storage controller
        :param StorageControllerType controller_type:
            The storage controller type to get the setting for.
        :rtype: bool
        :returns:
            Returned flag indicating the default value
        """
        ret = bool(self._call_method('getDefaultIoCacheSettingForStorageController', controller_type))
        return ret

    def get_storage_controller_hotplug_capable(self, controller_type):
        """Returns whether the given storage controller supports
        hot-plugging devices.
        :param StorageControllerType controller_type:
            The storage controller to check the setting for.
        :rtype: bool
        :returns:
            Returned flag indicating whether the controller is hotplug capable
        """
        ret = bool(self._call_method('getStorageControllerHotplugCapable', controller_type))
        return ret

    def get_max_instances_of_usb_controller_type(self, chipset, type_):
        """Returns the maximum number of USB controller instances which
        can be configured for each VM. This corresponds to the number of
        USB controllers one can have. Value may depend on chipset type
        used.
        :param ChipsetType chipset:
            The chipset type to get the value for.
        :param USBControllerType type_:
            The USB controller type to get the value for.
        :rtype: int
        :returns:
            The maximum number of instances for the given USB controller type.
        """
        ret = int(self._call_method('getMaxInstancesOfUSBControllerType', chipset, type_))
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
        """Checks if a specific drag'n drop MIME / Content-type format is supported.
        :param str format_:
            Format to check for.
        :rtype: bool
        :returns:
            Returns @c true if the specified format is supported, @c false if not.
        """
        ret = bool(self._call_method('isFormatSupported', format_))
        return ret

    def add_formats(self, formats):
        """Adds MIME / Content-type formats to the supported formats.
        :param typing.List[str] formats:
            Collection of formats to add.
        """
        self._call_method('addFormats', formats)

    def remove_formats(self, formats):
        """Removes MIME / Content-type formats from the supported formats.
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
        """Ask the source if there is any drag and drop operation pending.
        If no drag and drop operation is pending currently, DnDAction_Ignore is returned.
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        :rtype: typing.Tuple[DnDAction, typing.List[str], typing.List[DnDAction]]
        """
        default_action, formats, allowed_actions = self._call_method('dragIsPending', screen_id)
        default_action = DnDAction(default_action)
        allowed_actions = DnDAction(allowed_actions)
        return default_action, formats, allowed_actions

    def drop(self, format_, action):
        """Informs the source that a drop event occurred for a pending
        drag and drop operation.
        :param str format_:
            The mime type the data must be in.
        :param DnDAction action:
            The action to use.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('drop', format_, action))
        return ret

    def receive_data(self):
        """Receive the data of a previously drag and drop event from the source.
        :rtype: typing.List[bytes]
        :returns:
            The actual data.
        """
        ret = bytes(self._call_method('receiveData'))
        return ret


class DnDTarget(DnDBase):
    """Abstract interface for handling drag'n drop targets.
    """
    def enter(self, screen_id, y, x, default_action, allowed_actions, formats):
        """Informs the target about a drag and drop enter event.
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
        ret = DnDAction(self._call_method('enter', screen_id, y, x, default_action, allowed_actions, formats))
        return ret

    def move(self, screen_id, x, y, default_action, allowed_actions, formats):
        """Informs the target about a drag and drop move event.
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
        ret = DnDAction(self._call_method('move', screen_id, x, y, default_action, allowed_actions, formats))
        return ret

    def leave(self, screen_id):
        """Informs the target about a drag and drop leave event.
        :param int screen_id:
            The screen ID where the drag and drop event occurred.
        """
        self._call_method('leave', screen_id)

    def drop(self, screen_id, x, y, default_action, allowed_actions, formats):
        """Informs the target about a drop event.
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
        """Initiates sending data to the target.
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
        ret = Progress(self._call_method('sendData', screen_id, format_, data))
        return ret

    def cancel(self):
        """Requests cancelling the current operation. The target can veto
        the request in case the operation is not cancelable at the moment.
        :rtype: bool
        :returns:
            Whether the target has vetoed cancelling the operation.
        """
        ret = bool(self._call_method('cancel'))
        return ret


class GuestSession(Interface):
    """A guest session represents one impersonated user account in the guest, so
      every operation will use the same credentials specified when creating
      the session object via
    """
    def close(self):
        """Closes this session. All opened guest directories, files and
        processes which are not referenced by clients anymore will be
        closed. Guest processes which fall into this category and still
        are running in the guest will be terminated automatically.
        """
        self._call_method('close')

    def directory_copy(self, source, destination, flags):
        """Recursively copies a directory from one guest location to another.
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
        ret = Progress(self._call_method('directoryCopy', source, destination, flags))
        return ret

    def directory_copy_from_guest(self, source, destination, flags):
        """Recursively copies a directory from the guest to the host.
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
        ret = Progress(self._call_method('directoryCopyFromGuest', source, destination, flags))
        return ret

    def directory_copy_to_guest(self, source, destination, flags):
        """Recursively copies a directory from the host to the guest.
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
        ret = Progress(self._call_method('directoryCopyToGuest', source, destination, flags))
        return ret

    def directory_create(self, path, mode, flags):
        """Creates a directory in the guest.
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
        """Creates a temporary directory in the guest.
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
        ret = str(self._call_method('directoryCreateTemp', template_name, mode, path, secure))
        return ret

    def directory_exists(self, path, follow_symlinks):
        """Checks whether a directory exists in the guest or not.
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
        ret = bool(self._call_method('directoryExists', path, follow_symlinks))
        return ret

    def directory_open(self, path, filter_, flags):
        """Opens a directory in the guest and creates a
        :param str path:
            Path to the directory to open. Guest path style.
        :param str filter_:
            Optional directory listing filter to apply.  This uses the DOS/NT
          style wildcard characters '?' and '*'.
        :param typing.List[DirectoryOpenFlag] flags:
            Zero or more
        :rtype: GuestDirectory
        """
        ret = GuestDirectory(self._call_method('directoryOpen', path, filter_, flags))
        return ret

    def directory_remove(self, path):
        """Removes a guest directory if empty.
        :param str path:
            Path to the directory that should be removed. Guest path style.
        """
        self._call_method('directoryRemove', path)

    def directory_remove_recursive(self, path, flags):
        """Removes a guest directory recursively.
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
        ret = Progress(self._call_method('directoryRemoveRecursive', path, flags))
        return ret

    def environment_schedule_set(self, name, value):
        """Schedules setting an environment variable when creating the next guest
        process.  This affects the
        :param str name:
            Name of the environment variable to set.  This cannot be empty
          nor can it contain any equal signs.
        :param str value:
            Value to set the session environment variable to.
        """
        self._call_method('environmentScheduleSet', name, value)

    def environment_schedule_unset(self, name):
        """Schedules unsetting (removing) an environment variable when creating
        the next guest process.  This affects the
        :param str name:
            Name of the environment variable to unset.  This cannot be empty
          nor can it contain any equal signs.
        """
        self._call_method('environmentScheduleUnset', name)

    def environment_get_base_variable(self, name):
        """Gets an environment variable from the session's base environment
        (
        :param str name:
            Name of the environment variable to   get.This cannot be empty
          nor can it contain any equal signs.
        :rtype: str
        :returns:
            The value of the variable.  Empty if not found.  To deal with
          variables that may have empty values, use
        """
        ret = str(self._call_method('environmentGetBaseVariable', name))
        return ret

    def environment_does_base_variable_exist(self, name):
        """Checks if the given environment variable exists in the session's base
        environment (
        :param str name:
            Name of the environment variable to look for.  This cannot be
          empty nor can it contain any equal signs.
        :rtype: bool
        :returns:
            TRUE if the variable exists, FALSE if not.
        """
        ret = bool(self._call_method('environmentDoesBaseVariableExist', name))
        return ret

    def file_copy(self, source, destination, flags):
        """Copies a file from one guest location to another.
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
        ret = Progress(self._call_method('fileCopy', source, destination, flags))
        return ret

    def file_copy_from_guest(self, source, destination, flags):
        """Copies a file from the guest to the host.
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
        ret = Progress(self._call_method('fileCopyFromGuest', source, destination, flags))
        return ret

    def file_copy_to_guest(self, source, destination, flags):
        """Copies a file from the host to the guest.
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
        ret = Progress(self._call_method('fileCopyToGuest', source, destination, flags))
        return ret

    def file_create_temp(self, template_name, mode, path, secure):
        """Creates a temporary file in the guest.
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
        ret = GuestFile(self._call_method('fileCreateTemp', template_name, mode, path, secure))
        return ret

    def file_exists(self, path, follow_symlinks):
        """Checks whether a regular file exists in the guest or not.
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
        ret = bool(self._call_method('fileExists', path, follow_symlinks))
        return ret

    def file_open(self, path, access_mode, open_action, creation_mode):
        """Opens a file and creates a
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
        ret = GuestFile(self._call_method('fileOpen', path, access_mode, open_action, creation_mode))
        return ret

    def file_open_ex(self, path, access_mode, open_action, sharing_mode, creation_mode, flags):
        """Opens a file and creates a
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
        ret = GuestFile(self._call_method('fileOpenEx', path, access_mode, open_action, sharing_mode, creation_mode, flags))
        return ret

    def file_query_size(self, path, follow_symlinks):
        """Queries the size of a regular file in the guest.
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
        ret = int(self._call_method('fileQuerySize', path, follow_symlinks))
        return ret

    def fs_obj_exists(self, path, follow_symlinks):
        """Checks whether a file system object (file, directory, etc) exists in
        the guest or not.
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
        ret = bool(self._call_method('fsObjExists', path, follow_symlinks))
        return ret

    def fs_obj_query_info(self, path, follow_symlinks):
        """Queries information about a file system object (file, directory, etc)
        in the guest.
        :param str path:
            Path to the file system object to gather information about.
          Guest path style.
        :param bool follow_symlinks:
            Information about symbolic links is returned if @c false.  Otherwise,
           symbolic links are followed and the returned information concerns
           itself with the symlink target if @c true.
        :rtype: GuestFsObjInfo
        """
        ret = GuestFsObjInfo(self._call_method('fsObjQueryInfo', path, follow_symlinks))
        return ret

    def fs_obj_remove(self, path):
        """Removes a file system object (file, symlink, etc) in the guest.  Will
        not work on directories, use
        :param str path:
            Path to the file system object to remove.  Guest style path.
        """
        self._call_method('fsObjRemove', path)

    def fs_obj_rename(self, old_path, new_path, flags):
        """Renames a file system object (file, directory, symlink, etc) in the
        guest.
        :param str old_path:
            The current path to the object.  Guest path style.
        :param str new_path:
            The new path to the object.  Guest path style.
        :param typing.List[FsObjRenameFlag] flags:
            Zero or more
        """
        self._call_method('fsObjRename', old_path, new_path, flags)

    def fs_obj_move(self, source, destination, flags):
        """Moves a file system object (file, directory, symlink, etc) from one
        guest location to another.

        This differs from
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
        ret = Progress(self._call_method('fsObjMove', source, destination, flags))
        return ret

    def fs_obj_set_acl(self, path, follow_symlinks, acl, mode):
        """Sets the access control list (ACL) of a file system object (file,
        directory, etc) in the guest.
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
        """Creates a new process running in the guest. The new process will be
        started asynchronously, meaning on return of this function it is not
        be guaranteed that the guest process is in a started state. To wait for
        successful startup, use the
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
        ret = GuestProcess(self._call_method('processCreate', executable, arguments, environment_changes, flags, timeout_ms))
        return ret

    def process_create_ex(self, executable, arguments, environment_changes, flags, timeout_ms, priority, affinity):
        """Creates a new process running in the guest with the extended options
        for setting the process priority and affinity.

        See
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
        ret = GuestProcess(self._call_method('processCreateEx', executable, arguments, environment_changes, flags, timeout_ms, priority, affinity))
        return ret

    def process_get(self, pid):
        """Gets a certain guest process by its process ID (PID).
        :param int pid:
            Process ID (PID) to get guest process for.
        :rtype: GuestProcess
        :returns:
            Guest process of specified process ID (PID).
        """
        ret = GuestProcess(self._call_method('processGet', pid))
        return ret

    def symlink_create(self, symlink, target, type_):
        """Creates a symbolic link in the guest.
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
        """Checks whether a symbolic link exists in the guest.
        :param str symlink:
            Path to the alleged symbolic link.  Guest path style.
        :rtype: bool
        :returns:
            Returns @c true if the symbolic link exists.  Returns @c false if it
          does not exist, if the file system object identified by the path is
          not a symbolic link, or if the object type is inaccessible to the
          user, or if the @a symlink argument is empty.
        """
        ret = bool(self._call_method('symlinkExists', symlink))
        return ret

    def symlink_read(self, symlink, flags):
        """Reads the target value of a symbolic link in the guest.
        :param str symlink:
            Path to the symbolic link to read.
        :param typing.List[SymlinkReadFlag] flags:
            Zero or more
        :rtype: str
        :returns:
            Target value of the symbolic link.  Guest path style.
        """
        ret = str(self._call_method('symlinkRead', symlink, flags))
        return ret

    def wait_for(self, wait_for, timeout_ms):
        """Waits for one or more events to happen.
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
        ret = GuestSessionWaitResult(self._call_method('waitFor', wait_for, timeout_ms))
        return ret

    def wait_for_array(self, wait_for, timeout_ms):
        """Waits for one or more events to happen.
        Scriptable version of
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
        ret = GuestSessionWaitResult(self._call_method('waitForArray', wait_for, timeout_ms))
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
        """Waits for one or more events to happen.
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
        ret = ProcessWaitResult(self._call_method('waitFor', wait_for, timeout_ms))
        return ret

    def wait_for_array(self, wait_for, timeout_ms):
        """Waits for one or more events to happen.
        Scriptable version of
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
        ret = ProcessWaitResult(self._call_method('waitForArray', wait_for, timeout_ms))
        return ret

    def read(self, handle, to_read, timeout_ms):
        """Reads data from a running process.
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
        ret = bytes(self._call_method('read', handle, to_read, timeout_ms))
        return ret

    def write(self, handle, flags, data, timeout_ms):
        """Writes data to a running process.
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
        ret = int(self._call_method('write', handle, flags, data, timeout_ms))
        return ret

    def write_array(self, handle, flags, data, timeout_ms):
        """Writes data to a running process.
        Scriptable version of
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
        ret = int(self._call_method('writeArray', handle, flags, data, timeout_ms))
        return ret

    def terminate(self):
        """Terminates (kills) a running process.
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


class Directory(Interface):
    """Abstract parent interface for directories handled by VirtualBox.
    """
    def close(self):
        """Closes this directory. After closing operations like reading the next
        directory entry will not be possible anymore.
        """
        self._call_method('close')

    def read(self):
        """Reads the next directory entry of this directory.
        :rtype: FsObjInfo
        :returns:
            Object information of the current directory entry read. Also see
        """
        ret = FsObjInfo(self._call_method('read'))
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


class File(Interface):
    """Abstract parent interface for files handled by VirtualBox.
    """
    def close(self):
        """Closes this file. After closing operations like reading data,
        writing data or querying information will not be possible anymore.
        """
        self._call_method('close')

    def query_info(self):
        """Queries information about this file.
        :rtype: FsObjInfo
        :returns:
            Object information of this file. Also see
        """
        ret = FsObjInfo(self._call_method('queryInfo'))
        return ret

    def query_size(self):
        """Queries the current file size.
        :rtype: int
        :returns:
            Queried file size.
        """
        ret = int(self._call_method('querySize'))
        return ret

    def read(self, to_read, timeout_ms):
        """Reads data from this file.
        :param int to_read:
            Number of bytes to read.
        :param int timeout_ms:
            Timeout (in ms) to wait for the operation to complete.
          Pass 0 for an infinite timeout.
        :rtype: typing.List[bytes]
        :returns:
            Array of data read.
        """
        ret = bytes(self._call_method('read', to_read, timeout_ms))
        return ret

    def read_at(self, offset, to_read, timeout_ms):
        """Reads data from an offset of this file.
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
        ret = bytes(self._call_method('readAt', offset, to_read, timeout_ms))
        return ret

    def seek(self, offset, whence):
        """Changes the current file position of this file.

        The file current position always applies to the
        :param int offset:
            Offset to seek relative to the position specified by @a whence.
        :param FileSeekOrigin whence:
            One of the
        :rtype: int
        :returns:
            The new file offset after the seek operation.
        """
        ret = int(self._call_method('seek', offset, whence))
        return ret

    def set_acl(self, acl, mode):
        """Sets the ACL of this file.
        :param str acl:
            The ACL specification string. To-be-defined.
        :param int mode:
            UNIX-style mode mask to use if @a acl is empty. As mention in
        """
        self._call_method('setACL', acl, mode)

    def set_size(self, size):
        """Changes the file size.
        :param int size:
            The new file size.
        """
        self._call_method('setSize', size)

    def write(self, data, timeout_ms):
        """Writes bytes to this file.
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
        ret = int(self._call_method('write', data, timeout_ms))
        return ret

    def write_at(self, offset, data, timeout_ms):
        """Writes bytes at a certain offset to this file.
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
        ret = int(self._call_method('writeAt', offset, data, timeout_ms))
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


class Guest(Interface):
    """The IGuest interface represents information about the operating system
      running inside the virtual machine. Used in
    """
    def internal_get_statistics(self):
        """Internal method; do not use as it might change at any time.
        :rtype: typing.Tuple[int, int, int, int, int, int, int, int, int, int, int, int, int]
        """
        cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total = self._call_method('internalGetStatistics')
        return cpu_user, cpu_kernel, cpu_idle, mem_total, mem_free, mem_balloon, mem_shared, mem_cache, paged_total, mem_alloc_total, mem_free_total, mem_balloon_total, mem_shared_total

    def get_facility_status(self, facility):
        """Get the current status of a Guest Additions facility.
        :param AdditionsFacilityType facility:
            Facility to check status for.
        :rtype: typing.Tuple[AdditionsFacilityStatus, int]
        """
        status, timestamp = self._call_method('getFacilityStatus', facility)
        status = AdditionsFacilityStatus(status)
        return status, timestamp

    def get_additions_status(self, level):
        """Retrieve the current status of a certain Guest Additions run level.
        :param AdditionsRunLevelType level:
            Status level to check
        :rtype: bool
        :returns:
            Flag whether the status level has been reached or not
        """
        ret = bool(self._call_method('getAdditionsStatus', level))
        return ret

    def set_credentials(self, user_name, password, domain, allow_interactive_logon):
        """Store login credentials that can be queried by guest operating
        systems with Additions installed. The credentials are transient
        to the session and the guest may also choose to erase them. Note
        that the caller cannot determine whether the guest operating system
        has queried or made use of the credentials.
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
        """Creates a new guest session for controlling the guest. The new session
        will be started asynchronously, meaning on return of this function it is
        not guaranteed that the guest session is in a started and/or usable state.
        To wait for successful startup, use the
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
        ret = GuestSession(self._call_method('createSession', user, password, domain, session_name))
        return ret

    def find_session(self, session_name):
        """Finds guest sessions by their friendly name and returns an interface
        array with all found guest sessions.
        :param str session_name:
            The session's friendly name to find. Wildcards like ? and * are allowed.
        :rtype: typing.List[GuestSession]
        :returns:
            Array with all guest sessions found matching the name specified.
        """
        ret = GuestSession(self._call_method('findSession', session_name))
        return ret

    def update_guest_additions(self, source, arguments, flags):
        """Automatically updates already installed Guest Additions in a VM.

        At the moment only Windows guests are supported.

        Because the VirtualBox Guest Additions drivers are not WHQL-certified
        yet there might be warning dialogs during the actual Guest Additions
        update. These need to be confirmed manually in order to continue the
        installation process. This applies to Windows 2000 and Windows XP guests
        and therefore these guests can't be updated in a fully automated fashion
        without user interaction. However, to start a Guest Additions update for
        the mentioned Windows versions anyway, the flag
        AdditionsUpdateFlag_WaitForUpdateStartOnly can be specified. See
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
        ret = Progress(self._call_method('updateGuestAdditions', source, arguments, flags))
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

    def wait_for_completion(self, timeout):
        """Waits until the task is done (including all sub-operations)
          with a given timeout in milliseconds; specify -1 for an indefinite wait.

          Note that the VirtualBox/XPCOM/COM/native event queues of the calling
          thread are not processed while waiting. Neglecting event queues may
          have dire consequences (degrade performance, resource hogs,
          deadlocks, etc.), this is specially so for the main thread on
          platforms using XPCOM. Callers are advised wait for short periods
          and service their event queues between calls, or to create a worker
          thread to do the waiting.
        :param int timeout:
            Maximum time in milliseconds to wait or -1 to wait indefinitely.
        """
        self._call_method('waitForCompletion', timeout)

    def wait_for_operation_completion(self, operation, timeout):
        """Waits until the given operation is done with a given timeout in
          milliseconds; specify -1 for an indefinite wait.

          See
        :param int operation:
            Number of the operation to wait for.
          Must be less than
        :param int timeout:
            Maximum time in milliseconds to wait or -1 to wait indefinitely.
        """
        self._call_method('waitForOperationCompletion', operation, timeout)

    def wait_for_async_progress_completion(self, p_progress_async):
        """Waits until the other task is completed (including all
          sub-operations) and forward all changes from the other progress to
          this progress. This means sub-operation number, description, percent
          and so on.

          You have to take care on setting up at least the same count on
          sub-operations in this progress object like there are in the other
          progress object.

          If the other progress object supports cancel and this object gets any
          cancel request (when here enabled as well), it will be forwarded to
          the other progress object.

          If there is an error in the other progress, this error isn't
          automatically transfered to this progress object. So you have to
          check any operation error within the other progress object, after
          this method returns.
        :param Progress p_progress_async:
            The progress object of the asynchrony process.
        """
        self._call_method('waitForAsyncProgressCompletion', p_progress_async)

    def cancel(self):
        """Cancels the task.
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
        """Returns the number of direct children of this snapshot.
        :rtype: int
        :returns:
            
        """
        ret = int(self._call_method('getChildrenCount'))
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
        """Changes the UUID and parent UUID for a hard disk medium.
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
        """If the current medium state (see
        :rtype: MediumState
        :returns:
            New medium state.
        """
        ret = MediumState(self._call_method('refreshState'))
        return ret

    def get_snapshot_ids(self, machine_id):
        """Returns an array of UUIDs of all snapshots of the given machine where
        this medium is attached to.

        If the medium is attached to the machine in the current state, then the
        first element in the array will always be the ID of the queried machine
        (i.e. the value equal to the @c machineId argument), followed by
        snapshot IDs (if any).

        If the medium is not attached to the machine in the current state, then
        the array will contain only snapshot IDs.

        The returned array may be @c null if this medium is not attached
        to the given machine at all, neither in the current state nor in one of
        the snapshots.
        :param str machine_id:
            UUID of the machine to query.
        :rtype: typing.List[str]
        :returns:
            Array of snapshot UUIDs of the given machine using this medium.
        """
        ret = str(self._call_method('getSnapshotIds', machine_id))
        return ret

    def lock_read(self):
        """Locks this medium for reading.

        A read lock is shared: many clients can simultaneously lock the
        same medium for reading unless it is already locked for writing (see
        :rtype: Token
        :returns:
            Token object, when this is released (reference count reaches 0) then
          the lock count is decreased. The lock is released when the lock count
          reaches 0.
        """
        ret = Token(self._call_method('lockRead'))
        return ret

    def lock_write(self):
        """Locks this medium for writing.

        A write lock, as opposed to
        :rtype: Token
        :returns:
            Token object, when this is released (reference count reaches 0) then
          the lock is released.
        """
        ret = Token(self._call_method('lockWrite'))
        return ret

    def close(self):
        """Closes this medium.

        The medium must not be attached to any known virtual machine
        and must not have any known child media, otherwise the
        operation will fail.

        When the medium is successfully closed, it is removed from
        the list of registered media, but its storage unit is not
        deleted. In particular, this means that this medium can
        later be opened again using the
        """
        self._call_method('close')

    def get_property(self, name):
        """Returns the value of the custom medium property with the given name.

        The list of all properties supported by the given medium format can
        be obtained with
        :param str name:
            Name of the property to get.
        :rtype: str
        :returns:
            Current property value.
        """
        ret = str(self._call_method('getProperty', name))
        return ret

    def set_property(self, name, value):
        """Sets the value of the custom medium property with the given name.

        The list of all properties supported by the given medium format can
        be obtained with
        :param str name:
            Name of the property to set.
        :param str value:
            Property value to set.
        """
        self._call_method('setProperty', name, value)

    def get_properties(self, names):
        """Returns values for a group of properties in one call.

        The names of the properties to get are specified using the @a names
        argument which is a list of comma-separated property names or
        an empty string if all properties are to be returned.
        :param str names:
            Names of properties to get.
        :rtype: typing.List[typing.Tuple[str, str]]
        """
        return_values, return_names = self._call_method('getProperties', names)
        return return_values, return_names

    def set_properties(self, names, values):
        """Sets values for a group of properties in one call.

        The names of the properties to set are passed in the @a names
        array along with the new values for them in the @a values array. Both
        arrays have the same number of elements with each element at the given
        index in the first array corresponding to an element at the same index
        in the second array.

        If there is at least one property name in @a names that is not valid,
        the method will fail before changing the values of any other properties
        from the @a names array.

        Using this method over
        :param typing.List[str] names:
            Names of properties to set.
        :param typing.List[str] values:
            Values of properties to set.
        """
        self._call_method('setProperties', names, values)

    def create_base_storage(self, logical_size, variant):
        """Starts creating a hard disk storage unit (fixed/dynamic, according
        to the variant flags) in in the background. The previous storage unit
        created for this object, if any, must first be deleted using
        :param int logical_size:
            Maximum logical size of the medium in bytes.
        :param typing.List[MediumVariant] variant:
            Exact image variant which should be created (as a combination of
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('createBaseStorage', logical_size, variant))
        return ret

    def delete_storage(self):
        """Starts deleting the storage unit of this medium.

        The medium must not be attached to any known virtual machine and must
        not have any known child media, otherwise the operation will fail.
        It will also fail if there is no storage unit to delete or if deletion
        is already in progress, or if the medium is being in use (locked for
        read or for write) or inaccessible. Therefore, the only valid state for
        this operation to succeed is
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('deleteStorage'))
        return ret

    def create_diff_storage(self, target, variant):
        """Starts creating an empty differencing storage unit based on this
        medium in the format and at the location defined by the @a target
        argument.

        The target medium must be in
        :param Medium target:
            Target medium.
        :param typing.List[MediumVariant] variant:
            Exact image variant which should be created (as a combination of
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('createDiffStorage', target, variant))
        return ret

    def merge_to(self, target):
        """Starts merging the contents of this medium and all intermediate
        differencing media in the chain to the given target medium.

        The target medium must be either a descendant of this medium or
        its ancestor (otherwise this method will immediately return a failure).
        It follows that there are two logical directions of the merge operation:
        from ancestor to descendant (
        :param Medium target:
            Target medium.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('mergeTo', target))
        return ret

    def clone_to(self, target, variant, parent):
        """Starts creating a clone of this medium in the format and at the
        location defined by the @a target argument.

        The target medium must be either in
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
        ret = Progress(self._call_method('cloneTo', target, variant, parent))
        return ret

    def clone_to_base(self, target, variant):
        """Starts creating a clone of this medium in the format and at the
    location defined by the @a target argument.

    The target medium must be either in
        :param Medium target:
            Target medium.
        :param typing.List[MediumVariant] variant:
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('cloneToBase', target, variant))
        return ret

    def set_location(self, location):
        """Changes the location of this medium. Some medium types may support
        changing the storage unit location by simply changing the value of the
        associated property. In this case the operation is performed
        immediately, and @a progress is returning a @c null reference.
        Otherwise on success there is a progress object returned, which
        signals progress and completion of the operation. This distinction is
        necessary because for some formats the operation is very fast, while
        for others it can be very slow (moving the image file by copying all
        data), and in the former case it'd be a waste of resources to create
        a progress object which will immediately signal completion.

        When setting a location for a medium which corresponds to a/several
        regular file(s) in the host's file system, the given file name may be
        either relative to the
        :param str location:
            New location.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('setLocation', location))
        return ret

    def compact(self):
        """Starts compacting of this medium. This means that the medium is
        transformed into a possibly more compact storage representation.
        This potentially creates temporary images, which can require a
        substantial amount of additional disk space.

        This medium will be placed to
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('compact'))
        return ret

    def resize(self, logical_size):
        """Starts resizing this medium. This means that the nominal size of the
        medium is set to the new value. Both increasing and decreasing the
        size is possible, and there are no safety checks, since VirtualBox
        does not make any assumptions about the medium contents.

        Resizing usually needs additional disk space, and possibly also
        some temporary disk space. Note that resize does not create a full
        temporary copy of the medium, so the additional disk space requirement
        is usually much lower than using the clone operation.

        This medium will be placed to
        :param int logical_size:
            New nominal capacity of the medium in bytes.
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('resize', logical_size))
        return ret

    def reset(self):
        """Starts erasing the contents of this differencing medium.

        This operation will reset the differencing medium to its initial
        state when it does not contain any sector data and any read operation is
        redirected to its parent medium. This automatically gets called
        during VM power-up for every medium whose
        :rtype: Progress
        :returns:
            Progress object to track the operation completion.
        """
        ret = Progress(self._call_method('reset'))
        return ret

    def change_encryption(self, current_password, cipher, new_password, new_password_id):
        """Starts encryption of this medium. This means that the stored data in the
        medium is encrypted.

        This medium will be placed to
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
        ret = Progress(self._call_method('changeEncryption', current_password, cipher, new_password, new_password_id))
        return ret

    def get_encryption_settings(self):
        """Returns the encryption settings for this medium.
        :rtype: typing.Tuple[str, str]
        """
        password_id, cipher = self._call_method('getEncryptionSettings')
        return password_id, cipher

    def check_encryption_password(self, password):
        """Checks whether the supplied password is correct for the medium.
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
        """Returns two arrays describing the supported file extensions.

        The first array contains the supported extensions and the seconds one
        the type each extension supports. Both have the same size.

        Note that some backends do not work on files, so this array may be
        empty.
        :rtype: typing.List[typing.Tuple[str, DeviceType]]
        """
        extensions, types = self._call_method('describeFileExtensions')
        types = DeviceType(types)
        return extensions, types

    def describe_properties(self):
        """Returns several arrays describing the properties supported by this
        format.

        An element with the given index in each array describes one
        property. Thus, the number of elements in each returned array is the
        same and corresponds to the number of supported properties.

        The returned arrays are filled in only if the
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
        """Releases this token. Cannot be undone in any way, and makes the
        token object unusable (even the
        """
        self._call_method('abandon')

    def dummy(self):
        """Purely a NOOP. Useful when using proxy type API bindings (e.g. the
        webservice) which manage objects on behalf of the actual client, using
        an object reference expiration time based garbage collector.
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
        """Sends a scancode to the keyboard.
        :param int scancode:
        """
        self._call_method('putScancode', scancode)

    def put_scancodes(self, scancodes):
        """Sends an array of scancodes to the keyboard.
        :param int scancodes:
        :rtype: int
        """
        ret = int(self._call_method('putScancodes', scancodes))
        return ret

    def put_cad(self):
        """Sends the Ctrl-Alt-Del sequence to the keyboard. This
      function is nothing special, it is just a convenience function
      calling
        """
        self._call_method('putCAD')

    def release_keys(self):
        """Causes the virtual keyboard to release any keys which are
      currently pressed. Useful when host and guest keyboard may be out
      of sync.
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

class Mouse(Interface):
    """The IMouse interface represents the virtual machine's mouse. Used in
    """
    def put_mouse_event(self, dx, dy, dz, dw, button_state):
        """Initiates a mouse event using relative pointer movements
        along x and y axis.
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
        """Positions the mouse pointer using absolute x and y coordinates.
        These coordinates are expressed in pixels and
        start from
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
        """Sends a multi-touch pointer event. The coordinates are expressed in
        pixels and start from
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
        """
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
        """Information about the screen bitmap.
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
        """Informs about an update.
        Gets called by the display object where this buffer is
        registered.
        :param int x:
        :param int y:
        :param int width:
        :param int height:
        """
        self._call_method('notifyUpdate', x, y, width, height)

    def notify_update_image(self, x, y, width, height, image):
        """Informs about an update and provides 32bpp bitmap.
        :param int x:
        :param int y:
        :param int width:
        :param int height:
        :param typing.List[bytes] image:
            Array with 32BPP image data.
        """
        self._call_method('notifyUpdateImage', x, y, width, height, image)

    def notify_change(self, screen_id, x_origin, y_origin, width, height):
        """Requests a size change.
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
        """Returns whether the frame buffer implementation is willing to
        support a given video mode. In case it is not able to render
        the video mode (or for some reason not willing), it should
        return @c false. Usually this method is called when the guest
        asks the VMM device whether a given video mode is supported
        so the information returned is directly exposed to the guest.
        It is important that this method returns very quickly.
        :param int width:
        :param int height:
        :param int bpp:
        :rtype: bool
        """
        ret = bool(self._call_method('videoModeSupported', width, height, bpp))
        return ret

    def get_visible_region(self, rectangles, count):
        """Returns the visible region of this frame buffer.

        If the @a rectangles parameter is @c null then the value of the
        @a count parameter is ignored and the number of elements necessary to
        describe the current visible region is returned in @a countCopied.

        If @a rectangles is not @c null but @a count is less
        than the required number of elements to store region data, the method
        will report a failure. If @a count is equal or greater than the
        required number of elements, then the actual number of elements copied
        to the provided array will be returned in @a countCopied.
        :param bytes rectangles:
            Pointer to the @c RTRECT array to receive region data.
        :param int count:
            Number of @c RTRECT elements in the @a rectangles array.
        :rtype: int
        :returns:
            Number of elements copied to the @a rectangles array.
        """
        ret = int(self._call_method('getVisibleRegion', rectangles, count))
        return ret

    def set_visible_region(self, rectangles, count):
        """Suggests a new visible region to this frame buffer. This region
        represents the area of the VM display which is a union of regions of
        all top-level windows of the guest operating system running inside the
        VM (if the Guest Additions for this system support this
        functionality). This information may be used by the frontends to
        implement the seamless desktop integration feature.
        :param bytes rectangles:
            Pointer to the @c RTRECT array.
        :param int count:
            Number of @c RTRECT elements in the @a rectangles array.
        """
        self._call_method('setVisibleRegion', rectangles, count)

    def process_vhwa_command(self, command):
        """Posts a Video HW Acceleration Command to the frame buffer for processing.
        The commands used for 2D video acceleration (DDraw surface creation/destroying, blitting, scaling, color conversion, overlaying, etc.)
        are posted from quest to the host to be processed by the host hardware.
        :param bytes command:
            Pointer to VBOXVHWACMD containing the command to execute.
        """
        self._call_method('processVHWACommand', command)

    def notify_3d_event(self, type_, data):
        """Notifies framebuffer about 3D backend event.
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
        """Changes the overlay's position relative to the IFramebuffer.
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

class Display(Interface):
    """The IDisplay interface represents the virtual machine's display.

      The object implementing this interface is contained in each
    """
    def get_screen_resolution(self, screen_id):
        """Queries certain attributes such as display width, height, color depth
        and the X and Y origin for a given guest screen.

        The parameters @a xOrigin and @a yOrigin return the X and Y
        coordinates of the framebuffer's origin.

        All return parameters are optional.
        :param int screen_id:
        :rtype: typing.Tuple[int, int, int, int, int, GuestMonitorStatus]
        """
        width, height, bits_per_pixel, x_origin, y_origin, guest_monitor_status = self._call_method('getScreenResolution', screen_id)
        guest_monitor_status = GuestMonitorStatus(guest_monitor_status)
        return width, height, bits_per_pixel, x_origin, y_origin, guest_monitor_status

    def attach_framebuffer(self, screen_id, framebuffer):
        """Sets the graphics update target for a screen.
        :param int screen_id:
        :param Framebuffer framebuffer:
        :rtype: str
        """
        ret = str(self._call_method('attachFramebuffer', screen_id, framebuffer))
        return ret

    def detach_framebuffer(self, screen_id, id_):
        """Removes the graphics updates target for a screen.
        :param int screen_id:
        :param str id_:
        """
        self._call_method('detachFramebuffer', screen_id, id_)

    def query_framebuffer(self, screen_id):
        """Queries the graphics updates targets for a screen.
        :param int screen_id:
        :rtype: Framebuffer
        """
        ret = Framebuffer(self._call_method('queryFramebuffer', screen_id))
        return ret

    def set_video_mode_hint(self, display, enabled, change_origin, origin_x, origin_y, width, height, bits_per_pixel):
        """Asks VirtualBox to request the given video mode from
        the guest. This is just a hint and it cannot be guaranteed
        that the requested resolution will be used. Guest Additions
        are required for the request to be seen by guests. The caller
        should issue the request and wait for a resolution change and
        after a timeout retry.

        Specifying @c 0 for either @a width, @a height or @a bitsPerPixel
        parameters means that the corresponding values should be taken from the
        current video mode (i.e. left unchanged).

        If the guest OS supports multi-monitor configuration then the @a display
        parameter specifies the number of the guest display to send the hint to:
        @c 0 is the primary display, @c 1 is the first secondary and
        so on. If the multi-monitor configuration is not supported, @a display
        must be @c 0.
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
        """Enables or disables seamless guest display rendering (seamless desktop
        integration) mode.
        :param bool enabled:
        """
        self._call_method('setSeamlessMode', enabled)

    def take_screen_shot(self, screen_id, address, width, height, bitmap_format):
        """Takes a screen shot of the requested size and format and copies it to the
        buffer allocated by the caller and pointed to by @a address.
        The buffer size must be enough for a 32 bits per pixel bitmap,
        i.e. width * height * 4 bytes.
        :param int screen_id:
        :param bytes address:
        :param int width:
        :param int height:
        :param BitmapFormat bitmap_format:
        """
        self._call_method('takeScreenShot', screen_id, address, width, height, bitmap_format)

    def take_screen_shot_to_array(self, screen_id, width, height, bitmap_format):
        """Takes a guest screen shot of the requested size and format
        and returns it as an array of bytes.
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
        ret = bytes(self._call_method('takeScreenShotToArray', screen_id, width, height, bitmap_format))
        return ret

    def draw_to_screen(self, screen_id, address, x, y, width, height):
        """Draws a 32-bpp image of the specified size from the given buffer
        to the given point on the VM display.
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
        """Does a full invalidation of the VM display and instructs the VM
        to update it.
        """
        self._call_method('invalidateAndUpdate')

    def invalidate_and_update_screen(self, screen_id):
        """Redraw the specified VM screen.
        :param int screen_id:
            The guest screen to redraw.
        """
        self._call_method('invalidateAndUpdateScreen', screen_id)

    def complete_vhwa_command(self, command):
        """Signals that the Video HW Acceleration command has completed.
        :param bytes command:
            Pointer to VBOXVHWACMD containing the completed command.
        """
        self._call_method('completeVHWACommand', command)

    def viewport_changed(self, screen_id, x, y, width, height):
        """Signals that framebuffer window viewport has changed.
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
        """Obtains the guest screen bitmap parameters.
        :param int screen_id:
        :rtype: DisplaySourceBitmap
        """
        ret = DisplaySourceBitmap(self._call_method('querySourceBitmap', screen_id))
        return ret

    def notify_scale_factor_change(self, screen_id, u32_scale_factor_w_multiplied, u32_scale_factor_h_multiplied):
        """Notify OpenGL HGCM host service about graphics content scaling factor change.
        :param int screen_id:
        :param int u32_scale_factor_w_multiplied:
        :param int u32_scale_factor_h_multiplied:
        """
        self._call_method('notifyScaleFactorChange', screen_id, u32_scale_factor_w_multiplied, u32_scale_factor_h_multiplied)

    def notify_hi_dpi_output_policy_change(self, f_unscaled_hi_dpi):
        """Notify OpenGL HGCM host service about HiDPI monitor scaling policy change.
        :param bool f_unscaled_hi_dpi:
        """
        self._call_method('notifyHiDPIOutputPolicyChange', f_unscaled_hi_dpi)

    def set_screen_layout(self, screen_layout_mode, guest_screen_info):
        """Set video modes for the guest screens.
        :param ScreenLayoutMode screen_layout_mode:
        :param typing.List[GuestScreenInfo] guest_screen_info:
        """
        self._call_method('setScreenLayout', screen_layout_mode, guest_screen_info)

    def detach_screens(self, screen_ids):
        """Unplugs monitors from the virtual graphics card.
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
        """Returns the value of the network attachment property with the given name.

        If the requested data @a key does not exist, this function will
        succeed and return an empty string in the @a value argument.
        :param str key:
            Name of the property to get.
        :rtype: str
        :returns:
            Current property value.
        """
        ret = str(self._call_method('getProperty', key))
        return ret

    def set_property(self, key, value):
        """Sets the value of the network attachment property with the given name.

        Setting the property value to @c null or an empty string is equivalent
        to deleting the existing value.
        :param str key:
            Name of the property to set.
        :param str value:
            Property value to set.
        """
        self._call_method('setProperty', key, value)

    def get_properties(self, names):
        """Returns values for a group of properties in one call.

        The names of the properties to get are specified using the @a names
        argument which is a list of comma-separated property names or
        an empty string if all properties are to be returned.
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

class MachineDebugger(Interface):
    def dump_guest_core(self, filename, compression):
        """Takes a core dump of the guest.

        See include/VBox/dbgfcorefmt.h for details on the file format.
        :param str filename:
            The name of the output file. The file must not exist.
        :param str compression:
            Reserved for future compression method indicator.
        """
        self._call_method('dumpGuestCore', filename, compression)

    def dump_host_process_core(self, filename, compression):
        """Takes a core dump of the VM process on the host.

        This feature is not implemented in the 4.0.0 release but it may show up
        in a dot release.
        :param str filename:
            The name of the output file. The file must not exist.
        :param str compression:
            Reserved for future compression method indicator.
        """
        self._call_method('dumpHostProcessCore', filename, compression)

    def info(self, name, args):
        """Interfaces with the info dumpers (DBGFInfo).

        This feature is not implemented in the 4.0.0 release but it may show up
        in a dot release.
        :param str name:
            The name of the info item.
        :param str args:
            Arguments to the info dumper.
        :rtype: str
        :returns:
            The into string.
        """
        ret = str(self._call_method('info', name, args))
        return ret

    def inject_nmi(self):
        """Inject an NMI into a running VT-x/AMD-V VM.
        """
        self._call_method('injectNMI')

    def modify_log_groups(self, settings):
        """Modifies the group settings of the debug or release logger.
        :param str settings:
            The group settings string. See iprt/log.h for details. To target the
          release logger, prefix the string with "release:".
        """
        self._call_method('modifyLogGroups', settings)

    def modify_log_flags(self, settings):
        """Modifies the debug or release logger flags.
        :param str settings:
            The flags settings string. See iprt/log.h for details. To target the
          release logger, prefix the string with "release:".
        """
        self._call_method('modifyLogFlags', settings)

    def modify_log_destinations(self, settings):
        """Modifies the debug or release logger destinations.
        :param str settings:
            The destination settings string. See iprt/log.h for details. To target the
          release logger, prefix the string with "release:".
        """
        self._call_method('modifyLogDestinations', settings)

    def read_physical_memory(self, address, size):
        """Reads guest physical memory, no side effects (MMIO++).

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :param int address:
            The guest physical address.
        :param int size:
            The number of bytes to read.
        :rtype: typing.List[bytes]
        :returns:
            The bytes read.
        """
        ret = bytes(self._call_method('readPhysicalMemory', address, size))
        return ret

    def write_physical_memory(self, address, size, bytes_):
        """Writes guest physical memory, access handles (MMIO++) are ignored.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :param int address:
            The guest physical address.
        :param int size:
            The number of bytes to read.
        :param typing.List[bytes] bytes_:
            The bytes to write.
        """
        self._call_method('writePhysicalMemory', address, size, bytes_)

    def read_virtual_memory(self, cpu_id, address, size):
        """Reads guest virtual memory, no side effects (MMIO++).

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
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
        ret = bytes(self._call_method('readVirtualMemory', cpu_id, address, size))
        return ret

    def write_virtual_memory(self, cpu_id, address, size, bytes_):
        """Writes guest virtual memory, access handles (MMIO++) are ignored.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
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
        """Loads a DBGF plug-in.
        :param str name:
            The plug-in name or DLL. Special name 'all' loads all installed plug-ins.
        :rtype: str
        :returns:
            The name of the loaded plug-in.
        """
        ret = str(self._call_method('loadPlugIn', name))
        return ret

    def unload_plug_in(self, name):
        """Unloads a DBGF plug-in.
        :param str name:
            The plug-in name or DLL. Special name 'all' unloads all plug-ins.
        """
        self._call_method('unloadPlugIn', name)

    def detect_os(self):
        """Tries to (re-)detect the guest OS kernel.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :rtype: str
        :returns:
            The detected OS kernel on success.
        """
        ret = str(self._call_method('detectOS'))
        return ret

    def query_os_kernel_log(self, max_messages):
        """Tries to get the kernel log (dmesg) of the guest OS.
        :param int max_messages:
            Max number of messages to return, counting from the end of the
          log.  If 0, there is no limit.
        :rtype: str
        :returns:
            The kernel log.
        """
        ret = str(self._call_method('queryOSKernelLog', max_messages))
        return ret

    def get_register(self, cpu_id, name):
        """Gets one register.
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param str name:
            The register name, case is ignored.
        :rtype: str
        :returns:
            The register value. This is usually a hex value (always 0x prefixed)
          but other format may be used for floating point registers (TBD).
        """
        ret = str(self._call_method('getRegister', cpu_id, name))
        return ret

    def get_registers(self, cpu_id):
        """Gets all the registers for the given CPU.
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :rtype: typing.List[typing.Tuple[str, str]]
        """
        names, values = self._call_method('getRegisters', cpu_id)
        return names, values

    def set_register(self, cpu_id, name, value):
        """Gets one register.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
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
        """Sets zero or more registers atomically.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :param typing.List[str] names:
            Array containing the register names, case ignored.
        :param typing.List[str] values:
            Array paralell to the names holding the register values. See
        """
        self._call_method('setRegisters', cpu_id, names, values)

    def dump_guest_stack(self, cpu_id):
        """Produce a simple stack dump using the current guest state.

        This feature is not implemented in the 4.0.0 release but may show up
        in a dot release.
        :param int cpu_id:
            The identifier of the Virtual CPU.
        :rtype: str
        :returns:
            String containing the formatted stack dump.
        """
        ret = str(self._call_method('dumpGuestStack', cpu_id))
        return ret

    def reset_stats(self, pattern):
        """Reset VM statistics.
        :param str pattern:
            The selection pattern. A bit similar to filename globbing.
        """
        self._call_method('resetStats', pattern)

    def dump_stats(self, pattern):
        """Dumps VM statistics.
        :param str pattern:
            The selection pattern. A bit similar to filename globbing.
        """
        self._call_method('dumpStats', pattern)

    def get_stats(self, pattern, with_descriptions):
        """Get the VM statistics in a XMLish format.
        :param str pattern:
            The selection pattern. A bit similar to filename globbing.
        :param bool with_descriptions:
            Whether to include the descriptions.
        :rtype: str
        :returns:
            The XML document containing the statistics.
        """
        ret = str(self._call_method('getStats', pattern, with_descriptions))
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
        """Creates a new USB device filter. All attributes except
        the filter name are set to empty (any match),
        :param str name:
            Filter name. See
        :rtype: USBDeviceFilter
        :returns:
            Created filter object.
        """
        ret = USBDeviceFilter(self._call_method('createDeviceFilter', name))
        return ret

    def insert_device_filter(self, position, filter_):
        """Inserts the given USB device to the specified position
        in the list of filters.

        Positions are numbered starting from
        :param int position:
            Position to insert the filter to.
        :param USBDeviceFilter filter_:
            USB device filter to insert.
        """
        self._call_method('insertDeviceFilter', position, filter_)

    def remove_device_filter(self, position):
        """Removes a USB device filter from the specified position in the
        list of filters.

        Positions are numbered starting from
        :param int position:
            Position to remove the filter from.
        :rtype: USBDeviceFilter
        :returns:
            Removed USB device filter.
        """
        ret = USBDeviceFilter(self._call_method('removeDeviceFilter', position))
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
        """Sets a VRDE specific property string.

        If you pass @c null or empty string as a key @a value, the given @a key
        will be deleted.
        :param str key:
            Name of the key to set.
        :param str value:
            Value to assign to the key.
        """
        self._call_method('setVRDEProperty', key, value)

    def get_vrde_property(self, key):
        """Returns a VRDE specific property string.

        If the requested data @a key does not exist, this function will
        succeed and return an empty string in the @a value argument.
        :param str key:
            Name of the key to get.
        :rtype: str
        :returns:
            Value of the requested key.
        """
        ret = str(self._call_method('getVRDEProperty', key))
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
        """Assigns the machine and the (remote) console object associated with
        this remote-type session.
        :param Machine machine:
        :param Console console:
        """
        self._call_method('assignRemoteMachine', machine, console)

    def update_machine_state(self, machine_state):
        """Updates the machine state in the VM process.
        Must be called only in certain cases
        (see the method implementation).
        :param MachineState machine_state:
        """
        self._call_method('updateMachineState', machine_state)

    def uninitialize(self):
        """Uninitializes (closes) this session. Used by VirtualBox to close
        the corresponding remote session when the direct session dies
        or gets closed.
        """
        self._call_method('uninitialize')

    def on_network_adapter_change(self, network_adapter, change_adapter):
        """Triggered when settings of a network adapter of the
        associated virtual machine have changed.
        :param NetworkAdapter network_adapter:
        :param bool change_adapter:
        """
        self._call_method('onNetworkAdapterChange', network_adapter, change_adapter)

    def on_audio_adapter_change(self, audio_adapter):
        """Triggerd when settings of the audio adapter of the
        associated virtual machine have changed.
        :param AudioAdapter audio_adapter:
        """
        self._call_method('onAudioAdapterChange', audio_adapter)

    def on_serial_port_change(self, serial_port):
        """Triggered when settings of a serial port of the
        associated virtual machine have changed.
        :param SerialPort serial_port:
        """
        self._call_method('onSerialPortChange', serial_port)

    def on_parallel_port_change(self, parallel_port):
        """Triggered when settings of a parallel port of the
        associated virtual machine have changed.
        :param ParallelPort parallel_port:
        """
        self._call_method('onParallelPortChange', parallel_port)

    def on_storage_controller_change(self):
        """Triggered when settings of a storage controller of the
        associated virtual machine have changed.
        """
        self._call_method('onStorageControllerChange')

    def on_medium_change(self, medium_attachment, force):
        """Triggered when attached media of the
        associated virtual machine have changed.
        :param MediumAttachment medium_attachment:
            The medium attachment which changed.
        :param bool force:
            If the medium change was forced.
        """
        self._call_method('onMediumChange', medium_attachment, force)

    def on_storage_device_change(self, medium_attachment, remove, silent):
        """Triggered when attached storage devices of the
        associated virtual machine have changed.
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
        """Notification when the shared clipboard mode changes.
        :param ClipboardMode clipboard_mode:
            The new shared clipboard mode.
        """
        self._call_method('onClipboardModeChange', clipboard_mode)

    def on_drag_and_drop_mode_change(self, dnd_mode):
        """Notification when the drag'n drop mode changes.
        :param DnDMode dnd_mode:
            The new mode for drag'n drop.
        """
        self._call_method('onDnDModeChange', dnd_mode)

    def on_cpu_change(self, cpu, add):
        """Notification when a CPU changes.
        :param int cpu:
            The CPU which changed
        :param bool add:
            Flag whether the CPU was added or removed
        """
        self._call_method('onCPUChange', cpu, add)

    def on_cpu_execution_cap_change(self, execution_cap):
        """Notification when the CPU execution cap changes.
        :param int execution_cap:
            The new CPU execution cap value. (1-100)
        """
        self._call_method('onCPUExecutionCapChange', execution_cap)

    def on_vrde_server_change(self, restart):
        """Triggered when settings of the VRDE server object of the
        associated virtual machine have changed.
        :param bool restart:
            Flag whether the server must be restarted
        """
        self._call_method('onVRDEServerChange', restart)

    def on_video_capture_change(self):
        """Triggered when video capture settings have changed.
        """
        self._call_method('onVideoCaptureChange')

    def on_usb_controller_change(self):
        """Triggered when settings of the USB controller object of the
        associated virtual machine have changed.
        """
        self._call_method('onUSBControllerChange')

    def on_shared_folder_change(self, global_):
        """Triggered when a permanent (global or machine) shared folder has been
        created or removed.
        :param bool global_:
        """
        self._call_method('onSharedFolderChange', global_)

    def on_usb_device_attach(self, device, error, masked_interfaces, capture_filename):
        """Triggered when a request to capture a USB device (as a result
        of matched USB filters or direct call to
        :param USBDevice device:
        :param VirtualBoxErrorInfo error:
        :param int masked_interfaces:
        :param str capture_filename:
        """
        self._call_method('onUSBDeviceAttach', device, error, masked_interfaces, capture_filename)

    def on_usb_device_detach(self, id_, error):
        """Triggered when a request to release the USB device (as a result
        of machine termination or direct call to
        :param str id_:
        :param VirtualBoxErrorInfo error:
        """
        self._call_method('onUSBDeviceDetach', id_, error)

    def on_show_window(self, check):
        """Called by
        :param bool check:
        :rtype: typing.Tuple[bool, int]
        """
        can_show, win_id = self._call_method('onShowWindow', check)
        return can_show, win_id

    def on_bandwidth_group_change(self, bandwidth_group):
        """Notification when one of the bandwidth groups change.
        :param BandwidthGroup bandwidth_group:
            The bandwidth group which changed.
        """
        self._call_method('onBandwidthGroupChange', bandwidth_group)

    def access_guest_property(self, name, value, flags, access_mode):
        """Called by
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
        """Return a list of the guest properties matching a set of patterns along
        with their values, time stamps and flags.
        :param str patterns:
            The patterns to match the properties against as a comma-separated
          string. If this is empty, all properties currently set will be
          returned.
        :rtype: typing.List[typing.Tuple[str, str, int, str]]
        """
        keys, values, timestamps, flags = self._call_method('enumerateGuestProperties', patterns)
        return keys, values, timestamps, flags

    def online_merge_medium(self, medium_attachment, source_idx, target_idx, progress):
        """Triggers online merging of a hard disk. Used internally when deleting
        a snapshot while a VM referring to the same hard disk chain is running.
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
        """Reconfigure all specified medium attachments in one go, making sure
        the current state corresponds to the specified medium.
        :param typing.List[MediumAttachment] attachments:
            Array containing the medium attachments which need to be
          reconfigured.
        """
        self._call_method('reconfigureMediumAttachments', attachments)

    def enable_vmm_statistics(self, enable):
        """Enables or disables collection of VMM RAM statistics.
        :param bool enable:
            True enables statistics collection.
        """
        self._call_method('enableVMMStatistics', enable)

    def pause_with_reason(self, reason):
        """Internal method for triggering a VM pause with a specified reason code.
        The reason code can be interpreted by device/drivers and thus it might
        behave slightly differently than a normal VM pause.
        :param Reason reason:
            Specify the best matching reason code please.
        """
        self._call_method('pauseWithReason', reason)

    def resume_with_reason(self, reason):
        """Internal method for triggering a VM resume with a specified reason code.
        The reason code can be interpreted by device/drivers and thus it might
        behave slightly differently than a normal VM resume.
        :param Reason reason:
            Specify the best matching reason code please.
        """
        self._call_method('resumeWithReason', reason)

    def save_state_with_reason(self, reason, progress, snapshot, state_file_path, pause_vm):
        """Internal method for triggering a VM save state with a specified reason
        code. The reason code can be interpreted by device/drivers and thus it
        might behave slightly differently than a normal VM save state.

        This call is fully synchronous, and the caller is expected to have set
        the machine state appropriately (and has to set the follow-up machine
        state if this call failed).
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
        ret = bool(self._call_method('saveStateWithReason', reason, progress, snapshot, state_file_path, pause_vm))
        return ret

    def cancel_save_state_with_reason(self):
        """Internal method for cancelling a VM save state.
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
        """Unlocks a machine that was previously locked for the current session.

        Calling this method is required every time a machine has been locked
        for a particular session using the
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
        """Returns the name of the interface that this managed object represents,
        for example, "IMachine", as a string.
        :rtype: str
        """
        ret = str(self._call_method('getInterfaceName'))
        return ret

    def release(self):
        """Releases this managed object reference and frees the resources that
        were allocated for it in the webservice server process. After calling
        this method, the identifier of the reference can no longer be used.
        """
        self._call_method('release')


class WebsessionManager(Interface):
    """Websession manager. This provides essential services
      to webservice clients.
    """
    def logon(self, username, password):
        """Logs a new client onto the webservice and returns a managed object reference to
        the IVirtualBox instance, which the client can then use as a basis to further
        queries, since all calls to the VirtualBox API are based on the IVirtualBox
        interface, in one way or the other.
        :param str username:
        :param str password:
        :rtype: VirtualBox
        """
        ret = VirtualBox(self._call_method('logon', username, password))
        return ret

    def get_session_object(self, ref_i_virtual_box):
        """Returns a managed object reference to a new ISession object for every
        call to this method.
        :param VirtualBox ref_i_virtual_box:
        :rtype: Session
        """
        ret = Session(self._call_method('getSessionObject', ref_i_virtual_box))
        return ret

    def logoff(self, ref_i_virtual_box):
        """Logs off the client who has previously logged on with
        :param VirtualBox ref_i_virtual_box:
        """
        self._call_method('logoff', ref_i_virtual_box)


class PerformanceCollector(Interface):
    """The IPerformanceCollector interface represents a service that collects
      and stores performance metrics data.

      Performance metrics are associated with objects of interfaces like IHost
      and IMachine. Each object has a distinct set of performance metrics. The
      set can be obtained with
    """
    def get_metrics(self, metric_names, objects):
        """Returns parameters of specified metrics for a set of objects.
        :param typing.List[str] metric_names:
            Metric name filter. Currently, only a comma-separated list of metrics
          is supported.
        :param typing.List[nterface] objects:
            Set of objects to return metric parameters for.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of returned metric parameters.
        """
        ret = PerformanceMetric(self._call_method('getMetrics', metric_names, objects))
        return ret

    def setup_metrics(self, metric_names, objects, period, count):
        """Sets parameters of specified base metrics for a set of objects. Returns
        an array of
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
        ret = PerformanceMetric(self._call_method('setupMetrics', metric_names, objects, period, count))
        return ret

    def enable_metrics(self, metric_names, objects):
        """Turns on collecting specified base metrics. Returns an array of
        :param typing.List[str] metric_names:
            Metric name filter. Comma-separated list of metrics with wildcard
          support.
        :param typing.List[nterface] objects:
            Set of objects to enable metrics for.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of metrics that have been modified by the call to this method.
        """
        ret = PerformanceMetric(self._call_method('enableMetrics', metric_names, objects))
        return ret

    def disable_metrics(self, metric_names, objects):
        """Turns off collecting specified base metrics. Returns an array of
        :param typing.List[str] metric_names:
            Metric name filter. Comma-separated list of metrics with wildcard
          support.
        :param typing.List[nterface] objects:
            Set of objects to disable metrics for.
        :rtype: typing.List[PerformanceMetric]
        :returns:
            Array of metrics that have been modified by the call to this method.
        """
        ret = PerformanceMetric(self._call_method('disableMetrics', metric_names, objects))
        return ret

    def query_metrics_data(self, metric_names, objects):
        """Queries collected metrics data for a set of objects.

        The data itself and related metric information are returned in seven
        parallel and one flattened array of arrays. Elements of
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


class ExtPackBase(Interface):
    """Interface for querying information about an extension pack as well as
      accessing COM objects within it.
    """
    def query_license(self, preferred_locale, preferred_language, format_):
        """Full feature version of the license attribute.
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
        ret = str(self._call_method('queryLicense', preferred_locale, preferred_language, format_))
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
        """Queries the IUnknown interface to an object in the extension pack
        main module. This allows plug-ins and others to talk directly to an
        extension pack.
        :param str obj_uuid:
            The object ID. What exactly this is
        :rtype: nterface
        :returns:
            The queried interface.
        """
        ret = nterface(self._call_method('queryObject', obj_uuid))
        return ret


class ExtPackFile(ExtPackBase):
    """Extension pack file (aka tarball, .vbox-extpack) representation returned
      by
    """
    def install(self, replace, display_info):
        """Install the extension pack.
        :param bool replace:
            Set this to automatically uninstall any existing extension pack with
          the same name as the one being installed.
        :param str display_info:
            Platform specific display information. Reserved for future hacks.
        :rtype: Progress
        :returns:
            Progress object for the operation.
        """
        ret = Progress(self._call_method('install', replace, display_info))
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
        """Returns the extension pack with the specified name if found.
        :param str name:
            The name of the extension pack to locate.
        :rtype: ExtPack
        :returns:
            The extension pack if found.
        """
        ret = ExtPack(self._call_method('find', name))
        return ret

    def open_ext_pack_file(self, path):
        """Attempts to open an extension pack file in preparation for
        installation.
        :param str path:
            The path of the extension pack tarball. This can optionally be
        followed by a "::SHA-256=hex-digit" of the tarball.
        :rtype: ExtPackFile
        :returns:
            The interface of the extension pack file object.
        """
        ret = ExtPackFile(self._call_method('openExtPackFile', path))
        return ret

    def uninstall(self, name, forced_removal, display_info):
        """Uninstalls an extension pack, removing all related files.
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
        ret = Progress(self._call_method('uninstall', name, forced_removal, display_info))
        return ret

    def cleanup(self):
        """Cleans up failed installs and uninstalls
        """
        self._call_method('cleanup')

    def query_all_plug_ins_for_frontend(self, frontend_name):
        """Gets the path to all the plug-in modules for a given frontend.

        This is a convenience method that is intended to simplify the plug-in
        loading process for a frontend.
        :param str frontend_name:
            The name of the frontend or component.
        :rtype: typing.List[str]
        :returns:
            Array containing the plug-in modules (full paths).
        """
        ret = str(self._call_method('queryAllPlugInsForFrontend', frontend_name))
        return ret

    def is_ext_pack_usable(self, name):
        """Check if the given extension pack is loaded and usable.
        :param str name:
            The name of the extension pack to check for.
        :rtype: bool
        :returns:
            Is the given extension pack loaded and usable.
        """
        ret = bool(self._call_method('isExtPackUsable', name))
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

class BandwidthControl(Interface):
    """Controls the bandwidth groups of one machine used to cap I/O done by a VM.
      This includes network and disk I/O.
    """
    def create_bandwidth_group(self, name, type_, max_bytes_per_sec):
        """Creates a new bandwidth group.
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
        """Deletes a new bandwidth group.
        :param str name:
            Name of the bandwidth group to delete.
        """
        self._call_method('deleteBandwidthGroup', name)

    def get_bandwidth_group(self, name):
        """Get a bandwidth group by name.
        :param str name:
            Name of the bandwidth group to get.
        :rtype: BandwidthGroup
        :returns:
            Where to store the bandwidth group on success.
        """
        ret = BandwidthGroup(self._call_method('getBandwidthGroup', name))
        return ret

    def get_all_bandwidth_groups(self):
        """Get all managed bandwidth groups.
        :rtype: typing.List[BandwidthGroup]
        :returns:
            The array of managed bandwidth groups.
        """
        ret = BandwidthGroup(self._call_method('getAllBandwidthGroups'))
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
        """Perform error checking before using an
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
        """Creates a new listener object, useful for passive mode.
        :rtype: EventListener
        """
        ret = EventListener(self._call_method('createListener'))
        return ret

    def create_aggregator(self, subordinates):
        """Creates an aggregator event source, collecting events from multiple sources.
        This way a single listener can listen for events coming from multiple sources,
        using a single blocking
        :param typing.List[EventSource] subordinates:
            Subordinate event source this one aggregates.
        :rtype: EventSource
        :returns:
            Event source aggregating passed sources.
        """
        ret = EventSource(self._call_method('createAggregator', subordinates))
        return ret

    def register_listener(self, listener, interesting, active):
        """Register an event listener.
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
        """Unregister an event listener. If listener is passive, and some waitable events are still
        in queue they are marked as processed automatically.
        :param EventListener listener:
            Listener to unregister.
        """
        self._call_method('unregisterListener', listener)

    def fire_event(self, event, timeout):
        """Fire an event for this source.
        :param Event event:
            Event to deliver.
        :param int timeout:
            Maximum time to wait for event processing (if event is waitable), in ms;
          0 = no wait, -1 = indefinite wait.
        :rtype: bool
        :returns:
            true if an event was delivered to all targets, or is non-waitable.
        """
        ret = bool(self._call_method('fireEvent', event, timeout))
        return ret

    def get_event(self, listener, timeout):
        """Get events from this peer's event queue (for passive mode). Calling this method
        regularly is required for passive event listeners to avoid system overload;
        see
        :param EventListener listener:
            Which listener to get data for.
        :param int timeout:
            Maximum time to wait for events, in ms;
          0 = no wait, -1 = indefinite wait.
        :rtype: Event
        :returns:
            Event retrieved, or null if none available.
        """
        ret = Event(self._call_method('getEvent', listener, timeout))
        return ret

    def event_processed(self, listener, event):
        """Must be called for waitable events after a particular listener finished its
        event processing. When all listeners of a particular event have called this
        method, the system will then call
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
        """Handle event callback for active listeners. It is not called for
        passive listeners. After calling
        :param Event event:
            Event available.
        """
        self._call_method('handleEvent', event)


class Event(Interface):
    """Abstract parent interface for VirtualBox events. Actual events will typically implement
      a more specific interface which derives from this (see below).
    """
    def set_processed(self):
        """Internal method called by the system when all listeners of a particular event have called
        """
        self._call_method('setProcessed')

    def wait_processed(self, timeout):
        """Wait until time outs, or this event is processed. Event must be waitable for this operation to have
        described semantics, for non-waitable returns true immediately.
        :param int timeout:
            Maximum time to wait for event processing, in ms;
          0 = no wait, -1 = indefinite wait.
        :rtype: bool
        :returns:
            If this event was processed before timeout.
        """
        ret = bool(self._call_method('waitProcessed', timeout))
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
        """Marks an event as reused, increments 'generation', fields shall no
        longer be considered valid.
        """
        self._call_method('reuse')

    @property
    def generation(self):
        """Current generation of event, incremented on reuse.
        :rtype: int
        """
        return self._get_property('generation')


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

class VetoEvent(Event):
    """Base abstract interface for veto events.
    """
    def add_veto(self, reason):
        """Adds a veto on this event.
        :param str reason:
            Reason for veto, could be null or empty string.
        """
        self._call_method('addVeto', reason)

    def is_vetoed(self):
        """If this event was vetoed.
        :rtype: bool
        :returns:
            Reason for veto.
        """
        ret = bool(self._call_method('isVetoed'))
        return ret

    def get_vetos(self):
        """Current veto reason list, if size is 0 - no veto.
        :rtype: typing.List[str]
        :returns:
            Array of reasons for veto provided by different event handlers.
        """
        ret = str(self._call_method('getVetos'))
        return ret

    def add_approval(self, reason):
        """Adds an approval on this event.
        :param str reason:
            Reason for approval, could be null or empty string.
        """
        self._call_method('addApproval', reason)

    def is_approved(self):
        """If this event was approved.
        :rtype: bool
        """
        ret = bool(self._call_method('isApproved'))
        return ret

    def get_approvals(self):
        """Current approval reason list, if size is 0 - no approvals.
        :rtype: typing.List[str]
        :returns:
            Array of reasons for approval provided by different event handlers.
        """
        ret = str(self._call_method('getApprovals'))
        return ret


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

class VBoxSVCRegistration(Interface):
    """Implemented by the VirtualBox class factory and registered with VBoxSDS
          so it can retrieve IVirtualBox on behalf of other VBoxSVCs.
    """
    def get_virtual_box(self):
        """Gets an IUnknown interface to the VirtualBox object in the VBoxSVC process.
        :rtype: nterface
        :returns:
            Where to return the IUnknown interface.
        """
        ret = nterface(self._call_method('getVirtualBox'))
        return ret

    def notify_clients_finished(self):
        """Notify service that their clients finished.
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
        """Registers a VBoxSVC instance with the SDS.
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
        ret = nterface(self._call_method('registerVBoxSVC', vbox_svc, pid))
        return ret

    def deregister_virtualbox_svc(self, vbox_svc, pid):
        """Registers a VBoxSVC instance with the SDS.
        :param VBoxSVCRegistration vbox_svc:
            Same as specified during registration.
        :param int pid:
            The process ID of the VBoxSVC instance (same as during registration).
        """
        self._call_method('deregisterVBoxSVC', vbox_svc, pid)

    def notify_clients_finished(self):
        """Notify SDS that clients finished.
        """
        self._call_method('notifyClientsFinished')


class VirtualBoxClientList(Interface):
    """The IVirtualBoxClientList interface represents a list of VirtualBox API clients.
    """
    def register_client(self, pid):
        """Register VirtualBox API Client.
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
