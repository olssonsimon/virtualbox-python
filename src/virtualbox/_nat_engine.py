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


import attr
import typing
import ipaddress
from ._base import Interface
from ._enums import NATProtocol, NATAliasMode



@attr.s
class NetworkSettings:
    mtu = attr.ib(type=int)
    sock_send = attr.ib(type=int)
    sock_recv = attr.ib(type=int)
    tcp_window_send = attr.ib(type=int)
    tcp_window_recv = attr.ib(type=int)


@attr.s
class NATRedirect:
    name = attr.ib(type=str)  # type: str
    protocol = attr.ib(type=NATProtocol)  # type: NATProtocol
    host_ip = attr.ib(type=str)  # type: str
    host_port = attr.ib(type=int)  # type: int
    guest_ip = attr.ib(type=str)  # type: str
    guest_port = attr.ib(type=int)  # type: int


class _NATEngineRedirects(object):
    def __init__(self, interface: Interface):
        self._interface = interface

    def add(self, redirect: NATRedirect):
        self._interface._call_method('addRedirect', *attr.astuple(redirect))

    def remove(self, name: str):
        self._interface._call_method('removeRedirect', name)

    def __iter__(self) -> typing.Iterable[NATRedirect]:
        return [NATRedirect(*x) for x in self._interface._get_property('redirects')]


class NATEngine(Interface):
    """Interface for managing a NAT engine which is used with a virtual machine. This
      allows for changing NAT behavior such as port-forwarding rules. This interface is
      used in the
    """
    def __init__(self, _interface=None):
        Interface.__init__(_interface)
        self.redirects = _NATEngineRedirects(self)

    @property
    def network_settings(self) -> NetworkSettings:
        return NetworkSettings(*self._call_method('getNetworkSettings'))

    @network_settings.setter
    def network_settings(self, network_settings: NetworkSettings):
        self._call_method('setNetworkSettings', *attr.astuple(network_settings))

    @property
    def network(self):
        """The network attribute of the NAT engine (the same value is used with built-in
        DHCP server to fill corresponding fields of DHCP leases).
        :rtype: str
        """
        return self._get_property('network')

    @property
    def host_ip(self) -> ipaddress._IPAddressBase:
        return ipaddress.ip_address(self._get_property('hostIP'))

    @property
    def tftp_prefix(self) -> str:
        """TFTP prefix attribute which is used with the built-in DHCP server to fill
        the corresponding fields of DHCP leases.
        :rtype: str
        """
        return self._get_property('TFTPPrefix')

    @property
    def tftp_boot_file(self) -> str:
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
    def alias_mode(self) -> NATAliasMode:
        return NATAliasMode(self._get_property('aliasMode'))

    @property
    def dns_pass_domain(self) -> bool:
        """Whether the DHCP server should pass the DNS domain used by the host.
        :rtype: bool
        """
        return bool(self._get_property('DNSPassDomain'))

    @property
    def dns_proxy(self) -> bool:
        """Whether the DHCP server (and the DNS traffic by NAT) should pass the address
        of the DNS proxy and process traffic using DNS servers registered on the host.
        :rtype: bool
        """
        return bool(self._get_property('DNSProxy'))

    @property
    def dns_use_host_resolver(self) -> bool:
        """Whether the DHCP server (and the DNS traffic by NAT) should pass the address
        of the DNS proxy and process traffic using the host resolver mechanism.
        :rtype: bool
        """
        return bool(self._get_property('DNSUseHostResolver'))
