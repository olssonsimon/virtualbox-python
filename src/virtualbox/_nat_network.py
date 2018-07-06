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


import re
import attr
import ipaddress
import typing
from ._base import Interface
from ._enums import NATProtocol


PORT_FORWARD_RULE_REGEX = re.compile(r"^(.*):([01]):\[?([^:]+)\]?:(\d+):\[?([^:]+)\]?:(\d+)$")


@attr.s
class PortForwardRule:
    name = attr.attrib(type=str)  # type: str
    protocol = attr.ib(type=NATProtocol)  # type: NATProtocol
    host_ip = attr.ib(type=str)  # type: str
    host_port = attr.ib(type=int)  # type: int
    guest_ip = attr.ib(type=str)  # type: str
    guest_port = attr.ib(type=int)  # type: int


class _NATNetworkPortForwardRules(object):
    def __init__(self, interface: Interface, is_ipv6: bool):
        self._interface = interface
        self._is_ipv6 = is_ipv6

    def add(self, rule: PortForwardRule):
        self._interface._call_method(
            'addPortForwardRule',
            rule.is_ipv6,
            rule.name,
            rule.nat_protocol,
            rule.host_ip,
            rule.host_port,
            rule.guest_ip,
            rule.guest_port
        )

    def remove(self, name: str):
        self._interface._call_method('removePortForwardRule', self._is_ipv6, name)

    def __iter__(self) -> typing.Iterable[PortForwardRule]:
        return iter([
            PortForwardRule(*PORT_FORWARD_RULE_REGEX.match(x).groups())
            for x in self._interface._get_property(f'portForwardRules{6 if self._is_ipv6 else 4}')
        ])


class NATNetwork(Interface):
    def __init__(self, _interface=None):
        Interface.__init__(self, _interface)
        self.ipv4_port_forward_rules = _NATNetworkPortForwardRules(self, is_ipv6=False)
        self.ipv6_port_forward_rules = _NATNetworkPortForwardRules(self, is_ipv6=True)

    def add_local_mapping(self, hostid, offset):
        """
        :param str hostid:
        :param int offset:
        """
        self._call_method('addLocalMapping', hostid, offset)

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
    def name(self) -> str:
        """TBD: the idea, technically we can start any number of the NAT networks,
        but we should expect that at some point we will get collisions because of
        port-forwanding rules. so perhaps we should support only single instance of NAT
        network.
        :rtype: str
        """
        return self._get_property('networkName')

    @property
    def enabled(self) -> bool:
        """None
        :rtype: bool
        """
        return self._get_property('enabled')

    @property
    def network(self) -> ipaddress.IPv4Address:
        """This is CIDR IPv4 string. Specifying it user defines IPv4 addresses
        of gateway (low address + 1) and DHCP server (= low address + 2).
        Note: If there are defined IPv4 port-forward rules update of network
        will be ignored (because new assignment could break existing rules).
        :rtype: str
        """
        return ipaddress.IPv4Address(self._get_property('network'))

    @property
    def gateway(self) -> ipaddress.IPv4Address:
        """This attribute is read-only. It's recalculated on changing
        network attribute (low address of network + 1).
        :rtype: str
        """
        return ipaddress.IPv4Address(self._get_property('gateway'))

    @property
    def ipv6_enabled(self) -> bool:
        """This attribute define whether gateway will support IPv6 or not.
        :rtype: bool
        """
        return self._get_property('IPv6Enabled')

    @property
    def ipv6_prefix(self) -> typing.Optional[ipaddress.IPv6Address]:
        """This a CIDR IPv6 defining prefix for link-local addresses
        autoconfiguration within network. Note: ignored if attribute
        IPv6Enabled is false.
        :rtype: str
        """
        return self._get_property('IPv6Prefix')

    @property
    def advertise_default_ipv6_route_enabled(self) -> bool:
        """None
        :rtype: bool
        """
        return self._get_property('advertiseDefaultIPv6RouteEnabled')

    @property
    def need_dhcp_server(self) -> bool:
        """None
        :rtype: bool
        """
        return self._get_property('needDhcpServer')

    @property
    def event_source(self) -> EventSource:
        """None
        :rtype: EventSource
        """
        return EventSource(self._get_property('eventSource'))

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
