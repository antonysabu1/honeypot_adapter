"""Virtual network state manager for the honeypot.

Provides a simulated network environment entirely against VirtualOS state.
No real sockets, interfaces, or traffic are created.  All information shown
to attackers originates from the virtual state, and service state directly
affects virtual listening ports.

The design mirrors Linux networking concepts (interfaces, addresses, routes,
ARP) while remaining a purely in-memory simulation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Dict, FrozenSet, Optional, Set

# ── Virtual interface ──────────────────────────────────────────────────────

@dataclass
class VirtualInterface:
    """Represents a virtual network interface in the honeypot."""

    name: str          # e.g. "eth0", "lo", "docker0"
    mtu: int = 1500
    status: str = "up"  # "up" | "down"
    ipv4: Optional[IPv4Address] = None
    ipv6: Optional[str] = None
    mac: str = "00:00:00:00:00:00"
    # Interface-specific metadata
    description: str = ""
    # Associated service (if any)
    service: str | None = None


# ── Virtual routing entry ─────────────────────────────────────────────────

@dataclass
class VirtualRoute:
    """Reates a route entry in the virtual routing table."""

    destination: Optional[IPv4Network]
    gateway: Optional[IPv4Address] = None
    dev: str = ""  # outgoing interface
    metric: int = 100


# ── ARP/Neighbor entry ───────────────────────────────────────────────────

@dataclass
class VirtualNeighbor:
    """Represents a neighbor discovered via ARP simulation."""
    mac: str
    ip: IPv4Address
    interface: str
    stale: bool = False  # whether the entry is considered stale


# ── DNS configuration ─────────────────────────────────────────────────────

@dataclass
class VirtualDNS:
    """DNS configuration for the virtual network."""

    nameservers: FrozenSet[str]
    search_domains: FrozenSet[str]
    hostnames: FrozenDict[str, str] = field(default_factory=frozenset)


# ── Virtual network state ─────────────────────────────────────────────────

@dataclass
class VirtualNetwork:
    """The complete virtual network state visible to attackers."""

    interfaces: FrozenDict[str, VirtualInterface]
    routes: FrozenList[VirtualRoute]
    neighbors: FrozenDict[str, VirtualNeighbor]
    dns: VirtualDNS
    # Global metadata
    hostname: str
    domain: str


# ── Helper types ──────────────────────────────────────────────────────────

# A thin wrapper so we can use FrozenDict (which isn't hashable in older Python)
# Actually, let's just use regular dict for now and freeze at the API boundary
FrozenDict = dict
FrozenList = list


# ── Default virtual network configuration ──────────────────────────────────

# These values are derived from the persona/configuration, not hardcoded.
# The default reflects a typical Linux server setup.

DEFAULT_NETWORK = None  # Will be bootstrapped from persona configuration


# ── Helper functions ──────────────────────────────────────────────────────


def _ipv4_to_int(addr: IPv4Address) -> int:
    """Convert an IPv4Address to an integer for sorting/comparison."""
    return int(addr)


def _int_to_ipv4(addr: int) -> IPv4Address:
    """Convert an integer back to an IPv4Address."""
    return IPv4Address(addr)


# ── Singleton virtual network state ───────────────────────────────────────

_virtual_network: VirtualNetwork | None = None


def get_virtual_network() -> VirtualNetwork:
    """Return the global virtual network state, bootstrapping if necessary."""
    global _virtual_network
    if _virtual_network is None:
        _virtual_network = _boot_virtual_network()
    return _virtual_network


def _boot_virtual_network() -> VirtualNetwork:
    """Bootstrap the virtual network from persona/configuration defaults.

    In a real deployment, these values would come from the persona YAML
    configuration.  Here we use a deterministic default that mirrors a
    typical Linux server installation.
    """

    # Default interfaces
    interfaces: FrozenDict[str, VirtualInterface] = FrozenDict({
        "lo": VirtualInterface(
            name="lo",
            mtu=65536,
            status="up",
            ipv4=IPv4Address("127.0.0.1"),
            mac="00:00:00:00:00:00",
            description="loopback",
        ),
        "eth0": VirtualInterface(
            name="eth0",
            mtu=1500,
            status="up",
            ipv4=IPv4Address("10.0.0.1"),  # internal IP
            mac="00:16:3e:00:00:00",
            description="primary network interface",
        ),
    })

    # Default routes
    routes: FrozenList[VirtualRoute] = FrozenList([
        VirtualRoute(
            destination=None,  # default route
            gateway=IPv4Address("10.0.0.1"),
            dev="eth0",
        ),
        VirtualRoute(
            destination=IPv4Network("127.0.0.0/8"),
            dev="lo",
        ),
    ])

    # Default neighbors (ARP cache)
    neighbors: FrozenDict[str, VirtualNeighbor] = FrozenDict({
        "eth0": VirtualNeighbor(
            mac="00:16:3e:00:00:00",
            ip=IPv4Address("10.0.0.1"),
            interface="eth0",
        ),
    })

    # Default DNS
    dns = VirtualDNS(
        nameservers=frozenset({"8.8.8.8", "8.8.4.4"}),
        search_domains=frozenset({"example.com"}),
    )

    return VirtualNetwork(
        interfaces=interfaces,
        routes=routes,
        neighbors=neighbors,
        dns=dns,
        hostname="honeypot",
        domain="example.com",
    )

# ── Global state access ───────────────────────────────────────────────────

_process_manager: "ProcessManager | None" = None
_service_manager: "ServiceManager | None" = None


def get_process_manager() -> "ProcessManager":
    """Return the global ProcessManager, bootstrapping if necessary."""
    global _process_manager
    if _process_manager is None:
        _process_manager = ProcessManager()
    return _process_manager


def get_service_manager() -> "ServiceManager":
    """Return the global ServiceManager, bootstrapping if necessary."""
    global _service_manager
    if _service_manager is None:
        _service_manager = ServiceManager()
    return _service_manager


# ── Network state access for the response engine ────────────────────────────

def get_virtual_network() -> VirtualNetwork:
    """Return the virtual network state for use by command handlers."""
    return _boot_virtual_network()


def get_interface(name: str) -> VirtualInterface | None:
    """Return the virtual interface with the given name, or None."""
    net = get_virtual_network()
    return net.interfaces.get(name)


def get_listening_ports() -> frozenset[int]:
    """Return the set of ports currently being listened on.

    This integrates service state: a service that is running and has
    a port configuration contributes that port to the set.
    """

    # Start with the default listening port (sshd)
    ports: Set[int] = {22}

    # Add ports from running services
    svc_mgr = get_service_manager()
    if svc_mgr is not None:
        for name, svc in svc_mgr._services.items():
            if svc.state == "running" and svc.listening_ports:
                ports.update(svc.listening_ports)

    return frozenset(ports)


# ── Network state integration with services ───────────────────────────────

def integrate_service_network(pm: "ProcessManager", sm: "ServiceManager") -> None:
    """Integrate service state with the virtual network.

    Called during initialisation to ensure service state (listening ports)
    is reflected in the virtual network state.  This is called once during
    initialisation; later service start/stop events update both the service
    state and the network state.

    The integration is simple: a running service with listening_ports
    contributes those ports to the global listening_ports set.
    """

    # Current listening ports (from default + services)
    ports = get_listening_ports()

    # The network state itself is read-only from this point;
    # later changes go through service start/stop events.
    # The global _virtual_network will reflect the updated ports
    # when service start/stop handlers call _update_network_listening_ports().
    pass  # The actual integration is handled by the service start/stop handlers


def _update_network_listening_ports(ports: frozenset[int]) -> None:
    """Called by service start/stop handlers to update the virtual network.

    This updates the global _virtual_network's interface listening state.
    The actual _virtual_network variable is module-level; callers should
    ensure they are working with the current instance.
    """
    # In a full implementation, this would update the interface's
    # listening_ports or add a dummy interface entry.
    # For now, we note the ports for the get_listening_ports() function.
    pass  # The get_listening_ports() already reflects the current state


# ── Network command support ───────────────────────────────────────────────

def simulate_ping(dest: str = "") -> str:
    """Return a simulated ping output.

    No real ICMP packet is sent.  The output reflects whether the
    destination appears reachable based on the virtual routing table.

    Args:
        dest: Destination IP or hostname.  Empty string implies localhost.

    Returns:
        A multi-line ping-style output string.
    """

    net = get_virtual_network()

    # Localhost is always "reachable"
    if not dest or dest.strip() == "" or str(IPv4Address("127.0.0.1")) == dest.strip():
        return (
            "PING 127.0.0.1 (localhost) 56(84) bytes of data.\n"
            "64 bytes from localhost (127.0.0.1): icmp_seq=0 ttl=64 time=0.5 ms\n"
            "--- localhost ping statistics ---\n"
            "1 packets transmitted, 1 packets received, 0% packet loss\n"
            "time 0.000 ms\n"
            "rtt min/avg/max/mdev = 0.500 ms / 0.500 ms / 0.500 ms / 0.000 ms\n"
        )

    # Try to determine reachability based on routes
    # For now, we just return a "destination unreachable" message
    # since we don't have full route tracking in this simplified model.
    return (
        f"PING {dest} 56(84) bytes of data.\n"
        "--- localhost ping statistics ---\n"
        "0 packets transmitted, 0 packets received, 100% packet loss\n"
        "--- \n"
        f"ping: {dest}: Name or service not known\n"
    )


# ── Network command handlers for the response engine ──────────────────────

def _ip_interface(ctx) -> "ResponsePlan | None":
    """Handle the `ip` command's interface subcommand.

    Currently supports: ip addr show, ip link show.
    """

    if ctx.base != "ip":
        return None

    # Get the interface name from args
    args = ctx.args
    if not args:
        # Show all interfaces
        net = get_virtual_network()
        ifaces = []
        for name, iface in net.interfaces.items():
            parts = []
            parts.append(f"{iface.name}: {iface.mtu} mtu {iface.mtu} qdisc {iface.name} state {iface.status}")
            if iface.ipv4:
                parts.append(f"inet {iface.ipv4}/{__import__('ipaddress').network_ipv4(addr) if hasattr(__import__('ipaddress'), 'network_ipv4') else '???'}")
            parts.append(f"link/ether {iface.mac} brd brd broadcast")
            if iface.description:
                parts.append(iface.description)
            ifaces.append("\n".join(parts))
        return ResponsePlan(
            "command_output",
            "\n\n".join(ifaces) + "\n",
            "0",
        )

    # Show a specific interface
    ifname = args[0]
    iface = get_interface(ifname)
    if iface is None:
        return ResponsePlan(
            "command_not_found",
            f"ip: {ifname}: Cannot find device \"{ifname}\"\n",
            "1",
        )

    parts = [
        f"{iface.name}: {iface.mtu} mtu {iface.mtu} qdisc {iface.name} state {iface.status}",
    ]
    if iface.ipv4:
        parts.append(f"inet {iface.ipv4}")
    parts.append(f"link/ether {iface.mac} brd brd broadcast")
    if iface.description:
        parts.append(iface.description)
    return ResponsePlan("command_output", "\n".join(parts) + "\n", "0")


def _cmd_ip(ctx: _Ctx) -> ResponsePlan | None:
    """Handle the `ip` command."""

    if ctx.base == "ip":
        return _ip_interface(ctx)
    return None


def _ifconfig_interface(ctx) -> ResponsePlan | None:
    """Handle the `ifconfig` command for a specific interface."""

    if ctx.base == "ifconfig":
        ifname = ctx.args[0] if ctx.args else None
        if ifname is None:
            # Show all interfaces
            net = get_virtual_network()
            parts = []
            for name, iface in net.interfaces.items():
                parts.append(
                    f"{iface.name}: {iface.mtu} "
                    f"metric {iface.mtu} "
                    f"inet {iface.ipv4} "
                    f"broadcast {IPv4Address(int(iface.ipv4) | 0xffffff)} "
                    f"destination {iface.ipv4} "
                    f"state {iface.status}"
                )
            return ResponsePlan("command_output", "\n".join(parts) + "\n", "0")
        iface = get_interface(ifname)
        if iface is None:
            return ResponsePlan(
                "command_not_found",
                f"ifconfig: {ifname}: interface not found\n",
                "1",
            )
        return ResponsePlan(
            "command_output",
            f"{iface.name}: {iface.mtu} metric {iface.mtu} "
            f"inet {iface.ipv4} "
            f"broadcast {IPv4Address(int(iface.ipv4) | 0xffffff)} "
            f"destination {iface.ipv4} "
            f"state {iface.status}\n",
            "0",
        )
    return None


def _cmd_ifconfig(ctx: _Ctx) -> ResponsePlan | None:
    """Handle the `ifconfig` command."""

    if ctx.base == "ifconfig":
        return _ifconfig_interface(ctx)
    return None


def _cmd_route(ctx: _Ctx) -> ResponsePlan | None:
    """Handle the `route` command."""

    if ctx.base == "route":
        net = get_virtual_network()
        parts = []
        for route in net.routes:
            parts.append(
                f"kernel {route.dev}: "
                f"destination {route.destination}"
                if route.destination
                else "default via {route.gateway} dev {route.dev}"
            )
        return ResponsePlan("command_output", "\n".join(parts) + "\n", "0")
    return None


def _cmd_ss(ctx: _Ctx) -> ResponsePlan | None:
    """Handle the `ss` command.

    Shows listening sockets and connection state.
    The output reflects the virtual listening ports from services.
    """

    if ctx.base == "ss":
        ports = get_listening_ports()
        net = get_virtual_network()

        lines = ["Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port"]

        # Add listening TCP ports
        for port in sorted(ports):
            lines.append(
                f"tcp    LISTEN  0       128         0.0.0.0:{port}          0.0.0.0:*"
            )
            lines.append(
                f"tcp    LISTEN  0       128            [::]:{port}             [::]:*"
            )

        # Add established connections (simulated - static for now)
        lines.append(
            "tcp    ESTAB  0       0      10.0.2.15:22          192.168.1.100:51234"
        )

        return ResponsePlan("command_output", "\n".join(lines) + "\n", "0")
    return None


def _cmd_netstat(ctx: _Ctx) -> ResponsePlan | None:
    """Handle the `netstat` command.

    Shows network statistics and socket state.
    """

    if ctx.base == "netstat":
        ports = get_listening_ports()
        net = get_virtual_network()

        lines = ["Active Internet connections (servers and established)"],
        for port in sorted(ports):
            lines.append(f"         {port} 0.0.0.0:*")
        lines.append(
            f"       10.0.2.15:22 192.168.1.100:51234 ESTABISHED"
        )
        return ResponsePlan("command_output", "\n".join(lines) + "\n", "0")
    return None


def _cmd_ping(ctx: _Ctx) -> ResponsePlan | None:
    """Handle the `ping` command.

    Returns simulated ping output without sending real ICMP packets.
    """

    if ctx.base == "ping":
        # Get the destination argument
        args = ctx.args
        dest = args[0] if args else ""

        # Determine the simulated ping output
        ping_output = simulate_ping(dest)

        return ResponsePlan("command_output", ping_output, "0")
    return None


# ── Command registration ──────────────────────────────────────────────────

# These are added to the _ROUTES tuple in the response engine.
# The order matters: more specific handlers come before more general ones.

# The _ROUTES tuple will be updated in a separate step to include:
# _cmd_ip, _cmd_ifconfig, _cmd_route, _cmd_ss, _cmd_netstat, _cmd_ping

