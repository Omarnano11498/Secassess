"""Target parsing, normalization and authorization-scope enforcement.

Rules enforced here (all must pass before any active check):

* A target is an IP address, a CIDR network or an RFC 1123 hostname. Anything else
  (including strings that start with ``-`` and could be read as tool options) is rejected.
* An IP/CIDR target must be fully contained in one of the configured ``allowed_cidrs``.
* A hostname must be listed verbatim in ``allowed_hostnames`` and, at resolution time,
  every address it resolves to must also lie inside ``allowed_cidrs``.
* Publicly routable addresses are rejected unless ``allow_public_targets = true`` is set
  in the configuration *and* the address is inside an allowed CIDR.
* Multicast, unspecified, reserved and broadcast-style targets are always rejected.
* The total number of expanded hosts is bounded by ``max_hosts``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from secassess.errors import ScopeError

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# RFC 5737 / RFC 3849 documentation ranges. Safe for examples; never routed on the Internet.
DOCUMENTATION_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
HARD_MAX_HOSTS = 65536


def is_documentation(net: IPNetwork) -> bool:
    """True if ``net`` lies entirely inside a documentation-only range."""
    return any(net.version == d.version and net.subnet_of(d) for d in DOCUMENTATION_NETWORKS)  # type: ignore[arg-type]


NON_PUBLIC_NETWORKS: tuple[IPNetwork, ...] = (
    *DOCUMENTATION_NETWORKS,
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


def is_public(net: IPNetwork) -> bool:
    """True unless ``net`` lies entirely inside one well-known non-public block."""
    return not any(
        net.version == block.version and net.subnet_of(block)  # type: ignore[arg-type]
        for block in NON_PUBLIC_NETWORKS
    )


def validate_hostname(name: str) -> str:
    """Validate an RFC 1123 hostname and return it lower-cased without a trailing dot."""
    candidate = name.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        raise ScopeError(f"invalid hostname length: {name!r}")
    labels = candidate.split(".")
    if not all(_HOST_LABEL.match(label) for label in labels):
        raise ScopeError(f"invalid hostname: {name!r}")
    if labels[-1].isdigit():
        raise ScopeError(f"hostname has a numeric top-level label (malformed IP?): {name!r}")
    return candidate


@dataclass(frozen=True, slots=True)
class Target:
    """A normalized target: either a network (single IPs are /32 or /128) or a hostname."""

    raw: str
    network: IPNetwork | None = None
    hostname: str | None = None

    @property
    def display(self) -> str:
        """Canonical string form."""
        if self.network is not None:
            if self.network.num_addresses == 1:
                return str(self.network.network_address)
            return str(self.network)
        return str(self.hostname)


def parse_target(raw: str) -> Target:
    """Parse and normalize one operator-supplied target string."""
    if not isinstance(raw, str):
        raise ScopeError("target must be a string")
    text = raw.strip()
    if not text:
        raise ScopeError("empty target")
    if text.startswith("-"):
        raise ScopeError(f"target may not start with '-': {raw!r}")
    if any(ch.isspace() for ch in text) or "," in text:
        raise ScopeError(f"one target per value; whitespace/commas not allowed: {raw!r}")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        if "/" in text or ":" in text:
            raise ScopeError(f"malformed IP/CIDR target: {raw!r}") from None
        return Target(raw=raw, hostname=validate_hostname(text))
    # Host bits (e.g. 10.0.0.5/24) are normalized to the network; the scope preview shows the
    # normalized form so the operator sees exactly what will be covered.
    return Target(raw=raw, network=net)


@dataclass(slots=True)
class ScopePolicy:
    """The operator-approved authorization scope."""

    allowed_networks: list[IPNetwork]
    allowed_hostnames: set[str] = field(default_factory=set)
    allow_public_targets: bool = False
    max_hosts: int = 256

    @classmethod
    def build(
        cls,
        allowed_cidrs: Iterable[str],
        allowed_hostnames: Iterable[str] = (),
        allow_public_targets: bool = False,
        max_hosts: int = 256,
    ) -> ScopePolicy:
        """Validate raw configuration values and build a policy."""
        networks: list[IPNetwork] = []
        for cidr in allowed_cidrs:
            try:
                net = ipaddress.ip_network(str(cidr).strip(), strict=True)
            except ValueError as exc:
                raise ScopeError(f"invalid allowed CIDR {cidr!r}: {exc}") from exc
            _reject_special(net, context="allowed CIDR")
            if net.prefixlen == 0:
                raise ScopeError(f"allowed CIDR {cidr!r} covers the entire address space")
            networks.append(net)
        if not networks:
            raise ScopeError(
                "scope.allowed_cidrs is empty; at least one approved range is required"
            )
        if not 1 <= int(max_hosts) <= HARD_MAX_HOSTS:
            raise ScopeError(f"max_hosts must be between 1 and {HARD_MAX_HOSTS}")
        hostnames = {validate_hostname(h) for h in allowed_hostnames}
        return cls(networks, hostnames, bool(allow_public_targets), int(max_hosts))

    def contains_network(self, net: IPNetwork) -> bool:
        """True if ``net`` is fully contained in an allowed network of the same IP version."""
        return any(
            net.version == allowed.version and net.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in self.allowed_networks
        )

    def check_network(self, net: IPNetwork, raw: str) -> None:
        """Raise ScopeError unless ``net`` may be assessed."""
        _reject_special(net, context=f"target {raw!r}")
        if not self.contains_network(net):
            raise ScopeError(f"target {raw!r} ({net}) is outside the approved scope")
        if is_public(net) and not self.allow_public_targets:
            raise ScopeError(
                f"target {raw!r} is publicly routable; set scope.allow_public_targets = true "
                "only if you are explicitly authorized to assess it"
            )

    def validate(self, targets: Sequence[str]) -> list[Target]:
        """Parse all targets and ensure each is inside the scope. Fails closed on any error."""
        if not targets:
            raise ScopeError("no targets supplied")
        parsed: list[Target] = []
        seen: set[str] = set()
        total = 0
        for raw in targets:
            target = parse_target(raw)
            if target.network is not None:
                self.check_network(target.network, raw)
                total += _host_count(target.network)
            else:
                if target.hostname is None:  # pragma: no cover - parse_target guarantees one
                    raise ScopeError(f"internal error: empty target {raw!r}")
                if target.hostname not in self.allowed_hostnames:
                    raise ScopeError(
                        f"hostname {target.hostname!r} is not listed in scope.allowed_hostnames"
                    )
                total += 1
            if target.display not in seen:
                seen.add(target.display)
                parsed.append(target)
        if total > self.max_hosts:
            raise ScopeError(
                f"targets expand to {total} hosts, above scope.max_hosts={self.max_hosts}"
            )
        return parsed

    def fingerprint(self, targets: Sequence[Target]) -> str:
        """Short stable ID binding a confirmation to this exact scope and target list."""
        payload = json.dumps(
            {
                "allowed": sorted(str(n) for n in self.allowed_networks),
                "hostnames": sorted(self.allowed_hostnames),
                "public": self.allow_public_targets,
                "targets": sorted(t.display for t in targets),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]


Resolver = Callable[[str], list[str]]


def system_resolver(hostname: str) -> list[str]:
    """Resolve a hostname to unique IP strings using the OS resolver (generates DNS traffic)."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ScopeError(f"could not resolve {hostname!r}: {exc}") from exc
    return sorted({str(info[4][0]) for info in infos})


def resolve_to_addresses(
    policy: ScopePolicy, targets: Sequence[Target], resolver: Resolver = system_resolver
) -> list[str]:
    """Expand targets into the exact address list handed to the scanner.

    Hostnames are resolved here, once, and every resolved address is re-checked against the
    scope. Scanners then receive only IPs, which prevents DNS changes from widening the scope.
    """
    out: list[str] = []
    for target in targets:
        if target.network is not None:
            out.append(target.display)
            continue
        if target.hostname is None:  # pragma: no cover - parse_target guarantees one
            raise ScopeError(f"internal error: empty target {target.raw!r}")
        addresses = resolver(target.hostname)
        if not addresses:
            raise ScopeError(f"{target.hostname!r} resolved to no addresses")
        for addr in addresses:
            net = ipaddress.ip_network(addr)
            try:
                policy.check_network(net, f"{target.hostname} -> {addr}")
            except ScopeError as exc:
                raise ScopeError(f"hostname resolves outside scope: {exc}") from exc
            out.append(addr)
    return sorted(set(out), key=_sort_key)


def address_in_scope(policy: ScopePolicy, address: str) -> bool:
    """Defense in depth: check a single address reported back by a scanner."""
    try:
        net = ipaddress.ip_network(address)
        policy.check_network(net, address)
    except (ValueError, ScopeError):
        return False
    return True


def _reject_special(net: IPNetwork, context: str) -> None:
    addr = net.network_address
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        raise ScopeError(f"{context} is a multicast/unspecified/reserved range: {net}")
    if isinstance(net, ipaddress.IPv4Network) and net.overlaps(
        ipaddress.ip_network("255.255.255.255/32")
    ):
        raise ScopeError(f"{context} includes the limited broadcast address")


def _host_count(net: IPNetwork) -> int:
    if net.num_addresses > HARD_MAX_HOSTS:
        return HARD_MAX_HOSTS + 1
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 31:
        return net.num_addresses - 2
    return net.num_addresses


def _sort_key(value: str) -> tuple[int, int | str]:
    try:
        ip = ipaddress.ip_address(value)
        return (ip.version, int(ip))
    except ValueError:
        net = ipaddress.ip_network(value)
        return (net.version, int(net.network_address))
