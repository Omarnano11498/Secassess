"""Scope enforcement tests."""

from __future__ import annotations

import pytest

from secassess.errors import ScopeError
from secassess.scope import (
    ScopePolicy,
    address_in_scope,
    is_public,
    parse_target,
    resolve_to_addresses,
)


@pytest.fixture
def policy() -> ScopePolicy:
    return ScopePolicy.build(
        ["192.0.2.0/24", "10.0.0.0/16", "2001:db8::/48"], ["web01.example.com"], max_hosts=300
    )


def test_ip_and_cidr_inside_scope(policy: ScopePolicy) -> None:
    targets = policy.validate(["192.0.2.10", "10.0.5.0/24", "2001:db8::1"])
    assert [t.display for t in targets] == ["192.0.2.10", "10.0.5.0/24", "2001:db8::1"]


def test_host_bits_are_normalized(policy: ScopePolicy) -> None:
    (t,) = policy.validate(["10.0.5.77/28"])
    assert t.display == "10.0.5.64/28"


@pytest.mark.parametrize(
    "target", ["192.0.3.1", "10.1.0.0/16", "10.0.0.0/15", "8.8.8.8", "2001:db9::1", "192.168.50.1"]
)
def test_out_of_scope_rejected(policy: ScopePolicy, target: str) -> None:
    with pytest.raises(ScopeError):
        policy.validate([target])


@pytest.mark.parametrize(
    "target",
    [
        "-sS",
        "--script=vuln",
        "10.0.0.1 10.0.0.2",
        "10.0.0.1,2",
        "",
        "bad_host!",
        "10.0.0.256",
        "1.2.3",
        "a..b",
    ],
)
def test_malformed_targets_rejected(policy: ScopePolicy, target: str) -> None:
    with pytest.raises(ScopeError):
        policy.validate([target])


def test_unlisted_hostname_rejected(policy: ScopePolicy) -> None:
    with pytest.raises(ScopeError, match="not listed"):
        policy.validate(["other.example.com"])


def test_hostname_case_and_trailing_dot(policy: ScopePolicy) -> None:
    (t,) = policy.validate(["WEB01.example.com."])
    assert t.hostname == "web01.example.com"


def test_public_rejected_even_if_in_allowed_cidrs() -> None:
    p = ScopePolicy.build(["8.8.8.0/24"])
    with pytest.raises(ScopeError, match="publicly routable"):
        p.validate(["8.8.8.8"])
    p_ok = ScopePolicy.build(["8.8.8.0/24"], allow_public_targets=True)
    assert p_ok.validate(["8.8.8.8"])[0].display == "8.8.8.8"


def test_special_ranges_rejected() -> None:
    for cidr in ["224.0.0.0/24", "0.0.0.0/8", "240.0.0.0/8", "0.0.0.0/0"]:
        with pytest.raises(ScopeError):
            ScopePolicy.build([cidr])


def test_empty_scope_rejected() -> None:
    with pytest.raises(ScopeError, match="empty"):
        ScopePolicy.build([])


def test_max_hosts_enforced(policy: ScopePolicy) -> None:
    with pytest.raises(ScopeError, match="max_hosts"):
        policy.validate(["10.0.0.0/23"])


def test_no_targets(policy: ScopePolicy) -> None:
    with pytest.raises(ScopeError):
        policy.validate([])


def test_hostname_resolution_rechecked(policy: ScopePolicy) -> None:
    targets = policy.validate(["web01.example.com", "192.0.2.5"])
    ok = resolve_to_addresses(policy, targets, lambda _h: ["10.0.1.2"])
    assert ok == ["10.0.1.2", "192.0.2.5"]
    with pytest.raises(ScopeError, match="outside scope"):
        resolve_to_addresses(policy, targets, lambda _h: ["10.0.1.2", "93.184.216.34"])


def test_address_in_scope_defense(policy: ScopePolicy) -> None:
    assert address_in_scope(policy, "10.0.3.3")
    assert not address_in_scope(policy, "203.0.113.5")
    assert not address_in_scope(policy, "not-an-ip")


def test_fingerprint_binds_targets(policy: ScopePolicy) -> None:
    a = policy.fingerprint(policy.validate(["10.0.0.1"]))
    b = policy.fingerprint(policy.validate(["10.0.0.2"]))
    assert a != b and len(a) == 12
    assert a == policy.fingerprint(policy.validate(["10.0.0.1"]))


def test_is_public() -> None:
    assert is_public(parse_target("8.8.8.8").network)  # type: ignore[arg-type]
    assert not is_public(parse_target("192.0.2.1").network)  # type: ignore[arg-type]
    assert is_public(parse_target("10.0.0.0/7").network)  # type: ignore[arg-type]
