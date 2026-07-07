"""Shared DNS helpers (a single configured resolver used across enrichers)."""

from __future__ import annotations

import dns.resolver
import dns.reversename


def make_resolver(resolvers: list[str], timeout: int) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(resolvers)
    r.timeout = timeout
    r.lifetime = timeout
    return r


def query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    """Return record values for name/rdtype, or [] on any failure (NXDOMAIN, timeout...)."""
    try:
        answers = resolver.resolve(name, rdtype)
    except Exception:
        return []
    return sorted(r.to_text().strip('"') for r in answers)


def reverse_dns(resolver: dns.resolver.Resolver, ip: str) -> str | None:
    """PTR record for an IP, or None."""
    try:
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:
        return None
