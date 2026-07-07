"""IP-level enrichment: RDAP/WHOIS ownership + reverse DNS."""

from __future__ import annotations

import ipaddress
from typing import Any

import dns.resolver
from ipwhois import IPWhois

from .dns_tools import reverse_dns


def rdap_lookup(ip: str) -> dict[str, Any]:
    """RDAP lookup for an IP: netblock owner, ASN, abuse contact.

    Returns a compact, register-friendly dict. On failure returns {"error": ...}
    so a single unreachable IP never aborts a whole scan.
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
    except Exception as exc:  # network error, rate limit, no data...
        return {"error": str(exc)}

    network = res.get("network") or {}
    # Find an abuse email if present in the entity objects.
    abuse = None
    for entity in (res.get("objects") or {}).values():
        contact = entity.get("contact") or {}
        roles = entity.get("roles") or []
        if "abuse" in roles:
            emails = contact.get("email") or []
            if emails:
                abuse = emails[0].get("value")
                break

    return {
        "asn": res.get("asn"),
        "asn_description": res.get("asn_description"),
        "asn_country_code": res.get("asn_country_code"),
        "network_name": network.get("name"),
        "network_cidr": network.get("cidr"),
        "network_country": network.get("country"),
        "registry": res.get("asn_registry"),
        "abuse_contact": abuse,
    }


def enrich_ip(ip: str, resolver: dns.resolver.Resolver) -> dict[str, Any]:
    return {
        "ptr": reverse_dns(resolver, ip),
        "rdap": rdap_lookup(ip),
    }


def hosts_in_network(cidr: str, cap: int) -> list[str]:
    """Usable host addresses in a network, capped at `cap` to keep scans bounded."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts_iter = net.hosts() if net.num_addresses > 2 else iter([net.network_address])
    out: list[str] = []
    for host in hosts_iter:
        out.append(str(host))
        if len(out) >= cap:
            break
    return out
