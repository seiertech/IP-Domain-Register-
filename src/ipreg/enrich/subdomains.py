"""Subdomain discovery.

Passive (default): Certificate Transparency logs via crt.sh — finds every hostname
that has ever had a TLS certificate issued. Zero traffic to the target.

Active (opt-in): DNS brute-force against a wordlist — finds hosts that never got a
cert. Generates lookup traffic, so it only runs when explicitly requested.

Every discovered name is then resolved to determine live/dead status and whether it
points back into an owned IP range.
"""

from __future__ import annotations

from typing import Any

import dns.resolver
import requests

from .dns_tools import query

CRTSH_URL = "https://crt.sh/"

# Small built-in wordlist for active mode; can be extended via a file later.
DEFAULT_WORDLIST = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "vpn", "remote", "portal",
    "api", "dev", "staging", "stage", "test", "uat", "qa", "app", "apps",
    "admin", "cpanel", "autodiscover", "ns1", "ns2", "mx", "gw", "git",
    "jira", "confluence", "jenkins", "grafana", "kibana", "cloud", "cdn",
    "static", "assets", "img", "files", "ftp", "sftp", "db", "sql", "backup",
]


def from_crtsh(domain: str, timeout: int) -> set[str]:
    """Return the set of unique (sub)domains seen in CT logs for `domain`."""
    found: set[str] = set()
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "ip-domain-register/0.1"},
        )
        resp.raise_for_status()
        for row in resp.json():
            name_value = row.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    found.add(name)
    except Exception:
        # Passive source unreachable / malformed — return whatever we have.
        pass
    return found


def from_bruteforce(domain: str, resolver: dns.resolver.Resolver, wordlist: list[str]) -> set[str]:
    found: set[str] = set()
    for word in wordlist:
        candidate = f"{word}.{domain}"
        if query(resolver, candidate, "A"):
            found.add(candidate)
    return found


def resolve_status(
    subdomain: str,
    resolver: dns.resolver.Resolver,
    ip_in_owned_ranges,
) -> dict[str, Any]:
    a = query(resolver, subdomain, "A")
    cname = query(resolver, subdomain, "CNAME")
    live = bool(a)
    in_range = live and all(ip_in_owned_ranges(ip) for ip in a)
    return {
        "status": "live" if live else "dead",
        "ips": a,
        "cname": cname,
        "in_owned_range": in_range if live else None,
    }


def discover_subdomains(
    domain: str,
    resolver: dns.resolver.Resolver,
    ip_in_owned_ranges,
    crtsh_timeout: int,
    active: bool = False,
    wordlist: list[str] | None = None,
) -> dict[str, Any]:
    names = from_crtsh(domain, crtsh_timeout)
    if active:
        names |= from_bruteforce(domain, resolver, wordlist or DEFAULT_WORDLIST)
    names.discard(domain)  # the root domain is tracked separately

    return {
        name: resolve_status(name, resolver, ip_in_owned_ranges)
        for name in sorted(names)
    }
