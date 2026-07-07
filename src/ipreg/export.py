"""CSV export of the register.

Deliberately simple: reads the already-built register and flattens it into three
spreadsheet-friendly CSV files (hosts, domains, subdomains). Uses only the stdlib
`csv` module and adds nothing to the scan pipeline.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .register import Register


def _join(values) -> str:
    if isinstance(values, list):
        return "; ".join(str(v) for v in values)
    return "" if values is None else str(values)


def _write(path: Path, header: list[str], rows: list[list]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _hosts_rows(reg: Register) -> list[list]:
    rows = []
    for cidr, r in sorted(reg.ip_ranges.items()):
        for ip, h in sorted(r.get("hosts", {}).items()):
            rdap = h.get("rdap", {})
            rows.append([
                cidr, ip, h.get("ptr", ""),
                rdap.get("asn", ""), rdap.get("asn_description", ""),
                rdap.get("network_name", ""), rdap.get("registry", ""),
                rdap.get("abuse_contact", ""), rdap.get("error", ""),
            ])
    return rows


def _domain_rows(reg: Register) -> list[list]:
    rows = []
    for dom, d in sorted(reg.domains.items()):
        w = d.get("whois", {})
        dns = d.get("dns", {})
        rows.append([
            dom, d.get("resolves", ""), d.get("validation", ""),
            _join(d.get("resolves_to")), w.get("registrar", ""),
            w.get("expiry", ""), w.get("days_to_expiry", ""),
            w.get("expiring_soon", ""), _join(dns.get("NS")), _join(dns.get("MX")),
        ])
    return rows


def _subdomain_rows(reg: Register) -> list[list]:
    rows = []
    for dom, d in sorted(reg.domains.items()):
        for sub, s in sorted(d.get("subdomains", {}).items()):
            rows.append([
                dom, sub, s.get("status", ""), _join(s.get("ips")),
                _join(s.get("cname")), s.get("in_owned_range", ""),
            ])
    return rows


def export_csv(reg: Register, out_dir: str | Path) -> list[Path]:
    """Write hosts.csv, domains.csv and subdomains.csv into out_dir. Returns the paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    hosts = out / "hosts.csv"
    domains = out / "domains.csv"
    subs = out / "subdomains.csv"

    _write(hosts, ["cidr", "ip", "ptr", "asn", "asn_description",
                   "network_name", "registry", "abuse_contact", "error"],
           _hosts_rows(reg))
    _write(domains, ["domain", "resolves", "validation", "resolves_to", "registrar",
                     "expiry", "days_to_expiry", "expiring_soon", "ns", "mx"],
           _domain_rows(reg))
    _write(subs, ["parent_domain", "subdomain", "status", "ips", "cname", "in_owned_range"],
           _subdomain_rows(reg))

    return [hosts, domains, subs]
