"""Domain-level enrichment: WHOIS (registrar/expiry), DNS records, ownership validation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import dns.resolver
import whois

from .dns_tools import query

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "CNAME"]


def _to_iso(value: Any) -> str | None:
    """WHOIS libraries return datetime | list[datetime] | str | None. Normalise it."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc).isoformat()
    return str(value)


def domain_whois(domain: str, expiry_warning_days: int) -> dict[str, Any]:
    try:
        w = whois.whois(domain)
    except Exception as exc:
        return {"error": str(exc)}

    expiry_iso = _to_iso(w.expiration_date)
    days_to_expiry = None
    expiring_soon = False
    if expiry_iso:
        try:
            exp_dt = datetime.fromisoformat(expiry_iso)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days_to_expiry = (exp_dt - datetime.now(timezone.utc)).days
            expiring_soon = 0 <= days_to_expiry <= expiry_warning_days
        except ValueError:
            pass

    registrar = w.registrar
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    return {
        "registrar": registrar,
        "created": _to_iso(w.creation_date),
        "updated": _to_iso(w.updated_date),
        "expiry": expiry_iso,
        "days_to_expiry": days_to_expiry,
        "expiring_soon": expiring_soon,
        "registrant_org": w.get("org") if isinstance(w, dict) else getattr(w, "org", None),
        "status": w.status if not isinstance(w.status, list) else sorted(set(w.status)),
    }


def dns_records(domain: str, resolver: dns.resolver.Resolver) -> dict[str, list[str]]:
    return {rt: query(resolver, domain, rt) for rt in RECORD_TYPES}


def enrich_domain(
    domain: str,
    resolver: dns.resolver.Resolver,
    expiry_warning_days: int,
    ip_in_owned_ranges,
) -> dict[str, Any]:
    records = dns_records(domain, resolver)
    a_records = records.get("A", [])
    in_range = bool(a_records) and all(ip_in_owned_ranges(ip) for ip in a_records)
    partial = bool(a_records) and any(ip_in_owned_ranges(ip) for ip in a_records)

    if not a_records:
        validation = "no_a_record"
    elif in_range:
        validation = "in_owned_range"
    elif partial:
        validation = "partially_in_range"
    else:
        validation = "out_of_range"

    return {
        "resolves": bool(a_records),
        "resolves_to": a_records,
        "validation": validation,
        "dns": records,
        "whois": domain_whois(domain, expiry_warning_days),
    }
