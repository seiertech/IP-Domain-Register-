"""The register: persistent, versioned store of enriched assets + change detection.

The register is a plain JSON document so it lives cleanly in Git. Change detection
is a structural diff between the previously saved register and a freshly scanned one,
which is what makes the register "always up to date" and auditable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Register:
    """In-memory representation of the register document."""

    ip_ranges: dict[str, Any] = field(default_factory=dict)
    domains: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=_now)

    # ------------------------------------------------------------------ IO
    @classmethod
    def load(cls, path: str | Path) -> "Register":
        path = Path(path)
        if not path.exists():
            return cls(ip_ranges={}, domains={}, generated_at=_now())
        data = json.loads(path.read_text() or "{}")
        return cls(
            ip_ranges=data.get("ip_ranges", {}),
            domains=data.get("domains", {}),
            generated_at=data.get("generated_at", _now()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "ip_ranges": self.ip_ranges,
            "domains": self.domains,
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # sort_keys keeps the JSON stable so Git diffs stay meaningful.
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")


# ----------------------------------------------------------------------- diff
@dataclass
class Change:
    kind: str          # "added" | "removed" | "modified"
    category: str      # "ip_range" | "host" | "domain" | "subdomain"
    identifier: str    # what changed
    detail: str = ""   # human-readable summary of the change


def _flatten(prefix: str, obj: Any, out: dict[str, Any]) -> None:
    """Flatten a nested dict into dotted paths -> scalar values for field-level diff."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out)
    elif isinstance(obj, list):
        out[prefix] = ", ".join(sorted(str(x) for x in obj))
    else:
        out[prefix] = obj


def _diff_entry(old: Any, new: Any) -> list[str]:
    """Return field-level change descriptions between two enrichment entries."""
    old_flat: dict[str, Any] = {}
    new_flat: dict[str, Any] = {}
    _flatten("", old, old_flat)
    _flatten("", new, new_flat)
    changes: list[str] = []
    for key in sorted(set(old_flat) | set(new_flat)):
        ov, nv = old_flat.get(key), new_flat.get(key)
        if ov != nv:
            changes.append(f"{key}: {ov!r} -> {nv!r}")
    return changes


def diff(old: Register, new: Register) -> list[Change]:
    """Structural diff between two registers. This is the heart of drift detection."""
    changes: list[Change] = []

    # --- IP ranges + their hosts
    for cidr in sorted(set(old.ip_ranges) | set(new.ip_ranges)):
        o = old.ip_ranges.get(cidr)
        n = new.ip_ranges.get(cidr)
        if o is None:
            changes.append(Change("added", "ip_range", cidr))
            continue
        if n is None:
            changes.append(Change("removed", "ip_range", cidr))
            continue
        o_hosts = o.get("hosts", {})
        n_hosts = n.get("hosts", {})
        for ip in sorted(set(o_hosts) | set(n_hosts)):
            oh, nh = o_hosts.get(ip), n_hosts.get(ip)
            if oh is None:
                changes.append(Change("added", "host", ip, str(nh.get("ptr", ""))))
            elif nh is None:
                changes.append(Change("removed", "host", ip))
            else:
                for d in _diff_entry(oh, nh):
                    changes.append(Change("modified", "host", ip, d))

    # --- Domains + their subdomains
    for dom in sorted(set(old.domains) | set(new.domains)):
        o = old.domains.get(dom)
        n = new.domains.get(dom)
        if o is None:
            changes.append(Change("added", "domain", dom))
            continue
        if n is None:
            changes.append(Change("removed", "domain", dom))
            continue
        # compare everything except the subdomains subtree at the field level
        o_top = {k: v for k, v in o.items() if k != "subdomains"}
        n_top = {k: v for k, v in n.items() if k != "subdomains"}
        for d in _diff_entry(o_top, n_top):
            changes.append(Change("modified", "domain", dom, d))
        # subdomains
        o_subs = o.get("subdomains", {})
        n_subs = n.get("subdomains", {})
        for sub in sorted(set(o_subs) | set(n_subs)):
            os_, ns_ = o_subs.get(sub), n_subs.get(sub)
            if os_ is None:
                changes.append(Change("added", "subdomain", sub, str(ns_.get("status", ""))))
            elif ns_ is None:
                changes.append(Change("removed", "subdomain", sub))
            else:
                for d in _diff_entry(os_, ns_):
                    changes.append(Change("modified", "subdomain", sub, d))

    return changes
