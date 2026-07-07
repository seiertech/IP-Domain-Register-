"""Loading and validation of the owned-asset inventory (input config)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Settings:
    max_ips_per_range: int = 256
    resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    expiry_warning_days: int = 45
    timeout: int = 10          # per-lookup timeout for fast DNS/RDAP queries
    crtsh_timeout: int = 45    # crt.sh (CT logs) is slow; give it its own budget


@dataclass
class AssetConfig:
    ip_ranges: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)

    @classmethod
    def load(cls, path: str | Path) -> "AssetConfig":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Asset config not found: {path}")
        data = yaml.safe_load(path.read_text()) or {}

        raw_settings = data.get("settings") or {}
        settings = Settings(
            max_ips_per_range=int(raw_settings.get("max_ips_per_range", 256)),
            resolvers=list(raw_settings.get("resolvers", ["1.1.1.1", "8.8.8.8"])),
            expiry_warning_days=int(raw_settings.get("expiry_warning_days", 45)),
            timeout=int(raw_settings.get("timeout", 10)),
            crtsh_timeout=int(raw_settings.get("crtsh_timeout", 45)),
        )

        cfg = cls(
            ip_ranges=[str(r).strip() for r in (data.get("ip_ranges") or [])],
            domains=[str(d).strip().lower() for d in (data.get("domains") or [])],
            settings=settings,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        for r in self.ip_ranges:
            try:
                ipaddress.ip_network(r, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid IP range in config: {r!r} ({exc})") from exc

    def networks(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(r, strict=False) for r in self.ip_ranges]

    def ip_in_owned_ranges(self, ip: str) -> bool:
        """True if the given IP falls inside any configured owned range."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks())
