"""Orchestration: run all enrichers over the configured assets and build a Register."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

from .config import AssetConfig
from .enrich.dns_tools import make_resolver
from .enrich.domain import enrich_domain
from .enrich.ip import enrich_ip, hosts_in_network
from .enrich.subdomains import discover_subdomains
from .register import Register


def scan(cfg: AssetConfig, active: bool = False, workers: int = 16) -> Register:
    resolver = make_resolver(cfg.settings.resolvers, cfg.settings.timeout)
    reg = Register()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        transient=True,
    ) as progress:
        _scan_ip_ranges(cfg, reg, resolver, workers, progress)
        _scan_domains(cfg, reg, resolver, active, workers, progress)

    return reg


def _scan_ip_ranges(cfg, reg, resolver, workers, progress) -> None:
    for cidr in cfg.ip_ranges:
        hosts = hosts_in_network(cidr, cfg.settings.max_ips_per_range)
        task = progress.add_task(f"IP range {cidr}", total=len(hosts))
        host_results: dict[str, dict] = {}

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(enrich_ip, ip, resolver): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    host_results[ip] = fut.result()
                except Exception as exc:
                    host_results[ip] = {"error": str(exc)}
                progress.advance(task)

        reg.ip_ranges[cidr] = {"cidr": cidr, "hosts": host_results}


def _scan_domains(cfg, reg, resolver, active, workers, progress) -> None:
    if not cfg.domains:
        return
    task = progress.add_task("Domains", total=len(cfg.domains))
    ip_check: Callable[[str], bool] = cfg.ip_in_owned_ranges

    for domain in cfg.domains:
        entry = enrich_domain(domain, resolver, cfg.settings.expiry_warning_days, ip_check)
        entry["subdomains"] = discover_subdomains(
            domain, resolver, ip_check, cfg.settings.crtsh_timeout, active=active
        )
        reg.domains[domain] = entry
        progress.advance(task)
