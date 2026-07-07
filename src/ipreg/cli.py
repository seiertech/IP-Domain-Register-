"""Command-line interface for the IP range and domain register."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from . import __version__
from .config import AssetConfig
from .export import export_csv
from .register import Register, diff
from .report import collect_alerts, console, print_change_report, print_summary
from .scanner import scan

DEFAULT_CONFIG = "config/assets.yaml"
DEFAULT_REGISTER = "register/register.json"


@click.group()
@click.version_option(__version__, prog_name="ipreg")
def cli() -> None:
    """Maintain an always-up-to-date register of owned IP ranges and domains."""


@cli.command("scan")
@click.option("--config", "config_path", default=DEFAULT_CONFIG, show_default=True,
              help="Path to the owned-asset inventory (input).")
@click.option("--register", "register_path", default=DEFAULT_REGISTER, show_default=True,
              help="Path to the register JSON (output, versioned).")
@click.option("--active", is_flag=True, default=False,
              help="Enable active subdomain brute-force (generates traffic to your hosts).")
@click.option("--workers", default=16, show_default=True, help="Concurrent lookup workers.")
@click.option("--dry-run", is_flag=True, default=False,
              help="Scan and show changes but do NOT write the register.")
@click.option("--fail-on", type=click.Choice(["never", "drift", "alert", "any"]),
              default="never", show_default=True,
              help="Exit non-zero for CI/cron gating: on register drift, on alerts "
                   "(expiring/out-of-range), or on either ('any').")
def scan_cmd(config_path, register_path, active, workers, dry_run, fail_on) -> None:
    """Scan owned assets, update the register, and report what changed."""
    cfg = _load_config(config_path)

    previous = Register.load(register_path)
    console.print(f"Scanning [bold]{len(cfg.ip_ranges)}[/bold] range(s) and "
                  f"[bold]{len(cfg.domains)}[/bold] domain(s)"
                  + (" [yellow](active mode)[/yellow]" if active else "") + " ...")

    current = scan(cfg, active=active, workers=workers)
    changes = diff(previous, current)

    print_summary(current, cfg.settings.expiry_warning_days)
    print_change_report(changes)

    if dry_run:
        console.print("\n[dim]Dry run — register not written.[/dim]")
    else:
        current.save(register_path)
        console.print(f"\n[green]Register written to[/green] {register_path}")

    _maybe_fail(fail_on, changes, current, cfg.settings.expiry_warning_days)


def _maybe_fail(fail_on, changes, current, expiry_warning_days) -> None:
    """Exit non-zero when the configured gating condition is met (for CI/cron)."""
    if fail_on == "never":
        return
    alerts = collect_alerts(current, expiry_warning_days)
    drift = bool(changes)
    trip = (
        (fail_on in ("drift", "any") and drift)
        or (fail_on in ("alert", "any") and bool(alerts))
    )
    if trip:
        reasons = []
        if fail_on in ("drift", "any") and drift:
            reasons.append(f"{len(changes)} change(s)")
        if fail_on in ("alert", "any") and alerts:
            reasons.append(f"{len(alerts)} alert(s)")
        console.print(f"\n[red]Exiting non-zero (--fail-on={fail_on}): "
                      f"{', '.join(reasons)}.[/red]")
        sys.exit(1)


@cli.command("report")
@click.option("--register", "register_path", default=DEFAULT_REGISTER, show_default=True)
@click.option("--config", "config_path", default=DEFAULT_CONFIG, show_default=True)
def report_cmd(register_path, config_path) -> None:
    """Show a summary + alerts for the current register without scanning."""
    reg = Register.load(register_path)
    if not reg.ip_ranges and not reg.domains:
        console.print("[yellow]Register is empty — run `ipreg scan` first.[/yellow]")
        return
    warning_days = 45
    if Path(config_path).exists():
        warning_days = _load_config(config_path).settings.expiry_warning_days
    print_summary(reg, warning_days)


@cli.command("diff")
@click.argument("old_register", type=click.Path(exists=True))
@click.argument("new_register", type=click.Path(exists=True))
def diff_cmd(old_register, new_register) -> None:
    """Show the changes between two saved register snapshots."""
    print_change_report(diff(Register.load(old_register), Register.load(new_register)))


@cli.command("export")
@click.option("--register", "register_path", default=DEFAULT_REGISTER, show_default=True)
@click.option("--out-dir", default="exports", show_default=True,
              help="Directory to write hosts.csv, domains.csv and subdomains.csv into.")
def export_cmd(register_path, out_dir) -> None:
    """Export the current register to spreadsheet-friendly CSV files."""
    reg = Register.load(register_path)
    if not reg.ip_ranges and not reg.domains:
        console.print("[yellow]Register is empty — run `ipreg scan` first.[/yellow]")
        return
    paths = export_csv(reg, out_dir)
    console.print("[green]Exported:[/green]")
    for p in paths:
        console.print(f"  • {p}")


def _load_config(config_path: str) -> AssetConfig:
    try:
        return AssetConfig.load(config_path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
