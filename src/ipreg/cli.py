"""Command-line interface for the IP range and domain register."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from . import __version__
from .config import AssetConfig
from .register import Register, diff
from .report import console, print_change_report, print_summary
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
def scan_cmd(config_path, register_path, active, workers, dry_run) -> None:
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
        return

    current.save(register_path)
    console.print(f"\n[green]Register written to[/green] {register_path}")


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


def _load_config(config_path: str) -> AssetConfig:
    try:
        return AssetConfig.load(config_path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
