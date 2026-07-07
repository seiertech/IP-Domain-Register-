"""Human-readable reporting: register summary + change report."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from .register import Change, Register

console = Console()


def print_change_report(changes: list[Change]) -> None:
    if not changes:
        console.print("[green]No changes detected — register is already up to date.[/green]")
        return

    counts: dict[str, int] = {}
    for c in changes:
        counts[c.kind] = counts.get(c.kind, 0) + 1
    summary = "  ".join(f"[bold]{k}[/bold]: {v}" for k, v in sorted(counts.items()))
    console.print(f"\n[yellow]Register drift detected[/yellow] — {summary}\n")

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Change")
    table.add_column("Type")
    table.add_column("Asset", overflow="fold")
    table.add_column("Detail", overflow="fold")

    colours = {"added": "green", "removed": "red", "modified": "yellow"}
    for c in changes:
        colour = colours.get(c.kind, "white")
        table.add_row(f"[{colour}]{c.kind}[/{colour}]", c.category, c.identifier, c.detail)
    console.print(table)


def print_summary(reg: Register, expiry_warning_days: int) -> None:
    n_ranges = len(reg.ip_ranges)
    n_hosts = sum(len(r.get("hosts", {})) for r in reg.ip_ranges.values())
    n_domains = len(reg.domains)
    n_subs = sum(len(d.get("subdomains", {})) for d in reg.domains.values())

    table = Table(title="Register summary", header_style="bold", show_header=False)
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("IP ranges", str(n_ranges))
    table.add_row("Hosts enriched", str(n_hosts))
    table.add_row("Domains", str(n_domains))
    table.add_row("Subdomains discovered", str(n_subs))
    console.print(table)

    # Surface anything that needs attention.
    _print_alerts(reg, expiry_warning_days)


def _print_alerts(reg: Register, expiry_warning_days: int) -> None:
    alerts: list[str] = []
    for dom, entry in reg.domains.items():
        w = entry.get("whois", {})
        if w.get("expiring_soon"):
            alerts.append(f"[red]EXPIRING[/red] {dom} in {w.get('days_to_expiry')} days")
        validation = entry.get("validation")
        if validation == "out_of_range":
            alerts.append(f"[red]OUT OF RANGE[/red] {dom} resolves outside owned ranges: {entry.get('resolves_to')}")
        elif validation == "partially_in_range":
            alerts.append(f"[yellow]PARTIAL[/yellow] {dom} partly outside owned ranges: {entry.get('resolves_to')}")
        for sub, s in entry.get("subdomains", {}).items():
            if s.get("status") == "live" and s.get("in_owned_range") is False:
                alerts.append(f"[yellow]SUBDOMAIN OUT OF RANGE[/yellow] {sub} -> {s.get('ips')}")

    if alerts:
        console.print("\n[bold]Attention[/bold]")
        for a in alerts:
            console.print(f"  • {a}")
