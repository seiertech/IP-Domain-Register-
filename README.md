# ip-domain-register

A self-updating register of the external **IP ranges** and **domains** you own.

Point it at your ranges and root domains and it pulls WHOIS/RDAP ownership,
reverse DNS, domain registration + expiry, DNS records and subdomains — then
writes it all to a **versioned register** and tells you exactly what changed
since last time. Run it on a schedule and the register stays accurate on its own.

> **Docs:**
> - [`docs/DESIGN.md`](docs/DESIGN.md) — full architecture, data model, enrichment
>   pipeline, change-detection design, automation model and security/scope.
> - [`docs/PROCESS_FLOW.md`](docs/PROCESS_FLOW.md) — step-by-step of exactly what
>   happens during a scan, start to finish.

## What it collects

**Per IP** (RDAP + DNS):
- Netblock owner / network name, ASN + description, registry, abuse contact
- Reverse DNS (PTR)

**Per domain** (WHOIS + DNS):
- Registrar, creation/updated dates, **expiry date + days remaining** (flags expiring soon)
- Registration status codes
- `A` / `AAAA` / `NS` / `MX` / `TXT` / `CNAME` records
- **Validation:** does it resolve back into one of *your* owned ranges? (catches
  shadow IT, repointed domains, and things you no longer control)

**Subdomains:**
- **Passive (default):** Certificate Transparency logs via [crt.sh] — every host that
  has ever had a TLS cert. No traffic to your infrastructure.
- **Active (opt-in, `--active`):** DNS brute-force against a wordlist.
- Each subdomain is resolved and marked **live/dead** and **in/out of owned range**.

## Why it stays accurate

The register is a plain JSON file that lives in Git. Every scan diffs the new
results against the last saved register and reports **added / removed / modified**
assets down to the field level. Committed to Git, the file's history becomes a
full **audit trail** of every ownership, expiry, DNS and subdomain change over time.

## Install

```bash
git clone https://github.com/<your-org>/ip-domain-register.git
cd ip-domain-register
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Configure

Edit `config/assets.yaml` with the ranges and domains you own:

```yaml
ip_ranges:
  - 203.0.113.0/24
  - 198.51.100.10
domains:
  - your-company.com
settings:
  max_ips_per_range: 256   # safety cap per range
  expiry_warning_days: 45  # warn when a domain expires within N days
  timeout: 10              # fast DNS/RDAP per-lookup timeout (s)
  crtsh_timeout: 45        # crt.sh is slow; give it a bigger budget (s)
```

## Use

```bash
# Scan, update the register, and print what changed
ipreg scan

# Include active subdomain brute-force (touches your hosts)
ipreg scan --active

# See changes without writing anything
ipreg scan --dry-run

# Summarise the current register (no scan)
ipreg report

# Compare two saved register snapshots
ipreg diff old.json new.json

# Export the register to CSV (hosts.csv, domains.csv, subdomains.csv)
ipreg export --out-dir exports
```

Passive by default (WHOIS, RDAP, DNS and CT logs generate no traffic to your
hosts). `--active` performs live DNS brute-force and should only be used against
ranges/domains you own.

## Keep it current automatically

`.github/workflows/refresh-register.yml` runs a scan on a weekly cron (and on
demand), commits any register drift back to the repo, and opens an issue
summarising what changed. Enable Actions on the repo and it maintains itself.

## Scope note

This is an asset-inventory / attack-surface tool intended for ranges and domains
you own or are authorised to assess. Keep active scanning pointed only at your
own assets.

[crt.sh]: https://crt.sh/
