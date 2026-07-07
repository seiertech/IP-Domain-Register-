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

## Loading your assets

Everything the tool scans comes from **one file you control**: `config/assets.yaml`.
It is the only input. The tool never edits it — it only reads it and writes findings
to `register/register.json`.

Open `config/assets.yaml`, delete the placeholder examples, and add your real assets:

```yaml
ip_ranges:
  - 203.0.113.0/24        # a whole CIDR block
  - 198.51.100.0/28       # a smaller block
  - 192.0.2.15            # a single IP is also fine

domains:
  - your-company.com      # root domain only — subdomains are found automatically
  - another-brand.co.uk

settings:
  max_ips_per_range: 256   # safety cap per range (a /16 won't run forever)
  expiry_warning_days: 45  # warn when a domain expires within N days
  timeout: 10              # fast DNS/RDAP per-lookup timeout (s)
  crtsh_timeout: 45        # crt.sh is slow; give it a bigger budget (s)
```

**Rules — that's genuinely all there is to it:**

| You have | How to enter it | Example |
|----------|-----------------|---------|
| A range of IPs | CIDR notation | `203.0.113.0/24` |
| One IP | Just the address | `192.0.2.15` |
| IPv6 | Same, CIDR or single | `2001:db8::/48` |
| A domain | The **root** domain only | `your-company.com` |
| A subdomain | **Don't list it** — it's discovered for you | *(automatic)* |

Invalid IP ranges are rejected immediately with a clear error, so typos can't
silently corrupt the register. Domain case doesn't matter.

### Managing separate estates (optional)

If you look after distinct sets of assets (e.g. per client or business unit), keep
them in separate files and point at each with its own register:

```bash
ipreg scan --config config/client-a.yaml --register register/client-a.json
ipreg scan --config config/client-b.yaml --register register/client-b.json
```

### Once your list is in

```bash
ipreg scan   # builds/updates the register and prints what changed
```
Commit `config/assets.yaml` to Git so even your *claimed* inventory has a change history.

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

# Gate CI/cron on findings: exit non-zero on drift, on alerts, or either
ipreg scan --fail-on drift   # exit 1 if the register changed
ipreg scan --fail-on alert   # exit 1 if anything is expiring / out of range
ipreg scan --fail-on any     # exit 1 on either
```

### Using it as a gate

By default `ipreg scan` always exits `0`. Pass `--fail-on` to make it exit `1` when
there is drift and/or alerts, so a scheduled job, CI step, or monitor can treat
"the register changed" or "something is expiring / out of range" as a failure to act on.

Passive by default (WHOIS, RDAP, DNS and CT logs generate no traffic to your
hosts). `--active` performs live DNS brute-force and should only be used against
ranges/domains you own.

## Scheduling (keep it current automatically)

The register maintains itself via GitHub Actions
(`.github/workflows/refresh-register.yml`): on a schedule it scans, commits any drift
back to `main`, and opens an issue summarising what changed. So the register — and its
Git history — stays accurate with no manual runs.

**1. Turn it on.** On GitHub: **Settings → Actions → General**, allow workflows to run,
and ensure workflow write permission is enabled (**Workflow permissions → Read and write**).
The workflow needs this to commit the refreshed register and open drift issues.

**2. It runs automatically.** By default it runs every **Monday at 06:00 UTC**.

**3. Change the frequency.** Edit the `cron` line at the top of
`.github/workflows/refresh-register.yml`:

```yaml
on:
  schedule:
    - cron: "0 6 * * 1"     # min hour day-of-month month day-of-week
```

Common alternatives (replace that one line):

| Frequency | cron line |
|-----------|-----------|
| Every day at 06:00 UTC | `0 6 * * *` |
| Every Monday 06:00 UTC (default) | `0 6 * * 1` |
| 1st of each month, 06:00 UTC | `0 6 1 * *` |
| Every 6 hours | `0 */6 * * *` |

(Cron here is always **UTC**. Syntax reference: [crontab.guru](https://crontab.guru).)

**4. Run it on demand.** In the repo: **Actions → Refresh register → Run workflow**.
There's an optional `active` toggle to include active subdomain brute-force for that run.

**5. Gate on findings (optional).** To make a run *fail loudly* on change or risk,
add `--fail-on` to the scan step in the workflow (e.g. `ipreg scan ... --fail-on any`),
so drift or expiring/out-of-range assets turn the run red.

## Scope note

This is an asset-inventory / attack-surface tool intended for ranges and domains
you own or are authorised to assess. Keep active scanning pointed only at your
own assets.

[crt.sh]: https://crt.sh/
