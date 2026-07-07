# Design Document — IP-Domain-Register

**Status:** v0.1
**Owner:** Seiertech
**Scope:** Internal asset-inventory / external attack-surface tooling

---

## 1. Purpose

Maintain an **always-accurate register** of the external **IP ranges** and **domains**
that the organisation owns or is responsible for. The register is not a one-off
snapshot; it is a continuously refreshed, version-controlled record that answers,
at any point in time:

- Which external IPs and ranges do we own, and who does WHOIS/RDAP say owns them?
- Which domains do we own, when do they expire, and where do they point?
- Do our domains and subdomains resolve back into ranges we actually control?
- **What has changed since we last looked?**

The last question is the reason the tool exists. Registers rot because they are
maintained by hand. This tool makes the register self-maintaining and turns every
change into an auditable event.

### 1.1 Non-goals

- It is **not** a vulnerability scanner or exploitation tool.
- It does **not** perform authenticated inspection of hosts.
- It is intended only for ranges and domains the operator owns or is authorised to assess.

---

## 2. Design principles

1. **Passive by default.** WHOIS, RDAP, DNS resolution and Certificate Transparency
   log queries generate no traffic to the target hosts. Anything that touches the
   hosts directly (active DNS brute-force) is strictly opt-in.
2. **Git is the database.** The register is a single, stable, sorted JSON file that
   lives in the repository. Its Git history *is* the audit trail. No external DB.
3. **Fail soft, never abort.** A single unreachable IP, rate-limited WHOIS server or
   slow CT log must never abort a whole scan. Every enricher degrades to a recorded
   error for that one asset.
4. **Deterministic output.** Output is sorted and stable so that Git diffs reflect
   real change, not serialisation noise.
5. **Separation of input and output.** `config/assets.yaml` is human-maintained
   (what we claim to own). `register/register.json` is machine-maintained (what we
   found). They are never mixed.

---

## 3. High-level architecture

```
                 config/assets.yaml  (INPUT: owned ranges + domains)
                          │
                          ▼
                   ┌──────────────┐
                   │   config.py  │  load + validate, ownership predicate
                   └──────┬───────┘
                          ▼
                   ┌──────────────┐        ┌─────────────────────────────┐
                   │  scanner.py  │ ─────▶ │ enrich/                     │
                   │ orchestration│        │  ip.py        (RDAP + PTR)  │
                   │ (thread pool)│        │  domain.py    (WHOIS + DNS) │
                   └──────┬───────┘        │  subdomains.py(CT + active) │
                          │                │  dns_tools.py (resolver)    │
                          ▼                └─────────────────────────────┘
                   ┌──────────────┐
                   │ register.py  │  build Register, diff vs previous
                   └──────┬───────┘
             ┌────────────┴────────────┐
             ▼                         ▼
   register/register.json        report.py  (summary + change report + alerts)
   (versioned output)                 │
                                      ▼
                                  CLI (cli.py): scan / report / diff
```

The GitHub Actions workflow (`.github/workflows/refresh-register.yml`) drives the
CLI on a schedule and commits any drift back to the repo.

---

## 4. Component design

### 4.1 Configuration (`config.py`)

- `AssetConfig.load(path)` reads `assets.yaml`, validates every IP range with
  `ipaddress.ip_network`, and normalises domains to lowercase.
- `Settings` holds tunables: `max_ips_per_range`, `resolvers`, `expiry_warning_days`,
  `timeout` (fast DNS/RDAP) and `crtsh_timeout` (slow CT-log HTTP).
- `ip_in_owned_ranges(ip)` is the **ownership predicate** — the single source of truth
  used everywhere to decide whether a resolved IP falls inside a range we own. This is
  how validation catches domains/subdomains that point outside our estate.

### 4.2 Orchestration (`scanner.py`)

- Builds one shared, explicitly-configured DNS resolver (no reliance on host DNS).
- IP enrichment is parallelised with a `ThreadPoolExecutor` (default 16 workers) because
  it is I/O-bound (network round-trips). `max_ips_per_range` caps how many hosts in a
  range are enriched so a large CIDR cannot run unbounded.
- Domain enrichment runs per-domain and includes subdomain discovery.
- A `rich` progress display is shown during the scan (transient).

### 4.3 IP enrichment (`enrich/ip.py`)

Per IP:
- **RDAP** via `ipwhois` (`lookup_rdap`) → ASN, ASN description, registry, network
  name/CIDR/country, and abuse contact (extracted from entity objects with role `abuse`).
- **Reverse DNS (PTR)** via the shared resolver.
- Failures are captured as `{"error": ...}` for that IP only.

### 4.4 Domain enrichment (`enrich/domain.py`)

Per domain:
- **WHOIS** via `python-whois` → registrar, creation/updated/expiry dates, status codes,
  registrant org. Expiry is normalised to ISO, `days_to_expiry` computed, and
  `expiring_soon` set when within `expiry_warning_days`.
- **DNS records**: `A`, `AAAA`, `NS`, `MX`, `TXT`, `CNAME`.
- **Validation** derived from the `A` records against the ownership predicate:
  - `in_owned_range` — all A records inside owned ranges
  - `partially_in_range` — some inside, some outside
  - `out_of_range` — resolves, but nothing inside owned ranges
  - `no_a_record` — does not resolve to an address

### 4.5 Subdomain discovery (`enrich/subdomains.py`)

- **Passive (default):** query **crt.sh** for `%.<domain>` from Certificate Transparency
  logs — every hostname that has ever had a TLS certificate issued. No target traffic.
  Given its own, larger `crtsh_timeout` because crt.sh is slow (observed ~20s).
- **Active (opt-in, `--active`):** DNS brute-force of a built-in wordlist. Generates
  lookup traffic; only for owned assets.
- Every discovered name is resolved and recorded with `status` (live/dead), its `ips`,
  any `cname`, and `in_owned_range`.

### 4.6 Register + change detection (`register.py`)

- `Register` is an in-memory document (`ip_ranges`, `domains`, `generated_at`),
  serialised to sorted, indented JSON so diffs are stable.
- `diff(old, new)` produces a list of `Change(kind, category, identifier, detail)`:
  - `kind` ∈ {added, removed, modified}
  - `category` ∈ {ip_range, host, domain, subdomain}
  - Modifications are computed at **field level** by flattening nested entries to dotted
    paths and comparing scalars — so a report reads e.g.
    `pen.example.org  ips: '192.0.33.8' -> '192.0.46.8'`.

### 4.7 Reporting (`report.py`)

- `print_summary` — counts of ranges/hosts/domains/subdomains.
- `_print_alerts` — surfaces domains expiring soon, out-of-range / partially-in-range
  domains, and live subdomains resolving outside owned ranges.
- `print_change_report` — colourised added/removed/modified table, or a clear
  "already up to date" message when there is no drift.

### 4.8 CLI (`cli.py`)

- `ipreg scan [--config --register --active --workers --dry-run]` — scan, diff against
  the saved register, report, and (unless `--dry-run`) write the register.
- `ipreg report [--register --config]` — summarise the current register without scanning.
- `ipreg diff <old.json> <new.json>` — compare two saved snapshots.

---

## 5. Register data model

```jsonc
{
  "generated_at": "<ISO-8601 UTC>",
  "ip_ranges": {
    "<cidr>": {
      "cidr": "<cidr>",
      "hosts": {
        "<ip>": {
          "ptr": "<hostname|null>",
          "rdap": {
            "asn": "...", "asn_description": "...", "asn_country_code": "...",
            "network_name": "...", "network_cidr": "...", "network_country": "...",
            "registry": "...", "abuse_contact": "..."
          }
        }
      }
    }
  },
  "domains": {
    "<domain>": {
      "resolves": true,
      "resolves_to": ["<ip>", "..."],
      "validation": "in_owned_range|partially_in_range|out_of_range|no_a_record",
      "dns": { "A": [...], "AAAA": [...], "NS": [...], "MX": [...], "TXT": [...], "CNAME": [...] },
      "whois": {
        "registrar": "...", "created": "...", "updated": "...",
        "expiry": "...", "days_to_expiry": 0, "expiring_soon": false,
        "registrant_org": "...", "status": [ "..." ]
      },
      "subdomains": {
        "<subdomain>": {
          "status": "live|dead",
          "ips": ["<ip>"],
          "cname": ["..."],
          "in_owned_range": true
        }
      }
    }
  }
}
```

---

## 6. Automation & operating model

- **Trigger:** weekly cron + manual `workflow_dispatch` (with an optional `active` input).
- **Action:** install the package, run `ipreg scan`, and if `register/register.json`
  changed, commit it back to `main` with a timestamped message and open a
  `register-drift` issue containing the change report.
- **Result:** the register stays current automatically, and every change is both a Git
  commit (diff/blame history) and a GitHub issue (notification + discussion).

---

## 7. Security & authorisation

- Only assets listed in `config/assets.yaml` are ever touched.
- Passive sources (WHOIS/RDAP/DNS/CT) are safe to run at any time.
- Active mode (`--active`) performs live DNS brute-force and must only be pointed at
  owned/authorised assets.
- No credentials or secrets are stored in the register; WHOIS output is public data.

---

## 8. Limitations & future work

- **crt.sh dependency / latency.** Single passive source today. *Future:* add a second
  CT source (e.g. certspotter) and/or passive-DNS providers for resilience.
- **WHOIS parsing variance.** `python-whois` output varies by TLD/registrar; some fields
  may be `null`. *Future:* prefer RDAP for domains where available.
- **Active wordlist is small/built-in.** *Future:* support an external wordlist file.
- **No per-host port/service data.** Intentionally out of scope for v0.1 (passive-first).
  *Future:* optional active service discovery behind its own flag.
- **Scale.** Bounded by `max_ips_per_range`. *Future:* range-level sharding for very large
  estates.

---

## 9. Testing / verification

v0.1 was verified live against public, safe assets:
- IP RDAP + PTR (ASN, abuse contact, network, reverse DNS) — populated correctly.
- Domain WHOIS + full DNS records + expiry computation — populated correctly.
- Validation correctly flagged assets resolving outside the configured owned range.
- Subdomain discovery returned CT-log results with live/dead + in/out-of-range status.
- Change detection verified idempotent (no false positives) and correctly reported a
  real single-field IP change on re-scan.
