# Process Flow — IP-Domain-Register

How a single `ipreg scan` run turns your list of owned assets into an updated,
audited register. Read top to bottom: it follows the exact order the tool executes.

---

## End-to-end flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│ 0. TRIGGER                                                                 │
│    A person runs `ipreg scan`, OR the weekly GitHub Actions cron fires.    │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. LOAD INPUT              config/assets.yaml                              │
│    • read owned ip_ranges + domains + settings                             │
│    • validate every CIDR; lowercase domains                                │
│    • build the ownership predicate  ip_in_owned_ranges(ip)                 │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. LOAD PREVIOUS REGISTER  register/register.json                          │
│    • this is "what we knew last time" — used later to compute drift        │
│    • if it doesn't exist yet, start from empty                             │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 3. ENRICH IP RANGES         (parallel, per host)                          │
│    for each range → expand to hosts (capped by max_ips_per_range)          │
│      for each host, in a thread pool:                                      │
│        3a. RDAP lookup   → ASN, netblock owner, registry, abuse contact    │
│        3b. reverse DNS   → PTR hostname                                     │
│      (one host failing is recorded as an error, scan continues)            │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 4. ENRICH DOMAINS           (per domain)                                   │
│    for each domain:                                                        │
│      4a. WHOIS       → registrar, created/updated, EXPIRY + days left      │
│      4b. DNS records → A / AAAA / NS / MX / TXT / CNAME                     │
│      4c. VALIDATE    → do the A records fall inside an owned range?         │
│                        → in_range / partial / out_of_range / no_a_record   │
│      4d. SUBDOMAINS  → passive: crt.sh (CT logs)                           │
│                        → active (only with --active): DNS brute-force      │
│                        → resolve each: live/dead + in/out of owned range   │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 5. BUILD NEW REGISTER (in memory)                                          │
│    assemble everything from steps 3 + 4 into the register structure        │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 6. DIFF   previous register  vs  new register                             │
│    produce a list of changes: added / removed / modified                   │
│    for IP ranges, hosts, domains and subdomains — down to field level      │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 7. REPORT                                                                  │
│    • summary counts                                                        │
│    • ALERTS: expiring domains, out-of-range domains/subdomains             │
│    • change table (or "already up to date")                                │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 8. WRITE      register/register.json   (unless --dry-run)                  │
│    stable, sorted JSON so Git diffs are meaningful                         │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 9. PERSIST (automation only)                                               │
│    GitHub Actions commits the changed register to main + opens an issue    │
│    summarising the drift. Git history becomes the audit trail.             │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Step-by-step detail

### Step 0 — Trigger
Two ways in: a person runs `ipreg scan` on demand, or the scheduled workflow
(`.github/workflows/refresh-register.yml`) runs it weekly. Same code path either way.

### Step 1 — Load input (`config.py`)
Reads `config/assets.yaml` — your hand-maintained list of what you own. Every IP range
is validated as a real CIDR; invalid entries stop the run with a clear error. Domains are
lowercased. Crucially, this step produces the **ownership predicate** — a function that
answers "is this IP inside one of our ranges?" — reused throughout the scan.

### Step 2 — Load previous register (`register.py`)
Loads the last `register/register.json`. This is the "before" picture. If it's the first
ever run, it starts empty (so everything will show up as "added").

### Step 3 — Enrich IP ranges (`scanner.py` → `enrich/ip.py`)
Each range is expanded into individual host addresses, capped by `max_ips_per_range` so a
big block can't run forever. Hosts are processed concurrently in a thread pool (network
lookups are I/O-bound). For each host:
- **RDAP** (`ipwhois`) → who owns the netblock, ASN + description, registry, abuse contact.
- **Reverse DNS** → the PTR hostname.

If one host errors (rate limit, no data), that error is recorded for that host only and
the scan keeps going.

### Step 4 — Enrich domains (`scanner.py` → `enrich/domain.py`, `enrich/subdomains.py`)
For each root domain:
- **4a WHOIS** → registrar, creation/updated dates, and the important one — **expiry date
  and days remaining**, with an `expiring_soon` flag driven by `expiry_warning_days`.
- **4b DNS records** → A, AAAA, NS, MX, TXT, CNAME.
- **4c Validation** → checks the domain's A records against the ownership predicate and
  labels it `in_owned_range`, `partially_in_range`, `out_of_range`, or `no_a_record`.
  This is how you catch a domain that has been repointed away from your estate.
- **4d Subdomains** → passively pulls every hostname that ever had a TLS cert from
  **crt.sh** (Certificate Transparency logs). With `--active`, it also brute-forces a
  wordlist against DNS. Each discovered subdomain is then resolved and tagged **live/dead**
  and **in/out of owned range**.

### Step 5 — Build the new register
All results from steps 3 and 4 are assembled into the register data structure in memory —
the fresh "after" picture.

### Step 6 — Diff (`register.py`)
The heart of the tool. It compares the previous register (step 2) with the new one
(step 5) and emits a list of changes classified as **added / removed / modified**, across
IP ranges, hosts, domains and subdomains. Modifications are computed at the **field level**
(e.g. `ips: '192.0.33.8' -> '192.0.46.8'`), so you see exactly what moved.

### Step 7 — Report (`report.py`)
Prints a summary (counts), an **Attention** block (domains expiring soon, domains/subdomains
resolving outside owned ranges), and a colour-coded change table — or a clear "already up to
date" message when nothing changed.

### Step 8 — Write the register
Unless `--dry-run` was passed, the new register is written to `register/register.json` as
stable, sorted JSON so that Git diffs reflect real changes, not formatting noise.

If `--fail-on` was given, the command finally exits non-zero when the chosen condition is
met — `drift` (the register changed), `alert` (something is expiring or out of range), or
`any` (either). This is what lets a scheduled job or CI step *act* on a change rather than
just record it. Without the flag, `scan` always exits `0`.

### Step 9 — Persist & notify (automation)
In the GitHub Actions run, if the register file changed, the workflow commits it back to
`main` with a timestamped message and opens a `register-drift` issue containing the change
report. The register stays current on its own, and every change is preserved as both a Git
commit and a GitHub issue — your audit trail.

---

## Where each step lives in the code

| Step | Module |
|------|--------|
| 0 Trigger | `cli.py`, `.github/workflows/refresh-register.yml` |
| 1 Load input | `config.py` |
| 2 Load previous register | `register.py` (`Register.load`) |
| 3 IP enrichment | `scanner.py`, `enrich/ip.py`, `enrich/dns_tools.py` |
| 4 Domain enrichment | `enrich/domain.py`, `enrich/subdomains.py` |
| 5 Build register | `scanner.py` |
| 6 Diff | `register.py` (`diff`) |
| 7 Report | `report.py` |
| 8 Write register | `register.py` (`Register.save`) |
| 9 Persist & notify | `.github/workflows/refresh-register.yml` |
