# recon-wolf

Multi-stage recon + vulnerability discovery pipeline for **authorized** bug bounty and pentest engagements. Chains passive/active subdomain enumeration, DNS resolution, URL discovery, JS analysis, and a wide range of scanning tools (nuclei, dalfox, ffuf, sqlmap, naabu, and more) into a single checkpointed, resumable run.

> **⚠️ Authorized use only.** This tool performs active scanning (port scans, directory/vhost fuzzing, SQL injection testing, GitHub org secret scanning, etc.) against the targets you give it. Only run it against domains and GitHub organizations you have **explicit written authorization** to test — e.g. an in-scope bug bounty program or a signed pentest agreement. Running this against out-of-scope targets, including a company's GitHub org without permission, may violate the law and the platform's terms. You are responsible for how you use this tool.

## What it does

- **Subdomain enumeration**: subfinder, amass, DNS bruteforce (puredns), permutations (alterx)
- **Resolution & filtering**: dnsx wildcard filtering, internal/private-IP leak detection
- **Live host probing**: httpx (status, title, tech-detect)
- **Port scanning**: naabu
- **URL discovery**: katana, gau, waybackurls, deduped by path + param signature
- **JS analysis**: subjs harvesting, secret/endpoint regex mining, sourcemap recovery
- **Parameter discovery**: arjun
- **Vulnerability scanning**: nuclei (per-target, dual template roots + tag-based sweeps)
- **XSS**: dalfox (parameter analysis + live payload/DOM testing)
- **Content/vhost discovery**: ffuf (with computed baseline filtering)
- **Cloud recon**: s3scanner (bucket hunting), wafw00f (WAF fingerprinting)
- **Secrets**: gitleaks / trufflehog against a target's GitHub org
- **LFI/path-traversal**: parameter-name-based candidate extraction + ffuf
- **SQLi**: candidate extraction + sqlmap-dev handoff
- **Screenshots**: gowitness
- **Optional AI triage**: pipes findings through the `claude` CLI for a first-pass severity/noise assessment

Every stage is checkpointed — interrupt and resume with `./recon.sh <input> `, and skip individual tools with `--no-<tool>` without dropping into full `--fast` mode.

## Requirements

**Hard-required:**
```
subfinder httpx nuclei katana gau
```

**Optional (each unlocks one or more stages; missing tools are skipped with an install hint):**
```
dnsx puredns alterx waybackurls subjs arjun dalfox ffuf gowitness naabu jq anew
amass s3scanner wafw00f notify dig gitleaks trufflehog python3
```

Most are Go-installable via `go install github.com/<...>@latest`; run the script once and it will print exact install hints for anything missing.

Also expects [SecLists](https://github.com/danielmiessler/SecLists) at `/usr/share/seclists` (override with `SECLISTS_BASE`), and optionally a local `sqlmap-dev` checkout (override with `SQLMAP_DIR`).

## Usage

```bash
./recon.sh <input_file> [output_file] [flags]
```

- `<input_file>` — one domain per line, blank lines and `#` comments ignored
- `--status` — show checkpoint progress and exit
- `--reset` — clear checkpoint state and cached output (subdomain history is preserved)
- `--fast` — skip slow/bruteforce/fuzzing stages
- `--low-resource` — cut concurrency further (useful on a laptop/VM)
- `--fullurl` — run tech-detect-triggered targeted scans (e.g. IIS-specific templates)
- `--no-claude` — skip the final AI analysis pass
- `--no-lfi-scan` / `--no-sqlmap` — skip those stages specifically
- `--sqlmap-level <1-5>` / `--sqlmap-risk <1-3>` — tune sqlmap aggressiveness
- `--github-org <org>` — explicit org for secret scanning (auto-guessed from domain if omitted)
- `--no-<tool>` — force-skip one tool's stage even if installed (e.g. `--no-ffuf`, `--no-naabu`, `--no-nuclei`)

Run `./recon.sh --help` for the full flag list.

### Examples

```bash
./recon.sh domains.txt
./recon.sh domains.txt --fast --no-claude
./recon.sh domains.txt --status
./recon.sh domains.txt --reset
./recon.sh domains.txt --fullurl --github-org myorg
./recon.sh domains.txt --no-lfi-scan --no-sqlmap --no-gowitness
```

## Output

All output for a run lives under `allresults/<input_basename>/`, including a generated `*_TRIAGE_SUMMARY.md` that indexes every result file and key counts. This directory is git-ignored — see `.gitignore`.

## Configuration

Tunables (rate limits, concurrency, wordlist paths, template roots) are set via environment variables with sensible defaults — see the top of `recon.sh` for the full list, e.g.:

```bash
CUSTOM_NUCLEI_TEMPLATES=/path/to/my-templates \
STOCK_NUCLEI_TEMPLATES=$HOME/nuclei-templates \
SECLISTS_BASE=/usr/share/seclists \
./recon.sh domains.txt
```

## Disclaimer

This tool is provided for legitimate security research and authorized testing only. The author is not responsible for misuse. Always confirm scope and authorization before scanning.
