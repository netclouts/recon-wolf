#!/usr/bin/env bash
#
# recon3.sh — Extended recon + vuln discovery pipeline (v3)
#
# v2 additions (kept):
#   - dnsx           : bulk DNS resolution + wildcard filtering (kills false live-hosts)
#   - puredns        : DNS bruteforce against a wordlist (finds subs subfinder never will)
#   - alterx         : permutation-based subdomain generation fed back into dnsx
#   - subjs + katana  : JS file harvesting
#   - JS secret/endpoint mining via nuclei "exposures/files" + custom regex pass
#   - arjun          : hidden GET/POST parameter discovery on live endpoints
#   - dalfox         : dedicated reflected/DOM XSS scanning (stronger than nuclei's xss tags)
#   - ffuf            : wordlist-based content/dir discovery
#   - gowitness      : screenshot triage for fast visual review of large host sets
#   - naabu          : fast port scan on resolved hosts (surfaces non-80/443 services)
#   - parallelized nuclei jobs, URL dedup by path+param-keys, checkpoint/resume, claude analysis
#
# v3 additions (new in this version, merged into v2's checkpointed architecture):
#   - amass          : additional passive subdomain source via `amass enum` (v5 CLI). NOTE:
#                       older amass (v4-) had `intel -whois` for reverse-WHOIS/ASN-based org
#                       expansion; OWASP Amass v5 removed that subcommand entirely, so this
#                       stage now just adds amass's own passive sources to the subdomain pool
#                       rather than doing netblock/org discovery. Gated behind --fast (slow).
#   - s3scanner      : cloud storage bucket hunting (S3/GCS/Azure-style) using domain-derived
#                       search terms. Alerts on public/misconfigured buckets.
#   - wafw00f        : WAF fingerprinting per live host — tells you what's in front of a
#                       target before you burn payloads against it.
#   - vhost fuzzing  : ffuf-based Host-header fuzzing against each resolved IP, now using a
#                       DEDICATED vhost wordlist (not the subdomain list — that was a v3-draft
#                       bug) plus baseline response-size filtering to cut false positives.
#   - notify         : optional push-alert integration (Slack/Discord/etc via ProjectDiscovery's
#                       notify) for high-signal findings (buckets, nuclei hits, vhost matches).
#   - state diffing  : anew-based new-vs-seen subdomain tracking, so repeat runs against the
#                       same scope only deep-scan what's new (still fully checkpointed inside
#                       a single run via the existing state file mechanism).
#
# v6 additions (this version):
#   - github-secrets : gitleaks + trufflehog against GitHub orgs/users derived from the target
#                       domain (and any explicitly supplied via --github-org). Catches leaked
#                       creds/tokens in public repos and commit history — a source most nuclei-
#                       only pipelines never touch at all.
#   - js-sourcemaps  : detects and pulls .js.map files referenced by harvested JS, and reverses
#                       them back into readable pseudo-source with source-map-explorer/js tools
#                       when available, else just extracts the sourcesContent JSON fields
#                       directly with a plain jq/python pass. This routinely recovers full
#                       unminified source (internal routes, comments, TODOs) that plain JS
#                       regex mining on the minified bundle misses entirely.
#   - internal-hosts : flags any resolved subdomain whose DNS record points at RFC1918/loopback/
#                       link-local space (i.e. leaked from split-horizon DNS) -- these are some
#                       of the highest-signal, most overlooked findings in recon since they
#                       reveal internal naming/infra without any active scanning.
#
# v8 additions (this version):
#   - lfi/path-traversal candidates : the deduped URL corpus is grepped for parameters whose
#                       NAME suggests file/path inclusion (file=, path=, doc=, page=, folder=,
#                       include=, template=, load=, read=, filename=, etc). For each candidate,
#                       a real ffuf -fs baseline is computed (root/original value size + a
#                       garbage-value "not found" size, same two-point method as the content-
#                       discovery and vhost stages), then ffuf fuzzes that exact parameter with
#                       a dedicated dotdotpwn traversal wordlist -- not the generic content
#                       wordlist -- filtered by that baseline.
#   - sqlmap handoff  : URLs with any parameter (the same pool dalfox draws from) are collected
#                       as injection candidates and handed to a local sqlmap-dev checkout in
#                       bulk (-m) --batch mode, run from that checkout's own directory (matches
#                       how it's normally invoked: `cd ~/sqlmap-dev && python3 sqlmap.py ...`)
#                       so it picks up its bundled data/tamper/plugin files correctly, with
#                       results written back out to this run's own output directory.
#
# v7 additions:
#   - port-aware targets : any live host is now tracked both as a bare hostname AND, when it
#                           was seen on a non-default port (host:port), as that explicit
#                           host:port target too. A service on :8443 or :8080 is frequently a
#                           different app/vhost than whatever answers on 80/443 for the same
#                           name, and earlier versions silently dropped the port on extraction,
#                           losing that target entirely. httpx, katana, and the URL corpus now
#                           all see both forms.
#   - real ffuf baselines : every ffuf content-discovery call (not just vhost fuzzing) now
#                           computes a `-fs` baseline from TWO live requests -- the target root
#                           AND a guaranteed-nonexistent random path -- instead of guessing or
#                           skipping baselining, so soft-404 pages get filtered out properly.
#   - per-domain nuclei   : nuclei is now invoked per-target with `-u` against each configured
#                           template root separately (your custom template repo AND the stock
#                           ~/nuclei-templates), instead of one `-l <hostlist>` batch call per
#                           template group. This avoids the common failure mode where one bad
#                           target or template in a big -l batch quietly starves/truncates the
#                           whole run; each (target, template-root) pair is its own checkpointed
#                           job that can fail/retry independently.
#   - --fullurl / tech scans : new --fullurl flag turns on tech-detect-triggered targeted scans
#                           (e.g. IIS-specific templates against any host httpx fingerprinted
#                           as IIS), on top of the generic scans everything else already gets.
#
# All new stages are checkpointed like everything else, skip cleanly when their binary is
# missing, and are gated behind --fast where they're expensive (amass enum, puredns, vhost
# fuzzing, ffuf, gowitness, s3scanner, github-secrets).
#
# v5: per-tool skip switches. Every optional (and semi-optional) tool stage can now be
# force-skipped individually with --no-<tool>, on top of the existing --fast/--no-amass/
# --low-resource knobs. This is for cases where a tool is installed and working fine but
# you don't want it to run this time (e.g. --no-ffuf to skip both ffuf stages -- content
# discovery AND vhost fuzzing -- without dropping into --fast and losing everything else,
# or --no-nuclei if you just want recon/enum without triggering active scanning at all,
# e.g. because it's saturating a VM's virtual NIC).
#
# Usage:
#   ./recon3.sh <input_file> [output_file]
#   ./recon3.sh <input_file> --reset
#   ./recon3.sh <input_file> --status
#   ./recon3.sh <input_file> --no-claude
#   ./recon3.sh <input_file> --fast          # skip slow/bruteforce/fuzzing stages
#   ./recon3.sh <input_file> --low-resource  # cut concurrency further if the pipeline is
#                                             # making the machine slow/unresponsive
#   ./recon3.sh <input_file> --fullurl       # also run tech-detect-triggered targeted scans
#                                             # (e.g. IIS-specific templates for IIS hosts)
#   ./recon3.sh <input_file> --no-lfi-scan   # skip LFI/path-traversal candidate extraction + ffuf
#   ./recon3.sh <input_file> --no-sqlmap     # skip the sqlmap-dev handoff stage
#   ./recon3.sh <input_file> --sqlmap-level <1-5>   # override sqlmap --level (default 1)
#   ./recon3.sh <input_file> --sqlmap-risk <1-3>    # override sqlmap --risk (default 1)
#   ./recon3.sh <input_file> --github-org <org>  # explicit GitHub org/user for secret scanning
#                                                 # (auto-derived from domain name if omitted)
#   ./recon3.sh <input_file> --no-<tool>     # force-skip one tool's stage(s) even if
#                                             # installed. Supported: --no-amass, --no-dnsx,
#                                             # --no-puredns, --no-alterx, --no-waybackurls,
#                                             # --no-subjs, --no-arjun, --no-dalfox, --no-ffuf,
#                                             # --no-gowitness, --no-naabu, --no-anew,
#                                             # --no-s3scanner, --no-wafw00f, --no-notify,
#                                             # --no-nuclei, --no-katana, --no-gau,
#                                             # --no-gitleaks, --no-trufflehog, --no-sourcemaps
#   (multiple --no-* flags can be combined, e.g. --no-ffuf --no-naabu --no-gowitness)
#
# v4: default concurrency was reduced across the board (nuclei especially -- it's the
# stage most likely to make a single machine hang, since NUCLEI_PARALLEL_JOBS parallel
# nuclei processes each run NUCLEI_CONCURRENCY templates concurrently). Heavy scanning
# tools also now run under `nice`/`ionice` so they don't starve your desktop session.
# Nuclei -t paths and -tags groups are validated against your local template repo
# before a job is queued, so a renamed/missing path is skipped with a clear message
# instead of silently retrying 3x and failing ("no templates provided").
#
# Requires (in addition to the original hard-required set: subfinder httpx nuclei katana gau):
#   dnsx puredns alterx subjs arjun dalfox ffuf gowitness naabu jq anew
#   amass s3scanner wafw00f notify dig(dnsutils) gitleaks trufflehog
#
# Missing optional binaries are warned about with an install hint and the related stage
# is skipped — the script never hard-fails on a missing optional tool.
set -uo pipefail

# Cleanup: if the script exits/is interrupted at any point, kill any background jobs
# we spawned (heartbeat tickers, parallel nuclei/wafw00f workers) instead of leaving
# orphaned processes running after the script itself has exited.
cleanup_bg_jobs() {
    local pids
    pids="$(jobs -rp 2>/dev/null)"
    [[ -n "$pids" ]] && kill $pids 2>/dev/null
}
trap cleanup_bg_jobs EXIT INT TERM

# =====================================================================
# TUNABLES
#
# v4 note: defaults below were cut roughly in half-to-a-third from the v3
# draft. The old defaults (NUCLEI_PARALLEL_JOBS=4 x NUCLEI_CONCURRENCY=40)
# meant up to ~160 simultaneous nuclei template executions PLUS whatever
# httpx/ffuf/wafw00f/gowitness happened to be running alongside -- fine on
# a beefy VPS, not fine on a single laptop, and the usual symptom is the
# whole machine (not just the terminal) becoming unresponsive. Pass
# --low-resource for a second, more aggressive cut on top of these if it's
# still too much (e.g. running on battery, or alongside a VM/browser).
# =====================================================================
NUCLEI_RATE_LIMIT=100
NUCLEI_CONCURRENCY=15
NUCLEI_BULK_SIZE=10
HTTPX_RATE_LIMIT=100
HTTPX_THREADS=25
KATANA_RATE_LIMIT=80
KATANA_CONCURRENCY=10
GAU_THREADS=8
DNSX_THREADS=40
PUREDNS_RATE_LIMIT=1000        # puredns handles its own high-volume DNS well; tune to your resolver capacity
NAABU_RATE_LIMIT=300
FFUF_THREADS=25
FFUF_RATE_LIMIT=0              # 0 = unlimited, respect target; set if you need to throttle
DALFOX_WORKERS=15
ARJUN_THREADS=8
GOWITNESS_THREADS=3
NUCLEI_PARALLEL_JOBS=2          # how many nuclei jobs to run CONCURRENTLY -- the single
                                 # biggest lever on system load; raise only if your machine can take it
AMASS_TIMEOUT_MIN=10             # amass enum -timeout: minutes without progress before it gives up
WAFW00F_PARALLEL_JOBS=3
VHOST_FFUF_THREADS=15
GITHUB_SECRETS_PARALLEL_JOBS=2   # gitleaks/trufflehog per-repo parallelism
SOURCEMAP_FETCH_TIMEOUT=10
FFUF_BASELINE_TIMEOUT=10         # curl timeout (s) when computing ffuf -fs baselines
NUCLEI_JS_WALLCLOCK_TIMEOUT=600  # hard wall-clock cap (s) on the JS-corpus nuclei pass

CLAUDE_CHUNK_PAUSE=30
CLAUDE_MAX_LINES_PER_CHUNK=400
RUN_CLAUDE_ANALYSIS=1

# nuclei template roots -- v7: every target now gets scanned against BOTH of these
# separately (per-target `-u` jobs, see run_nuclei_per_host below), not merged into
# a single -t invocation and not run as one big -l batch.
CUSTOM_NUCLEI_TEMPLATES="${CUSTOM_NUCLEI_TEMPLATES:-$HOME/abbageneral/mycusutumnucliewordlist/nuclei-templates}"
STOCK_NUCLEI_TEMPLATES="${STOCK_NUCLEI_TEMPLATES:-$HOME/nuclei-templates}"

# v8: LFI/path-traversal candidate scanning
DOTDOTPWN_WORDLIST="${DOTDOTPWN_WORDLIST:-/home/netclouts/abbageneral/phpmyadminstuff/phpmyadminandothers/wordlists/dotdotpwn.txt}"
LFI_FFUF_THREADS="${LFI_FFUF_THREADS:-25}"
# Parameter NAMES (not values) that suggest file/path inclusion. Matched case-insensitively
# against query-string keys. Extend as needed -- this is deliberately conservative (misses
# are cheaper than flooding sqlmap/ffuf with every parameter on the site).
LFI_PARAM_REGEX='^(file|filename|filepath|path|pathname|doc|document|page|pg|folder|dir|directory|include|inc|template|tpl|load|loadfile|read|show|view|display|target|resource|src|source|conf|config|locale|lang|style|css)$'

# v8: sqlmap-dev handoff
SQLMAP_DIR="${SQLMAP_DIR:-$HOME/sqlmap-dev}"
SQLMAP_LEVEL="${SQLMAP_LEVEL:-1}"
SQLMAP_RISK="${SQLMAP_RISK:-1}"
SQLMAP_THREADS="${SQLMAP_THREADS:-4}"

# Wordlists — adjust paths to whatever you have installed (SecLists is assumed)
SECLISTS_BASE="${SECLISTS_BASE:-/usr/share/seclists}"
SUBDOMAIN_WORDLIST="${SUBDOMAIN_WORDLIST:-${SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-110000.txt}"
RESOLVERS_FILE="${RESOLVERS_FILE:-${SECLISTS_BASE}/../resolvers.txt}"   # override with a fresh public resolver list
FFUF_WORDLIST="${FFUF_WORDLIST:-${SECLISTS_BASE}/Discovery/Web-Content/raft-medium-directories.txt}"
# Dedicated vhost wordlist -- NOT the discovered-subdomains list. Using subdomain names as
# Host-header fuzz values (as an earlier draft did) mostly just re-confirms names you already
# resolved; a real vhost wordlist targets common internal/staging/dev naming patterns instead.
VHOST_WORDLIST="${VHOST_WORDLIST:-${SECLISTS_BASE}/Discovery/DNS/namelist.txt}"
# notify integration is configured via ~/.config/notify/provider-config.yaml (Slack/Discord/etc);
# see https://github.com/projectdiscovery/notify -- no extra path needed here.

# ---- Argument handling -----------------------------------------------------
print_usage() {
    cat <<EOF
Usage: $0 <input_file> [output_file] [flags]

  <input_file>       File with one domain per line (blank lines / lines
                      starting with # are ignored).
  [output_file]       Optional; defaults to <input_file_basename>_live.txt

Modes:
  --status            Show checkpoint progress for this input file and exit.
  --reset             Clear all checkpoint state and cached output files for
                      this input file, then run fresh. (Cross-run subdomain
                      history in *_subs_seen.txt is preserved -- delete it
                      manually for a truly clean slate.)
  -h, --help          Show this help and exit.

Run modifiers:
  --fast              Skip slow/bruteforce/fuzzing stages (amass enum,
                      puredns, alterx perms, naabu, s3scanner, wafw00f
                      is NOT skipped, vhost fuzzing, arjun, ffuf content
                      discovery, gowitness, github secrets).
  --low-resource      Cut concurrency further on top of the (already
                      reduced) defaults -- use if the pipeline is making
                      the machine slow/unresponsive.
  --fullurl           Also run tech-detect-triggered targeted scans (e.g.
                      IIS-specific templates against hosts fingerprinted
                      as IIS by httpx).
  --no-claude         Skip the final Claude analysis pass.
  --no-lfi-scan       Skip LFI/path-traversal candidate extraction + the
                      dotdotpwn-wordlist ffuf stage.
  --no-sqlmap         Skip the sqlmap-dev handoff stage.
  --sqlmap-level <1-5>   Override sqlmap --level (default: $SQLMAP_LEVEL).
  --sqlmap-risk <1-3>    Override sqlmap --risk  (default: $SQLMAP_RISK).
  --github-org <org>  Explicit GitHub org/user for secret scanning
                      (auto-derived from the first domain if omitted).

Per-tool skip switches (force-skip one stage even if the tool is
installed and working, without dropping into --fast):
  --no-amass  --no-dnsx      --no-puredns    --no-alterx
  --no-waybackurls  --no-subjs   --no-arjun   --no-dalfox
  --no-ffuf   --no-gowitness    --no-naabu    --no-anew
  --no-s3scanner  --no-wafw00f  --no-notify
  --no-nuclei --no-katana   --no-gau
  --no-gitleaks   --no-trufflehog  --no-sourcemaps

  (multiple --no-* flags can be combined, e.g. --no-ffuf --no-naabu --no-gowitness)

Examples:
  $0 domains.txt
  $0 domains.txt --fast --no-claude
  $0 domains.txt --status
  $0 domains.txt --reset
  $0 domains.txt --fullurl --github-org myorg
  $0 domains.txt --no-lfi-scan --no-sqlmap --no-gowitness
EOF
}

for early_arg in "$@"; do
    case "$early_arg" in
        -h|--help) print_usage; exit 0 ;;
    esac
done

if [[ $# -lt 1 ]]; then
    print_usage >&2
    exit 1
fi

INPUT_FILE="$1"
shift || true

RESET=0
STATUS_ONLY=0
FAST_MODE=0
LOW_RESOURCE=0
FULLURL_MODE=0
NO_LFI_SCAN=0
NO_SQLMAP=0
OUTPUT_FILE_ARG=""
GITHUB_ORG=""

# ---- Per-tool skip switches -------------------------------------------------
# Every optional tool gets its own NO_<TOOL>=0/1 flag, set via --no-<tool>.
# These are checked as an additional AND-condition alongside the existing
# "${HAVE[tool]}" checks at each stage -- a tool that's installed and
# working can still be force-skipped for a given run without reaching for
# --fast (which skips a fixed bundle of stages, not a single tool).
declare -A NO_TOOL=(
    [amass]=0 [dnsx]=0 [puredns]=0 [alterx]=0 [waybackurls]=0 [subjs]=0
    [arjun]=0 [dalfox]=0 [ffuf]=0 [gowitness]=0 [naabu]=0 [anew]=0
    [s3scanner]=0 [wafw00f]=0 [notify]=0 [nuclei]=0 [katana]=0 [gau]=0
    [gitleaks]=0 [trufflehog]=0 [sourcemaps]=0
)

# Simple index-based parse (not a for-each) so --github-org can consume its
# value from the next array slot.
ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
    arg="${ARGS[$i]}"
    case "$arg" in
        -h|--help) print_usage; exit 0 ;;
        --reset) RESET=1 ;;
        --status) STATUS_ONLY=1 ;;
        --no-claude) RUN_CLAUDE_ANALYSIS=0 ;;
        --fast) FAST_MODE=1 ;;
        --low-resource) LOW_RESOURCE=1 ;;
        --fullurl) FULLURL_MODE=1 ;;
        --no-lfi-scan) NO_LFI_SCAN=1 ;;
        --no-sqlmap) NO_SQLMAP=1 ;;
        --sqlmap-level)
            i=$((i+1))
            SQLMAP_LEVEL="${ARGS[$i]:-1}"
            ;;
        --sqlmap-risk)
            i=$((i+1))
            SQLMAP_RISK="${ARGS[$i]:-1}"
            ;;
        --github-org)
            i=$((i+1))
            GITHUB_ORG="${ARGS[$i]:-}"
            ;;
        --no-amass) NO_TOOL[amass]=1 ;;
        --no-dnsx) NO_TOOL[dnsx]=1 ;;
        --no-puredns) NO_TOOL[puredns]=1 ;;
        --no-alterx) NO_TOOL[alterx]=1 ;;
        --no-waybackurls) NO_TOOL[waybackurls]=1 ;;
        --no-subjs) NO_TOOL[subjs]=1 ;;
        --no-arjun) NO_TOOL[arjun]=1 ;;
        --no-dalfox) NO_TOOL[dalfox]=1 ;;
        --no-ffuf) NO_TOOL[ffuf]=1 ;;
        --no-gowitness) NO_TOOL[gowitness]=1 ;;
        --no-naabu) NO_TOOL[naabu]=1 ;;
        --no-anew) NO_TOOL[anew]=1 ;;
        --no-s3scanner) NO_TOOL[s3scanner]=1 ;;
        --no-wafw00f) NO_TOOL[wafw00f]=1 ;;
        --no-notify) NO_TOOL[notify]=1 ;;
        --no-nuclei) NO_TOOL[nuclei]=1 ;;
        --no-katana) NO_TOOL[katana]=1 ;;
        --no-gau) NO_TOOL[gau]=1 ;;
        --no-gitleaks) NO_TOOL[gitleaks]=1 ;;
        --no-trufflehog) NO_TOOL[trufflehog]=1 ;;
        --no-sourcemaps) NO_TOOL[sourcemaps]=1 ;;
        --no-*)
            echo "[!] Unknown --no-* flag: '$arg' -- ignoring. Supported tools: ${!NO_TOOL[*]}" >&2
            ;;
        *) OUTPUT_FILE_ARG="$arg" ;;
    esac
    i=$((i+1))
done

# Back-compat alias: keep $NO_AMASS working since it's referenced by name
# further down and may be relied on if anyone sources this script.
NO_AMASS="${NO_TOOL[amass]}"

# --low-resource: halve the already-reduced defaults again. Useful on a laptop
# running on battery, alongside a VM/browser, or if the machine still hangs
# at the normal defaults above.
if [[ "$LOW_RESOURCE" -eq 1 ]]; then
    NUCLEI_CONCURRENCY=$(( NUCLEI_CONCURRENCY / 2 )); [[ "$NUCLEI_CONCURRENCY" -lt 1 ]] && NUCLEI_CONCURRENCY=1
    NUCLEI_BULK_SIZE=$(( NUCLEI_BULK_SIZE / 2 )); [[ "$NUCLEI_BULK_SIZE" -lt 1 ]] && NUCLEI_BULK_SIZE=1
    NUCLEI_PARALLEL_JOBS=1
    HTTPX_THREADS=$(( HTTPX_THREADS / 2 )); [[ "$HTTPX_THREADS" -lt 5 ]] && HTTPX_THREADS=5
    DNSX_THREADS=$(( DNSX_THREADS / 2 )); [[ "$DNSX_THREADS" -lt 10 ]] && DNSX_THREADS=10
    FFUF_THREADS=$(( FFUF_THREADS / 2 )); [[ "$FFUF_THREADS" -lt 5 ]] && FFUF_THREADS=5
    VHOST_FFUF_THREADS=$(( VHOST_FFUF_THREADS / 2 )); [[ "$VHOST_FFUF_THREADS" -lt 5 ]] && VHOST_FFUF_THREADS=5
    DALFOX_WORKERS=$(( DALFOX_WORKERS / 2 )); [[ "$DALFOX_WORKERS" -lt 5 ]] && DALFOX_WORKERS=5
    ARJUN_THREADS=$(( ARJUN_THREADS / 2 )); [[ "$ARJUN_THREADS" -lt 3 ]] && ARJUN_THREADS=3
    GOWITNESS_THREADS=1
    WAFW00F_PARALLEL_JOBS=1
    NAABU_RATE_LIMIT=$(( NAABU_RATE_LIMIT / 2 )); [[ "$NAABU_RATE_LIMIT" -lt 50 ]] && NAABU_RATE_LIMIT=50
    GITHUB_SECRETS_PARALLEL_JOBS=1
    echo "[*] --low-resource: concurrency trimmed further (nuclei parallel jobs=1, concurrency=${NUCLEI_CONCURRENCY})." >&2
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] Error: file '$INPUT_FILE' not found in current directory ($(pwd))." >&2
    exit 1
fi

BASENAME="$(basename "$INPUT_FILE")"
BASENAME_NOEXT="${BASENAME%.*}"

# ---------------------------------------------------------------------------
# ALL output for this run lives under one top-level results directory instead
# of being scattered as loose ${BASENAME_NOEXT}_* files/dirs next to the
# script. Every path below is now rooted at $ALLRESULTS_DIR (still namespaced
# per-input-file via a ${BASENAME_NOEXT}/ subdirectory, so multiple scope
# files don't collide with each other inside the same allresults/ tree).
# Override the root with ALLRESULTS_DIR=/some/path ./recon3.sh ... if needed.
# ---------------------------------------------------------------------------
ALLRESULTS_DIR="${ALLRESULTS_DIR:-./allresults}"
RUN_DIR="${ALLRESULTS_DIR}/${BASENAME_NOEXT}"
mkdir -p "$RUN_DIR"

OUTPUT_FILE="${OUTPUT_FILE_ARG:-${RUN_DIR}/${BASENAME_NOEXT}_live.txt}"
HOSTS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_hosts.txt"
HOSTS_ALL_RAW_FILE="${RUN_DIR}/${BASENAME_NOEXT}_hosts_raw_with_ports.txt"
HOSTS_WITH_PORT_FILE="${RUN_DIR}/${BASENAME_NOEXT}_hosts_with_port.txt"
PROBE_TARGETS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_probe_targets.txt"
RESOLVED_HOSTS="${RUN_DIR}/${BASENAME_NOEXT}_resolved.txt"
BRUTE_HOSTS="${RUN_DIR}/${BASENAME_NOEXT}_bruteforced.txt"
PERM_HOSTS="${RUN_DIR}/${BASENAME_NOEXT}_permutations.txt"
ALL_SUBS="${RUN_DIR}/${BASENAME_NOEXT}_all_subdomains.txt"
PORT_SCAN_FILE="${RUN_DIR}/${BASENAME_NOEXT}_ports.txt"
URLS_DIR="${RUN_DIR}/${BASENAME_NOEXT}_urls"
URLS_COMBINED="${RUN_DIR}/${BASENAME_NOEXT}_urls_all.txt"
URLS_DEDUPED="${RUN_DIR}/${BASENAME_NOEXT}_urls_deduped.txt"
JS_FILES="${RUN_DIR}/${BASENAME_NOEXT}_js_files.txt"
JS_FINDINGS_DIR="${RUN_DIR}/${BASENAME_NOEXT}_js_findings"
PARAMS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_params.txt"
FFUF_OUT_DIR="${RUN_DIR}/${BASENAME_NOEXT}_ffuf_results"
# --- Dalfox / XSS pipeline outputs (gau/crawler -> params -> dalfox -> analysis -> verified) ---
URLS_WITH_PARAMS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_urls_with_params.txt"
DALFOX_OUT="${RUN_DIR}/${BASENAME_NOEXT}_dalfox_xss.txt"
DALFOX_RAW_JSON="${RUN_DIR}/${BASENAME_NOEXT}_dalfox_xss_raw.json"
XSS_VERIFIED_FILE="${RUN_DIR}/${BASENAME_NOEXT}_xss_verified.txt"
SCREENSHOT_DIR="${RUN_DIR}/${BASENAME_NOEXT}_screenshots"
NUCLEI_OUT_DIR="${RUN_DIR}/${BASENAME_NOEXT}_nuclei_results"
PROGRESS_DIR="${RUN_DIR}/${BASENAME_NOEXT}_progress"
STATE_FILE="${PROGRESS_DIR}/state.txt"
DOMAIN_LOCK="${PROGRESS_DIR}/.lock"
CLAUDE_OUT_DIR="${RUN_DIR}/${BASENAME_NOEXT}_claude_analysis"
CLAUDE_CHUNKS_DIR="${CLAUDE_OUT_DIR}/chunks"
CLAUDE_FINAL_SUMMARY="${RUN_DIR}/${BASENAME_NOEXT}_claude_analysis_summary.md"
TRIAGE_REPORT="${RUN_DIR}/${BASENAME_NOEXT}_TRIAGE_SUMMARY.md"
AMASS_ENUM_OUT_FILE="${RUN_DIR}/${BASENAME_NOEXT}_amass_enum.txt"
AMASS_RAW_LOG="${RUN_DIR}/${BASENAME_NOEXT}_amass_raw.log"
BUCKET_FINDINGS="${RUN_DIR}/${BASENAME_NOEXT}_cloud_buckets.txt"
WAF_MAP_FILE="${RUN_DIR}/${BASENAME_NOEXT}_waf_mapping.txt"
VHOST_OUT_FILE="${RUN_DIR}/${BASENAME_NOEXT}_vhosts.txt"
SUBS_SEEN_FILE="${RUN_DIR}/${BASENAME_NOEXT}_subs_seen.txt"       # anew's persistent "master" list across runs
SUBS_NEW_FILE="${RUN_DIR}/${BASENAME_NOEXT}_subs_new_this_run.txt"
GITHUB_SECRETS_DIR="${RUN_DIR}/${BASENAME_NOEXT}_github_secrets"
GITHUB_SECRETS_SUMMARY="${RUN_DIR}/${BASENAME_NOEXT}_github_secrets_summary.txt"
SOURCEMAPS_DIR="${RUN_DIR}/${BASENAME_NOEXT}_sourcemaps"
SOURCEMAP_FINDINGS="${RUN_DIR}/${BASENAME_NOEXT}_sourcemap_findings.md"
INTERNAL_HOSTS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_internal_hosts.txt"
IIS_HOSTS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_iis_hosts.txt"
LFI_CANDIDATES_FILE="${RUN_DIR}/${BASENAME_NOEXT}_lfi_candidates.txt"
LFI_FUZZ_MAP_FILE="${RUN_DIR}/${BASENAME_NOEXT}_lfi_fuzz_map.txt"
LFI_FFUF_OUT_DIR="${RUN_DIR}/${BASENAME_NOEXT}_lfi_ffuf_results"
SQLI_CANDIDATES_FILE="${RUN_DIR}/${BASENAME_NOEXT}_sqli_candidates.txt"
SQLMAP_OUT_DIR="${RUN_DIR}/${BASENAME_NOEXT}_sqlmap_results"

mkdir -p "$PROGRESS_DIR" "$NUCLEI_OUT_DIR" "$URLS_DIR" "$JS_FINDINGS_DIR" "$FFUF_OUT_DIR" \
         "$GITHUB_SECRETS_DIR" "$SOURCEMAPS_DIR" "$LFI_FFUF_OUT_DIR" "$SQLMAP_OUT_DIR"
touch "$STATE_FILE" "$SUBS_SEEN_FILE" "$HOSTS_WITH_PORT_FILE"
echo "[*] All output for this run -> $RUN_DIR/"

is_done() { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }
mark_done() {
    ( flock -x 200; echo "$1" >> "$STATE_FILE" ) 200>"$DOMAIN_LOCK"
}

# Runs the heavy scanning tools (nuclei/wafw00f/ffuf/gowitness/naabu/amass) at
# lowered CPU (nice) and I/O (ionice) priority so they don't starve your desktop
# session / other apps even while several of them are running concurrently.
# Falls back to running the command unprefixed if neither tool is available.
run_niced() {
    if command -v ionice >/dev/null 2>&1 && command -v nice >/dev/null 2>&1; then
        ionice -c3 nice -n 10 "$@"
    elif command -v nice >/dev/null 2>&1; then
        nice -n 10 "$@"
    else
        "$@"
    fi
}

# High-signal alerting -- pushes to notify (Slack/Discord/etc) if configured, always echoes.
alert_finding() {
    local message="[RECON-ALERT] $1"
    echo "$message"
    if [[ "${HAVE[notify]:-0}" -eq 1 && "${NO_TOOL[notify]:-0}" -eq 0 ]]; then
        echo "$message" | notify -silent 2>/dev/null || true
    fi
}

# =====================================================================
# v7: port-aware host extraction
#
# Earlier versions extracted bare hostnames only, stripping any :port off
# whatever httpx echoed back -- which silently threw away targets. A host
# answering on :8443 or :8080 alongside (or instead of) 80/443 is frequently
# a completely different app/vhost, not just an alternate route to the same
# one, so losing the port loses a real target.
#
# extract_hosts reads a URL-bearing file (httpx output) and produces:
#   - HOSTS_FILE            : bare hostnames only (existing behavior, still
#                              what dnsx/puredns/alterx/naabu/gau expect)
#   - HOSTS_WITH_PORT_FILE  : host:port entries, ONLY for the ones that were
#                              actually seen on a non-default port
#   - PROBE_TARGETS_FILE    : bare ∪ host:port, for anything that should
#                              treat both forms as distinct scan targets
#                              (httpx re-probe, katana -list)
# =====================================================================
extract_hosts() {
    local src="$1"
    grep -oE 'https?://[^][:space:]]+' "$src" \
        | sed -E 's#^https?://##; s#/.*$##' \
        | tr 'A-Z' 'a-z' | sort -u > "$HOSTS_ALL_RAW_FILE"

    sed -E 's#:[0-9]+$##' "$HOSTS_ALL_RAW_FILE" | sort -u > "$HOSTS_FILE"
    grep -E ':[0-9]+$' "$HOSTS_ALL_RAW_FILE" | sort -u > "$HOSTS_WITH_PORT_FILE"
    cat "$HOSTS_FILE" "$HOSTS_WITH_PORT_FILE" | sort -u > "$PROBE_TARGETS_FILE"
}

# =====================================================================
# v7: shared ffuf baseline helper
#
# Computes a `-fs` (filter-by-size) argument set from TWO real requests
# against the target: the root URL itself, and a guaranteed-nonexistent
# random path. Using only the root (as the old vhost-fuzz stage did) misses
# soft-404 pages whose size differs from the root but is still constant
# garbage across every FUZZ word; using only a random 404 misses targets
# whose "not found" behavior differs from a generic path. Using both and
# passing them all to -fs covers both cases.
#
# Usage: ffuf_baseline_fs "https://target.tld" outvar_name
# Populates outvar_name (via eval) as a bash array suitable for splicing
# straight into an ffuf command line, e.g. "${fs_args[@]}".
# =====================================================================
ffuf_baseline_fs() {
    local url="$1" __outvar="$2"
    local rand_path size_root size_404
    rand_path="nonexistent-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 12)-probe"
    [[ -z "$rand_path" || "$rand_path" == "nonexistent--probe" ]] && rand_path="nonexistent-$$-$RANDOM-probe"

    size_root="$(curl -s -o /dev/null -w '%{size_download}' -m "$FFUF_BASELINE_TIMEOUT" "$url" 2>/dev/null || echo 0)"
    size_404="$(curl -s -o /dev/null -w '%{size_download}' -m "$FFUF_BASELINE_TIMEOUT" "${url%/}/${rand_path}" 2>/dev/null || echo 0)"

    local sizes=()
    [[ "$size_root" =~ ^[0-9]+$ && "$size_root" -gt 0 ]] && sizes+=("$size_root")
    [[ "$size_404" =~ ^[0-9]+$ && "$size_404" -gt 0 && "$size_404" != "$size_root" ]] && sizes+=("$size_404")

    if [[ "${#sizes[@]}" -gt 0 ]]; then
        local joined
        joined="$(IFS=,; echo "${sizes[*]}")"
        eval "$__outvar=(-fs \"$joined\")"
    else
        eval "$__outvar=()"
    fi
}

# =====================================================================
# v8: LFI/path-traversal baseline helper
#
# Same two-point idea as ffuf_baseline_fs, but computed against the actual
# candidate URL with its vulnerable-looking parameter swapped out -- once
# for the ORIGINAL value (call it the "normal" response) and once for a
# garbage/nonexistent value in that same parameter (the "not found"
# response) -- rather than against the URL root. A path-traversal param's
# 404 behavior can differ from the site's generic 404, so baselining on
# the actual parameter is more accurate than reusing the root-page baseline.
#
# Usage: lfi_baseline_fs "https://target/x?file=FUZZ&other=1" "realvalue.txt" outvar_name
# =====================================================================
lfi_baseline_fs() {
    local fuzz_url="$1" original_value="$2" __outvar="$3"
    local rand_val normal_url notfound_url size_normal size_404

    rand_val="nonexistent-$$-$RANDOM-probe"
    normal_url="${fuzz_url//FUZZ/$original_value}"
    notfound_url="${fuzz_url//FUZZ/$rand_val}"

    size_normal="$(curl -s -o /dev/null -w '%{size_download}' -m "$FFUF_BASELINE_TIMEOUT" "$normal_url" 2>/dev/null || echo 0)"
    size_404="$(curl -s -o /dev/null -w '%{size_download}' -m "$FFUF_BASELINE_TIMEOUT" "$notfound_url" 2>/dev/null || echo 0)"

    local sizes=()
    [[ "$size_normal" =~ ^[0-9]+$ && "$size_normal" -gt 0 ]] && sizes+=("$size_normal")
    [[ "$size_404" =~ ^[0-9]+$ && "$size_404" -gt 0 && "$size_404" != "$size_normal" ]] && sizes+=("$size_404")

    if [[ "${#sizes[@]}" -gt 0 ]]; then
        local joined
        joined="$(IFS=,; echo "${sizes[*]}")"
        eval "$__outvar=(-fs \"$joined\")"
    else
        eval "$__outvar=()"
    fi
}

if [[ "$RESET" -eq 1 ]]; then
    echo "[*] --reset given: clearing checkpoint state."
    : > "$STATE_FILE"
    rm -f "$OUTPUT_FILE" "$HOSTS_FILE" "$HOSTS_ALL_RAW_FILE" "$HOSTS_WITH_PORT_FILE" "$PROBE_TARGETS_FILE" \
          "$RESOLVED_HOSTS" "$BRUTE_HOSTS" "$PERM_HOSTS" "$ALL_SUBS" \
          "$PORT_SCAN_FILE" "$URLS_COMBINED" "$URLS_DEDUPED" "$JS_FILES" "$PARAMS_FILE" \
          "$URLS_WITH_PARAMS_FILE" "$DALFOX_OUT" "$DALFOX_RAW_JSON" "$XSS_VERIFIED_FILE" \
          "$CLAUDE_FINAL_SUMMARY" "$TRIAGE_REPORT" \
          "$AMASS_ENUM_OUT_FILE" "$AMASS_RAW_LOG" "$BUCKET_FINDINGS" "$WAF_MAP_FILE" "$VHOST_OUT_FILE" "$SUBS_NEW_FILE" \
          "$GITHUB_SECRETS_SUMMARY" "$SOURCEMAP_FINDINGS" "$INTERNAL_HOSTS_FILE" "$IIS_HOSTS_FILE" \
          "$LFI_CANDIDATES_FILE" "$LFI_FUZZ_MAP_FILE" "$SQLI_CANDIDATES_FILE"
    rm -rf "$NUCLEI_OUT_DIR" "$URLS_DIR" "$JS_FINDINGS_DIR" "$FFUF_OUT_DIR" "$SCREENSHOT_DIR" "$CLAUDE_OUT_DIR" \
           "$GITHUB_SECRETS_DIR" "$SOURCEMAPS_DIR" "$LFI_FFUF_OUT_DIR" "$SQLMAP_OUT_DIR"
    mkdir -p "$NUCLEI_OUT_DIR" "$URLS_DIR" "$JS_FINDINGS_DIR" "$FFUF_OUT_DIR" "$GITHUB_SECRETS_DIR" "$SOURCEMAPS_DIR" \
             "$LFI_FFUF_OUT_DIR" "$SQLMAP_OUT_DIR"
    echo "[*] Note: $SUBS_SEEN_FILE (cross-run subdomain history) is preserved across --reset."
    echo "    Delete it manually if you want a truly clean slate for diff tracking."
fi

# ---- Dependency checks ------------------------------------------------------
REQUIRED_BINS=(subfinder httpx nuclei katana gau)
OPTIONAL_BINS=(dnsx puredns alterx waybackurls subjs arjun dalfox ffuf gowitness naabu jq anew \
               amass s3scanner wafw00f notify dig gitleaks trufflehog python3)

declare -A INSTALL_HINT=(
    [dnsx]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [puredns]="go install github.com/d3mondev/puredns/v2@latest"
    [alterx]="go install github.com/projectdiscovery/alterx/cmd/alterx@latest"
    [waybackurls]="go install github.com/tomnomnom/waybackurls@latest"
    [subjs]="go install github.com/lc/subjs@latest"
    [arjun]="pipx install arjun  # or: sudo apt install -y arjun"
    [dalfox]="go install github.com/hahwul/dalfox/v2@latest"
    [ffuf]="sudo apt install -y ffuf"
    [gowitness]="go install github.com/sensepost/gowitness@latest"
    [naabu]="sudo apt install -y naabu"
    [jq]="sudo apt install -y jq"
    [anew]="go install github.com/tomnomnom/anew@latest"
    [amass]="sudo apt install -y amass"
    [s3scanner]="pip3 install s3scanner"
    [wafw00f]="sudo apt install -y wafw00f"
    [notify]="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
    [dig]="sudo apt install -y dnsutils"
    [gitleaks]="brew install gitleaks   # or download a release binary: https://github.com/gitleaks/gitleaks/releases"
    [trufflehog]="curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin  # or: pip install trufflehog3 / brew install trufflehog"
    [python3]="sudo apt install -y python3"
)

for bin in "${REQUIRED_BINS[@]}"; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "[!] Error: required tool '$bin' not found in PATH." >&2
        exit 1
    fi
done

declare -A HAVE
for bin in "${OPTIONAL_BINS[@]}"; do
    if command -v "$bin" >/dev/null 2>&1; then
        HAVE["$bin"]=1
    else
        HAVE["$bin"]=0
        hint="${INSTALL_HINT[$bin]:-}"
        if [[ -n "$hint" ]]; then
            echo "[!] Optional tool '$bin' not found -- related stage will be skipped. Install: $hint" >&2
        else
            echo "[!] Optional tool '$bin' not found -- related stage will be skipped." >&2
        fi
    fi
done

# Report any --no-<tool> flags the user passed that are actually forcing a skip
# (as opposed to the tool already being missing, which is reported above).
for t in "${!NO_TOOL[@]}"; do
    if [[ "${NO_TOOL[$t]}" -eq 1 ]]; then
        if [[ "$t" == "nuclei" || "$t" == "katana" || "$t" == "gau" ]]; then
            echo "[*] --no-$t given: $t stage(s) will be force-skipped even though it's a core/required tool." >&2
        elif [[ "${HAVE[$t]:-0}" -eq 1 ]]; then
            echo "[*] --no-$t given: forcing skip of $t stage(s) (tool is installed but won't be used this run)." >&2
        fi
    fi
done

if [[ "${HAVE[notify]:-0}" -eq 1 && "${NO_TOOL[notify]:-0}" -eq 0 ]] && ! [[ -f "${HOME}/.config/notify/provider-config.yaml" ]]; then
    echo "[!] 'notify' is installed but no provider config found at ~/.config/notify/provider-config.yaml" >&2
    echo "    Alerts will be printed to stdout only until it's configured. See: https://github.com/projectdiscovery/notify" >&2
fi

if [[ "${NO_TOOL[gitleaks]}" -eq 0 && "${NO_TOOL[trufflehog]}" -eq 0 && "${HAVE[gitleaks]:-0}" -eq 0 && "${HAVE[trufflehog]:-0}" -eq 0 ]]; then
    echo "[!] Neither gitleaks nor trufflehog is installed -- GitHub secret-scanning stage will be fully skipped." >&2
    echo "    This is one of the highest-signal, most commonly-skipped recon stages -- consider installing at least one:" >&2
    echo "      gitleaks:   ${INSTALL_HINT[gitleaks]}" >&2
    echo "      trufflehog: ${INSTALL_HINT[trufflehog]}" >&2
fi

if [[ "${NO_TOOL[sourcemaps]}" -eq 0 && "${HAVE[python3]:-0}" -eq 0 ]]; then
    echo "[!] python3 not found -- JS sourcemap extraction stage will be skipped. Install: ${INSTALL_HINT[python3]}" >&2
fi

if [[ "$RUN_CLAUDE_ANALYSIS" -eq 1 ]] && ! command -v claude >/dev/null 2>&1; then
    echo "[!] Warning: 'claude' CLI not found in PATH -- final analysis step will be skipped." >&2
    RUN_CLAUDE_ANALYSIS=0
fi

if [[ "$FULLURL_MODE" -eq 1 ]]; then
    echo "[*] --fullurl enabled: tech-detect-triggered targeted scans (e.g. IIS) will run after the generic scans."
fi

if [[ "$NO_LFI_SCAN" -eq 0 && ! -f "$DOTDOTPWN_WORDLIST" ]]; then
    echo "[!] dotdotpwn wordlist not found at $DOTDOTPWN_WORDLIST -- LFI/path-traversal ffuf stage will be skipped." >&2
    echo "    Override with: DOTDOTPWN_WORDLIST=/path/to/list $0 ..." >&2
fi

if [[ "$NO_SQLMAP" -eq 0 && ! -f "${SQLMAP_DIR}/sqlmap.py" ]]; then
    echo "[!] sqlmap.py not found at ${SQLMAP_DIR}/sqlmap.py -- sqlmap handoff stage will be skipped." >&2
    echo "    Override with: SQLMAP_DIR=/path/to/sqlmap-dev $0 ..." >&2
fi

mapfile -t DOMAINS < <(tr -d '\r' < "$INPUT_FILE" | sed '/^\s*$/d' | sed '/^\s*#/d')
if [[ ${#DOMAINS[@]} -eq 0 ]]; then
    echo "[!] No domains found in '$INPUT_FILE'." >&2
    exit 1
fi

# Derive a best-guess GitHub org/user slug from the first domain if the user
# didn't pass --github-org explicitly. This is a heuristic (strip TLD/subdomain,
# take the registrable-ish label) -- it will often be right for a company's
# primary org name but should be treated as a starting guess, not gospel.
if [[ -z "$GITHUB_ORG" && ${#DOMAINS[@]} -gt 0 ]]; then
    GITHUB_ORG="$(echo "${DOMAINS[0]}" | awk -F. '{ if (NF>=2) print $(NF-1); else print $1 }')"
    echo "[*] No --github-org given; guessing GitHub org/user from domain: '$GITHUB_ORG' (override with --github-org <name> if wrong)"
fi

# ---- Status mode -------------------------------------------------------------
if [[ "$STATUS_ONLY" -eq 1 ]]; then
    total_domains=${#DOMAINS[@]}
    done_domains=0
    for d in "${DOMAINS[@]}"; do is_done "domain:$d" && ((done_domains++)); done
    echo "===== Checkpoint status for: $INPUT_FILE ====="
    echo "Domains:  $done_domains / $total_domains done"
    for stage in "amass:enum" "stage1:complete" "dns:resolved" "dns:bruteforce" "dns:permutations" \
                 "ports:scanned" "hosts:extracted" "urls:katana" "urls:gau" "urls:waybackurls" \
                 "urls:combined" "urls:deduped" "js:collected" "js:analyzed" "params:discovered" \
                 "highsignal:fastpass" "xss:dalfox" "ffuf:complete" "screenshots:complete" \
                 "buckets:scanned" "waf:mapped" "vhosts:scanned" "github:secrets" "js:sourcemaps" \
                 "internal:hosts" "fullurl:tech" "lfi:scanned" "sqlmap:scanned" "claude:complete"; do
        is_done "$stage" && echo "  [x] $stage" || echo "  [ ] $stage"
    done
    nuclei_done=$(grep -cE '^(hostscan|urlscan|iisscan|tmpl|tag|urltmpl|urltag):' "$STATE_FILE" 2>/dev/null || echo 0)
    echo "  nuclei jobs completed: $nuclei_done"
    echo
    echo "Resume with:  $0 $INPUT_FILE"
    echo "Start over:   $0 $INPUT_FILE --reset"
    exit 0
fi

touch "$OUTPUT_FILE"
echo "[*] Loaded ${#DOMAINS[@]} domain(s) from: $INPUT_FILE"
echo "[*] Fast mode: $([[ $FAST_MODE -eq 1 ]] && echo ON || echo off)"
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 0: amass enum — additional passive subdomain source
#
# NOTE (migration): amass v4 and earlier had a separate `intel -whois` mode
# that did reverse-WHOIS/ASN-based org expansion (find related netblocks from
# a domain). OWASP Amass v5 removed the `intel` subcommand entirely -- there
# is no direct replacement for that specific reverse-WHOIS capability in the
# current CLI. `enum`'s -asn/-cidr flags are INPUTS (seed amass with ASNs you
# already know), not outputs, so they don't recover the old behavior.
#
# What this stage does instead: runs amass's own passive enumeration engine
# (pulls from its own certificate-transparency/passive-source set, which
# partially overlaps subfinder's sources but isn't identical) as an
# additional subdomain feed into the pipeline. It's no longer doing ASN/org
# discovery -- if you specifically need reverse-WHOIS/netblock expansion,
# that requires either a pinned older amass binary or a different tool
# entirely (e.g. BGP.he.net / Hurricane Electric lookups, or a WHOIS API).
#
# -active is deliberately NOT set: that would enable zone transfer attempts
# and cert-grabbing against live hosts, which is more intrusive than plain
# passive enumeration and shouldn't run without deciding that's in-scope.
# -passive is omitted since v5 made it the (deprecated-flag) default.
# -v is set: amass queries dozens of passive sources, some of which are slow
# or rate-limited, so there can be genuine multi-minute gaps with no new
# hostname even though it's actively working. -v makes amass itself print
# status/debug info during those gaps instead of going silent.
#
# A background heartbeat also prints "[amass] still running -- Ns elapsed"
# every 20s regardless of what amass itself outputs, so a long quiet stretch
# is visibly "still working" rather than indistinguishable from a hang. The
# heartbeat is killed as soon as that domain's amass run exits.
#
# Uses amass's own -timeout (minutes without progress, not wall-clock), which
# is more reliable than wrapping it in an external `timeout` command. stdin
# is redirected from /dev/null so nothing it shells out to can hang the
# pipeline waiting on a password/input prompt that will never arrive in a
# non-interactive run.
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[amass]}" -eq 0 && "${HAVE[amass]:-0}" -eq 1 ]]; then
    if is_done "amass:enum"; then
        echo "[=] Skipping (done): amass enum"
    else
        echo "[*] Running amass enum (passive, -v, capped at ${AMASS_TIMEOUT_MIN}m without progress)..."
        for domain in "${DOMAINS[@]}"; do
            echo "[*] amass enum: $domain"

            # Heartbeat: prints a "still alive" line every 20s in the background so a
            # slow passive source doesn't look indistinguishable from a hung process.
            # Runs in its own subshell; killed unconditionally once amass exits below.
            (
                elapsed=0
                while true; do
                    sleep 20
                    elapsed=$((elapsed + 20))
                    echo "[amass] still running on $domain -- ${elapsed}s elapsed, $(wc -l < "$AMASS_ENUM_OUT_FILE" 2>/dev/null | tr -d ' ') subdomain(s) parsed so far"
                done
            ) &
            heartbeat_pid=$!

            # Dropped -silent, added -v, so progress/results/status all stream to the
            # terminal live (matches Stage 1's subfinder|httpx behavior) instead of running
            # invisibly for up to 10 minutes. Raw output (banner + status lines + hostnames
            # all mixed) goes to AMASS_RAW_LOG via tee so you can watch/review it; only lines
            # that look like valid hostnames get filtered into AMASS_ENUM_OUT_FILE so the
            # banner art/status text doesn't pollute the subdomain list that merges into scope.
            amass enum -d "$domain" -timeout "$AMASS_TIMEOUT_MIN" -v \
                < /dev/null 2>&1 | tee -a "$AMASS_RAW_LOG" \
                | grep -oE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$' \
                >> "$AMASS_ENUM_OUT_FILE"
            amass_status="${PIPESTATUS[0]}"

            # Heartbeat's only job was to fill silence while amass ran; stop it now.
            kill "$heartbeat_pid" 2>/dev/null
            wait "$heartbeat_pid" 2>/dev/null

            # PIPESTATUS[0] is amass's own exit code -- the pipe's overall $? would reflect
            # grep's status instead (grep exits 1 if it matched nothing, which isn't a failure).
            if [[ "$amass_status" -ne 0 ]]; then
                echo "[!] amass enum timed out or failed for $domain -- continuing." >&2
            fi
        done
        sort -u -o "$AMASS_ENUM_OUT_FILE" "$AMASS_ENUM_OUT_FILE" 2>/dev/null || true
        # feed amass's finds into the same all-subdomains pool DNS bruteforce/permutations use
        cat "$AMASS_ENUM_OUT_FILE" >> "$ALL_SUBS" 2>/dev/null || true
        sort -u -o "$ALL_SUBS" "$ALL_SUBS" 2>/dev/null || true
        mark_done "amass:enum"
        AMASS_COUNT=$(wc -l < "$AMASS_ENUM_OUT_FILE" 2>/dev/null | tr -d ' ')
        echo "[+] amass enum -> $AMASS_ENUM_OUT_FILE (${AMASS_COUNT:-0} subdomain(s), merged into scope)"
        if [[ "${AMASS_COUNT:-0}" -gt 0 ]]; then
            echo "    Discovered:"
            sed 's/^/      /' "$AMASS_ENUM_OUT_FILE"
        else
            echo "    No subdomains parsed out of amass's output -- check $AMASS_RAW_LOG for the raw run"
            echo "    (could be zero results, or the hostname filter regex didn't match this domain's TLD format)."
        fi
    fi
else
    echo "[=] Skipping amass enum (fast mode, --no-amass, or amass not installed)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 1: subfinder + httpx (passive subdomain enum + live probing)
# =====================================================================
if is_done "stage1:complete"; then
    echo "[+] Stage 1 already complete. Skipping."
else
    for domain in "${DOMAINS[@]}"; do
        job="domain:$domain"
        if is_done "$job"; then echo "[=] Skipping: $domain"; continue; fi

        echo "[*] Passive enum + probe: $domain"
        attempt=1; max_attempts=3; success=0
        while [[ $attempt -le $max_attempts ]]; do
            if subfinder -d "$domain" -silent -all -exclude-sources digitorus | \
               httpx -sc -title -cl -location -web-server -tech-detect -follow-redirects \
                     -rate-limit "$HTTPX_RATE_LIMIT" -threads "$HTTPX_THREADS" \
                     -timeout 10 -retries 1 | tee -a "$OUTPUT_FILE"; then
                success=1; break
            else
                echo "[!] Attempt $attempt/$max_attempts failed for $domain. Retrying in 5s..." >&2
                sleep 5; ((attempt++))
            fi
        done

        if [[ "$success" -eq 1 ]]; then mark_done "$job"; else
            echo "[!] Giving up on $domain after $max_attempts attempts." >&2; exit 2
        fi
    done
    mark_done "stage1:complete"
    echo "[+] Stage 1 done -> $OUTPUT_FILE"
fi

echo "[*] Extracting hostnames (bare + host:port) -> $HOSTS_FILE / $HOSTS_WITH_PORT_FILE"
extract_hosts "$OUTPUT_FILE"
cp "$HOSTS_FILE" "$ALL_SUBS"
PORT_HOST_COUNT=$(wc -l < "$HOSTS_WITH_PORT_FILE" 2>/dev/null | tr -d ' ')
if [[ "${PORT_HOST_COUNT:-0}" -gt 0 ]]; then
    echo "[+] $PORT_HOST_COUNT host(s) seen on a non-default port -- kept as explicit host:port target(s) in $HOSTS_WITH_PORT_FILE"
fi

# Cross-run diff tracking: anew appends only genuinely-new lines to SUBS_SEEN_FILE and
# echoes just those new lines. This persists ACROSS runs (survives --reset, see above),
# so re-running this script against the same scope next week tells you what's new without
# re-scanning everything from scratch by hand. This is informational/tracking only --
# it does NOT narrow the rest of THIS run's scope, which still processes the full host list.
if [[ "${HAVE[anew]:-0}" -eq 1 && "${NO_TOOL[anew]}" -eq 0 ]]; then
    sort -u "$HOSTS_FILE" | anew "$SUBS_SEEN_FILE" > "$SUBS_NEW_FILE" 2>/dev/null || true
    NEW_SUB_COUNT=$(wc -l < "$SUBS_NEW_FILE" 2>/dev/null | tr -d ' ')
    if [[ "${NEW_SUB_COUNT:-0}" -gt 0 ]]; then
        echo "[+] $NEW_SUB_COUNT host(s) new since the last run against this scope -> $SUBS_NEW_FILE"
        alert_finding "$NEW_SUB_COUNT new subdomain(s) discovered for ${BASENAME_NOEXT}: $(tr '\n' ' ' < "$SUBS_NEW_FILE" | cut -c1-300)"
    else
        echo "[*] No new hosts since the last tracked run (or this is the first run)."
    fi
else
    echo "[=] Skipping cross-run diff tracking (anew not installed or --no-anew)"
fi

HOST_COUNT=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
if [[ "${HOST_COUNT:-0}" -eq 0 ]]; then
    echo "[!] No live hosts from stage 1. Aborting." >&2
    exit 0
fi
echo "[+] $HOST_COUNT host(s) from passive enum"

# Full live URLs (scheme+host[:port]), needed by several later stages (WAF mapping,
# vhost fuzzing, URL discovery seeding) -- built once here so ordering doesn't matter.
# Deliberately NOT stripping ports here: a URL like https://sub.domain.com:8443 needs
# to stay intact so downstream ffuf/nuclei/wafw00f target the actual service, not the
# default-port host that may not even be running the same app.
LIVE_URLS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_live_urls.txt"
grep -oE '^https?://[^][:space:]]+' "$OUTPUT_FILE" | sort -u > "$LIVE_URLS_FILE"

# =====================================================================
# STAGE 2: DNS bruteforce + permutations — finds what subfinder can't
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[puredns]}" -eq 0 && "${HAVE[puredns]}" -eq 1 && -f "$RESOLVERS_FILE" ]]; then
    if is_done "dns:bruteforce"; then
        echo "[=] Skipping (done): puredns bruteforce"
    else
        for domain in "${DOMAINS[@]}"; do
            echo "[*] puredns bruteforce: $domain"
            if [[ -f "$SUBDOMAIN_WORDLIST" ]]; then
                puredns bruteforce "$SUBDOMAIN_WORDLIST" "$domain" \
                    -r "$RESOLVERS_FILE" --rate-limit "$PUREDNS_RATE_LIMIT" \
                    --write "${BRUTE_HOSTS}.tmp" 2>/dev/null || true
                cat "${BRUTE_HOSTS}.tmp" >> "$BRUTE_HOSTS" 2>/dev/null || true
                rm -f "${BRUTE_HOSTS}.tmp"
            else
                echo "[!] Subdomain wordlist not found at $SUBDOMAIN_WORDLIST -- skipping bruteforce for $domain" >&2
            fi
        done
        sort -u -o "$BRUTE_HOSTS" "$BRUTE_HOSTS" 2>/dev/null || true
        mark_done "dns:bruteforce"
        echo "[+] puredns bruteforce found $(wc -l < "$BRUTE_HOSTS" 2>/dev/null | tr -d ' ') host(s)"
    fi
else
    echo "[=] Skipping puredns bruteforce (fast mode, --no-puredns, tool missing, or no resolvers file at $RESOLVERS_FILE)"
fi

if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[alterx]}" -eq 0 && "${HAVE[alterx]}" -eq 1 && "${NO_TOOL[dnsx]}" -eq 0 && "${HAVE[dnsx]}" -eq 1 ]]; then
    if is_done "dns:permutations"; then
        echo "[=] Skipping (done): alterx permutations"
    else
        echo "[*] Generating + resolving permutations with alterx + dnsx..."
        alterx -l "$HOSTS_FILE" -silent | \
            dnsx -silent -threads "$DNSX_THREADS" -resp-only > "$PERM_HOSTS" 2>/dev/null || true
        mark_done "dns:permutations"
        echo "[+] alterx/dnsx found $(wc -l < "$PERM_HOSTS" 2>/dev/null | tr -d ' ') permutation host(s)"
    fi
else
    echo "[=] Skipping alterx permutations (fast mode, --no-alterx/--no-dnsx, or alterx/dnsx missing)"
fi

# merge everything discovered so far, resolve with dnsx to kill dead/wildcard entries
cat "$HOSTS_FILE" "$BRUTE_HOSTS" "$PERM_HOSTS" 2>/dev/null | sort -u > "$ALL_SUBS"

if [[ "${NO_TOOL[dnsx]}" -eq 0 && "${HAVE[dnsx]}" -eq 1 ]]; then
    if is_done "dns:resolved"; then
        echo "[=] Skipping (done): dnsx resolution pass"
    else
        echo "[*] Resolving full subdomain set + filtering wildcards with dnsx..."
        dnsx -l "$ALL_SUBS" -silent -threads "$DNSX_THREADS" -wd "${DOMAINS[0]}" -resp-only > "$RESOLVED_HOSTS" 2>/dev/null || true
        mark_done "dns:resolved"
        echo "[+] $(wc -l < "$RESOLVED_HOSTS" 2>/dev/null | tr -d ' ') resolved host(s) after wildcard filtering"
    fi
    # re-probe any NEW hosts (bruteforce/permutation finds) through httpx to get them into the live set
    NEW_HOSTS_FILE="${RUN_DIR}/${BASENAME_NOEXT}_new_hosts.txt"
    comm -23 <(sort -u "$RESOLVED_HOSTS" 2>/dev/null) <(sort -u "$HOSTS_FILE") > "$NEW_HOSTS_FILE" 2>/dev/null || true
    if [[ -s "$NEW_HOSTS_FILE" ]]; then
        echo "[*] Probing $(wc -l < "$NEW_HOSTS_FILE" | tr -d ' ') newly discovered host(s) with httpx..."
        httpx -l "$NEW_HOSTS_FILE" -sc -title -cl -location -web-server -tech-detect -follow-redirects \
              -rate-limit "$HTTPX_RATE_LIMIT" -threads "$HTTPX_THREADS" -timeout 10 -retries 1 \
              | tee -a "$OUTPUT_FILE"
        # refresh hostname lists (bare + host:port + probe-targets) to include these
        extract_hosts "$OUTPUT_FILE"
        # keep LIVE_URLS_FILE in sync too, since WAF/vhost/bucket/nuclei stages consume it
        grep -oE '^https?://[^][:space:]]+' "$OUTPUT_FILE" | sort -u > "$LIVE_URLS_FILE"
    fi
else
    echo "[=] Skipping dnsx resolution (--no-dnsx or tool missing) -- using passive-only host list"
fi

HOST_COUNT=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
echo "[+] $HOST_COUNT total live host(s) after DNS expansion"
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 2a-int: Internal/private-address subdomain flagging
#
# One of the most overlooked recon findings: split-horizon or misconfigured
# DNS sometimes leaks a subdomain that resolves to RFC1918/loopback/link-local
# space. This means either (a) you're on a network with route visibility to
# it (VPN, corp wifi, cloud peering), or (b) the record itself confirms an
# internal hostname/naming scheme even if you can't reach the IP -- both are
# useful. This is a pure grep over data dnsx already produced above -- no
# extra scanning, no extra requests, purely passive re-analysis of resolved
# records. Runs regardless of --fast since it costs nothing.
# =====================================================================
if [[ "${NO_TOOL[dnsx]}" -eq 0 && "${HAVE[dnsx]:-0}" -eq 1 ]]; then
    if is_done "internal:hosts"; then
        echo "[=] Skipping (done): internal-host flagging"
    else
        echo "[*] Flagging subdomains resolving to private/internal address space..."
        : > "$INTERNAL_HOSTS_FILE"
        if [[ -f "$ALL_SUBS" && -s "$ALL_SUBS" ]]; then
            dnsx -l "$ALL_SUBS" -silent -threads "$DNSX_THREADS" -a -resp \
                2>/dev/null \
                | grep -E '\[(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)' \
                > "$INTERNAL_HOSTS_FILE" || true
        fi
        mark_done "internal:hosts"
        INTERNAL_COUNT=$(wc -l < "$INTERNAL_HOSTS_FILE" 2>/dev/null | tr -d ' ')
        echo "[+] internal-host flagging -> $INTERNAL_HOSTS_FILE (${INTERNAL_COUNT:-0} host(s) pointing at private/internal IP space)"
        if [[ "${INTERNAL_COUNT:-0}" -gt 0 ]]; then
            alert_finding "${INTERNAL_COUNT} subdomain(s) for ${BASENAME_NOEXT} resolve to private/internal IP space -- likely split-horizon DNS leak. See $INTERNAL_HOSTS_FILE"
        fi
    fi
else
    echo "[=] Skipping internal-host flagging (--no-dnsx or dnsx not installed)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 2b: Port scan with naabu — surfaces non-standard services
# (admin panels on weird ports, exposed DBs, internal services, etc.)
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[naabu]}" -eq 0 && "${HAVE[naabu]}" -eq 1 ]]; then
    if is_done "ports:scanned"; then
        echo "[=] Skipping (done): naabu port scan"
    else
        echo "[*] Running naabu top-1000 port scan..."
        run_niced naabu -l "$HOSTS_FILE" -top-ports 1000 -rate "$NAABU_RATE_LIMIT" -silent -o "$PORT_SCAN_FILE" 2>/dev/null || true
        mark_done "ports:scanned"
        echo "[+] naabu found $(wc -l < "$PORT_SCAN_FILE" 2>/dev/null | tr -d ' ') open host:port pair(s)"
        echo "    Review $PORT_SCAN_FILE manually for non-80/443 services worth investigating."
    fi
else
    echo "[=] Skipping naabu port scan (fast mode, --no-naabu, or tool missing)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 2c: Cloud storage bucket hunting (s3scanner)
# Derives search terms from the target domains (dots->underscores, and the
# bare org name from each domain) and checks for public/misconfigured buckets.
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[s3scanner]}" -eq 0 && "${HAVE[s3scanner]:-0}" -eq 1 ]]; then
    if is_done "buckets:scanned"; then
        echo "[=] Skipping (done): s3scanner bucket hunt"
    else
        echo "[*] Deriving bucket-name candidates and scanning with s3scanner..."
        BUCKET_WORDS_FILE="$(mktemp)"
        for domain in "${DOMAINS[@]}"; do
            echo "$domain" | sed 's/\./_/g' >> "$BUCKET_WORDS_FILE"
            echo "$domain" | sed 's/\./-/g' >> "$BUCKET_WORDS_FILE"
            echo "$domain" | awk -F. '{print $1}' >> "$BUCKET_WORDS_FILE"
        done
        sort -u -o "$BUCKET_WORDS_FILE" "$BUCKET_WORDS_FILE"

        # NOTE: s3scanner's CLI flags have changed across versions -- v2.x uses
        # `s3scanner scan -bf <file>` for bucket-name-file input, not
        # `--search-terms`. Check `s3scanner scan --help` against your installed
        # version and adjust the invocation below if it errors.
        if s3scanner scan -bf "$BUCKET_WORDS_FILE" < /dev/null 2>/dev/null | grep -iE "bucket_exists.*true|public" > "$BUCKET_FINDINGS"; then
            :
        else
            : > "$BUCKET_FINDINGS"
        fi
        rm -f "$BUCKET_WORDS_FILE"
        mark_done "buckets:scanned"

        if [[ -s "$BUCKET_FINDINGS" ]]; then
            alert_finding "Public/misconfigured storage bucket candidates found for ${BASENAME_NOEXT}: see $BUCKET_FINDINGS"
        else
            echo "[+] No public bucket candidates found."
        fi
    fi
else
    echo "[=] Skipping s3scanner (fast mode, --no-s3scanner, or tool missing)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 2d: WAF fingerprinting (wafw00f)
# Tells you what's in front of each live host BEFORE you spend payloads —
# knowing it's Cloudflare/Akamai/etc changes how you approach fuzzing and
# which nuclei tags are worth prioritizing (evasion-relevant templates).
# Runs in parallel (was fully sequential in the v3 draft).
# =====================================================================
if [[ "${NO_TOOL[wafw00f]}" -eq 0 && "${HAVE[wafw00f]:-0}" -eq 1 ]]; then
    if is_done "waf:mapped"; then
        echo "[=] Skipping (done): wafw00f mapping"
    else
        echo "[*] Fingerprinting WAFs across live hosts (parallel, $WAFW00F_PARALLEL_JOBS at a time)..."
        : > "$WAF_MAP_FILE"
        while read -r target_url; do
            [[ -z "$target_url" ]] && continue
            (
                result="$(run_niced wafw00f "$target_url" -a -s -o - < /dev/null 2>/dev/null | grep -iE 'is behind|no waf')"
                [[ -n "$result" ]] && { flock -x 201; echo "$target_url -> $result" >> "$WAF_MAP_FILE"; } 201>"${WAF_MAP_FILE}.lock"
            ) &
            while [[ "$(jobs -rp | wc -l)" -ge "$WAFW00F_PARALLEL_JOBS" ]]; do sleep 0.5; done
        done < "$LIVE_URLS_FILE"
        wait
        rm -f "${WAF_MAP_FILE}.lock"
        mark_done "waf:mapped"
        echo "[+] WAF mapping -> $WAF_MAP_FILE"
    fi
else
    echo "[=] Skipping wafw00f (--no-wafw00f or tool missing)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 2e: Virtual host (vhost) discovery via Host-header fuzzing
# FIX vs earlier draft: uses a DEDICATED vhost wordlist ($VHOST_WORDLIST),
# not the list of subdomains we already found (fuzzing with names you
# already resolved just re-confirms what you know). Also uses the shared
# ffuf_baseline_fs helper (root + guaranteed-404 baseline) so a host that
# returns 200 for every Host header doesn't flood the output with false
# positives.
#
# Gated on --no-ffuf too since this stage uses ffuf under the hood for the
# actual Host-header fuzzing, even though its purpose (vhost discovery) is
# distinct from stage 4c's content discovery.
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[ffuf]}" -eq 0 && "${HAVE[ffuf]:-0}" -eq 1 && "${HAVE[dig]:-0}" -eq 1 && -f "$VHOST_WORDLIST" ]]; then
    if is_done "vhosts:scanned"; then
        echo "[=] Skipping (done): vhost fuzzing"
    else
        echo "[*] Running vhost discovery (Host-header fuzzing) against resolved IPs..."
        : > "$VHOST_OUT_FILE"
        while read -r target_url; do
            [[ -z "$target_url" ]] && continue
            bare_host="$(echo "$target_url" | sed -E 's#https?://##; s#[/:].*$##')"
            ip="$(dig +short "$bare_host" | head -1)"
            [[ -z "$ip" ]] && continue

            ip_url="$(echo "$target_url" | sed "s#${bare_host}#${ip}#")"
            fs_args=()
            ffuf_baseline_fs "$ip_url" fs_args

            run_niced ffuf -u "$ip_url" \
                -H "Host: FUZZ.${bare_host}" -w "$VHOST_WORDLIST" \
                -mc 200,301,302,401,403 "${fs_args[@]}" \
                -t "$VHOST_FFUF_THREADS" -silent >> "$VHOST_OUT_FILE" 2>/dev/null || true
        done < "$LIVE_URLS_FILE"
        mark_done "vhosts:scanned"
        VHOST_HITS=$(wc -l < "$VHOST_OUT_FILE" 2>/dev/null | tr -d ' ')
        echo "[+] vhost fuzzing -> $VHOST_OUT_FILE ($VHOST_HITS candidate match(es), review for false positives)"
        if [[ "${VHOST_HITS:-0}" -gt 0 ]]; then
            alert_finding "$VHOST_HITS vhost candidate(s) found for ${BASENAME_NOEXT}: see $VHOST_OUT_FILE"
        fi
    fi
else
    echo "[=] Skipping vhost fuzzing (fast mode, --no-ffuf, ffuf/dig missing, or no vhost wordlist at $VHOST_WORDLIST)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 2f: GitHub secret scanning (gitleaks + trufflehog)
#
# One of the most commonly-skipped high-signal recon stages: developers
# leak API keys, tokens, and credentials in public repos (including in
# commit history for files later deleted). Nuclei/dalfox/ffuf never touch
# this surface at all since it isn't on the live web target.
#
# Uses GITHUB_ORG (explicit --github-org or auto-guessed from the domain,
# see above) to scan the org's public repos. Falls back gracefully: if
# only one of gitleaks/trufflehog is installed, runs just that one; if
# neither is installed, the whole stage is skipped with an install hint.
#
# trufflehog needs a GITHUB_TOKEN in the environment for anything beyond
# very limited unauthenticated rate limits -- warns but continues without
# one (results will just be sparser / slower).
#
# Gated behind --fast since scanning even a handful of repos' full commit
# history can take a while; use --no-gitleaks/--no-trufflehog to disable
# just one engine without dropping the whole stage.
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && -n "$GITHUB_ORG" && ( "${HAVE[gitleaks]:-0}" -eq 1 || "${HAVE[trufflehog]:-0}" -eq 1 ) ]]; then
    if is_done "github:secrets"; then
        echo "[=] Skipping (done): GitHub secret scanning"
    else
        echo "[*] Scanning GitHub org/user '$GITHUB_ORG' for leaked secrets..."
        : > "$GITHUB_SECRETS_SUMMARY"

        if [[ -z "${GITHUB_TOKEN:-}" ]]; then
            echo "[!] GITHUB_TOKEN not set in environment -- trufflehog/gitleaks org scans will be slow" >&2
            echo "    and rate-limited. Set it with: export GITHUB_TOKEN=ghp_xxxx  (repo:read scope is enough)" >&2
        fi

        if [[ "${NO_TOOL[trufflehog]}" -eq 0 && "${HAVE[trufflehog]:-0}" -eq 1 ]]; then
            echo "[*] Running trufflehog against GitHub org '$GITHUB_ORG' (verified secrets only)..."
            th_args=(github --org="$GITHUB_ORG" --only-verified --json)
            [[ -n "${GITHUB_TOKEN:-}" ]] && th_args+=(--token="$GITHUB_TOKEN")
            run_niced trufflehog "${th_args[@]}" < /dev/null \
                > "${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.json" 2>"${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.err" || \
                echo "[!] trufflehog scan failed or found nothing -- check ${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.err" >&2
            TH_COUNT=$(wc -l < "${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.json" 2>/dev/null | tr -d ' ')
            echo "trufflehog: ${TH_COUNT:-0} verified finding(s) -> ${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.json" >> "$GITHUB_SECRETS_SUMMARY"
        else
            echo "[=] Skipping trufflehog (--no-trufflehog or not installed)"
        fi

        if [[ "${NO_TOOL[gitleaks]}" -eq 0 && "${HAVE[gitleaks]:-0}" -eq 1 ]]; then
            echo "[*] Running gitleaks against public repos for '$GITHUB_ORG' (requires repos cloned or accessible via API)..."
            # gitleaks doesn't have a native "scan whole org" mode without repos on disk;
            # this uses its git-remote scanning against the org's primary repo naming guess
            # plus any repos already cloned locally under ./${GITHUB_ORG}-repos/ if present.
            # For full org coverage, clone repos first (e.g. via `gh repo list <org> --clone`)
            # and point gitleaks at each -- documented in the summary output below.
            if [[ -d "./${GITHUB_ORG}-repos" ]]; then
                for repo_dir in "./${GITHUB_ORG}-repos"/*/; do
                    [[ -d "$repo_dir" ]] || continue
                    repo_name="$(basename "$repo_dir")"
                    run_niced gitleaks detect --source "$repo_dir" --no-git -f json \
                        -r "${GITHUB_SECRETS_DIR}/gitleaks_${repo_name}.json" < /dev/null 2>/dev/null || true
                done
                GL_FILES=$(find "$GITHUB_SECRETS_DIR" -maxdepth 1 -name 'gitleaks_*.json' 2>/dev/null | wc -l | tr -d ' ')
                echo "gitleaks: scanned ${GL_FILES:-0} local repo(s) under ./${GITHUB_ORG}-repos/ -> ${GITHUB_SECRETS_DIR}/gitleaks_*.json" >> "$GITHUB_SECRETS_SUMMARY"
            else
                echo "gitleaks: no local repos found at ./${GITHUB_ORG}-repos/ -- skipped org-wide scan." >> "$GITHUB_SECRETS_SUMMARY"
                echo "  To enable: gh repo list ${GITHUB_ORG} --limit 200 --json name -q '.[].name' | xargs -I{} gh repo clone ${GITHUB_ORG}/{} ./${GITHUB_ORG}-repos/{}" >> "$GITHUB_SECRETS_SUMMARY"
                echo "[*] gitleaks: no local clone directory found -- see $GITHUB_SECRETS_SUMMARY for the one-liner to set that up."
            fi
        else
            echo "[=] Skipping gitleaks (--no-gitleaks or not installed)"
        fi

        mark_done "github:secrets"
        echo "[+] GitHub secret scanning summary -> $GITHUB_SECRETS_SUMMARY"
        cat "$GITHUB_SECRETS_SUMMARY" 2>/dev/null | sed 's/^/    /'

        # Alert if trufflehog found verified secrets (gitleaks JSON parsing left to review,
        # since without -r severity classification a raw count is less reliable as a trigger).
        if [[ -f "${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.json" && -s "${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.json" ]]; then
            alert_finding "trufflehog found verified secret(s) in GitHub org '${GITHUB_ORG}' for ${BASENAME_NOEXT}: see ${GITHUB_SECRETS_DIR}/trufflehog_${GITHUB_ORG}.json"
        fi
    fi
else
    echo "[=] Skipping GitHub secret scanning (fast mode, no org resolved, or neither gitleaks nor trufflehog installed)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 3: URL discovery — katana + gau + waybackurls, then dedupe
# katana now runs against PROBE_TARGETS_FILE (bare hosts + explicit
# host:port entries) so a service on a non-default port gets crawled too.
# =====================================================================
echo "[*] Stage 3: URL discovery"

if [[ "${NO_TOOL[katana]}" -eq 1 ]]; then
    echo "[=] Skipping: katana (--no-katana)"
    : > "${URLS_DIR}/katana.txt"
    mark_done "urls:katana"
elif is_done "urls:katana"; then
    echo "[=] Skipping: katana"
else
    echo "[*] Running katana (with JS crawling + form extraction)..."
    katana -list "$LIVE_URLS_FILE" -jc -kf all -d 3 -known-files all \
        -rl "$KATANA_RATE_LIMIT" -c "$KATANA_CONCURRENCY" -silent \
        -o "${URLS_DIR}/katana.txt" && mark_done "urls:katana" \
        || echo "[!] katana failed/partial -- will retry on resume." >&2
fi

if [[ "${NO_TOOL[gau]}" -eq 1 ]]; then
    echo "[=] Skipping: gau (--no-gau)"
    : > "${URLS_DIR}/gau.txt"
    mark_done "urls:gau"
elif is_done "urls:gau"; then
    echo "[=] Skipping: gau"
else
    echo "[*] Running gau..."
    gau --threads "$GAU_THREADS" --subs < "$HOSTS_FILE" > "${URLS_DIR}/gau.txt" && mark_done "urls:gau" \
        || echo "[!] gau failed/partial -- will retry on resume." >&2
fi

if [[ "${NO_TOOL[waybackurls]}" -eq 0 && "${HAVE[waybackurls]:-0}" -eq 1 ]]; then
    if is_done "urls:waybackurls"; then
        echo "[=] Skipping: waybackurls"
    else
        echo "[*] Running waybackurls..."
        waybackurls < "$HOSTS_FILE" > "${URLS_DIR}/waybackurls.txt" && mark_done "urls:waybackurls" \
            || echo "[!] waybackurls failed/partial -- will retry on resume." >&2
    fi
else
    : > "${URLS_DIR}/waybackurls.txt"
    [[ "${NO_TOOL[waybackurls]}" -eq 1 ]] && echo "[=] Skipping: waybackurls (--no-waybackurls)"
fi

if is_done "urls:combined"; then
    echo "[=] URL corpus already merged."
else
    cat "${URLS_DIR}"/*.txt 2>/dev/null | sort -u > "$URLS_COMBINED"
    mark_done "urls:combined"
fi

# Dedup by path+sorted-param-keys so we don't fuzz 500 near-identical URLs
# (?id=1, ?id=2, ?id=3 all collapse to one representative)
if is_done "urls:deduped"; then
    echo "[=] URL corpus already deduped."
else
    echo "[*] Deduping URL corpus by path + param-key signature..."
    python3 - "$URLS_COMBINED" "$URLS_DEDUPED" <<'PYEOF'
import sys
from urllib.parse import urlparse, parse_qs

seen = set()
out = []
with open(sys.argv[1]) as f:
    for line in f:
        u = line.strip()
        if not u:
            continue
        try:
            p = urlparse(u)
            keys = tuple(sorted(parse_qs(p.query).keys()))
            sig = (p.netloc, p.path, keys)
        except Exception:
            sig = u
        if sig not in seen:
            seen.add(sig)
            out.append(u)

with open(sys.argv[2], "w") as f:
    f.write("\n".join(out) + "\n")
PYEOF
    mark_done "urls:deduped"
fi

URL_COUNT=$(wc -l < "$URLS_COMBINED" 2>/dev/null | tr -d ' ')
DEDUP_COUNT=$(wc -l < "$URLS_DEDUPED" 2>/dev/null | tr -d ' ')
echo "[+] $URL_COUNT raw URL(s) -> $DEDUP_COUNT after dedup ($URLS_DEDUPED)"
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 3b: JS file harvesting + secret/endpoint mining
# subjs pulls JS URLs out of live pages; katana -jc already caught some,
# this stage isolates JS specifically and greps it for the stuff nuclei's
# generic exposure templates routinely miss: hardcoded endpoints, internal
# hostnames, leaked keys with unusual naming, GraphQL schema hints.
# =====================================================================
if [[ "${NO_TOOL[subjs]}" -eq 0 && "${HAVE[subjs]}" -eq 1 ]]; then
    if is_done "js:collected"; then
        echo "[=] Skipping: JS collection"
    else
        echo "[*] Harvesting JS file URLs with subjs..."
        subjs -i "$LIVE_URLS_FILE" > "$JS_FILES" 2>/dev/null || true
        grep -iE '\.js($|\?)' "$URLS_DEDUPED" >> "$JS_FILES" 2>/dev/null || true
        sort -u -o "$JS_FILES" "$JS_FILES"
        mark_done "js:collected"
        echo "[+] $(wc -l < "$JS_FILES" | tr -d ' ') JS file(s) collected"
    fi

    if [[ -s "$JS_FILES" ]]; then
        if is_done "js:analyzed"; then
            echo "[=] Skipping: JS analysis"
        elif [[ "${NO_TOOL[nuclei]}" -eq 1 ]]; then
            echo "[=] Skipping nuclei pass on JS corpus (--no-nuclei) -- running regex mining only..."
            {
                echo "# JS Secret/Endpoint Mining Report"
                echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
                echo
                while read -r jsurl; do
                    [[ -z "$jsurl" ]] && continue
                    body="$(curl -s -m 10 "$jsurl" 2>/dev/null | tr -d '\000')"
                    [[ -z "$body" ]] && continue
                    hits="$(echo "$body" | grep -oE \
                        '(https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9._/-]*)?)|("|'"'"')[a-zA-Z0-9_-]*(api[_-]?key|apikey|secret|token|password|bearer|authorization)[a-zA-Z0-9_-]*("|'"'"')\s*[:=]\s*("|'"'"')[a-zA-Z0-9._-]{8,}("|'"'"')' \
                        2>/dev/null | sort -u | head -50)"
                    if [[ -n "$hits" ]]; then
                        echo "## $jsurl"
                        echo '```'
                        echo "$hits"
                        echo '```'
                        echo
                    fi
                done < "$JS_FILES"
            } > "${JS_FINDINGS_DIR}/js_regex_mining.md"
            mark_done "js:analyzed"
            echo "[+] JS regex mining complete (nuclei pass skipped) -> ${JS_FINDINGS_DIR}/"
        else
            echo "[*] Running nuclei exposure templates against JS corpus..."
            # BUGFIX: this call was missing -timeout/-retries/-bs (every other nuclei
            # invocation in the script has them), so a single slow/unresponsive JS host
            # could hang it indefinitely with no visible progress -- that's what forced
            # the earlier double-Ctrl+C. run_niced + a wall-clock `timeout` belt-and-
            # braces it: nuclei's own -timeout bounds each request, and the outer
            # `timeout` guarantees the whole call returns even if nuclei itself wedges.
            run_niced timeout --preserve-status "$((NUCLEI_JS_WALLCLOCK_TIMEOUT))" \
                nuclei -l "$JS_FILES" -t "http/exposures" -t "http/miscellaneous/js-sri-check.yaml" \
                -rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_CONCURRENCY" -bs "$NUCLEI_BULK_SIZE" \
                -timeout 8 -retries 1 -silent \
                -o "${JS_FINDINGS_DIR}/nuclei_js_exposures.txt" 2>/dev/null \
                || echo "[!] nuclei JS exposure pass timed out or failed -- continuing (partial results, if any, kept)." >&2

            echo "[*] Regex-mining JS for endpoints/secrets nuclei templates don't cover..."
            {
                echo "# JS Secret/Endpoint Mining Report"
                echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
                echo
                while read -r jsurl; do
                    [[ -z "$jsurl" ]] && continue
                    body="$(curl -s -m 10 "$jsurl" 2>/dev/null | tr -d '\000')"
                    [[ -z "$body" ]] && continue
                    hits="$(echo "$body" | grep -oE \
                        '(https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9._/-]*)?)|("|'"'"')[a-zA-Z0-9_-]*(api[_-]?key|apikey|secret|token|password|bearer|authorization)[a-zA-Z0-9_-]*("|'"'"')\s*[:=]\s*("|'"'"')[a-zA-Z0-9._-]{8,}("|'"'"')' \
                        2>/dev/null | sort -u | head -50)"
                    if [[ -n "$hits" ]]; then
                        echo "## $jsurl"
                        echo '```'
                        echo "$hits"
                        echo '```'
                        echo
                    fi
                done < "$JS_FILES"
            } > "${JS_FINDINGS_DIR}/js_regex_mining.md"

            mark_done "js:analyzed"
            echo "[+] JS mining complete -> ${JS_FINDINGS_DIR}/"
        fi
    fi
else
    echo "[=] Skipping JS harvesting (--no-subjs or subjs not installed)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 3c-map: JS sourcemap discovery + extraction
#
# Very commonly missed: many bundlers emit a `//# sourceMappingURL=foo.js.map`
# comment at the end of the minified JS, or serve the .map file at the same
# path with .map appended. If exposed (often left on by mistake in prod),
# the sourcemap's "sourcesContent" field contains the FULL original,
# unminified source -- real file paths, internal comments, unused/debug
# routes, TODOs -- none of which survive minification and none of which
# the plain regex mining pass above can recover from minified code alone.
#
# This stage: for each harvested JS file, checks for a sourceMappingURL
# comment or a same-path *.map guess, fetches the map if present, and pulls
# out sourcesContent via a small python/json pass (no extra binary needed
# beyond python3, which is already a dependency of the URL-dedup stage above).
# =====================================================================
if [[ "${NO_TOOL[sourcemaps]}" -eq 0 && "${HAVE[python3]:-0}" -eq 1 && -s "$JS_FILES" ]]; then
    if is_done "js:sourcemaps"; then
        echo "[=] Skipping (done): JS sourcemap extraction"
    else
        echo "[*] Checking harvested JS files for exposed sourcemaps..."
        : > "$SOURCEMAP_FINDINGS"
        {
            echo "# JS Sourcemap Findings"
            echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo
        } >> "$SOURCEMAP_FINDINGS"

        map_count=0
        while read -r jsurl; do
            [[ -z "$jsurl" ]] && continue

            # 1) look for an explicit sourceMappingURL comment in the JS itself
            js_body="$(curl -s -m "$SOURCEMAP_FETCH_TIMEOUT" "$jsurl" 2>/dev/null | tr -d '\000')"
            [[ -z "$js_body" ]] && continue
            map_ref="$(echo "$js_body" | grep -oE '//# sourceMappingURL=.*' | sed 's#//# sourceMappingURL=##' | tail -1)"

            map_url=""
            if [[ -n "$map_ref" && "$map_ref" == http* ]]; then
                map_url="$map_ref"
            elif [[ -n "$map_ref" ]]; then
                # relative reference -- resolve against the JS file's own directory
                map_url="$(echo "$jsurl" | sed -E 's#[^/]+$##')${map_ref}"
            else
                # 2) fallback guess: same path with .map appended
                map_url="${jsurl}.map"
            fi

            map_body="$(curl -s -m "$SOURCEMAP_FETCH_TIMEOUT" -o - -w '\n%{http_code}' "$map_url" 2>/dev/null | tr -d '\000')"
            http_code="$(echo "$map_body" | tail -1)"
            map_content="$(echo "$map_body" | sed '$d')"

            if [[ "$http_code" == "200" && -n "$map_content" ]] && echo "$map_content" | grep -q '"sourcesContent"'; then
                map_count=$((map_count + 1))
                safe_name="$(echo "$jsurl" | sed -E 's#https?://##; s#[/:.]#_#g')"
                out_json="${SOURCEMAPS_DIR}/${safe_name}.map.json"
                echo "$map_content" > "$out_json"

                # Pull sourcesContent + sources arrays out with python so we don't need jq
                # as a hard dependency here; writes each recovered original file to disk.
                python3 - "$out_json" "$SOURCEMAPS_DIR" "$safe_name" <<'PYEOF' 2>/dev/null || true
import json, sys, os, re

map_path, out_dir, safe_name = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(map_path) as f:
        data = json.load(f)
except Exception:
    sys.exit(0)

sources = data.get("sources", [])
contents = data.get("sourcesContent", [])
if not contents:
    sys.exit(0)

recovered_dir = os.path.join(out_dir, f"{safe_name}_recovered")
os.makedirs(recovered_dir, exist_ok=True)
n = 0
for i, content in enumerate(contents):
    if not content:
        continue
    src_name = sources[i] if i < len(sources) else f"source_{i}.js"
    safe_src = re.sub(r'[^a-zA-Z0-9._-]', '_', src_name)[-150:]
    with open(os.path.join(recovered_dir, f"{i:04d}_{safe_src}"), "w") as out:
        out.write(content)
    n += 1
print(n)
PYEOF
                recovered_n="$(find "${SOURCEMAPS_DIR}/${safe_name}_recovered" -type f 2>/dev/null | wc -l | tr -d ' ')"
                if [[ "${recovered_n:-0}" -gt 0 ]]; then
                    {
                        echo "## $jsurl"
                        echo "- Sourcemap: $map_url"
                        echo "- Recovered original source file(s): ${recovered_n} -> ${SOURCEMAPS_DIR}/${safe_name}_recovered/"
                        echo
                    } >> "$SOURCEMAP_FINDINGS"
                fi
            fi
        done < "$JS_FILES"

        mark_done "js:sourcemaps"
        echo "[+] JS sourcemap extraction -> $SOURCEMAP_FINDINGS ($map_count exposed sourcemap(s) found)"
        if [[ "$map_count" -gt 0 ]]; then
            alert_finding "$map_count exposed JS sourcemap(s) with recoverable original source found for ${BASENAME_NOEXT}: see $SOURCEMAP_FINDINGS"
        fi
    fi
else
    echo "[=] Skipping JS sourcemap extraction (--no-sourcemaps, python3 missing, or no JS files collected)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 3d: Hidden parameter discovery with arjun
# Feeds discovered params back into the URL corpus so nuclei/dalfox
# actually have something to fuzz — a URL with no visible ?params= is
# often still vulnerable via undocumented ones.
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[arjun]}" -eq 0 && "${HAVE[arjun]}" -eq 1 ]]; then
    if is_done "params:discovered"; then
        echo "[=] Skipping: arjun param discovery"
    else
        echo "[*] Running arjun against a sample of live endpoints..."
        # cap to first 200 endpoints to keep this bounded on huge scopes
        head -n 200 "$URLS_DEDUPED" > "${URLS_DEDUPED}.sample"
        arjun -i "${URLS_DEDUPED}.sample" -t "$ARJUN_THREADS" -oT "$PARAMS_FILE" 2>/dev/null || true
        rm -f "${URLS_DEDUPED}.sample"
        mark_done "params:discovered"
        echo "[+] arjun results -> $PARAMS_FILE (append discovered params to fuzz targets manually or feed to ffuf/dalfox)"
    fi
else
    echo "[=] Skipping arjun (fast mode, --no-arjun, or tool missing)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 3e: LFI / path-traversal candidate extraction + targeted ffuf
#
# Pulls URLs out of the deduped corpus whose QUERY PARAMETER NAME (not
# value) looks file/path-related (file=, path=, doc=, page=, folder=,
# include=, template=, load=, read=, filename=, ...). For each match:
#   1. Build a FUZZ url by swapping that parameter's value for the literal
#      string FUZZ (python does the parsing/rebuild so encoding is correct).
#   2. Compute a real -fs baseline via lfi_baseline_fs: one request with the
#      original value, one with a random nonexistent value, both through the
#      *same* parameter (not the root page) so soft-404/redirect behavior
#      specific to that endpoint is what gets filtered.
#   3. Run ffuf against that FUZZ url with the dedicated dotdotpwn traversal
#      wordlist (NOT the generic content-discovery wordlist), -fs'd against
#      the computed baseline.
# =====================================================================
if [[ "$NO_LFI_SCAN" -eq 0 && "${NO_TOOL[ffuf]}" -eq 0 && "${HAVE[ffuf]:-0}" -eq 1 && -f "$DOTDOTPWN_WORDLIST" ]]; then
    if is_done "lfi:scanned"; then
        echo "[=] Skipping (done): LFI/path-traversal candidate scan"
    else
        echo "[*] Extracting LFI/path-traversal candidates (param name match) from URL corpus..."
        : > "$LFI_CANDIDATES_FILE"
        if [[ -s "$URLS_DEDUPED" ]]; then
            while read -r u; do
                [[ -z "$u" ]] && continue
                echo "$u" | grep -qE '\?.*=' || continue
                q="${u#*\?}"
                IFS='&' read -ra pairs <<< "$q"
                for p in "${pairs[@]}"; do
                    key="${p%%=*}"
                    if echo "$key" | grep -qiE "$LFI_PARAM_REGEX"; then
                        echo "$u" >> "$LFI_CANDIDATES_FILE"
                        break
                    fi
                done
            done < "$URLS_DEDUPED"
        fi
        sort -u -o "$LFI_CANDIDATES_FILE" "$LFI_CANDIDATES_FILE" 2>/dev/null || true
        LFI_CAND_COUNT=$(wc -l < "$LFI_CANDIDATES_FILE" 2>/dev/null | tr -d ' ')
        echo "[+] $LFI_CAND_COUNT LFI/path-traversal candidate(s) -> $LFI_CANDIDATES_FILE"

        if [[ "${LFI_CAND_COUNT:-0}" -gt 0 ]]; then
            echo "[*] Building FUZZ urls + running ffuf with dotdotpwn wordlist ($DOTDOTPWN_WORDLIST)..."
            : > "$LFI_FUZZ_MAP_FILE"
            python3 - "$LFI_CANDIDATES_FILE" "$LFI_PARAM_REGEX" <<'PYEOF' > "$LFI_FUZZ_MAP_FILE" 2>/dev/null
import sys, re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

src, pattern = sys.argv[1], sys.argv[2]
rx = re.compile(pattern, re.IGNORECASE)

with open(src) as f:
    for line in f:
        u = line.strip()
        if not u:
            continue
        try:
            p = urlparse(u)
            pairs = parse_qsl(p.query, keep_blank_values=True)
        except Exception:
            continue
        target_idx = None
        for i, (k, v) in enumerate(pairs):
            if rx.match(k):
                target_idx = i
                break
        if target_idx is None:
            continue
        orig_key, orig_val = pairs[target_idx]
        fuzz_pairs = list(pairs)
        fuzz_pairs[target_idx] = (orig_key, "FUZZPLACEHOLDER")
        fuzz_query = urlencode(fuzz_pairs, safe="")
        fuzz_query = fuzz_query.replace("FUZZPLACEHOLDER", "FUZZ")
        fuzz_url = urlunparse((p.scheme, p.netloc, p.path, p.params, fuzz_query, p.fragment))
        # tab-separated: fuzz_url <TAB> original_value (may be empty)
        print(f"{fuzz_url}\t{orig_val}")
PYEOF
            LFI_FUZZ_COUNT=$(wc -l < "$LFI_FUZZ_MAP_FILE" 2>/dev/null | tr -d ' ')
            echo "[+] $LFI_FUZZ_COUNT FUZZ url(s) built -> $LFI_FUZZ_MAP_FILE"

            while IFS=$'\t' read -r fuzz_url orig_val; do
                [[ -z "$fuzz_url" ]] && continue
                [[ -z "$orig_val" ]] && orig_val="1"

                fs_args=()
                lfi_baseline_fs "$fuzz_url" "$orig_val" fs_args

                safe_name="$(echo "$fuzz_url" | tr '/:.?&=' '_' | cut -c1-150)"
                run_niced ffuf -u "$fuzz_url" -w "$DOTDOTPWN_WORDLIST" -t "$LFI_FFUF_THREADS" \
                    -mc 200,206,301,302,403,500 "${fs_args[@]}" -of json \
                    -o "${LFI_FFUF_OUT_DIR}/${safe_name}.json" -s 2>/dev/null || true
            done < "$LFI_FUZZ_MAP_FILE"

            LFI_HIT_FILES=$(find "$LFI_FFUF_OUT_DIR" -type f -name '*.json' -newer "$LFI_CANDIDATES_FILE" 2>/dev/null | wc -l | tr -d ' ')
            echo "[+] LFI/path-traversal ffuf complete -> ${LFI_FFUF_OUT_DIR}/ ($LFI_HIT_FILES result file(s), review for real matches)"
            if [[ "${HAVE[jq]:-0}" -eq 1 ]]; then
                LFI_REAL_HITS=$(find "$LFI_FFUF_OUT_DIR" -type f -name '*.json' -exec jq -r '.results[]?.url' {} + 2>/dev/null | grep -c . || echo 0)
                if [[ "${LFI_REAL_HITS:-0}" -gt 0 ]]; then
                    alert_finding "$LFI_REAL_HITS LFI/path-traversal ffuf match(es) for ${BASENAME_NOEXT}: see ${LFI_FFUF_OUT_DIR}/"
                fi
            fi
        fi
        mark_done "lfi:scanned"
    fi
else
    echo "[=] Skipping LFI/path-traversal scan (--no-lfi-scan, --no-ffuf, ffuf missing, or wordlist not found at $DOTDOTPWN_WORDLIST)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 3f: SQL injection candidates -> sqlmap-dev handoff
#
# Reuses the same "has at least one query parameter" pool dalfox draws
# from (any URL matching \?.+=) as the injection-candidate list, then hands
# the whole batch to a local sqlmap-dev checkout via -m (bulk file mode) in
# --batch (non-interactive) mode. Run FROM that checkout's own directory
# (cd "$SQLMAP_DIR" && python3 sqlmap.py ...) since sqlmap resolves its
# bundled data/xml/tamper paths relative to its own location -- invoking it
# via an absolute path from elsewhere works too, but this matches how it's
# normally run and avoids any relative-path surprises. Results land back
# under this run's own SQLMAP_OUT_DIR via --output-dir with an absolute path
# so they aren't buried inside the sqlmap-dev checkout itself.
# =====================================================================
if [[ "$NO_SQLMAP" -eq 0 && -f "${SQLMAP_DIR}/sqlmap.py" ]]; then
    if is_done "sqlmap:scanned"; then
        echo "[=] Skipping (done): sqlmap injection scan"
    else
        echo "[*] Extracting SQL injection candidates (any parameterized URL) from URL corpus..."
        grep -E '\?.+=' "$URLS_DEDUPED" 2>/dev/null | sort -u > "$SQLI_CANDIDATES_FILE" || true
        SQLI_CAND_COUNT=$(wc -l < "$SQLI_CANDIDATES_FILE" 2>/dev/null | tr -d ' ')
        echo "[+] $SQLI_CAND_COUNT SQLi candidate(s) -> $SQLI_CANDIDATES_FILE"

        if [[ "${SQLI_CAND_COUNT:-0}" -gt 0 ]]; then
            ABS_CANDIDATES="$(cd "$(dirname "$SQLI_CANDIDATES_FILE")" && pwd)/$(basename "$SQLI_CANDIDATES_FILE")"
            ABS_SQLMAP_OUT="$(cd "$(dirname "$SQLMAP_OUT_DIR")" && pwd)/$(basename "$SQLMAP_OUT_DIR")"

            echo "[*] Handing off $SQLI_CAND_COUNT candidate(s) to sqlmap-dev at $SQLMAP_DIR"
            echo "    (--batch --level=$SQLMAP_LEVEL --risk=$SQLMAP_RISK --threads=$SQLMAP_THREADS, output -> $ABS_SQLMAP_OUT)"
            (
                cd "$SQLMAP_DIR" || exit 1
                run_niced python3 sqlmap.py -m "$ABS_CANDIDATES" --batch --random-agent \
                    --level="$SQLMAP_LEVEL" --risk="$SQLMAP_RISK" --threads="$SQLMAP_THREADS" \
                    --output-dir="$ABS_SQLMAP_OUT" < /dev/null \
                    > "${ABS_SQLMAP_OUT}/sqlmap_run.log" 2>&1
            )
            sqlmap_status=$?
            if [[ "$sqlmap_status" -ne 0 ]]; then
                echo "[!] sqlmap exited non-zero ($sqlmap_status) -- check ${ABS_SQLMAP_OUT}/sqlmap_run.log" >&2
            fi

            VULN_COUNT=$(grep -riIl "the following injection point" "$ABS_SQLMAP_OUT" 2>/dev/null | wc -l | tr -d ' ')
            echo "[+] sqlmap run complete -> $ABS_SQLMAP_OUT (log: sqlmap_run.log)"
            if [[ "${VULN_COUNT:-0}" -gt 0 ]]; then
                alert_finding "sqlmap found injection point(s) in ${VULN_COUNT} target log(s) for ${BASENAME_NOEXT}: see $ABS_SQLMAP_OUT"
            fi
        fi
        mark_done "sqlmap:scanned"
    fi
else
    echo "[=] Skipping sqlmap handoff (--no-sqlmap or sqlmap.py not found at ${SQLMAP_DIR}/sqlmap.py)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 4: nuclei
#
# v7 rewrite: instead of one `-l <hostlist>` batch call per template group,
# every (target, template-root) pair is now its own per-target `-u` job via
# run_nuclei_per_host. This matters for two reasons:
#   1) You specifically wanted BOTH your custom template repo
#      ($CUSTOM_NUCLEI_TEMPLATES) and the stock repo ($STOCK_NUCLEI_TEMPLATES)
#      run against every target, not merged into one -t list.
#   2) A single `-l` batch occasionally doesn't loop every target the way
#      you'd expect (a stuck/slow target can starve the rest of the batch,
#      or a template-loading hiccup on one target silently affects the run).
#      Per-target -u jobs are independent and independently checkpointed --
#      one bad target can't take out the others, and a resumed run only
#      re-does the (target, template-root) pairs that didn't finish.
#
# The existing high-signal fastpass and tag-group scans are left as `-l`
# batch jobs (fixed template sets against the whole host list) since those
# don't need the per-target dual-root treatment; it's specifically the
# broad host-corpus and URL-corpus scans that are now per-target.
# =====================================================================
SEVERITY_FLAG=()
NUCLEI_COMMON_FLAGS=(-rl "$NUCLEI_RATE_LIMIT" -c "$NUCLEI_CONCURRENCY" -bs "$NUCLEI_BULK_SIZE" -timeout 8 -retries 1)

run_nuclei_job_bg() {
    local job="$1" out_file="$2" target_file="$3"; shift 3
    if [[ "${NO_TOOL[nuclei]}" -eq 1 ]]; then return 0; fi
    if is_done "$job"; then echo "[=] Skipping: $job"; return 0; fi
    (
        attempt=1; max_attempts=3; success=0
        while [[ $attempt -le $max_attempts ]]; do
            if run_niced nuclei -l "$target_file" "$@" "${SEVERITY_FLAG[@]}" "${NUCLEI_COMMON_FLAGS[@]}" -o "$out_file" -silent; then
                success=1; break
            else
                sleep 5; ((attempt++))
            fi
        done
        if [[ "$success" -eq 1 ]]; then
            mark_done "$job"
        else
            # v4: surface this instead of failing silently -- the usual cause is a -t
            # path/-tags group that resolves to zero templates ("no templates provided").
            echo "[!] nuclei job '$job' failed after $max_attempts attempts -- check the -t/-tags args for it are valid (see NUCLEI_TEMPLATE_PATHS / NUCLEI_TAG_GROUPS)." >&2
        fi
    ) &
    # throttle concurrent background jobs
    while [[ "$(jobs -rp | wc -l)" -ge "$NUCLEI_PARALLEL_JOBS" ]]; do sleep 1; done
}

# v7: per-target, per-template-root nuclei runner.
#   job_prefix    -- short tag used in the state file (e.g. "hostscan", "urlscan", "iisscan")
#   targets_file  -- one target per line; bare hostnames get "https://<host>/" assumed,
#                     full URLs (and host:port entries) are used as-is
# Each (target, template-root) pair becomes its own checkpointed background job so a
# problem with one target/root can't silently zero out the whole pass.
run_nuclei_per_host() {
    local job_prefix="$1" targets_file="$2"
    [[ "${NO_TOOL[nuclei]}" -eq 1 ]] && { echo "[=] --no-nuclei: skipping $job_prefix"; return 0; }
    [[ -f "$targets_file" && -s "$targets_file" ]] || { echo "[!] $job_prefix: target file '$targets_file' empty/missing -- skipping." >&2; return 0; }

    while read -r target; do
        [[ -z "$target" ]] && continue
        local url="$target"
        if [[ "$url" != http*://* ]]; then
            url="https://${url}/"
        fi

        for troot_name in custom stock; do
            local troot
            if [[ "$troot_name" == "custom" ]]; then
                troot="$CUSTOM_NUCLEI_TEMPLATES"
            else
                troot="$STOCK_NUCLEI_TEMPLATES"
            fi
            [[ -d "$troot" ]] || continue

            local safe_target job out
            safe_target="$(echo "$target" | tr '/:.' '_')"
            job="${job_prefix}:${troot_name}:${target}"
            out="${NUCLEI_OUT_DIR}/${job_prefix}_${troot_name}_${safe_target}.txt"
            is_done "$job" && continue

            (
                if run_niced nuclei -u "$url" -t "$troot" \
                    "${SEVERITY_FLAG[@]}" "${NUCLEI_COMMON_FLAGS[@]}" -o "$out" -silent; then
                    mark_done "$job"
                else
                    echo "[!] nuclei failed for $url against template root '$troot_name' ($troot)" >&2
                fi
            ) &
            while [[ "$(jobs -rp | wc -l)" -ge "$NUCLEI_PARALLEL_JOBS" ]]; do sleep 1; done
        done
    done < "$targets_file"
    wait
}

# Skips a -t job before it's even queued if the path doesn't exist under
# ~/nuclei-templates -- avoids burning 3 retries x 5s sleep on something that
# can never succeed, and tells you exactly which path was the problem.
template_path_exists() {
    local rel="$1"
    [[ -d "$HOME/nuclei-templates/${rel}" || -f "$HOME/nuclei-templates/${rel}" ]]
}

# Same idea for -tags groups: a nonexistent/renamed tag returns 0 matching
# templates, which is the other common source of "no templates provided".
# This costs one quick `-tl` lookup per tag group before the loop runs.
tag_has_templates() {
    local tags="$1" count
    count="$(nuclei -tags "$tags" -tl -silent 2>/dev/null | wc -l | tr -d ' ')"
    [[ "${count:-0}" -gt 0 ]]
}

if [[ "${NO_TOOL[nuclei]}" -eq 1 ]]; then
    echo "[=] --no-nuclei given: skipping ALL nuclei stages (fastpass, per-target dual-root scans, tag-based scans)."
    echo "-------------------------------------------------------------------"
else

if [[ ! -d "$CUSTOM_NUCLEI_TEMPLATES" ]]; then
    echo "[!] Custom nuclei template root not found: $CUSTOM_NUCLEI_TEMPLATES -- per-target scans will use stock templates only." >&2
    echo "    Override with: CUSTOM_NUCLEI_TEMPLATES=/path/to/templates $0 ..." >&2
fi
if [[ ! -d "$STOCK_NUCLEI_TEMPLATES" ]]; then
    echo "[!] Stock nuclei template root not found: $STOCK_NUCLEI_TEMPLATES -- per-target scans will use custom templates only." >&2
fi

echo "[*] Running nuclei high-signal exposure fast-pass (hosts) — specific high-hit-rate templates..."
echo "    (these are already covered by the per-target dual-root scans below too; this pass just"
echo "     surfaces them fast/separately so you can triage before the full run finishes)"
NUCLEI_HIGHSIGNAL_FILES=(
    "http/exposures/files/gcloud-credentials.yaml"
    "http/exposures/files/google-api-private-key.yaml"
    "http/exposures/files/service-account-credentials.yaml"
    "http/exposures/files/database-credentials.yaml"
    "http/exposures/files/django-secret-key.yaml"
    "http/exposures/files/rails-secret-token-disclosure.yaml"
    "http/exposures/files/kubernetes-etcd-keys.yaml"
    "http/exposures/files/oauth-credentials-json.yaml"
    "http/exposures/files/npmrc-authtoken.yaml"
    "http/exposures/files/salesforce-credentials.yaml"
    "http/exposures/files/socks5-vpn-config.yaml"
    "http/exposures/files/credentials-json.yaml"
    "http/exposures/backups/sql-dump.yaml"
    "http/exposures/backups/exposed-mysql-initial.yaml"
    "http/exposures/backups/zip-backup-files.yaml"
    "http/exposures/backups/php-backup-files.yaml"
    "http/exposures/logs/laravel-log-file.yaml"
    "http/exposures/logs/django-debug-exposure.yaml"
    "http/exposures/logs/rails-debug-mode.yaml"
    "http/exposures/logs/git-exposure.yaml"
    "http/exposures/logs/go-pprof-debug.yaml"
    "http/exposures/apis/swagger-api.yaml"
    "http/exposures/apis/openapi.yaml"
    "http/exposures/apis/couchbase-buckets-api.yaml"
)
HIGHSIGNAL_OUT="${NUCLEI_OUT_DIR}/highsignal_fastpass.txt"
if is_done "highsignal:fastpass"; then
    echo "[=] Skipping: highsignal fastpass"
else
    # -t accepts multiple flags in one invocation; build them and run as a single job
    HS_TARGS=()
    for f in "${NUCLEI_HIGHSIGNAL_FILES[@]}"; do
        tpath="$HOME/nuclei-templates/${f}"
        if [[ -f "$tpath" ]]; then
            HS_TARGS+=(-t "$tpath")
        fi
    done
    if [[ "${#HS_TARGS[@]}" -gt 0 ]]; then
        run_nuclei_job_bg "highsignal:fastpass" "$HIGHSIGNAL_OUT" "$HOSTS_FILE" "${HS_TARGS[@]}"
        wait
    else
        echo "[!] None of the high-signal template files were found under ~/nuclei-templates -- skipping fastpass." >&2
    fi
fi
echo "-------------------------------------------------------------------"

echo "[*] Running per-target nuclei scans (hosts, custom + stock template roots)..."
echo "    Targets: $PROBE_TARGETS_FILE (bare hosts + any explicit host:port entries)"
run_nuclei_per_host "hostscan" "$PROBE_TARGETS_FILE"
echo "-------------------------------------------------------------------"

echo "[*] Running nuclei tag-based scans (hosts)..."
NUCLEI_TAG_GROUPS=(
    "google,apikey,exposure" "token,exposure,config" "aws,exposure" "secret,exposure"
    "misconfig,exposure" "panel,exposure" "takeover" "default-login" "cve,rce"
    "cve,sqli" "cve,ssrf" "cve,lfi" "cve,xxe" "cve,idor" "wordpress,cve"
    "js,exposure" "git,exposure" "env,exposure" "jwt" "graphql" "cors"
    "unauth,exposure" "backup" "debug"
)
for tags in "${NUCLEI_TAG_GROUPS[@]}"; do
    if ! tag_has_templates "$tags"; then
        echo "[!] Skipping nuclei tag group (0 matching templates): $tags" >&2
        continue
    fi
    safe_name="$(echo "$tags" | tr ',' '_')"
    run_nuclei_job_bg "tag:$tags" "${NUCLEI_OUT_DIR}/tags_${safe_name}.txt" "$HOSTS_FILE" -tags "$tags"
done
wait

echo "[*] Running per-target nuclei scans (deduped URL corpus, custom + stock template roots)..."
run_nuclei_per_host "urlscan" "$URLS_DEDUPED"
echo "-------------------------------------------------------------------"

echo "[*] Running nuclei tag-based scans (URL corpus)..."
NUCLEI_URL_TAG_GROUPS=(
    "sqli" "xss" "lfi" "ssrf" "idor" "exposure,token" "exposure,apikey" "redirect" "rce"
    "exposure,backup" "exposure,logs" "exposure,config" "exposure,apis" "exposure,files"
)
for tags in "${NUCLEI_URL_TAG_GROUPS[@]}"; do
    if ! tag_has_templates "$tags"; then
        echo "[!] Skipping nuclei tag group (0 matching templates): $tags" >&2
        continue
    fi
    safe_name="$(echo "$tags" | tr ',' '_')"
    run_nuclei_job_bg "urltag:$tags" "${NUCLEI_OUT_DIR}/urls_tags_${safe_name}.txt" "$URLS_DEDUPED" -tags "$tags"
done
wait

# =====================================================================
# --fullurl: tech-detect-triggered targeted scans
#
# httpx already ran with -tech-detect (Stage 1/2), so $OUTPUT_FILE lines
# carry Wappalyzer-derived tech strings. This grabs hosts fingerprinted as
# IIS and runs them through the same per-target dual-root nuclei pass,
# scoped to IIS-relevant templates when available under either root
# (falls back to the full dual-root pass if no dedicated IIS subfolder
# exists in your template repos, so you still get coverage either way).
# Extend this pattern for other techs by adding another grep block below.
# =====================================================================
if [[ "$FULLURL_MODE" -eq 1 && "${NO_TOOL[nuclei]}" -eq 0 ]]; then
    if is_done "fullurl:tech"; then
        echo "[=] Skipping (done): --fullurl tech-specific scans"
    else
        echo "[*] --fullurl: identifying tech-fingerprinted hosts for targeted scans..."
        : > "$IIS_HOSTS_FILE"
        grep -iE '\[iis' "$OUTPUT_FILE" | grep -oE '^https?://[^][:space:]]+' | sort -u >> "$IIS_HOSTS_FILE"
        grep -oiE 'https?://[^][:space:]]+.*\[iis[^]]*\]' "$OUTPUT_FILE" \
            | grep -oE '^https?://[^][:space:]]+' | sort -u >> "$IIS_HOSTS_FILE"
        sort -u -o "$IIS_HOSTS_FILE" "$IIS_HOSTS_FILE"

        IIS_COUNT=$(wc -l < "$IIS_HOSTS_FILE" 2>/dev/null | tr -d ' ')
        if [[ "${IIS_COUNT:-0}" -gt 0 ]]; then
            echo "[+] $IIS_COUNT IIS host(s) detected -> running targeted per-target dual-root nuclei scan"
            run_nuclei_per_host "iisscan" "$IIS_HOSTS_FILE"
        else
            echo "[*] No IIS hosts detected via tech-detect -- nothing to run for --fullurl this pass."
        fi
        mark_done "fullurl:tech"
    fi
else
    [[ "$FULLURL_MODE" -eq 1 ]] && echo "[=] Skipping --fullurl tech scans (--no-nuclei)"
fi

fi  # end --no-nuclei gate
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 4b: dalfox XSS pipeline — dedicated XSS scanning, stronger than
# nuclei's xss tags (real payload reflection + DOM analysis, not just
# pattern matching).
#
# Explicit pipeline (each step's output feeds the next):
#
#   gau / crawler (katana + gau + waybackurls -> $URLS_DEDUPED, Stage 3)
#         |
#   URLs containing parameters        (filter: $URLS_WITH_PARAMS_FILE)
#         |
#   dalfox                             (scan:   $DALFOX_RAW_JSON / $DALFOX_OUT)
#         |
#   parameter analysis                 (dalfox's own param-mining + our parse pass)
#         |
#   XSS testing                        (dalfox's live payload/reflection/DOM testing)
#         |
#   verified XSS candidates            ($XSS_VERIFIED_FILE)
#
# Step 1 (gau/crawler) already happened in Stage 3 — $URLS_DEDUPED is the
# deduped corpus from katana + gau + waybackurls. This stage picks up from
# there: filters to param-bearing URLs, runs dalfox, then splits dalfox's
# own confidence-tagged output into a separate "verified" file so triage
# doesn't have to wade through low-confidence/informational lines to find
# the real hits.
# =====================================================================
if [[ "${NO_TOOL[dalfox]}" -eq 0 && "${HAVE[dalfox]}" -eq 1 ]]; then
    if is_done "xss:dalfox"; then
        echo "[=] Skipping: dalfox XSS pipeline"
    else
        # --- Step 2: URLs containing parameters ---
        echo "[*] [XSS pipeline 1/4] Filtering crawled URL corpus (gau+katana+waybackurls) for parameterized URLs..."
        grep -E '\?.+=' "$URLS_DEDUPED" 2>/dev/null | sort -u > "$URLS_WITH_PARAMS_FILE" || true
        PARAM_URL_COUNT=$(wc -l < "$URLS_WITH_PARAMS_FILE" 2>/dev/null | tr -d ' ')
        echo "[+] $PARAM_URL_COUNT parameterized URL(s) -> $URLS_WITH_PARAMS_FILE"

        if [[ "${PARAM_URL_COUNT:-0}" -eq 0 ]]; then
            echo "[!] No parameterized URLs in the corpus -- nothing for dalfox to test. Skipping scan." >&2
            : > "$DALFOX_OUT"
            : > "$XSS_VERIFIED_FILE"
        else
            # --- Steps 3-4: dalfox (parameter analysis + live XSS testing) ---
            # --format json gives us structured, per-finding severity/type info so
            # "verified" candidates can be split out programmatically instead of by
            # eyeballing the plain-text log. Falls back to the plain-text log alone
            # if jq isn't available to parse the JSON.
            echo "[*] [XSS pipeline 2/4] Running dalfox: parameter analysis..."
            echo "[*] [XSS pipeline 3/4] Running dalfox: live XSS testing (payload reflection + DOM analysis)..."
            dalfox file "$URLS_WITH_PARAMS_FILE" --worker "$DALFOX_WORKERS" < /dev/null \
                --silence --no-spinner --format json \
                -o "$DALFOX_RAW_JSON" 2>/dev/null || true

            # Human-readable log alongside the JSON (some dalfox versions print
            # plain-text findings to stdout even in json -o mode; capture both).
            dalfox file "$URLS_WITH_PARAMS_FILE" --worker "$DALFOX_WORKERS" < /dev/null \
                --silence --no-spinner -o "$DALFOX_OUT" 2>/dev/null || true

            # --- Step 5: verified XSS candidates ---
            echo "[*] [XSS pipeline 4/4] Extracting verified XSS candidates..."
            : > "$XSS_VERIFIED_FILE"
            if [[ -s "$DALFOX_RAW_JSON" && "${HAVE[jq]:-0}" -eq 1 ]]; then
                # dalfox marks confirmed/high-confidence findings distinctly from
                # informational ones; keep only entries whose type/severity indicate
                # an actually-verified XSS (not just a reflected-parameter note).
                jq -r '
                    (if type=="array" then . else [.] end)[]
                    | select(
                        (.type // "" | test("V|VERIFY|G|R"; "i")) or
                        (.severity // "" | test("high|medium|critical"; "i"))
                      )
                    | "\(.type // "?")\t\(.severity // "?")\t\(.data // .poc // .payload // "")\t\(.url // "")"
                ' "$DALFOX_RAW_JSON" 2>/dev/null | sort -u > "$XSS_VERIFIED_FILE" || true
            fi
            # Fallback / supplement: dalfox's plain-text output tags confirmed
            # findings with [V] or [POC] -- pull those too in case JSON parsing
            # above found nothing (older dalfox versions, or jq missing).
            if [[ ! -s "$XSS_VERIFIED_FILE" && -s "$DALFOX_OUT" ]]; then
                grep -E '\[(V|POC|VERIFY)\]' "$DALFOX_OUT" 2>/dev/null | sort -u >> "$XSS_VERIFIED_FILE" || true
            fi

            VERIFIED_COUNT=$(wc -l < "$XSS_VERIFIED_FILE" 2>/dev/null | tr -d ' ')
            echo "[+] dalfox raw results -> $DALFOX_OUT ($DALFOX_RAW_JSON for structured data)"
            echo "[+] Verified XSS candidates -> $XSS_VERIFIED_FILE (${VERIFIED_COUNT:-0} finding(s))"
            if [[ "${VERIFIED_COUNT:-0}" -gt 0 ]]; then
                alert_finding "$VERIFIED_COUNT verified XSS candidate(s) for ${BASENAME_NOEXT}: see $XSS_VERIFIED_FILE"
            fi
        fi

        mark_done "xss:dalfox"
    fi
else
    echo "[=] Skipping dalfox XSS pipeline (--no-dalfox or not installed) -- relying on nuclei xss tag only, which is weaker"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 4c: ffuf content discovery — catches hidden panels/backups/debug
# routes that static nuclei exposure templates don't enumerate, because
# those templates only check known paths, not wordlist-driven discovery.
#
# v7: every host now gets a real `-fs` baseline computed via the shared
# ffuf_baseline_fs helper (root response size + a guaranteed-404 response
# size) before ffuf runs, instead of running unfiltered and drowning in
# soft-404 noise.
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[ffuf]}" -eq 0 && "${HAVE[ffuf]}" -eq 1 && -f "$FFUF_WORDLIST" ]]; then
    if is_done "ffuf:complete"; then
        echo "[=] Skipping: ffuf content discovery"
    else
        echo "[*] Running ffuf directory/file discovery against live hosts (with computed -fs baseline per host)..."
        while read -r url; do
            [[ -z "$url" ]] && continue
            host_safe="$(echo "$url" | sed -E 's#https?://##; s#[/:]#_#g')"

            fs_args=()
            ffuf_baseline_fs "$url" fs_args

            run_niced ffuf -u "${url}/FUZZ" -w "$FFUF_WORDLIST" -t "$FFUF_THREADS" \
                -mc 200,204,301,302,307,401,403 "${fs_args[@]}" -of json \
                -o "${FFUF_OUT_DIR}/${host_safe}.json" -s 2>/dev/null || true
        done < "$LIVE_URLS_FILE"
        mark_done "ffuf:complete"
        echo "[+] ffuf results -> ${FFUF_OUT_DIR}/"
    fi
else
    echo "[=] Skipping ffuf (fast mode, --no-ffuf, tool missing, or wordlist not found at $FFUF_WORDLIST)"
fi
echo "-------------------------------------------------------------------"

# =====================================================================
# STAGE 4d: gowitness — screenshot triage for fast visual review
# =====================================================================
if [[ "$FAST_MODE" -eq 0 && "${NO_TOOL[gowitness]}" -eq 0 && "${HAVE[gowitness]}" -eq 1 ]]; then
    if is_done "screenshots:complete"; then
        echo "[=] Skipping: gowitness screenshots"
    else
        echo "[*] Capturing screenshots with gowitness..."
        mkdir -p "$SCREENSHOT_DIR"
        run_niced gowitness file -f "$LIVE_URLS_FILE" -P "$SCREENSHOT_DIR" --threads "$GOWITNESS_THREADS" < /dev/null 2>/dev/null || true
        mark_done "screenshots:complete"
        echo "[+] Screenshots -> $SCREENSHOT_DIR/"
    fi
else
    echo "[=] Skipping gowitness (fast mode, --no-gowitness, or tool missing)"
fi
echo "-------------------------------------------------------------------"

# ---- Combine all nuclei findings ---------------------------------------------
COMBINED_FINDINGS="${RUN_DIR}/${BASENAME_NOEXT}_nuclei_all.txt"
find "$NUCLEI_OUT_DIR" -type f -name '*.txt' -exec cat {} + 2>/dev/null | sort -u > "$COMBINED_FINDINGS"
mark_done "all:complete"

if [[ -s "$COMBINED_FINDINGS" ]]; then
    alert_finding "Nuclei scan complete for ${BASENAME_NOEXT}: $(wc -l < "$COMBINED_FINDINGS" | tr -d ' ') finding(s). Review $COMBINED_FINDINGS"
fi

# ---- Triage summary: pull everything into one place --------------------------
{
    echo "# Recon Triage Summary — $BASENAME_NOEXT"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "## Counts"
    echo "- Live hosts: $HOST_COUNT"
    echo "- Live hosts on non-default ports: ${PORT_HOST_COUNT:-0}"
    echo "- URLs (raw / deduped): $URL_COUNT / $DEDUP_COUNT"
    echo "- Nuclei findings: $(wc -l < "$COMBINED_FINDINGS" 2>/dev/null | tr -d ' ')"
    [[ -f "$PORT_SCAN_FILE" ]] && echo "- Open host:port pairs (naabu): $(wc -l < "$PORT_SCAN_FILE" | tr -d ' ')"
    [[ -f "$DALFOX_OUT" ]] && echo "- Dalfox XSS candidates (raw): $(wc -l < "$DALFOX_OUT" 2>/dev/null | tr -d ' ')"
    [[ -f "$XSS_VERIFIED_FILE" ]] && echo "- XSS verified candidates: $(wc -l < "$XSS_VERIFIED_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$JS_FILES" ]] && echo "- JS files harvested: $(wc -l < "$JS_FILES" 2>/dev/null | tr -d ' ')"
    [[ -f "$AMASS_ENUM_OUT_FILE" ]] && echo "- Subdomains from amass enum: $(wc -l < "$AMASS_ENUM_OUT_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$BUCKET_FINDINGS" ]] && echo "- Cloud bucket candidates (s3scanner): $(wc -l < "$BUCKET_FINDINGS" 2>/dev/null | tr -d ' ')"
    [[ -f "$WAF_MAP_FILE" ]] && echo "- Hosts WAF-fingerprinted (wafw00f): $(wc -l < "$WAF_MAP_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$VHOST_OUT_FILE" ]] && echo "- Vhost candidates (ffuf Host-header fuzz): $(wc -l < "$VHOST_OUT_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$SUBS_NEW_FILE" ]] && echo "- New subdomains vs. last run (anew): $(wc -l < "$SUBS_NEW_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$INTERNAL_HOSTS_FILE" ]] && echo "- Subdomains resolving to internal/private IP space: $(wc -l < "$INTERNAL_HOSTS_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$SOURCEMAP_FINDINGS" ]] && echo "- Exposed JS sourcemaps with recovered source: $(grep -c '^## ' "$SOURCEMAP_FINDINGS" 2>/dev/null || echo 0)"
    [[ -f "$GITHUB_SECRETS_SUMMARY" ]] && echo "- GitHub secret scan: see $GITHUB_SECRETS_SUMMARY"
    [[ -f "$IIS_HOSTS_FILE" ]] && echo "- IIS hosts targeted via --fullurl: $(wc -l < "$IIS_HOSTS_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$LFI_CANDIDATES_FILE" ]] && echo "- LFI/path-traversal candidates: $(wc -l < "$LFI_CANDIDATES_FILE" 2>/dev/null | tr -d ' ')"
    [[ -f "$SQLI_CANDIDATES_FILE" ]] && echo "- SQLi candidates handed to sqlmap: $(wc -l < "$SQLI_CANDIDATES_FILE" 2>/dev/null | tr -d ' ')"
    echo
    echo "## Key output files"
    echo "- Nuclei combined: $COMBINED_FINDINGS"
    echo "- Nuclei per-target results (custom + stock roots): ${NUCLEI_OUT_DIR}/"
    echo "- Probe targets (bare hosts + host:port): $PROBE_TARGETS_FILE"
    echo "- JS secret mining: ${JS_FINDINGS_DIR}/js_regex_mining.md"
    echo "- JS sourcemap findings: $SOURCEMAP_FINDINGS"
    echo "- Parameters discovered: $PARAMS_FILE"
    echo "- XSS (dalfox raw): $DALFOX_OUT"
    echo "- XSS verified candidates: $XSS_VERIFIED_FILE"
    echo "- URLs with parameters (dalfox input): $URLS_WITH_PARAMS_FILE"
    echo "- ffuf content discovery: ${FFUF_OUT_DIR}/"
    echo "- Screenshots: ${SCREENSHOT_DIR}/"
    echo "- Port scan: $PORT_SCAN_FILE"
    echo "- Subdomains from amass enum: $AMASS_ENUM_OUT_FILE"
    echo "- Cloud bucket findings: $BUCKET_FINDINGS"
    echo "- WAF mapping: $WAF_MAP_FILE"
    echo "- Vhost candidates: $VHOST_OUT_FILE"
    echo "- Internal/private-IP hosts: $INTERNAL_HOSTS_FILE"
    echo "- IIS hosts (--fullurl): $IIS_HOSTS_FILE"
    echo "- LFI/path-traversal candidates: $LFI_CANDIDATES_FILE"
    echo "- LFI/path-traversal ffuf results: ${LFI_FFUF_OUT_DIR}/"
    echo "- SQLi candidates: $SQLI_CANDIDATES_FILE"
    echo "- sqlmap results (from sqlmap-dev): $SQLMAP_OUT_DIR/"
    echo "- GitHub secret scan summary: $GITHUB_SECRETS_SUMMARY"
    echo "- GitHub secret scan raw output dir: ${GITHUB_SECRETS_DIR}/"
    echo "- Cross-run new subdomains: $SUBS_NEW_FILE"
    echo "- Cross-run subdomain history (persists across --reset): $SUBS_SEEN_FILE"
} > "$TRIAGE_REPORT"

echo "[+] Done with recon/scan pipeline."
echo "    Triage summary: $TRIAGE_REPORT"
cat "$TRIAGE_REPORT"

# =====================================================================
# STAGE 5: Claude analysis pass (unchanged logic, now also fed JS + dalfox findings)
# =====================================================================
if [[ "$RUN_CLAUDE_ANALYSIS" -eq 1 ]]; then
    if is_done "claude:complete"; then
        echo "[+] Claude analysis already complete -> $CLAUDE_FINAL_SUMMARY"
    else
        echo "-------------------------------------------------------------------"
        echo "[*] Stage 5: Claude Code analysis of findings"
        mkdir -p "$CLAUDE_CHUNKS_DIR"

        ALL_FOR_ANALYSIS="${CLAUDE_OUT_DIR}/combined_for_analysis.txt"
        {
            echo "=== NUCLEI FINDINGS ==="
            cat "$COMBINED_FINDINGS" 2>/dev/null
            echo
            echo "=== DALFOX XSS FINDINGS (raw) ==="
            cat "$DALFOX_OUT" 2>/dev/null
            echo
            echo "=== XSS VERIFIED CANDIDATES ==="
            cat "$XSS_VERIFIED_FILE" 2>/dev/null
            echo
            echo "=== JS SECRET/ENDPOINT MINING ==="
            cat "${JS_FINDINGS_DIR}/js_regex_mining.md" 2>/dev/null
            echo
            echo "=== JS SOURCEMAP FINDINGS ==="
            cat "$SOURCEMAP_FINDINGS" 2>/dev/null
            echo
            echo "=== CLOUD BUCKET FINDINGS ==="
            cat "$BUCKET_FINDINGS" 2>/dev/null
            echo
            echo "=== VHOST FUZZING CANDIDATES ==="
            cat "$VHOST_OUT_FILE" 2>/dev/null
            echo
            echo "=== INTERNAL/PRIVATE-IP HOST FLAGS ==="
            cat "$INTERNAL_HOSTS_FILE" 2>/dev/null
            echo
            echo "=== GITHUB SECRET SCAN SUMMARY ==="
            cat "$GITHUB_SECRETS_SUMMARY" 2>/dev/null
        } > "$ALL_FOR_ANALYSIS"

        if [[ ! -s "$ALL_FOR_ANALYSIS" ]]; then
            echo "[!] Nothing for claude to analyze. Skipping." >&2
        else
            split -l "$CLAUDE_MAX_LINES_PER_CHUNK" -d -a 3 "$ALL_FOR_ANALYSIS" "${CLAUDE_CHUNKS_DIR}/chunk_"
            chunk_files=("${CLAUDE_CHUNKS_DIR}"/chunk_*)
            total_chunks=${#chunk_files[@]}
            idx=0
            for chunk in "${chunk_files[@]}"; do
                idx=$((idx + 1))
                chunk_name="$(basename "$chunk")"
                job="claude:chunk:${chunk_name}"
                analysis_out="${CLAUDE_OUT_DIR}/${chunk_name}_analysis.md"
                if is_done "$job"; then echo "[=] Skipping: $chunk_name"; continue; fi

                echo "[*] Analyzing chunk $idx/$total_chunks: $chunk_name"
                prompt_file="$(mktemp)"
                {
                    echo "You are reviewing raw recon/scan output (nuclei, dalfox XSS, JS secret mining, JS sourcemap leaks, internal-host DNS flags, GitHub secret scan) from an authorized bug bounty engagement."
                    echo "This is chunk $idx of $total_chunks."
                    echo "For each finding: 1) name the check/URL, 2) real issue or noise, 3) severity + next test to confirm impact if real."
                    echo "Group duplicates. Be concise."
                    echo
                    echo "--- CHUNK ($chunk_name) ---"
                    cat "$chunk"
                } > "$prompt_file"

                if claude --dangerously-skip-permissions -p "$(cat "$prompt_file")" > "$analysis_out" 2>"${analysis_out}.err"; then
                    mark_done "$job"
                else
                    echo "[!] claude invocation failed for $chunk_name. Will retry on resume." >&2
                    rm -f "$prompt_file"; exit 2
                fi
                rm -f "$prompt_file"
                [[ $idx -lt $total_chunks ]] && sleep "$CLAUDE_CHUNK_PAUSE"
            done

            {
                echo "# Claude Analysis Summary"
                echo "Chunks analyzed: $total_chunks"
                echo
                for f in "${CLAUDE_OUT_DIR}"/chunk_*_analysis.md; do
                    [[ -f "$f" ]] || continue
                    echo "---"; echo "## $(basename "$f")"; cat "$f"; echo
                done
            } > "$CLAUDE_FINAL_SUMMARY"
            mark_done "claude:complete"
            echo "[+] Claude analysis complete -> $CLAUDE_FINAL_SUMMARY"
        fi
    fi
else
    echo "[*] Skipping claude analysis (--no-claude or claude CLI missing)."
fi

echo "-------------------------------------------------------------------"
echo "[+] All stages complete."
