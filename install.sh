#!/usr/bin/env bash
#
# install.sh - Installs dependencies required/used by recon.sh (recon-wolf)
#
# Installs everything recon.sh checks for at startup:
#   Required:  subfinder httpx nuclei katana gau
#   Optional:  dnsx puredns alterx waybackurls subjs arjun dalfox ffuf
#              gowitness naabu jq anew amass s3scanner wafw00f notify
#              dig gitleaks trufflehog python3
#
# Go-installable tools are installed via `go install`. A few tools aren't
# Go binaries (ffuf's apt package, jq, dig, wafw00f, s3scanner, gitleaks,
# trufflehog) and get their own install paths below. Nothing here is
# force-installed if it's already present, and failures are reported but
# don't stop the rest of the script.
set -uo pipefail

echo "===== recon-wolf dependency installer ====="

# ---- Go ----------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
    cat >&2 <<'EOF'
[!] Go is not installed or not in PATH.

    Most of these tools are Go binaries and require Go 1.21+.
    Install it first:

      Debian/Ubuntu:  sudo apt install golang-go
      macOS (brew):   brew install go
      Or download:    https://go.dev/dl/

    Then re-run this script.
EOF
    exit 1
fi

GOBIN="$(go env GOPATH)/bin"
echo "[*] Go found: $(go version)"
echo "[*] Go binaries will install to: $GOBIN"

if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "[!] Warning: $GOBIN is not in your PATH."
    echo "    Add this to your shell profile (~/.bashrc, ~/.zshrc, etc):"
    echo "      export PATH=\"\$PATH:$GOBIN\""
fi

install_go_tool() {
    local name="$1" pkg="$2"
    if command -v "$name" >/dev/null 2>&1; then
        echo "[+] $name already installed: $(command -v "$name")"
        return
    fi
    echo "[*] Installing $name..."
    if go install "$pkg"; then
        echo "[+] $name installed."
    else
        echo "[!] Failed to install $name." >&2
    fi
}

# ---- Required Go tools ---------------------------------------------------
echo "----- Required tools -----"
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei"    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "katana"    "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "gau"       "github.com/lc/gau/v2/cmd/gau@latest"

# ---- Optional Go tools ----------------------------------------------------
echo "----- Optional Go tools -----"
install_go_tool "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "puredns"     "github.com/d3mondev/puredns/v2@latest"
install_go_tool "alterx"      "github.com/projectdiscovery/alterx/cmd/alterx@latest"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_go_tool "subjs"       "github.com/lc/subjs@latest"
install_go_tool "dalfox"      "github.com/hahwul/dalfox/v2@latest"
install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"
install_go_tool "anew"        "github.com/tomnomnom/anew@latest"
install_go_tool "notify"      "github.com/projectdiscovery/notify/cmd/notify@latest"

# ---- Optional non-Go tools -------------------------------------------------
echo "----- Optional non-Go tools -----"

install_apt_pkg() {
    local bin="$1" pkg="$2"
    if command -v "$bin" >/dev/null 2>&1; then
        echo "[+] $bin already installed: $(command -v "$bin")"
        return
    fi
    if command -v apt >/dev/null 2>&1; then
        echo "[*] Installing $pkg via apt..."
        if sudo apt install -y "$pkg"; then
            echo "[+] $bin installed."
        else
            echo "[!] Failed to install $pkg via apt." >&2
        fi
    else
        echo "[!] apt not found -- install $bin manually (package: $pkg)." >&2
    fi
}

install_apt_pkg "ffuf"      "ffuf"
install_apt_pkg "jq"        "jq"
install_apt_pkg "dig"       "dnsutils"
install_apt_pkg "naabu"     "naabu"
install_apt_pkg "amass"     "amass"
install_apt_pkg "wafw00f"   "wafw00f"
install_apt_pkg "python3"   "python3"

# arjun / s3scanner -- pip-installable
install_pip_tool() {
    local bin="$1" pkg="$2"
    if command -v "$bin" >/dev/null 2>&1; then
        echo "[+] $bin already installed: $(command -v "$bin")"
        return
    fi
    if command -v pipx >/dev/null 2>&1; then
        echo "[*] Installing $pkg via pipx..."
        pipx install "$pkg" || echo "[!] Failed to install $pkg via pipx." >&2
    elif command -v pip3 >/dev/null 2>&1; then
        echo "[*] Installing $pkg via pip3..."
        pip3 install "$pkg" || echo "[!] Failed to install $pkg via pip3." >&2
    else
        echo "[!] Neither pipx nor pip3 found -- install $pkg manually." >&2
    fi
}

install_pip_tool "arjun"     "arjun"
install_pip_tool "s3scanner" "s3scanner"

# gitleaks -- release binary (no standard apt/go path)
if command -v gitleaks >/dev/null 2>&1; then
    echo "[+] gitleaks already installed: $(command -v gitleaks)"
elif command -v brew >/dev/null 2>&1; then
    echo "[*] Installing gitleaks via brew..."
    brew install gitleaks || echo "[!] Failed to install gitleaks via brew." >&2
else
    echo "[!] gitleaks not found -- no brew available. Install manually:" >&2
    echo "    https://github.com/gitleaks/gitleaks/releases" >&2
fi

# trufflehog -- official install script
if command -v trufflehog >/dev/null 2>&1; then
    echo "[+] trufflehog already installed: $(command -v trufflehog)"
else
    echo "[*] Installing trufflehog..."
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sudo sh -s -- -b /usr/local/bin; then
        echo "[+] trufflehog installed."
    else
        echo "[!] Failed to install trufflehog. Install manually:" >&2
        echo "    https://github.com/trufflesecurity/trufflehog" >&2
    fi
fi

# ---- nuclei-templates sync -------------------------------------------------
if command -v nuclei >/dev/null 2>&1; then
    echo "[*] Syncing nuclei-templates..."
    nuclei -ut
else
    echo "[!] Skipping template sync -- nuclei not found in PATH after install." >&2
    echo "    Make sure $GOBIN is in your PATH, then run: nuclei -ut"
fi

# ---- SecLists (recommended, not installed automatically) ------------------
if [[ ! -d /usr/share/seclists ]]; then
    echo
    echo "[!] SecLists not found at /usr/share/seclists -- several stages (DNS bruteforce,"
    echo "    ffuf content discovery, vhost fuzzing) need it. Install with:"
    echo "      sudo apt install -y seclists"
    echo "    or clone: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists"
fi

echo
echo "===== Done ====="
echo "Verify core tools with:"
echo "  subfinder -version"
echo "  httpx -version"
echo "  nuclei -version"
echo "  katana -version"
echo "  gau --version"
echo
echo "Optional tools not shown above may still need manual install/config"
echo "(e.g. GITHUB_TOKEN for trufflehog org scans, ~/.config/notify/provider-config.yaml for notify)."
echo "Re-run this script any time -- it skips anything already installed."
