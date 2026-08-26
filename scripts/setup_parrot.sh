#!/usr/bin/env bash
# Hour 1: ParrotOS toolchain sanity + missing installs.
# Run on the ParrotOS attacker laptop after cloning the repo.

set -eu

echo "[+] apt update"
sudo apt-get update -y

echo "[+] core recon tools"
sudo apt-get install -y \
    nmap masscan dnsutils whois curl jq git python3-pip python3-venv \
    trufflehog gitleaks dnstwist wafw00f whatweb

echo "[+] Go toolchain (for ProjectDiscovery latest)"
if ! command -v go >/dev/null; then
    sudo apt-get install -y golang-go
fi
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

echo "[+] ProjectDiscovery suite (latest)"
for t in subfinder httpx dnsx tlsx naabu nuclei katana; do
    go install "github.com/projectdiscovery/${t}/v2/cmd/${t}@latest" || \
    go install "github.com/projectdiscovery/${t}/cmd/${t}@latest"
done

echo "[+] gowitness (screenshots)"
go install github.com/sensepost/gowitness@latest

echo "[+] nuclei templates"
nuclei -update-templates -silent || true

echo "[+] python venv + editable install"
cd "$(dirname "$0")/.."
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .

# Optional semantic CVE search: this will use the GTX through CUDA when the
# installed PyTorch build can see it, otherwise safely runs on CPU.
# Enable later with: pip install -e '.[embed]'

echo "[+] verify"
for t in subfinder httpx dnsx nuclei naabu katana gowitness trufflehog dnstwist; do
    if command -v "$t" >/dev/null; then
        echo "  OK  $t"
    else
        echo "  MISSING $t"
    fi
done

cat <<EOF

[+] Done. Next:
    export PATH="\$PATH:\$HOME/go/bin"
    source .venv/bin/activate
    fullcheck --help
EOF
