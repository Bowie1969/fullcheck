#!/usr/bin/env bash
# setup_dropbox.sh — provision an x86 Parrot/Kali drop box for FullCheck-Internal.
#
# Run as root on the box you will place on the client LAN. Idempotent-ish: apt
# skips already-installed packages; pipx re-installs are harmless. Nothing here
# touches any target — it only installs the local toolchain the swarm and the
# exploit catalog shell out to.
set -euo pipefail

echo "[*] FullCheck-Internal drop-box setup (Parrot/Kali, x86)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] run as root (sudo)." >&2
  exit 1
fi

echo "[*] apt packages (discovery/enum + exploitation binaries)"
apt-get update -y
apt-get install -y \
  python3 python3-pip pipx git \
  nmap masscan \
  smbmap snmp snmp-mibs-downloader onesixtyone snmpcheck \
  responder mitm6 \
  crackmapexec \
  nuclei \
  hashcat john \
  || echo "[!] some apt packages unavailable on this distro — continuing"

echo "[*] pipx (Python tooling that moves faster than distro packages)"
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
pipx ensurepath >/dev/null 2>&1 || true

# NetExec is the maintained successor to crackmapexec; catalog calls `nxc`.
pipx install git+https://github.com/Pennyw0rth/NetExec 2>/dev/null || \
  pipx upgrade netexec 2>/dev/null || echo "[!] netexec install skipped"

pipx install impacket 2>/dev/null || echo "[!] impacket via pipx skipped (may be apt-provided)"
pipx install enum4linux-ng 2>/dev/null || \
  pip3 install --break-system-packages enum4linux-ng 2>/dev/null || echo "[!] enum4linux-ng skipped"
pipx install certipy-ad 2>/dev/null || echo "[!] certipy skipped"
pipx install bloodhound 2>/dev/null || echo "[!] bloodhound-python skipped"
pipx install kerbrute 2>/dev/null || echo "[!] kerbrute (pipx) skipped — grab the release binary if needed"

echo "[*] installing FullCheck-Internal itself"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pip3 install --break-system-packages -e "${HERE}" 2>/dev/null || pip3 install -e "${HERE}"

echo "[*] verifying key binaries are on PATH"
for b in nmap nxc responder ntlmrelayx.py secretsdump.py wmiexec.py nuclei smbmap snmp-check; do
  if command -v "$b" >/dev/null 2>&1; then
    printf '    [ok]   %s\n' "$b"
  else
    printf '    [MISS] %s  (that catalog technique / tool will be skipped)\n' "$b"
  fi
done

cat <<'EOF'

[*] done. Next:
    1. cp scope.internal.example.yaml scope.yaml  (edit for the engagement)
    2. fcx new <client> --auth-ref <REF>
    3. fcx swarm <client> --auth-ref <REF> --range 10.10.0.0/24
    4. fcx catalog          # see which techniques auto-run vs stop for approval
    5. fcx attack <client>  --technique <name> --target <host> --auth-ref <REF>
EOF
