#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

# Root check
if (( EUID != 0 )); then
  echo "This program must be run as root." >&2
  exit 1
fi

# Rocky 9+ check
. /etc/os-release 2>/dev/null || true
MAJOR="${VERSION_ID%%.*}"
if [[ "${ID:-}" != "rocky" || -z "${MAJOR}" || "${MAJOR}" -lt 9 ]]; then
  echo "Sorry, this installer supports Rocky Linux 9+ only." >&2
  exit 1
fi

echo "Installing Server Management"
echo "This installer provides a set of scripts wrapped in a dialog GUI."
echo "At any time from the CLI, run: server-manager"
echo
sleep 1

STAGE="/root/RADS-SMInstaller"   # cloned by the bootstrap
PAYLOAD_DIR="$STAGE/.servman"
LAUNCHER_SRC="$STAGE/server-manager"

# Basic sanity
[[ -d "$STAGE" ]] || { echo "Staging dir not found: $STAGE" >&2; exit 1; }
[[ -d "$PAYLOAD_DIR" ]] || { echo "Payload not found: $PAYLOAD_DIR" >&2; exit 1; }
[[ -f "$LAUNCHER_SRC" ]] || { echo "Launcher not found: $LAUNCHER_SRC" >&2; exit 1; }

# Lay down files
rm -rf /root/.servman
rm -f  /usr/bin/server-manager
sed -i '/\/usr\/bin\/server-manager/d' /root/.bash_profile || true

# Copy payload and set perms
cp -a "$PAYLOAD_DIR" /root/.servman
install -m 700 "$LAUNCHER_SRC" /usr/bin/server-manager
chmod -R 700 /root/.servman/

# Optional: auto-launch on login
grep -q '/usr/bin/server-manager' /root/.bash_profile || echo '/usr/bin/server-manager' >> /root/.bash_profile

# Cleanup the staging area (safe even while this script is executing)
rm -rf /root/RADS-SMInstaller
rm -rf /root/RADS-SM
rm -f  /root/RADS-SMInstaller.sh

echo
echo "Install completed."
echo "You can launch with: server-manager"
exit 0
