#!/bin/bash
set -Eeuo pipefail

# Root check
if (( EUID != 0 )); then
  echo "${RED}This program must be run as root.${TEXTRESET}" >&2
  exit 1
fi

# Rocky 9+ check
. /etc/os-release 2>/dev/null || true
MAJOR="${VERSION_ID%%.*}"
if [[ "${ID:-}" != rocky || -z "$MAJOR" || "$MAJOR" -lt 9 ]]; then
  echo "Sorry, this installer supports Rocky Linux 9+ only." >&2
  exit 1
fi

cat <<EOF
Installing Server Management${TEXTRESET}
This installer provides a set of scripts wrapped in a dialog GUI.
At any time from the CLI, run: server-manager

Continuing...
EOF

sleep 2

# Lay down files
rm -rf /root/.servman
rm -f  /usr/bin/server-manager
sed -i '/\/usr\/bin\/server-manager/d' /root/.bash_profile || true

cd /root/RADS-SMInstaller

# Move payload and set perms
mv -f ./.servman /root/
install -m 700 server-manager /usr/bin/server-manager
chmod -R 700 /root/.servman/

# Optional: auto-launch on login (keep if you want this behavior)
grep -q '/usr/bin/server-manager' /root/.bash_profile || echo '/usr/bin/server-manager' >>/root/.bash_profile

# Cleanup the staging area
rm -rf /root/RADS-SMInstaller
rm -rf /root/RADS-SM
rm -f  /root/RADS-SMInstaller.sh

echo
echo "Install completed."
echo "You can launch with: server-manager"

exit 0
