#!/bin/bash
set -Eeuo pipefail

# Colors only when stdout is a TTY (so logs aren’t full of escapes)
if [[ -t 1 ]]; then
  TEXTRESET=$(tput sgr0); RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
else
  TEXTRESET=""; RED=""; YELLOW=""; GREEN=""
fi

# Root check
if (( EUID != 0 )); then
  echo "${RED}This program must be run as root.${TEXTRESET}" >&2
  exit 1
fi

# Rocky 9+ check
. /etc/os-release 2>/dev/null || true
MAJOR="${VERSION_ID%%.*}"
if [[ "${ID:-}" != rocky || -z "$MAJOR" || "$MAJOR" -lt 9 ]]; then
  echo "${RED}Sorry, this installer supports Rocky Linux 9+ only.${TEXTRESET}" >&2
  exit 1
fi

cat <<EOF
${GREEN}Installing Server Management${TEXTRESET}
This installer provides a set of scripts wrapped in a dialog GUI.
At any time from the CLI, run: ${YELLOW}server-manager${TEXTRESET}

Continuing...
EOF

sleep 2

# Dependencies (quiet)
dnf -y install dialog nano htop iptraf-ng mc >/dev/null

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
rm -f  /root/RADS-SMInstaller.sh

echo
echo "${GREEN}Install completed.${TEXTRESET}"
echo "You can launch with: server-manager"
# IMPORTANT: Do not pkill dialog or start server-manager here.
exit 0
