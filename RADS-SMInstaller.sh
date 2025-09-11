#!/usr/bin/env bash
# RADS-SMInstaller.sh  — Bootstrap to Git repo and run RADS-SMInstall.sh

set -Eeuo pipefail
umask 022

REPO_URL="https://github.com/fumatchu/RADS-SM.git"
DEST="/root/RADS-SMInstaller"

# --- Require root ---
if (( EUID != 0 )); then
  echo "This program must be run as root." >&2
  exit 1
fi

# --- Require Rocky Linux 9+ ---
. /etc/os-release 2>/dev/null || true
MAJOR="${VERSION_ID%%.*}"
if [[ "${ID:-}" != "rocky" || -z "${MAJOR}" || "${MAJOR}" -lt 9 ]]; then
  echo "This installer supports Rocky Linux 9+ only." >&2
  exit 1
fi

echo "Installing prerequisites (git, wget)…"
dnf -y install git wget >/dev/null

echo "Retrieving files from GitHub…"
if [[ -d "$DEST/.git" ]]; then
  # Update existing checkout
  git -C "$DEST" fetch --depth=1 origin main >/dev/null
  git -C "$DEST" reset --hard origin/main >/dev/null
else
  rm -rf "$DEST"
  git clone --depth 1 "$REPO_URL" "$DEST" >/dev/null
fi

# Ensure scripts are executable (best-effort)
chmod 700 "$DEST"/RADS-SMInstall.sh 2>/dev/null || true
chmod 700 "$DEST"/RA* 2>/dev/null || true

echo "Launching RADS-SMInstall.sh…"
exec "$DEST/RADS-SMInstall.sh"
