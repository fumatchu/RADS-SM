#!/bin/bash
# ===============================
# Samba DC Local Backup Only
# Streams file list during backup + shows md5 list at end
# Preserves ownership, ACLs, xattrs via rsync -aAX
# Also records OS and Samba versions for restore compatibility checks
# ===============================

TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root!${TEXTRESET}"
    exit 1
fi

FQDN=$(hostname -f)
DATE=$(date +%Y%m%d-%H%M)
BACKUP_ROOT="/root/samba-dc-backups"

# ----------------------------
# --- Warn about downtime ---
# ----------------------------
dialog --title "Attention!" \
  --yesno "The Samba AD DC service will be stopped during the backup.\nThe domain will be offline temporarily.\n\nDo you want to continue?" 10 100
[[ $? -ne 0 ]] && clear && exit 0

# ----------------------------
# --- Prompt for backup dir ---
# ----------------------------
BACKUP_DIR=$(dialog --title "Backup Directory" --inputbox \
"Enter local backup directory path:" 10 60 "$BACKUP_ROOT" 3>&1 1>&2 2>&3) || { clear; exit 0; }

mkdir -p "$BACKUP_DIR"
BACKUP_PATH="$BACKUP_DIR/${FQDN}_backup-$DATE"
mkdir -p "$BACKUP_PATH"

# ----------------------------
# --- Record OS & Samba versions (NEW) ---
# ----------------------------
# OS info from /etc/os-release (if present) + kernel
OS_PRETTY="unknown"
OS_ID=""
OS_VERSION_ID=""
if [[ -f /etc/os-release ]]; then
  OS_PRETTY=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"')
  OS_ID=$(grep '^ID=' /etc/os-release | cut -d= -f2- | tr -d '"')
  OS_VERSION_ID=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2- | tr -d '"')
fi
KERNEL="$(uname -r)"
{
  echo "PRETTY_NAME: ${OS_PRETTY}"
  [[ -n "$OS_ID" ]] && echo "ID: ${OS_ID}"
  [[ -n "$OS_VERSION_ID" ]] && echo "VERSION_ID: ${OS_VERSION_ID}"
  echo "KERNEL: ${KERNEL}"
} > "$BACKUP_PATH/os_version.txt"

# Samba version (prefer 'samba -V' on AD DC, fall back to smbd -V)
SAMBA_VER="unknown"
if command -v samba >/dev/null 2>&1; then
  SAMBA_VER="$(samba -V 2>/dev/null)"
elif command -v smbd >/dev/null 2>&1; then
  SAMBA_VER="$(smbd -V 2>/dev/null)"
fi
PKG_VER=""
if command -v rpm >/dev/null 2>&1; then
  PKG_VER="$(rpm -q samba 2>/dev/null || true)"
elif command -v dpkg-query >/dev/null 2>&1; then
  PKG_VER="$(dpkg-query -W -f='${Package} ${Version}\n' samba 2>/dev/null || true)"
fi
{
  echo "Samba: ${SAMBA_VER}"
  [[ -n "$PKG_VER" ]] && echo "Package: ${PKG_VER}"
} > "$BACKUP_PATH/samba_version.txt"

# ----------------------------
# --- Stop Samba service ---
# ----------------------------
dialog --title "Stopping Samba" --infobox "Stopping samba..." 5 50
systemctl stop samba

# ----------------------------
# --- Live file list while backing up ---
# ----------------------------
(
  # Include set (adjust if you need to trim/expand)
  INCLUDE_PATHS=(
    /etc/samba
    /etc/krb5.conf
    /etc/nsswitch.conf
    /var/lib/samba
    /var/lib/samba/private
    /var/lib/samba/sysvol
    /var/lib/samba/ntp_signd
    /var/lib/samba/bind-dns
    /etc/named.conf
    /var/named
  )

  # Show versions at the top of the stream so it's obvious we captured them
  echo "Recorded OS info -> $BACKUP_PATH/os_version.txt"
  echo "Recorded Samba info -> $BACKUP_PATH/samba_version.txt"
  echo "-----------------------------------------------"

  # Find files (quietly ignore missing paths)
  find "${INCLUDE_PATHS[@]}" -type f 2>/dev/null | while read -r FILE; do
    REL_PATH="${FILE#/}"                                # relative to /
    DEST="$BACKUP_PATH/$REL_PATH"
    mkdir -p "$(dirname "$DEST")"
    echo "Backing up: $REL_PATH"
    rsync -aAX -- "$FILE" "$DEST"
  done
) | dialog --title "Backing up files (rsync -aAX)" --programbox 22 100

# ----------------------------
# --- Start Samba service ---
# ----------------------------
dialog --title "Starting Samba" --infobox "Starting samba..." 5 50
systemctl start samba

# ----------------------------
# --- MD5 checksums + show list ---
# ----------------------------
dialog --title "Generating MD5" --infobox "Computing checksums..." 5 50
(
  cd "$BACKUP_PATH"
  # Include the two version files in checksums as well
  find . -type f -print0 | xargs -0 md5sum > "$BACKUP_PATH/md5sums.txt"
)

# Show the full list (scrollable). User can PgUp/PgDn/search (/).
dialog --title "Backed-up files (with checksums)" \
  --textbox "$BACKUP_PATH/md5sums.txt" 24 100

# ----------------------------
# --- Completion message ---
# ----------------------------
dialog --title "Backup Complete" --msgbox \
"Backup completed successfully.

Backup path:
$BACKUP_PATH

Version metadata written:
  - os_version.txt
  - samba_version.txt

A full file list with checksums was saved to:
$BACKUP_PATH/md5sums.txt" 14 90

clear
exit 0
