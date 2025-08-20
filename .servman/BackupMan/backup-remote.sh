#!/bin/bash
# ===============================
# Samba DC Remote Backup Script (No Local Retention)
# Baseline UX: live per-file stream + md5 textbox
# Preserves ownership, ACLs, xattrs via rsync -aAX
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
TEMP_BASE=$(mktemp -d -p /tmp samba-dc-backup.XXXXXX)
BACKUP_PATH="$TEMP_BASE/${FQDN}_backup-$DATE"
mkdir -p "$BACKUP_PATH"

# ----------------------------
# --- Dialog: Warn about downtime ---
# ----------------------------
dialog --title "Attention!" \
--yesno "The Samba AD DC service will be stopped during the backup.\nThe domain will be offline temporarily.\n\nDo you want to continue?" 10 100
[[ $? -ne 0 ]] && clear && exit 0

# ----------------------------
# --- Prompt for Remote SSH Info ---
# ----------------------------
REMOTE_HOST=$(dialog --title "Remote Host" --inputbox "Enter SSH server IP or hostname:" 8 60 3>&1 1>&2 2>&3) || exit 0
REMOTE_USER=$(dialog --title "Remote User" --inputbox "Enter SSH username:" 8 60 "" 3>&1 1>&2 2>&3) || exit 0
REMOTE_DIR=$(dialog --title "Remote Directory" --inputbox "Enter remote directory to store backup:" 8 60 "/root/samba-dc-backup" 3>&1 1>&2 2>&3) || exit 0
REMOTE_PASS=$(dialog --insecure --title "SSH Password" --passwordbox "Enter SSH password for $REMOTE_USER@$REMOTE_HOST:" 10 60 3>&1 1>&2 2>&3) || exit 0

# ----------------------------
# --- Validate SSH Access & Write Permission ---
# ----------------------------
TEST_FILE=".samba_backup_test_$(date +%s)"
dialog --title "Testing SSH Access" --infobox "Checking remote login and write permission..." 6 60

mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keyscan -H "$REMOTE_HOST" >> ~/.ssh/known_hosts 2>/dev/null

command -v sshpass >/dev/null 2>&1 || {
    echo -e "${YELLOW}Installing sshpass...${TEXTRESET}"
    dnf -y install sshpass >/dev/null 2>&1 || yum -y install sshpass
}

sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" \
"mkdir -p '$REMOTE_DIR' && touch '$REMOTE_DIR/$TEST_FILE' && rm -f '$REMOTE_DIR/$TEST_FILE'" 2>/tmp/ssh_test_error

if [[ $? -ne 0 ]]; then
    ERROR_MSG=$(< /tmp/ssh_test_error)
    dialog --title "Connection Failed" --msgbox "Failed to connect or write to:\n$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR\n\nError:\n$ERROR_MSG" 12 80
    rm -f /tmp/ssh_test_error
    rm -rf "$TEMP_BASE"
    clear
    exit 1
fi
rm -f /tmp/ssh_test_error

# ----------------------------
# --- Record OS & Samba versions (for restore checks) ---
# ----------------------------
OS_PRETTY="unknown"; OS_ID=""; OS_VERSION_ID=""
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
# --- Stop Samba Service ---
# ----------------------------
dialog --title "Stopping Samba" --infobox "Stopping samba..." 5 50
systemctl stop samba

# ----------------------------
# --- Live file list while backing up (rsync -aAX) ---
# ----------------------------
(
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

  echo "Recorded OS info -> $BACKUP_PATH/os_version.txt"
  echo "Recorded Samba info -> $BACKUP_PATH/samba_version.txt"
  echo "-----------------------------------------------"

  find "${INCLUDE_PATHS[@]}" -type f 2>/dev/null | while read -r FILE; do
    REL_PATH="${FILE#/}"
    DEST="$BACKUP_PATH/$REL_PATH"
    mkdir -p "$(dirname "$DEST")"
    echo "Backing up: $REL_PATH"
    rsync -aAX -- "$FILE" "$DEST"
  done
) | dialog --title "Backing up files (rsync -aAX)" --programbox 22 100

# ----------------------------
# --- Start Samba Service ---
# ----------------------------
dialog --title "Starting Samba" --infobox "Starting samba..." 5 50
systemctl start samba

# ----------------------------
# --- MD5 checksums + show list ---
# ----------------------------
dialog --title "Generating MD5" --infobox "Computing checksums..." 5 50
(
  cd "$BACKUP_PATH"
  find . -type f -print0 | xargs -0 md5sum > "$BACKUP_PATH/md5sums.txt"
)

dialog --title "Backed-up files (with checksums)" \
  --textbox "$BACKUP_PATH/md5sums.txt" 24 100

# ----------------------------
# --- Transfer via SCP ---
# ----------------------------
dialog --title "Transferring Backup" --infobox "Sending backup to $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR ..." 7 60
sshpass -p "$REMOTE_PASS" scp -o StrictHostKeyChecking=no -r "$BACKUP_PATH" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" 2>/tmp/scp_error

if [[ $? -eq 0 ]]; then
    dialog --title "Transfer Successful" --msgbox "Backup was successfully copied to:\n$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" 10 70
    rm -rf "$TEMP_BASE"
else
    ERROR_MSG=$(< /tmp/scp_error)
    dialog --title "Transfer Failed" --msgbox "Backup transfer failed:\n$ERROR_MSG" 12 80
    rm -f /tmp/scp_error
    clear
    exit 1
fi
rm -f /tmp/scp_error

# ----------------------------
# --- Completion Message ---
# ----------------------------
dialog --title "Backup Complete" --msgbox "Backup completed and transferred successfully.

Remote: $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR

Version metadata included:
  - os_version.txt
  - samba_version.txt

Checksums file on remote inside the backup folder:
  - md5sums.txt" 14 90

clear
exit 0
