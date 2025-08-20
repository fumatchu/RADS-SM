#!/bin/bash
# ===============================
# Samba DC Remote Backup Script (No Local Retention)
# ===============================

TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)

USER=$(whoami)
if [ "$USER" != "root" ]; then
    echo -e "${RED}This script must be run as root!${TEXTRESET}"
    exit 1
fi

FQDN=$(hostname -f)
DATE=$(date +%Y%m%d-%H%M)
TEMP_BASE=$(mktemp -d -p /tmp samba-dc-backup.XXXXXX)
BACKUP_PATH="$TEMP_BASE/${FQDN}_backup-$DATE"
mkdir -p "$BACKUP_PATH"

TEMP_PIPE=$(mktemp -u)
mkfifo "$TEMP_PIPE"

# ----------------------------
# --- Dialog: Warn about downtime ---
# ----------------------------
dialog --title "Attention!" \
--yesno "The Samba AD DC service will be stopped during the backup.\nThe domain will be offline temporarily.\n\nDo you want to continue?" 10 100
DIALOG_EXIT=$?
[[ $DIALOG_EXIT -ne 0 ]] && clear && exit 0

# ----------------------------
# --- Prompt for Remote SCP Info ---
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

# Accept host key
ssh-keyscan -H "$REMOTE_HOST" >> ~/.ssh/known_hosts 2>/dev/null

# Ensure sshpass is available
command -v sshpass >/dev/null 2>&1 || {
    echo -e "${YELLOW}Installing sshpass...${TEXTRESET}"
    dnf -y install sshpass >/dev/null 2>&1 || yum -y install sshpass
}

# Check login & write access
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
# --- Stop Samba Service ---
# ----------------------------
dialog --title "Stopping Samba" --infobox "Stopping samba-ad-dc..." 5 50
systemctl stop samba-ad-dc

# ----------------------------
# --- Perform Backup with Progress ---
# ----------------------------
(
TOTAL_ITEMS=$(find /etc/samba /var/lib/samba/private /var/lib/samba/sysvol /var/lib/samba/locks /var/lib/samba/ldap -type f | wc -l)
COUNT=0
echo "0" > "$TEMP_PIPE"
for FILE in $(find /etc/samba /var/lib/samba/private /var/lib/samba/sysvol /var/lib/samba/locks /var/lib/samba/ldap -type f); do
    REL_PATH=$(realpath --relative-to=/ "$FILE")
    DEST="$BACKUP_PATH/$REL_PATH"
    mkdir -p "$(dirname "$DEST")"
    cp -a "$FILE" "$DEST"
    ((COUNT++))
    PERCENT=$(( COUNT * 100 / TOTAL_ITEMS ))
    echo "$PERCENT" > "$TEMP_PIPE"
    echo "XXX" > "$TEMP_PIPE"
    echo "Backing up: $REL_PATH" > "$TEMP_PIPE"
    echo "XXX" > "$TEMP_PIPE"
done
) &

dialog --backtitle "Samba DC Backup" --title "Backup Progress" --gauge "Initializing..." 10 60 0 < "$TEMP_PIPE"
rm -f "$TEMP_PIPE"

# ----------------------------
# --- Start Samba Service ---
# ----------------------------
dialog --title "Starting Samba" --infobox "Starting samba-ad-dc..." 5 50
systemctl start samba-ad-dc

# ----------------------------
# --- MD5 Checksum ---
# ----------------------------
dialog --title "Generating MD5" --infobox "Generating MD5 checksums..." 5 50
(cd "$BACKUP_PATH" && md5sum $(find . -type f) > "$BACKUP_PATH/md5sums.txt")

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
dialog --title "Backup Complete" --msgbox "Backup completed and transferred successfully.\n\nRemote path: $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR" 10 100
clear
exit 0
