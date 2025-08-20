#!/bin/bash
# ===============================
# Samba DC Local Backup Only
# MD5, Progress, Graceful Shutdown
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
BACKUP_ROOT="/root/samba-dc-backups"
TEMP_PIPE=$(mktemp -u)
mkfifo "$TEMP_PIPE"

# ----------------------------
# --- Dialog: Warn about downtime ---
# ----------------------------
dialog --title "Attention!" \
--yesno "The Samba AD DC service will be stopped during the backup.\nThe domain will be offline temporarily.\n\nDo you want to continue?" 10 100
DIALOG_EXIT=$?
if [[ $DIALOG_EXIT -ne 0 ]]; then
    clear
    exit 0
fi

# ----------------------------
# --- Prompt for Backup Directory ---
# ----------------------------
BACKUP_DIR=$(dialog --title "Backup Directory" --inputbox \
"Enter local backup directory path:" 10 60 "$BACKUP_ROOT" 3>&1 1>&2 2>&3)
DIALOG_EXIT=$?
if [[ $DIALOG_EXIT -ne 0 ]]; then
    clear
    exit 0
fi

# Ensure directory exists
mkdir -p "$BACKUP_DIR"

# Define the actual backup folder name
BACKUP_PATH="$BACKUP_DIR/${FQDN}_backup-$DATE"
mkdir -p "$BACKUP_PATH"

# ----------------------------
# --- Stop Samba Service ---
# ----------------------------
dialog --title "Stopping Samba" --infobox "Stopping samba-ad-dc..." 5 50
systemctl stop samba-ad-dc

# ----------------------------
# --- Perform Backup ---
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

    # update progress
    ((COUNT++))
    PERCENT=$(( COUNT * 100 / TOTAL_ITEMS ))
    echo "$PERCENT" > "$TEMP_PIPE"
    echo "XXX" > "$TEMP_PIPE"
    echo "Backing up: $REL_PATH" > "$TEMP_PIPE"
    echo "XXX" > "$TEMP_PIPE"
done
) &

# Show progress gauge
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
(
cd "$BACKUP_PATH"
md5sum $(find . -type f) > "$BACKUP_PATH/md5sums.txt"
)

# ----------------------------
# --- Completion Message ---
# ----------------------------
dialog --title "Backup Complete" --msgbox "Backup completed successfully!\nLocal backup path: $BACKUP_PATH\nSamba services restored." 10 100
clear
exit 0
