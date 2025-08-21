#!/bin/bash
user=$(whoami)
#Checking for user permissions
if [ "$user" != "root" ]; then
    echo ${red}"This program must be run as root ${textreset}"
    echo "Exiting"
    exit
else
    echo "Running Program"
fi

items=(1 "Backup Local"
       2 "Backup Remote"
       3 "Restore"
)

while choice=$(dialog --title "$TITLE" \
    --backtitle "Samba Backup and Restore" \
    --menu "Please select" 25 40 3 "${items[@]}" \
    2>&1 >/dev/tty); do
    case $choice in
    1) /root/.servman/BackupMan/backup-local.sh ;;
    2) /root/.servman/BackupMan/backup-remote.sh ;;
    3) /root/.servman/BackupMan/restore.sh ;;
    esac
done
clear # clear after user pressed Cancel
