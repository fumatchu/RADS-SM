#!/bin/bash

TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)

TMP_INPUT=$(mktemp)
trap 'rm -f "$TMP_INPUT"' EXIT

# === Detect Domain Controller ===
detect_dc() {
    local dc
    dc=$(hostname -f)
    if ! ping -c1 -W1 "$dc" &>/dev/null; then
        realm=$(samba-tool testparm --parameter-name="realm" 2>/dev/null | awk '{print $1}')
        dc=$(host -t A "$realm" | awk '/has address/ {print $NF; exit}')
    fi
    echo "$dc"
}

# === Prompt for Admin Password ===
prompt_admin_password() {
    while true; do
        ADMIN_PASS=$(dialog --insecure --passwordbox "Enter the Samba Administrator password:" 8 50 3>&1 1>&2 2>&3) || exit 1
        if samba-tool user list -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *" &>/dev/null; then
            break
        else
            dialog --msgbox "Authentication failed. Please try again." 7 50
        fi
    done
}

# === Prompt to Select and Delete User ===
delete_user() {
    mapfile -t USERS < <(samba-tool user list -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *" | sort)

    if [ ${#USERS[@]} -eq 0 ]; then
        dialog --msgbox "No users found in the directory." 7 40
        exit 1
    fi

    local choices=()
    for user in "${USERS[@]}"; do
        choices+=("$user" "")
    done

    SELECTED_USER=$(dialog --clear --title "Select User to Delete" \
        --menu "Select a user account to delete:" 20 60 10 \
        "${choices[@]}" \
        3>&1 1>&2 2>&3) || exit 1

    dialog --yesno "Are you sure you want to delete user: $SELECTED_USER?" 7 50
    if [ $? -eq 0 ]; then
        samba-tool user delete "$SELECTED_USER" -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *"
        dialog --msgbox "User '$SELECTED_USER' has been deleted." 6 50
    else
        dialog --msgbox "User deletion canceled." 6 40
    fi
}

# === Main ===
DC=$(detect_dc)
prompt_admin_password
delete_user
