#!/bin/bash

# === Detect DC ===
detect_dc() {
    local dc
    dc=$(hostname -f)
    if ! ping -c1 -W1 "$dc" &>/dev/null; then
        realm=$(samba-tool testparm --parameter-name="realm" 2>/dev/null | awk '{print $1}')
        dc=$(host -t A "$realm" | awk '/has address/ {print $NF; exit}')
    fi
    echo "$dc"
}

# === Prompt for Admin Password (handles special characters) ===
prompt_admin_password() {
    while true; do
        ADMIN_PASS=$(dialog --insecure --passwordbox "Enter the Samba Administrator password:" 8 50 3>&1 1>&2 2>&3) || exit 1
        if samba-tool dns zonelist "$DC" -U "Administrator" --password="$ADMIN_PASS" >/dev/null 2>&1; then
            break
        else
            dialog --msgbox "Authentication failed. Please try again." 7 50
        fi
    done
}

# === Convert to Full DN and Capitalize ===
to_full_dn() {
    local input="$1"
    local realm base_dn

    realm=$(samba-tool testparm --parameter-name="realm" 2>/dev/null | awk '{print $1}')
    base_dn=$(echo "$realm" | awk -F. '{ for (i=1; i<=NF; i++) printf "DC=%s%s", toupper($i), (i<NF?",":"") }')

    if [[ "$input" =~ ^OU=.+,DC=.+ ]]; then
        # Already full DN
        echo "$input"
    elif [[ "$input" =~ ^OU= ]]; then
        # Has OU= but not full DN
        echo "${input},${base_dn}"
    else
        # Short name, convert to full DN
        local ou_caps=$(echo "$input" | tr '[:lower:]' '[:upper:]')
        echo "OU=${ou_caps},${base_dn}"
    fi
}
ou_has_users() {
    local ou_dn="$1"
    ldbsearch -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" -b "$ou_dn" "(objectClass=user)" dn 2>/dev/null | \
        grep -v "^dn: $ou_dn$" | grep -q "^dn:"
}

get_users_in_ou() {
    local ou_dn="$1"
    ldbsearch -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" -b "$ou_dn" "(objectClass=user)" sAMAccountName 2>/dev/null | \
        awk '/^sAMAccountName:/ { print $2 }'
}

move_user_to_ou() {
    local username="$1"
    local target_ou="$2"
    samba-tool user move "$username" "$target_ou" -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" >/dev/null 2>&1
}


# === Setup ===
TMP_INPUT=$(mktemp)
cleanup() { rm -f "$TMP_INPUT"; }
trap cleanup EXIT

# === Menu Actions ===

list_ous() {
    samba-tool ou list -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" | tr '[:lower:]' '[:upper:]' > "$TMP_INPUT"
    dialog --backtitle "OU Manager" --title "Organizational Units" --textbox "$TMP_INPUT" 20 60
}

create_ou() {
    dialog --inputbox "Enter new OU name (e.g., sales or OU=sales,DC=example,DC=com):" 10 60 2>"$TMP_INPUT"
    [ $? -ne 0 ] && return
    RAW_INPUT=$(<"$TMP_INPUT")
    OU_DN=$(to_full_dn "$RAW_INPUT")
    samba-tool ou create "$OU_DN" -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" 2>&1 | tee "$TMP_INPUT"
    dialog --msgbox "$(cat "$TMP_INPUT")" 10 60
}

delete_ou() {
    mapfile -t OU_LIST < <(samba-tool ou list -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" | tr '[:lower:]' '[:upper:]')

    if [ ${#OU_LIST[@]} -eq 0 ]; then
        dialog --msgbox "No Organizational Units found." 7 50
        return
    fi

    MENU_ITEMS=()
    for ou in "${OU_LIST[@]}"; do
        MENU_ITEMS+=("$ou" "")
    done

    SELECTED_OU=$(dialog --title "Delete OU" --menu "Select an OU to delete:" 20 60 10 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)
    [ $? -ne 0 ] && return

    OU_DN=$(to_full_dn "$SELECTED_OU")

    # Check if OU has users
    if ou_has_users "$OU_DN"; then
        # Filter OUs excluding the one being deleted
        DEST_MENU_ITEMS=()
        for ou in "${OU_LIST[@]}"; do
            [[ "$ou" == "$SELECTED_OU" ]] && continue
            DEST_MENU_ITEMS+=("$ou" "")
        done

        if [ ${#DEST_MENU_ITEMS[@]} -eq 0 ]; then
            dialog --msgbox "Cannot delete. OU contains users, and no other OUs are available to move them to." 8 60
            return
        fi

        DEST_OU=$(dialog --title "Move Users" --menu "OU '$SELECTED_OU' has users. Select a destination OU to move them to:" 20 60 10 "${DEST_MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)
        [ $? -ne 0 ] && return

        DEST_DN=$(to_full_dn "$DEST_OU")

        # Migrate users
        mapfile -t USERS_TO_MOVE < <(get_users_in_ou "$OU_DN")
        for user in "${USERS_TO_MOVE[@]}"; do
            move_user_to_ou "$user" "$DEST_DN"
        done

        dialog --msgbox "Moved ${#USERS_TO_MOVE[@]} user(s) to $DEST_OU." 7 50
    fi

    # Confirm deletion
    dialog --yesno "Are you sure you want to delete OU: $SELECTED_OU ?" 7 60
    [ $? -ne 0 ] && return

    samba-tool ou delete "$OU_DN" -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" 2>&1 | tee "$TMP_INPUT"
    dialog --msgbox "$(cat "$TMP_INPUT")" 10 60
}

rename_ou() {
    mapfile -t OU_LIST < <(samba-tool ou list -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" | tr '[:lower:]' '[:upper:]')

    if [ ${#OU_LIST[@]} -eq 0 ]; then
        dialog --msgbox "No Organizational Units found." 7 50
        return
    fi

    MENU_ITEMS=()
    for ou in "${OU_LIST[@]}"; do
        MENU_ITEMS+=("$ou" "")
    done

    SELECTED_OU=$(dialog --title "Rename OU" --menu "Select an OU to rename:" 20 60 10 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)
    [ $? -ne 0 ] && return

    dialog --inputbox "Enter new name for OU '$SELECTED_OU' (e.g., MARKETING):" 10 60 2>"$TMP_INPUT"
    [ $? -ne 0 ] && return
    RAW_NEW_OU=$(cat "$TMP_INPUT")
    NEW_OU=$(to_full_dn "$RAW_NEW_OU")

    dialog --yesno "Rename OU '$SELECTED_OU' to '$NEW_OU'?" 7 60
    [ $? -ne 0 ] && return

    OLD_OU_DN=$(to_full_dn "$SELECTED_OU")

    samba-tool ou rename "$OLD_OU_DN" "$NEW_OU" -H ldap://"$DC" -U "Administrator" --password="$ADMIN_PASS" 2>&1 | tee "$TMP_INPUT"
    dialog --msgbox "$(cat "$TMP_INPUT")" 10 60
}

# === Main ===
DC=$(detect_dc)
prompt_admin_password

while true; do
    CHOICE=$(dialog --backtitle "Samba OU Manager" --title "Main Menu" --cancel-label "Exit" \
      --menu "Choose an action:" 15 50 6 \
      1 "List OUs" \
      2 "Create OU" \
      3 "Delete OU" \
      4 "Rename OU" \
      3>&1 1>&2 2>&3)

    [ $? -ne 0 ] && break

    case $CHOICE in
        1) list_ous ;;
        2) create_ou ;;
        3) delete_ou ;;
        4) rename_ou ;;
    esac
done

clear
