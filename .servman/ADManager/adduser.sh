#!/bin/bash

TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
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

# === Prompt for OU Selection ===
select_ou() {
    local OUS
    mapfile -t OUS < <(samba-tool ou list -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *" 2>/dev/null | sort)

    local choices=()
    for ou in "${OUS[@]}"; do
        tag=$(echo "$ou" | sed 's/^OU=//;s/,.*//')
        desc="$ou"
        choices+=("$tag" "$desc")
    done

    choices+=("DEFAULT" "Use top-level/default container")

    SELECTED_OU=$(dialog --clear --title "Select OU for the user (or choose DEFAULT):" \
      --menu "Select OU for the user (or choose DEFAULT):" 20 70 10 \
      "${choices[@]}" \
      3>&1 1>&2 2>&3) || exit 1

    if [ "$SELECTED_OU" != "DEFAULT" ]; then
        for ou in "${OUS[@]}"; do
            short=$(echo "$ou" | sed 's/^OU=//;s/,.*//')
            if [[ "$short" == "$SELECTED_OU" ]]; then
                USER_OU="$ou"
                break
            fi
        done
    else
        USER_OU=""
    fi
}

# === Prompt for Group Membership ===
prompt_group_membership() {
    local GROUP_RAW
    GROUP_RAW=$(samba-tool group list -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *" 2>&1)
    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ]; then
        echo "$GROUP_RAW" > "$TMP_INPUT"
        dialog --title "Group List Error" --textbox "$TMP_INPUT" 20 60
        return
    fi

    mapfile -t ALL_GROUPS < <(echo "$GROUP_RAW" | tr '[:lower:]' '[:upper:]')

    if [ ${#ALL_GROUPS[@]} -eq 0 ]; then
        dialog --msgbox "No groups were returned by samba-tool." 7 50
        return
    fi

    local added_groups=()
    while true; do
        CHOICES=()
        for g in "${ALL_GROUPS[@]}"; do
            CHOICES+=("$g" "")
        done

        GROUP=$(dialog --clear --title "Add user to group (ESC to finish)" \
          --menu "Select a group to add the user to:" 20 60 10 \
          "${CHOICES[@]}" \
          3>&1 1>&2 2>&3)

        [ $? -ne 0 ] && break

        samba-tool group addmembers "$GROUP" "$LOGIN" -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *"
        added_groups+=("$GROUP")
    done

    if [ ${#added_groups[@]} -eq 0 ]; then
        dialog --msgbox "User was not added to any groups." 6 40
    else
        dialog --msgbox "User added to: ${added_groups[*]}" 8 50
    fi
}

# === Main ===
DC=$(detect_dc)
prompt_admin_password

FIRST=$(dialog --inputbox "Enter the user's first name:" 8 50 3>&1 1>&2 2>&3) || exit 1
LAST=$(dialog --inputbox "Enter the user's last name:" 8 50 3>&1 1>&2 2>&3) || exit 1
INITIALS=$(dialog --inputbox "Enter the user's initials:" 8 50 3>&1 1>&2 2>&3) || exit 1
LOGIN=$(dialog --inputbox "Enter the login name for the account:" 8 50 3>&1 1>&2 2>&3) || exit 1

select_ou

# Password prompt
PASS1=$(dialog --insecure --passwordbox "Enter a password for the new user:" 8 50 3>&1 1>&2 2>&3) || exit 1
PASS2=$(dialog --insecure --passwordbox "Confirm the password:" 8 50 3>&1 1>&2 2>&3) || exit 1

if [ "$PASS1" != "$PASS2" ]; then
    dialog --msgbox "Passwords do not match. Exiting." 6 40
    exit 1
fi

# Create user
if [ -n "$USER_OU" ]; then
    samba-tool user add "$LOGIN" "$PASS1" \
      --given-name="$FIRST" --surname="$LAST" --initials="$INITIALS" \
      --userou="$USER_OU" -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" \
      --option="password server = *"
else
    samba-tool user add "$LOGIN" "$PASS1" \
      --given-name="$FIRST" --surname="$LAST" --initials="$INITIALS" \
      -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" \
      --option="password server = *"
fi

prompt_group_membership

samba-tool user show "$LOGIN" -H ldap://"$DC" -U "Administrator%$ADMIN_PASS" --option="password server = *" | tee "$TMP_INPUT"
dialog --textbox "$TMP_INPUT" 20 70
