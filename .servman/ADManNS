#!/bin/bash
set -euo pipefail

# === Ensure expect is installed ===
if ! command -v expect &>/dev/null; then
    echo "[INFO] Installing 'expect' package..."
    dnf -y install expect >/dev/null 2>&1 || {
        echo "[ERROR] Failed to install 'expect'. Please install it manually."; exit 1;
    }
fi

# === Expect helper ===
run_samba_tool() {
    local full_cmd="$*"
    expect <<EOF
        log_user 0
        spawn bash -c "$full_cmd"
        expect {
            "Password for*" {
                send "$ADMIN_PASS\r"
                exp_continue
            }
            eof {
                catch wait result
                exit [lindex \$result 3]
            }
        }
EOF
}

# === Temp + Colors ===
TMP_OUT=$(mktemp)
TEXTRESET=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)

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

# === Prompt for Password ===
prompt_admin_password() {
    while true; do
        ADMIN_PASS=$(dialog --insecure --passwordbox "Enter the Samba Administrator password:" 8 50 3>&1 1>&2 2>&3) || exit 1

        # Validate password with a test command
        if samba-tool dns zonelist "$DC" -U Administrator%"$ADMIN_PASS" >/dev/null 2>&1; then
            break
        else
            dialog --msgbox "Authentication failed. Please try again." 7 50
        fi
    done
}

# === Zone helpers ===
get_dns_zone_names() {
    samba-tool dns zonelist "$DC" -U Administrator%"$ADMIN_PASS" 2>/dev/null | awk '/pszZoneName/ {print $3}' | sort
}

view_all_zones() {
    samba-tool dns zonelist "$DC" -U Administrator%"$ADMIN_PASS" > "$TMP_OUT" 2>&1
    if [[ -s "$TMP_OUT" ]]; then
        dialog --textbox "$TMP_OUT" 25 80
    else
        dialog --msgbox "Failed to retrieve zones." 8 40
    fi
}

select_zone_menu() {
    ZONES=($(get_dns_zone_names))
    MENU_ITEMS=()
    for Z in "${ZONES[@]}"; do
        MENU_ITEMS+=("$Z" "")
    done
    dialog --clear --backtitle "Samba DNS Admin" --title "Select DNS Zone" \
        --menu "Choose a zone to manage:" 20 50 10 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
}

# === Validate Forward Records ===

validate_forward_records() {
    local fqdn ip ptr
    local result_output="=== Forward Validation Results ===\n"

    # Get list of forward zones
    mapfile -t FORWARD_ZONES < <(samba-tool dns zonelist "$DC" -U "Administrator%$ADMIN_PASS" 2>/dev/null | awk '/pszZoneName/ {print $3}' | grep -v in-addr.arpa)

    for zone in "${FORWARD_ZONES[@]}"; do
        # Query all records and pair Name + A manually
        mapfile -t ZONE_LINES < <(samba-tool dns query "$DC" "$zone" @ ALL -U "Administrator%$ADMIN_PASS" 2>/dev/null)

        for ((i=0; i<${#ZONE_LINES[@]}; i++)); do
            if [[ ${ZONE_LINES[i]} =~ ^[[:space:]]*Name=([a-zA-Z0-9._-]+), ]]; then
                fqdn_host="${BASH_REMATCH[1]}"
                if (( i + 1 < ${#ZONE_LINES[@]} )); then
                    next_line="${ZONE_LINES[i+1]}"
                    if [[ $next_line =~ A:[[:space:]]*([0-9.]+) ]]; then
                        ip="${BASH_REMATCH[1]}"
                        fqdn="$fqdn_host.$zone"
                        ptr_output=$(dig +short -x "$ip")

                        if [[ -z "$ptr_output" ]]; then
                            result_output+="[MISSING] A $fqdn -> $ip has no PTR record\n"

                            dialog --yesno "PTR record missing for A record: $fqdn -> $ip.\n\nDo you want to add PTR record for $ip -> $fqdn?" 10 60
                            if [[ $? -eq 0 ]]; then
                                IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
                                rev_zone="$o3.$o2.$o1.in-addr.arpa"
                                samba-tool dns add "$DC" "$rev_zone" "$o4" PTR "$fqdn" -U "Administrator%$ADMIN_PASS" 2>/dev/null && \
                                    result_output+="[ADDED] PTR record for $ip -> $fqdn\n"
                            fi
                        else
                            result_output+="[OK] A $fqdn -> $ip resolves to PTR $ptr_output\n"
                        fi
                    fi
                fi
            fi
        done
    done

    dialog --title "Forward Validation Results" --msgbox "$result_output" 20 80
}














# === Validate PTR Records ===

validate_ptr_records() {
    local reverse_zone_output
    local ptr_name
    local fqdn
    local ip
    local base_ip
    local result_output="=== PTR Validation Results ===\n"

    # Get list of reverse zones
    mapfile -t REVERSE_ZONES < <(samba-tool dns zonelist "$DC" -U 'Administrator%'"$ADMIN_PASS" 2>/dev/null | awk '/pszZoneName/ {print $3}' | grep in-addr.arpa)

    for zone in "${REVERSE_ZONES[@]}"; do
        # Extract base from reverse zone (e.g. 210.168.192.in-addr.arpa -> 192.168.210)
        IFS='.' read -r o3 o2 o1 _ <<< "$zone"
        base_ip="$o1.$o2.$o3"

        # Query all records and pair Name + PTR manually
        mapfile -t ZONE_LINES < <(samba-tool dns query "$DC" "$zone" @ ALL -U 'Administrator%'"$ADMIN_PASS" 2>/dev/null)

        for ((i=0; i<${#ZONE_LINES[@]}; i++)); do
            if [[ ${ZONE_LINES[i]} =~ ^[[:space:]]*Name=([0-9]+), ]]; then
                ptr_name="${BASH_REMATCH[1]}"
                next_line="${ZONE_LINES[i+1]}"
                if [[ $next_line =~ PTR:[[:space:]]*([a-zA-Z0-9._-]+) ]]; then
                    fqdn="${BASH_REMATCH[1]}"
                    ip="$base_ip.$ptr_name"
                    dig_output=$(dig +short -x "$ip")

                    if [[ -z "$dig_output" ]]; then
                        result_output+="[MISSING] PTR $ip expected to resolve to $fqdn, but no result\n"
                    else
                        result_output+="[OK] PTR $ip resolves to $dig_output\n"
                    fi
                fi
            fi
        done
    done

    dialog --title "PTR Validation Results" --msgbox "$result_output" 20 80
}



# === Delete DNS Rcords ===

delete_dns_record() {
    local ZONE_NAME="$1"
    local TMP_OUT=$(mktemp)

    while true; do
        ALL_RECORDS=$(mktemp)
        for TYPE in A AAAA PTR CNAME TXT SRV NS MX; do
            samba-tool dns query "$DC" "$ZONE_NAME" @ "$TYPE" -U Administrator%"$ADMIN_PASS" 2>/dev/null |
            awk -v type="$TYPE" '
                /^\s*Name=/ {
                    match($0, /Name=([^,]+)/, m)
                    name = m[1]
                    next
                }
                /^[[:space:]]*A:/ {
                    ip = $2
                    gsub(/[(),]/, "", ip)
                    printf "A|%s|%s\n", name, ip
                    next
                }
                /^[[:space:]]*PTR:/ {
                    ptr = $2
                    gsub(/[(),]/, "", ptr)
                    printf "PTR|%s|%s\n", name, ptr
                    next
                }
                /^[[:space:]]*CNAME:/ {
                    cname = $2
                    gsub(/[(),]/, "", cname)
                    printf "CNAME|%s|%s\n", name, cname
                    next
                }
                /^[[:space:]]*MX:/ {
                    pri = $2
                    target = $3
                    gsub(/[(),]/, "", target)
                    printf "MX|%s|%s %s\n", name, pri, target
                    next
                }
                /^[[:space:]]*NS:/ {
                    ns = $2
                    gsub(/[(),]/, "", ns)
                    printf "NS|%s|%s\n", name, ns
                    next
                }
                /^[[:space:]]*TXT:/ {
                    txt = substr($0, index($0, $2))
                    gsub(/[()"]/, "", txt)
                    printf "TXT|%s|%s\n", name, txt
                    next
                }
                /^[[:space:]]*SRV:/ {
                    pri = $2
                    weight = $3
                    port = $4
                    target = $5
                    gsub(/[(),]/, "", target)
                    printf "SRV|%s|%s %s %s %s\n", name, pri, weight, port, target
                    next
                }'
        done > "$ALL_RECORDS"

        if [[ ! -s "$ALL_RECORDS" ]]; then
            dialog --msgbox "No records found in zone $ZONE_NAME." 7 50
            return
        fi

        FORMATTED=$(mktemp)
        INDEXED=$(mktemp)
        while IFS="|" read -r TYPE NAME VALUE; do
            RECORD_NAME=$(echo "$NAME" | sed 's/[[:space:]]*$//')
            DISPLAY="[$TYPE] $RECORD_NAME -> $VALUE"
            echo "$DISPLAY" >> "$FORMATTED"
            echo "$TYPE|$VALUE|$RECORD_NAME|$DISPLAY" >> "$INDEXED"
        done < "$ALL_RECORDS"

        mapfile -t MENU_ITEMS < "$FORMATTED"
        CHOICES=()
        for i in "${MENU_ITEMS[@]}"; do
            CHOICES+=("$i" "")
        done

        SELECTED_ENTRY=$(dialog --backtitle "Delete Record from $ZONE_NAME" \
            --title "Select Record to Delete" \
            --menu "Choose a record to delete:" 20 90 15 \
            "${CHOICES[@]}" \
            3>&1 1>&2 2>&3) || break

        RECORD_RAW=$(grep -F "$SELECTED_ENTRY" "$INDEXED")
        RECORD_TYPE=$(echo "$RECORD_RAW" | cut -d'|' -f1)
        RECORD_VALUE=$(echo "$RECORD_RAW" | cut -d'|' -f2)
        RECORD_NAME=$(echo "$RECORD_RAW" | cut -d'|' -f3)

        dialog --yesno "Delete $RECORD_TYPE record for $RECORD_NAME: $RECORD_VALUE?" 8 60 || continue

        setsid bash -c "samba-tool dns delete \"$DC\" \"$ZONE_NAME\" \"$RECORD_NAME\" \"$RECORD_TYPE\" \"$RECORD_VALUE\" -U Administrator%\"$ADMIN_PASS\"" > "$TMP_OUT" 2>&1 < /dev/null

        # HACK: Redraw TTY screen after samba-tool kills it
        dialog --infobox "Refreshing interface..." 3 40
        sleep 0.7

        if grep -q "Record deleted successfully" "$TMP_OUT"; then
            dialog --msgbox "$RECORD_TYPE record successfully deleted from $ZONE_NAME." 7 60
        else
            dialog --textbox "$TMP_OUT" 20 70
        fi

        rm -f "$ALL_RECORDS" "$FORMATTED" "$INDEXED"
    done

    rm -f "$TMP_OUT"
}

# === Add DNS records ===
add_dns_record() {
    local ZONE_NAME="$1"
    local TMP_OUT=$(mktemp)

    if [[ "$ZONE_NAME" == *.in-addr.arpa || "$ZONE_NAME" == *.ip6.arpa ]]; then
        IP_ADDR=$(dialog --inputbox "Enter the full IP address to create PTR for:" 8 60 3>&1 1>&2 2>&3) || return
        VALUE=$(dialog --inputbox "Enter the FQDN for this PTR record (e.g., host.example.com):" 8 60 3>&1 1>&2 2>&3) || return

        PTR_NAME=$(echo "$IP_ADDR" | awk -F. '{print $4}')

        samba-tool dns add "$DC" "$ZONE_NAME" "$PTR_NAME" PTR "$VALUE." -U Administrator%"$ADMIN_PASS" > "$TMP_OUT" 2>&1 < /dev/null

        if grep -q "Record added successfully" "$TMP_OUT"; then
            dialog --msgbox "PTR record added successfully to $ZONE_NAME." 7 50
        else
            dialog --textbox "$TMP_OUT" 20 70
        fi
    else
        TYPE=$(dialog --radiolist "Select DNS record type:" 15 60 5 \
            "A"     "IPv4 address (A)" ON \
            "AAAA"  "IPv6 address (AAAA)" OFF \
            "CNAME" "Canonical name (CNAME)" OFF \
            "MX"    "Mail exchanger (MX)" OFF \
            "TXT"   "Text record (TXT)" OFF \
            3>&1 1>&2 2>&3) || return

        NAME=$(dialog --inputbox "Enter the record name (relative or FQDN):" 8 60 3>&1 1>&2 2>&3) || return
        VALUE=$(dialog --inputbox "Enter the value for the $TYPE record:" 8 60 3>&1 1>&2 2>&3) || return

        samba-tool dns add "$DC" "$ZONE_NAME" "$NAME" "$TYPE" "$VALUE" -U Administrator%"$ADMIN_PASS" > "$TMP_OUT" 2>&1 < /dev/null

        if grep -q "Record added successfully" "$TMP_OUT"; then
            dialog --msgbox "$TYPE record added successfully to $ZONE_NAME." 7 50
        else
            dialog --textbox "$TMP_OUT" 20 70
        fi
    fi

    rm -f "$TMP_OUT"
}



# === Create New Zones ===
create_zone() {
    ZONE_TYPE=$(dialog --radiolist "Select zone type to create:" 12 60 4 \
        "forward" "Forward DNS zone (e.g. example.com)" ON \
        "reverse" "Reverse DNS zone (e.g. 192.168.240)" OFF \
        3>&1 1>&2 2>&3) || return

    if [[ "$ZONE_TYPE" == "forward" ]]; then
        ZONE_NAME=$(dialog --inputbox "Enter the forward zone name (e.g. example.com):" 8 50 3>&1 1>&2 2>&3) || return
    else
        SUBNET=$(dialog --inputbox "Enter the subnet in standard format (e.g. 192.168.240):" 8 60 3>&1 1>&2 2>&3) || return
        ZONE_NAME=$(echo "$SUBNET" | awk -F. '{print $3"."$2"."$1".in-addr.arpa"}')
    fi

    if get_dns_zone_names | grep -qx "$ZONE_NAME"; then
        dialog --msgbox "Zone '$ZONE_NAME' already exists." 7 50
        return
    fi

    samba-tool dns zonecreate "$DC" "$ZONE_NAME" -U Administrator%"$ADMIN_PASS" 2>&1 | tee "$TMP_OUT"
    ZONE_CREATE_EXIT=${PIPESTATUS[0]}

    if [[ $ZONE_CREATE_EXIT -eq 0 ]]; then
        FQDN=$(hostname -f)
        sleep 1

        samba-tool dns add "$DC" "$ZONE_NAME" @ NS "${FQDN}." -U Administrator%"$ADMIN_PASS" 2>&1 | tee -a "$TMP_OUT"
        sleep 1

        EXISTING_NS=$(samba-tool dns query "$DC" "$ZONE_NAME" @ NS -U Administrator%"$ADMIN_PASS" 2>/dev/null | awk '/NS:/ {print $2}' | sed 's/[()]//g')
        for RECORD in $EXISTING_NS; do
            if [[ "$RECORD" != "${FQDN}." ]]; then
                samba-tool dns delete "$DC" "$ZONE_NAME" @ NS "$RECORD" -U Administrator%"$ADMIN_PASS" 2>&1 | tee -a "$TMP_OUT"
            fi
        done

        VERIFY_NS=$(samba-tool dns query "$DC" "$ZONE_NAME" @ NS -U Administrator%"$ADMIN_PASS" 2>/dev/null | grep -F "NS: ${FQDN}.")
        if [[ -n "$VERIFY_NS" ]]; then
            dialog --msgbox "Zone '$ZONE_NAME' created successfully with NS ${FQDN}." 7 60
        else
            dialog --msgbox "Zone created, but NS ${FQDN}. not confirmed. Check manually." 8 60
        fi
    else
        dialog --textbox "$TMP_OUT" 20 70
    fi
}

get_dns_zone_names() {
    samba-tool dns zonelist "$DC" -U Administrator%"$ADMIN_PASS" 2>/dev/null | awk '/pszZoneName/ {print $3}' | sort
}

view_all_zones() {
    samba-tool dns zonelist "$DC" -U Administrator%"$ADMIN_PASS" > "$TMP_OUT" 2>&1
    if [[ -s "$TMP_OUT" ]]; then
        dialog --textbox "$TMP_OUT" 25 80
    else
        dialog --msgbox "Failed to retrieve zones." 8 40
    fi
}



# === Delete Pre-Existing Zones ===
delete_zone() {
    ZONES=($(get_dns_zone_names))
    MENU_ITEMS=()
    for Z in "${ZONES[@]}"; do
        MENU_ITEMS+=("$Z" "")
    done

    SELECTED=$(dialog --clear --backtitle "Delete DNS Zone" --title "Select a zone to delete" \
        --menu "Choose a zone to delete:" 20 50 10 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3) || return

    dialog --yesno "Are you sure you want to delete zone '$SELECTED'?\nThis action cannot be undone." 8 60 || return

    samba-tool dns zonedelete "$DC" "$SELECTED" -U Administrator%"$ADMIN_PASS" > "$TMP_OUT" 2>&1
    if grep -q "successfully deleted" "$TMP_OUT"; then
        dialog --msgbox "Zone '$SELECTED' was deleted successfully." 7 50
    else
        dialog --textbox "$TMP_OUT" 20 70
    fi
}


# === Record Query ===
query_record() {
    local zone="$1"
    NAME=$(dialog --inputbox "Please enter an FQDN (i.e. host.domain.com) or IP  to search:
    (Leave blank to list all zone records)" 10 70 3>&1 1>&2 2>&3) || return

    if [[ -z "$NAME" ]]; then
        {
            for TYPE in A AAAA PTR CNAME TXT SRV NS MX; do
                echo "=== $TYPE Records ==="
                samba-tool dns query "$DC" "$zone" @ "$TYPE" -U Administrator%"$ADMIN_PASS" 2>/dev/null |
                awk '/Records=[1-9]/ {print; show=1; next} /Records=0/ {show=0; next} show==1 {print}'
                echo ""
            done
        } > "$TMP_OUT"
    else
        {
            echo "=== dig lookup ==="
            if [[ "$NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "Input detected as IP address."
                echo "PTR record for $NAME: $(dig +short -x "$NAME" || echo '[Not found]')"
                FWD=$(dig +short -x "$NAME")
                [[ -n "$FWD" ]] && echo "A record for $FWD: $(dig +short "$FWD")"
            else
                echo "Input detected as hostname."
                IP=$(dig +short "$NAME")
                echo "A record for $NAME: ${IP:-[Not found]}"
                [[ -n "$IP" ]] && echo "PTR record for $IP: $(dig +short -x "$IP" || echo '[Not found]')"
            fi
            echo ""

            echo "=== samba-tool search for matches ==="
            for TYPE in A AAAA PTR CNAME TXT SRV NS MX; do
                samba-tool dns query "$DC" "$zone" @ "$TYPE" -U Administrator%"$ADMIN_PASS" 2>/dev/null |
                awk -v name="$NAME" '/Records=[1-9]/ {rec=$0; next} /Records=0/ {next} tolower($0) ~ tolower(name) {print rec; print; print ""}'
            done
        } > "$TMP_OUT"
    fi

    if [[ -s "$TMP_OUT" ]]; then
        dialog --textbox "$TMP_OUT" 25 80
    else
        dialog --msgbox "No records found matching input or query failed." 8 50
    fi
}

# === Record Management Stubs ===
add_record() {
    local zone="$1"
    dialog --msgbox "Add Record coming soon" 6 40
}

delete_record() {
    local zone="$1"
    dialog --msgbox "Delete Record coming soon" 6 40
}

zone_action_menu() {
    local ZONE_NAME="$1"
    while true; do
        ACTION=$(dialog --clear --backtitle "Manage Zone: $ZONE_NAME" --title "Choose an action:" \
            --menu "Choose an action:" 12 50 6 \
            1 "List DNS Records" \
            2 "Add DNS Record" \
            3 "Delete DNS Record" \
            4 "Back to Main Menu" \
            3>&1 1>&2 2>&3) || return

        case "$ACTION" in
            1) query_record "$ZONE_NAME" ;;
            2) add_dns_record "$ZONE_NAME" ;;
            3) delete_dns_record "$ZONE_NAME" ;;
            4) break ;;
        esac
    done
}

main_menu() {
    while true; do
        CHOICE=$(dialog --clear --backtitle "Samba DNS Admin ($DC)" \
            --title "Main Menu" \
            --menu "Choose an action:" 15 60 7 \
            1 "View All Zones" \
            2 "Manage Zones" \
            3 "Create DNS Zone" \
            4 "Delete DNS Zone" \
            5 "Validate Zone Records" \
            6 "Exit" \
            3>&1 1>&2 2>&3)

        case $CHOICE in
            1) view_all_zones ;;
            2)
                ZONE=$(select_zone_menu) || continue
                zone_action_menu "$ZONE"
                ;;
            3) create_zone ;;
            4) delete_zone ;;
            5) validate_zones_menu ;;
            6) clear; break ;;
        esac
    done
}

validate_zones_menu() {
    while true; do
        CHOICE=$(dialog --clear --backtitle "Validate DNS Records" \
            --title "Validation Menu" \
            --menu "Select a validation task:" 15 60 5 \
            1 "Validate PTR Records" \
            2 "Validate Forward Records" \
            3 "Back to Main Menu" \
            3>&1 1>&2 2>&3)

        case $CHOICE in
            1) validate_ptr_records ;;
            2) validate_forward_records ;;
            3) break ;;
        esac
    done
}

# === Entry ===
DC=$(detect_dc)
prompt_admin_password
main_menu
rm -f "$TMP_OUT"
