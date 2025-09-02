#===========MANAGE FAIL2BAN SSH JAIL=============
manage_fail2ban_ssh() {
  set -euo pipefail

  local DIALOG="${DIALOG_BIN:-dialog}"
  local LOG_FILE="/var/log/fail2ban-setup.log"
  local JAIL_DIR="/etc/fail2ban/jail.d"
  local SSHD_LOCAL_FILE="$JAIL_DIR/sshd.local"

  # --- helpers ---
  require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
  require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root"; exit 1; }; }
  ts() { date +"%Y-%m-%d %H:%M:%S"; }

  # parse values from [sshd] section; empty if not set
 # parse values from [sshd] section; empty if not set
get_sshd_value() {
  local key="$1"
  [[ -f "$SSHD_LOCAL_FILE" ]] || { echo ""; return; }
  awk -v IGNORECASE=1 -v key="$key" '
    BEGIN { section=0 }
    /^[[:space:]]*\[/ {
      section = ($0 ~ /^[[:space:]]*\[sshd\][[:space:]]*$/)
      next
    }
    section {
      line=$0
      sub(/;.*$/,"",line)       # strip ; comments
      sub(/#.*$/,"",line)       # strip # comments
      # match: key = value   (spaces optional)
      if (match(line, "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*(.*)$", m)) {
        val = m[1]
        gsub(/^[[:space:]]+|[[:space:]]+$/,"",val)
        print val
        exit
      }
    }
  ' "$SSHD_LOCAL_FILE"
}

  # Write new config atomically, preserving a backup
  write_sshd_config() {
    local maxretry="$1" findtime="$2" bantime="$3" inc="$4" factor="$5"
    mkdir -p "$JAIL_DIR"
    umask 022

    if [[ -f "$SSHD_LOCAL_FILE" ]]; then
      cp -a "$SSHD_LOCAL_FILE" "${SSHD_LOCAL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    local tmp
    tmp=$(mktemp "${SSHD_LOCAL_FILE}.XXXXXX")

    cat > "$tmp" <<EOL
# Managed by dialog SSH jail manager on $(ts)
# Previous version backed up next to this file as *.bak.YYYYMMDDHHMMSS
[sshd]
enabled = true
maxretry = ${maxretry}
findtime = ${findtime}
bantime = ${bantime}
bantime.increment = ${inc}
bantime.factor = ${factor}
EOL

    # keep SELinux contexts correct if enabled
    mv -f "$tmp" "$SSHD_LOCAL_FILE"
    if command -v sestatus >/dev/null 2>&1 && sestatus 2>/dev/null | grep -qi "enabled"; then
      restorecon -v "$SSHD_LOCAL_FILE" >> "$LOG_FILE" 2>&1 || true
    fi
    echo "[$(ts)] Wrote $SSHD_LOCAL_FILE (maxretry=$maxretry findtime=$findtime bantime=$bantime inc=$inc factor=$factor)" >> "$LOG_FILE"
  }

  # Validate inputs
  is_int()   { [[ "$1" =~ ^[0-9]+$ ]]; }
  is_float() { [[ "$1" =~ ^([0-9]+([.][0-9]+)?)$ ]]; }
  is_bool()  { [[ "${1,,}" =~ ^(true|false)$ ]]; }

  # Status helpers
  show_status_box() {
    local out
    out=$(fail2ban-client status sshd 2>&1 || true)
    "$DIALOG" --backtitle "Fail2Ban SSH Management" --title "SSHD Jail Status" --msgbox "$out" 20 90
  }
  show_recent_bans() {
    # Show last 200 lines mentioning "Ban " from log
    local logfile="/var/log/fail2ban.log"
    local tmp; tmp=$(mktemp)
    if [[ -f "$logfile" ]]; then
      grep -E "Ban |Unban " "$logfile" | tail -n 200 > "$tmp" || true
    else
      echo "No /var/log/fail2ban.log found." > "$tmp"
    fi
    "$DIALOG" --backtitle "Fail2Ban SSH Management" --title "Recent Bans (tail)" --textbox "$tmp" 22 100
    rm -f "$tmp"
  }
  unban_ip() {
    local ip
    ip=$($DIALOG --backtitle "Fail2Ban SSH Management" --title "Unban IP" --inputbox "Enter an IP to unban from the sshd jail:" 8 60 2>&1 >/dev/tty) || return 0
    if [[ -n "$ip" ]]; then
      if fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1; then
        "$DIALOG" --title "Unbanned" --msgbox "Unbanned: $ip" 6 40
      else
        "$DIALOG" --title "Error" --msgbox "Failed to unban: $ip\n\nCheck jail name and IP format." 8 60
      fi
    fi
  }

  # Ensure prerequisites
  require_root
  require_cmd "$DIALOG"
  require_cmd fail2ban-client
  require_cmd systemctl

  # Create default file if missing
  if [[ ! -f "$SSHD_LOCAL_FILE" ]]; then
    mkdir -p "$JAIL_DIR"
    cat > "$SSHD_LOCAL_FILE" <<'EOL'
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL
    echo "[$(ts)] Created default $SSHD_LOCAL_FILE" >> "$LOG_FILE"
  fi

  # Main menu loop
  while true; do
    # Load current values (with fallbacks)
    local MAXRETRY FINDTIME BANTIME INC FACTOR
    MAXRETRY="$(get_sshd_value maxretry)"; [[ -n "${MAXRETRY}" ]] || MAXRETRY=5
    FINDTIME="$(get_sshd_value findtime)"; [[ -n "${FINDTIME}" ]] || FINDTIME=300
    BANTIME="$(get_sshd_value bantime)"; [[ -n "${BANTIME}" ]] || BANTIME=3600
    INC="$(get_sshd_value 'bantime.increment')"; [[ -n "${INC}" ]] || INC=true
    FACTOR="$(get_sshd_value 'bantime.factor')"; [[ -n "${FACTOR}" ]] || FACTOR=2

    local choice
    choice=$($DIALOG --clear --backtitle "Fail2Ban SSH Management (Rocky Linux)" --title "SSHD Jail Manager" \
      --menu "Choose an action" 14 72 6 \
      1 "Edit SSHD jail timeouts/retries" \
      2 "Apply & reload Fail2Ban (sshd)" \
      3 "Show SSHD jail status" \
      4 "Show recent bans" \
      5 "Unban an IP" \
      0 "Exit" 2>&1 >/dev/tty) || break

    case "$choice" in
      1)
        # Edit form
        local form_out
        form_out=$($DIALOG --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
          --form "Enter numeric seconds for times. 'bantime.increment' is true/false." 16 72 6 \
          "maxretry:"           1 2  "$MAXRETRY"  1 22  10  0 \
          "findtime (s):"       2 2  "$FINDTIME"  2 22  10  0 \
          "bantime (s):"        3 2  "$BANTIME"   3 22  10  0 \
          "bantime.increment:"  4 2  "$INC"       4 22  10  0 \
          "bantime.factor:"     5 2  "$FACTOR"    5 22  10  0 \
          2>&1 >/dev/tty) || continue

        # Parse fields into an array
        IFS=$'\n' read -r MAXRETRY FINDTIME BANTIME INC FACTOR <<< "$form_out"

        # Normalize bool
        INC="${INC,,}"

        # Validate
        local err=""
        is_int "$MAXRETRY" || err+="\n- maxretry must be an integer"
        is_int "$FINDTIME" || err+="\n- findtime must be an integer (seconds)"
        is_int "$BANTIME"  || err+="\n- bantime must be an integer (seconds)"
        is_bool "$INC"     || err+="\n- bantime.increment must be true or false"
        is_float "$FACTOR" || err+="\n- bantime.factor must be a number (e.g., 2 or 1.5)"

        if [[ -n "$err" ]]; then
          $DIALOG --title "Validation Errors" --msgbox "Please fix:\n$err" 12 70
          continue
        fi

        # Confirm and write
        $DIALOG --title "Confirm Changes" --yesno "Apply these settings to $SSHD_LOCAL_FILE?\n
maxretry:          $MAXRETRY
findtime (s):      $FINDTIME
bantime (s):       $BANTIME
bantime.increment: $INC
bantime.factor:    $FACTOR" 14 60
        if [[ $? -eq 0 ]]; then
          write_sshd_config "$MAXRETRY" "$FINDTIME" "$BANTIME" "$INC" "$FACTOR"
          $DIALOG --title "Saved" --msgbox "Configuration saved.\nYou can reload Fail2Ban next." 7 50
        fi
        ;;
      2)
        # Reload Fail2Ban
        if systemctl is-active --quiet fail2ban; then
          if fail2ban-client reload >/dev/null 2>&1; then
            $DIALOG --title "Reloaded" --msgbox "Fail2Ban reloaded successfully." 6 40
          else
            $DIALOG --title "Error" --msgbox "Reload failed.\nTrying to restart service instead..." 7 60
            if systemctl restart fail2ban; then
              $DIALOG --title "Restarted" --msgbox "Fail2Ban restarted successfully." 6 45
            else
              $DIALOG --title "Error" --msgbox "Fail2Ban restart failed. Check logs:\njournalctl -u fail2ban" 8 70
            fi
          fi
        else
          $DIALOG --title "Service Inactive" --yesno "Fail2Ban is not active.\nStart it now?" 7 50
          if [[ $? -eq 0 ]]; then
            if systemctl start fail2ban; then
              $DIALOG --title "Started" --msgbox "Fail2Ban started." 6 30
            else
              $DIALOG --title "Error" --msgbox "Failed to start Fail2Ban.\nSee: journalctl -u fail2ban" 8 70
            fi
          fi
        fi
        ;;
      3) show_status_box ;;
      4) show_recent_bans ;;
      5) unban_ip ;;
      0) break ;;
    esac
  done
}
manage_fail2ban_ssh
