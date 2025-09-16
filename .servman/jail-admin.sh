#===========MANAGE FAIL2BAN SSH JAIL=============
manage_fail2ban_ssh() {
  set -euo pipefail

  local DIALOG="${DIALOG_BIN:-dialog}"
  local LOG_FILE="/var/log/fail2ban-setup.log"
  local JAIL_DIR="/etc/fail2ban/jail.d"
  local SSHD_LOCAL_FILE="$JAIL_DIR/sshd.local"
  local JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
  local ORIGINAL_FILE="/etc/fail2ban/jail.conf"

  # --- helpers ---
  require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
  require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root"; exit 1; }; }
  ts() { date +"%Y-%m-%d %H:%M:%S"; }

  sanitize() {
    local s="$1"
    s="${s//$'\r'/}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
  }

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
        sub(/;.*$/,"",line)
        sub(/#.*$/,"",line)
        if (match(line, "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*(.*)$", m)) {
          val = m[1]
          gsub(/^[[:space:]]+|[[:space:]]+$/,"",val)
          print val
          exit
        }
      }
    ' "$SSHD_LOCAL_FILE"
  }

  parse_timespec() {
    local in="$1"
    shopt -s nocasematch
    if [[ "$in" =~ ^([0-9]+)([smhdw])?$ ]]; then
      local n="${BASH_REMATCH[1]}"
      local u="${BASH_REMATCH[2]:-s}"
      case "$u" in
        s) echo $((n)) ;;
        m) echo $((n*60)) ;;
        h) echo $((n*3600)) ;;
        d) echo $((n*86400)) ;;
        w) echo $((n*604800)) ;;
      esac
      return 0
    fi
    return 1
  }
  is_timespec() { parse_timespec "$1" >/dev/null; }

  normalize_bool() {
    local b="${1,,}"
    case "$b" in
      true|1|yes|on)   echo "true";  return 0 ;;
      false|0|no|off)  echo "false"; return 0 ;;
      *) return 1 ;;
    esac
  }

  write_sshd_config() {
    local maxretry="$1" findtime_s="$2" bantime_s="$3" inc="$4" factor="$5"
    mkdir -p "$JAIL_DIR"
    umask 022

    if [[ -f "$SSHD_LOCAL_FILE" ]]; then
      cp -a "$SSHD_LOCAL_FILE" "${SSHD_LOCAL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    local tmp; tmp=$(mktemp "${SSHD_LOCAL_FILE}.XXXXXX")
    cat > "$tmp" <<EOL
# Managed by dialog SSH jail manager on $(ts)
# Previous version backed up next to this file as *.bak.YYYYMMDDHHMMSS
[sshd]
enabled = true
maxretry = ${maxretry}
findtime = ${findtime_s}
bantime = ${bantime_s}
bantime.increment = ${inc}
bantime.factor = ${factor}
EOL

    mv -f "$tmp" "$SSHD_LOCAL_FILE"
    if command -v sestatus >/dev/null 2>&1 && sestatus 2>/dev/null | grep -qi "enabled"; then
      restorecon -v "$SSHD_LOCAL_FILE" >> "$LOG_FILE" 2>&1 || true
    fi
    echo "[$(ts)] Wrote $SSHD_LOCAL_FILE (maxretry=$maxretry findtime=${findtime_s}s bantime=${bantime_s}s inc=$inc factor=$factor)" >> "$LOG_FILE"
  }

  manual_edit_sshd_local() {
    mkdir -p "$JAIL_DIR"
    if [[ ! -f "$SSHD_LOCAL_FILE" ]]; then
      cat > "$SSHD_LOCAL_FILE" <<'EOL'
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL
    fi

    local tmp in out rc
    tmp=$(mktemp)
    cp -a "$SSHD_LOCAL_FILE" "$tmp"

    if $DIALOG --help 2>&1 | grep -q -- '--output-fd'; then
      $DIALOG --output-fd 3 \
        --backtitle "Fail2Ban SSH Management" \
        --title "Manual Edit: $SSHD_LOCAL_FILE" \
        --editbox "$tmp" 24 100 3>"$tmp.edited"
      rc=$?
    elif $DIALOG --help 2>&1 | grep -q -- '--stdout'; then
      $DIALOG --stdout \
        --backtitle "Fail2Ban SSH Management" \
        --title "Manual Edit: $SSHD_LOCAL_FILE" \
        --editbox "$tmp" 24 100 >"$tmp.edited"
      rc=$?
    else
      $DIALOG \
        --backtitle "Fail2Ban SSH Management" \
        --title "Manual Edit: $SSHD_LOCAL_FILE" \
        --editbox "$tmp" 24 100 2>"$tmp.edited" >/dev/tty
      rc=$?
    fi

    if [[ $rc -ne 0 ]]; then
      rm -f "$tmp" "$tmp.edited"
      return 0
    fi

    cp -a "$SSHD_LOCAL_FILE" "${SSHD_LOCAL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    tr -d '\r' < "$tmp.edited" > "$tmp.clean"
    mv -f "$tmp.clean" "$SSHD_LOCAL_FILE"
    rm -f "$tmp" "$tmp.edited"

    if command -v sestatus >/dev/null 2>&1 && sestatus 2>/dev/null | grep -qi "enabled"; then
      restorecon -v "$SSHD_LOCAL_FILE" >> "$LOG_FILE" 2>&1 || true
    fi

    echo "[$(ts)] Manually edited $SSHD_LOCAL_FILE via dialog editor" >> "$LOG_FILE"

    $DIALOG --title "Saved" --yesno "Saved changes to:\n$SSHD_LOCAL_FILE\n\nReload Fail2Ban now?" 10 60
    if [[ $? -eq 0 ]]; then
      if systemctl is-active --quiet fail2ban; then
        if ! fail2ban-client reload >/dev/null 2>&1; then
          systemctl restart fail2ban >/dev/null 2>&1 || true
        fi
        $DIALOG --title "Done" --msgbox "Fail2Ban reloaded (or restarted)." 6 50
      else
        $DIALOG --title "Service Inactive" --msgbox "Fail2Ban service is not active." 7 50
      fi
    fi
  }

  is_int()   { [[ "$1" =~ ^[0-9]+$ ]]; }
  is_float() { [[ "$1" =~ ^([0-9]+([.][0-9]+)?)$ ]]; }

  show_status_box() {
    local out; out=$(fail2ban-client status sshd 2>&1 || true)
    "$DIALOG" --backtitle "Fail2Ban SSH Management" --title "SSHD Jail Status" --msgbox "$out" 20 90
  }
  show_recent_bans() {
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

  # ───────────────────── Ensure Fail2Ban is installed & configured ─────────────────────
  ensure_fail2ban_ready() {
    # If not installed, offer to install (with gauge)
    if ! command -v fail2ban-client >/dev/null 2>&1; then
      $DIALOG --backtitle "Fail2Ban SSH Management" --title "Fail2Ban Not Found" \
        --yesno "Fail2Ban is not installed. Install it now?" 8 60 || return 1

      # Install with progress
      $DIALOG --backtitle "Configure Fail2ban for SSH" --title "Installing Fail2Ban" \
        --gauge "Installing fail2ban..." 10 60 0 < <(
          set +e
          echo 10; echo "XXX"; echo "Refreshing metadata..."; echo "XXX"
          dnf -y makecache --refresh >/dev/null 2>&1
          echo 40; echo "XXX"; echo "Installing fail2ban..."; echo "XXX"
          dnf -y install fail2ban >/dev/null 2>&1
          echo 70; echo "XXX"; echo "Enabling service..."; echo "XXX"
          systemctl enable fail2ban >/dev/null 2>&1
          echo 100; echo "XXX"; echo "Done."; echo "XXX"
          set -e
        )
    fi

    # If not configured (no jail.local or no sshd.local), configure it now
    if [[ ! -f "$JAIL_LOCAL_FILE" || ! -f "$SSHD_LOCAL_FILE" ]]; then
      # Show a single gauge that does: copy jail.conf → jail.local, write sshd.local, start service, SELinux recovery
      {
        echo "10"
        echo "# Copying jail.conf to jail.local..."
        if [[ -f "$ORIGINAL_FILE" ]]; then
          cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1 || true
        else
          # seed a minimal jail.local if distro doesn't ship jail.conf
          cat > "$JAIL_LOCAL_FILE" <<'MINI'
[DEFAULT]
banaction = firewallcmd-ipset
backend = systemd

[sshd]
enabled = true
MINI
        fi

        echo "30"
        echo "# Writing SSHD jail configuration..."
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

        echo "60"
        echo "# Enabling and starting Fail2Ban..."
        systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || true
        systemctl start fail2ban >> "$LOG_FILE" 2>&1 || true
        sleep 1

        echo "75"
        echo "# Checking Fail2Ban status..."
        if ! systemctl is-active --quiet fail2ban; then
          echo "Fail2Ban failed to start. Attempting SELinux recovery..." >> "$LOG_FILE"
          if command -v sestatus >/dev/null 2>&1 && sestatus 2>/dev/null | grep -qi "enabled"; then
            restorecon -v "$JAIL_LOCAL_FILE" "$SSHD_LOCAL_FILE" >> "$LOG_FILE" 2>&1 || true
            denials=$(ausearch -m avc -ts recent 2>/dev/null | grep -c "fail2ban-server" || true)
            if (( denials > 0 )) && command -v audit2allow >/dev/null 2>&1; then
              ausearch -c 'fail2ban-server' --raw 2>/dev/null | audit2allow -M my-fail2banserver >> "$LOG_FILE" 2>&1 || true
              semodule -X 300 -i my-fail2banserver.pp >> "$LOG_FILE" 2>&1 || true
              echo "Custom SELinux policy applied." >> "$LOG_FILE"
            fi
          fi
          systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || true
        fi

        echo "90"
        echo "# Verifying SSHD jail status..."
        local sshd_status
        sshd_status=$(fail2ban-client status sshd 2>&1 || true)
        echo "$sshd_status" >> "$LOG_FILE"

        echo "100"
      } | $DIALOG --backtitle "Configure Fail2ban for SSH" --title "Fail2Ban Setup" \
           --gauge "Installing and configuring Fail2Ban..." 10 60 0

      $DIALOG --backtitle "Configure Fail2ban for SSH" --title "Setup Complete" \
              --infobox "Fail2Ban is configured and started." 6 60
      sleep 1
    fi
  }

  # Ensure prerequisites / install+configure if needed
  require_root
  command -v "$DIALOG" >/dev/null 2>&1 || { echo "dialog not found. dnf -y install dialog" >&2; exit 1; }
  ensure_fail2ban_ready || return 1

  # Re-assert the tools now that we installed them
  require_cmd fail2ban-client
  require_cmd systemctl

  # Create default sshd.local if missing (defensive)
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

  # =========================== Main menu loop (unchanged) ===========================
  while true; do
    local MAXRETRY FINDTIME BANTIME INC FACTOR
    MAXRETRY="$(get_sshd_value maxretry)"; [[ -n "${MAXRETRY}" ]] || MAXRETRY=5
    FINDTIME="$(get_sshd_value findtime)"; [[ -n "${FINDTIME}" ]] || FINDTIME=300
    BANTIME="$(get_sshd_value bantime)"; [[ -n "${BANTIME}" ]] || BANTIME=3600
    INC="$(get_sshd_value 'bantime.increment')"; [[ -n "${INC}" ]] || INC=true
    FACTOR="$(get_sshd_value 'bantime.factor')"; [[ -n "${FACTOR}" ]] || FACTOR=2

    local choice
    choice=$($DIALOG --clear --backtitle "Fail2Ban SSH Management (Rocky Linux)" --title "SSHD Jail Manager" \
      --menu "Choose an action" 16 78 7 \
      1 "Edit SSHD jail timeouts/retries (guided form)" \
      2 "Apply & reload Fail2Ban (sshd)" \
      3 "Show SSHD jail status" \
      4 "Show recent bans" \
      5 "Unban an IP" \
      6 "Manual edit sshd.local" \
      0 "Exit" 2>&1 >/dev/tty) || break

    case "$choice" in
      1)
        local tmp form_out rc
        tmp=$(mktemp)

        if $DIALOG --help 2>&1 | grep -q -- '--output-fd'; then
          $DIALOG --output-fd 3 \
            --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
            --form "Times accept: N, Nm, Nh, Nd, Nw (e.g., 300, 10m, 2h). Booleans accept: true/false/yes/no/on/off/1/0." 18 74 6 \
            "maxretry:"           1 2  "$MAXRETRY"  1 22  12  0 \
            "findtime:"           2 2  "$FINDTIME"  2 22  12  0 \
            "bantime:"            3 2  "$BANTIME"   3 22  12  0 \
            "bantime.increment:"  4 2  "$INC"       4 22  12  0 \
            "bantime.factor:"     5 2  "$FACTOR"    5 22  12  0 \
            3>"$tmp"
          rc=$?
        elif $DIALOG --help 2>&1 | grep -q -- '--stdout'; then
          $DIALOG --stdout \
            --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
            --form "Times accept: N, Nm, Nh, Nd, Nw (e.g., 300, 10m, 2h). Booleans accept: true/false/yes/no/on/off/1/0." 18 74 6 \
            "maxretry:"           1 2  "$MAXRETRY"  1 22  12  0 \
            "findtime:"           2 2  "$FINDTIME"  2 22  12  0 \
            "bantime:"            3 2  "$BANTIME"   3 22  12  0 \
            "bantime.increment:"  4 2  "$INC"       4 22  12  0 \
            "bantime.factor:"     5 2  "$FACTOR"    5 22  12  0 >"$tmp"
          rc=$?
        else
          $DIALOG \
            --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
            --form "Times accept: N, Nm, Nh, Nd, Nw (e.g., 300, 10m, 2h). Booleans accept: true/false/yes/no/on/off/1/0." 18 74 6 \
            "maxretry:"           1 2  "$MAXRETRY"  1 22  12  0 \
            "findtime:"           2 2  "$FINDTIME"  2 22  12  0 \
            "bantime:"            3 2  "$BANTIME"   3 22  12  0 \
            "bantime.increment:"  4 2  "$INC"       4 22  12  0 \
            "bantime.factor:"     5 2  "$FACTOR"    5 22  12  0 \
            2>"$tmp" >/dev/tty
          rc=$?
        fi

        if [[ $rc -ne 0 ]]; then rm -f "$tmp"; continue; fi
        form_out="$(cat "$tmp")"; rm -f "$tmp"

        local __F=()
        while IFS= read -r line; do __F+=("$(sanitize "$line")"); done < <(printf '%s\n' "$form_out")
        while ((${#__F[@]} < 5)); do __F+=(""); done

        MAXRETRY="${__F[0]}"
        FINDTIME="${__F[1]}"
        BANTIME="${__F[2]}"
        INC="${__F[3]}"
        FACTOR="${__F[4]}"

        local err="" FINDTIME_S BANTIME_S INC_NORM
        is_int "$MAXRETRY" || err+="\n- maxretry must be an integer"
        if is_timespec "$FINDTIME"; then FINDTIME_S="$(parse_timespec "$FINDTIME")"; else err+="\n- findtime must be a number with optional unit (s/m/h/d/w)"; fi
        if is_timespec "$BANTIME";   then BANTIME_S="$(parse_timespec "$BANTIME")";   else err+="\n- bantime must be a number with optional unit (s/m/h/d/w)"; fi
        if INC_NORM="$(normalize_bool "$INC")"; then INC="$INC_NORM"; else err+="\n- bantime.increment must be true/false (yes/no/on/off/1/0 allowed)"; fi
        is_float "$FACTOR" || err+="\n- bantime.factor must be a number (e.g., 2 or 1.5)"

        if [[ -n "$err" ]]; then
          $DIALOG --title "Validation Errors" --msgbox "Please fix:$err" 14 74
          continue
        fi

        $DIALOG --title "Confirm Changes" --yesno "Apply these settings to $SSHD_LOCAL_FILE?\n
maxretry:          $MAXRETRY
findtime:          $FINDTIME  -> ${FINDTIME_S}s
bantime:           $BANTIME   -> ${BANTIME_S}s
bantime.increment: $INC
bantime.factor:    $FACTOR" 16 64
        if [[ $? -eq 0 ]]; then
          write_sshd_config "$MAXRETRY" "$FINDTIME_S" "$BANTIME_S" "$INC" "$FACTOR"
          $DIALOG --title "Saved" --msgbox "Configuration saved.\nYou can reload Fail2Ban next." 7 50
        fi
        ;;
      2)
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
      6) manual_edit_sshd_local ;;
      0) break ;;
    esac
  done
}
manage_fail2ban_ssh
