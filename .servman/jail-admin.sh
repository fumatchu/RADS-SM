#===========MANAGE FAIL2BAN SSH JAIL=============
manage_fail2ban_ssh() {
  set -Eeuo pipefail

  # ---- dialog wrapper (consistent backtitle) ----
  local DIALOG="${DIALOG_BIN:-dialog}"
  dlg() { "$DIALOG" --backtitle "Fail2Ban SSH Management" "$@"; }

  local LOG_FILE="/var/log/fail2ban-setup.log"
  local JAIL_DIR="/etc/fail2ban/jail.d"
  local SSHD_LOCAL_FILE="$JAIL_DIR/sshd.local"

  # --- helpers (no hard exits) ---
  require_cmd() { command -v "$1" >/dev/null 2>&1 || { dlg --title "Missing tool" --msgbox "Command not found: $1" 7 48; return 1; }; }
  require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { dlg --msgbox "Run as root." 6 28; return 1; }; }
  ts() { date +"%Y-%m-%d %H:%M:%S"; }

  sanitize() { local s="${1//$'\r'/}"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

  get_sshd_value() {
    local key="$1"
    [[ -f "$SSHD_LOCAL_FILE" ]] || { echo ""; return; }
    awk -v IGNORECASE=1 -v key="$key" '
      BEGIN { section=0 }
      /^[[:space:]]*\[/ { section = ($0 ~ /^[[:space:]]*\[sshd\][[:space:]]*$/); next }
      section {
        line=$0; sub(/;.*$/,"",line); sub(/#.*$/,"",line)
        if (match(line, "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*(.*)$", m)) {
          val = m[1]; gsub(/^[[:space:]]+|[[:space:]]+$/,"",val); print val; exit
        }
      }
    ' "$SSHD_LOCAL_FILE"
  }

  parse_timespec() {
    local in="$1"; shopt -s nocasematch
    if [[ "$in" =~ ^([0-9]+)([smhdw])?$ ]]; then
      local n="${BASH_REMATCH[1]}" u="${BASH_REMATCH[2]:-s}"
      case "$u" in s) echo $((n));; m) echo $((n*60));; h) echo $((n*3600));; d) echo $((n*86400));; w) echo $((n*604800));; esac
      return 0
    fi; return 1
  }
  is_timespec(){ parse_timespec "$1" >/dev/null; }
  normalize_bool(){ case "${1,,}" in true|1|yes|on) echo true;; false|0|no|off) echo false;; *) return 1;; esac; }
  is_int()   { [[ "$1" =~ ^[0-9]+$ ]]; }
  is_float() { [[ "$1" =~ ^([0-9]+([.][0-9]+)?)$ ]]; }

  write_sshd_config() {
    local maxretry="$1" findtime_s="$2" bantime_s="$3" inc="$4" factor="$5"
    mkdir -p "$JAIL_DIR"; umask 022
    [[ -f "$SSHD_LOCAL_FILE" ]] && cp -a "$SSHD_LOCAL_FILE" "${SSHD_LOCAL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    local tmp; tmp=$(mktemp "${SSHD_LOCAL_FILE}.XXXXXX")
    cat > "$tmp" <<EOL
# Managed by dialog SSH jail manager on $(ts)
# Previous version backed up as *.bak.YYYYMMDDHHMMSS
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
    local tmp rc; tmp=$(mktemp); cp -a "$SSHD_LOCAL_FILE" "$tmp"

    # run dialog (allow Cancel)
    if "$DIALOG" --help 2>&1 | grep -q -- '--output-fd'; then
      set +e; "$DIALOG" --output-fd 3 --backtitle "Fail2Ban SSH Management" \
        --title "Manual Edit: $SSHD_LOCAL_FILE" --editbox "$tmp" 24 100 3>"$tmp.edited"; rc=$?; set -e
    elif "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
      set +e; "$DIALOG" --stdout --backtitle "Fail2Ban SSH Management" \
        --title "Manual Edit: $SSHD_LOCAL_FILE" --editbox "$tmp" 24 100 >"$tmp.edited"; rc=$?; set -e
    else
      set +e; "$DIALOG" --backtitle "Fail2Ban SSH Management" \
        --title "Manual Edit: $SSHD_LOCAL_FILE" --editbox "$tmp" 24 100 2>"$tmp.edited" >/dev/tty; rc=$?; set -e
    fi
    if [[ $rc -ne 0 ]]; then rm -f "$tmp" "$tmp.edited"; return 0; fi

    cp -a "$SSHD_LOCAL_FILE" "${SSHD_LOCAL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    tr -d '\r' < "$tmp.edited" > "$SSHD_LOCAL_FILE"
    rm -f "$tmp" "$tmp.edited"
    if command -v sestatus >/dev/null 2>&1 && sestatus 2>/dev/null | grep -qi "enabled"; then
      restorecon -v "$SSHD_LOCAL_FILE" >> "$LOG_FILE" 2>&1 || true
    fi
    echo "[$(ts)] Manually edited $SSHD_LOCAL_FILE via dialog editor" >> "$LOG_FILE"

    set +e; dlg --title "Saved" --yesno "Saved changes to:\n$SSHD_LOCAL_FILE\n\nReload Fail2Ban now?" 10 60; rc=$?; set -e
    if [[ $rc -eq 0 ]]; then
      if systemctl is-active --quiet fail2ban; then
        fail2ban-client reload >/dev/null 2>&1 || systemctl restart fail2ban >/dev/null 2>&1 || true
        dlg --title "Done" --msgbox "Fail2Ban reloaded (or restarted)." 6 50
      else
        dlg --title "Service Inactive" --msgbox "Fail2Ban service is not active." 7 50
      fi
    fi
  }

  show_status_box()  { local out; out=$(fail2ban-client status sshd 2>&1 || true); dlg --title "SSHD Jail Status" --msgbox "$out" 20 90; }
  show_recent_bans() {
    local logfile="/var/log/fail2ban.log" tmp; tmp=$(mktemp)
    [[ -f "$logfile" ]] && grep -E "Ban |Unban " "$logfile" | tail -n 200 > "$tmp" || echo "No /var/log/fail2ban.log found." > "$tmp"
    dlg --title "Recent Bans (tail)" --textbox "$tmp" 22 100; rm -f "$tmp"
  }
  unban_ip() {
    local ip rc
    exec 3>&1
    set +e; ip=$(dlg --title "Unban IP" --inputbox "Enter an IP to unban from the sshd jail:" 8 60 2>&1 1>&3); rc=$?; set -e
    exec 3>&-
    [[ $rc -ne 0 || -z "${ip:-}" ]] && return 0
    if fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1; then
      dlg --title "Unbanned" --msgbox "Unbanned: $ip" 6 40
    else
      dlg --title "Error" --msgbox "Failed to unban: $ip\n\nCheck jail name and IP format." 8 60
    fi
  }

  # prerequisites
  require_root || return 0
  require_cmd "$DIALOG" || return 0
  require_cmd fail2ban-client || return 0
  require_cmd systemctl || return 0

  # seed default if missing
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

  # -------- main menu (Cancel returns here, not CLI) --------
  while true; do
    local MAXRETRY FINDTIME BANTIME INC FACTOR
    MAXRETRY="$(get_sshd_value maxretry)"; [[ -n "$MAXRETRY" ]] || MAXRETRY=5
    FINDTIME="$(get_sshd_value findtime)"; [[ -n "$FINDTIME" ]] || FINDTIME=300
    BANTIME="$(get_sshd_value bantime)";  [[ -n "$BANTIME"  ]] || BANTIME=3600
    INC="$(get_sshd_value 'bantime.increment')"; [[ -n "$INC" ]] || INC=true
    FACTOR="$(get_sshd_value 'bantime.factor')"; [[ -n "$FACTOR" ]] || FACTOR=2

    local choice rc
    exec 3>&1
    set +e
    choice=$(
      dlg --clear --title "SSHD Jail Manager" \
          --menu "Choose an action" 16 78 8 \
          1 "Edit timeouts/retries (guided form)" \
          2 "Apply & reload Fail2Ban (sshd)" \
          3 "Show SSHD jail status" \
          4 "Show recent bans" \
          5 "Unban an IP" \
          6 "Manual edit sshd.local" \
          7 "Service Control" \
          0 "Exit" 2>&1 1>&3
    ); rc=$?
    set -e
    exec 3>&-
    [[ $rc -ne 0 ]] && continue   # Cancel → return to this menu

    case "$choice" in
      1)
        # Guided form
        local tmp form_out; tmp=$(mktemp)

        if "$DIALOG" --help 2>&1 | grep -q -- '--output-fd'; then
          set +e; "$DIALOG" --output-fd 3 --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
            --form "Times accept: N, Nm, Nh, Nd, Nw (e.g., 300, 10m, 2h). Booleans: true/false/yes/no/on/off/1/0." 18 74 6 \
            "maxretry:"           1 2  "$MAXRETRY"  1 22  12  0 \
            "findtime:"           2 2  "$FINDTIME"  2 22  12  0 \
            "bantime:"            3 2  "$BANTIME"   3 22  12  0 \
            "bantime.increment:"  4 2  "$INC"       4 22  12  0 \
            "bantime.factor:"     5 2  "$FACTOR"    5 22  12  0 \
            3>"$tmp"; rc=$?; set -e
        elif "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
          set +e; "$DIALOG" --stdout --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
            --form "Times accept: N, Nm, Nh, Nd, Nw (e.g., 300, 10m, 2h). Booleans: true/false/yes/no/on/off/1/0." 18 74 6 \
            "maxretry:"           1 2  "$MAXRETRY"  1 22  12  0 \
            "findtime:"           2 2  "$FINDTIME"  2 22  12  0 \
            "bantime:"            3 2  "$BANTIME"   3 22  12  0 \
            "bantime.increment:"  4 2  "$INC"       4 22  12  0 \
            "bantime.factor:"     5 2  "$FACTOR"    5 22  12  0 >"$tmp"; rc=$?; set -e
        else
          set +e; "$DIALOG" --backtitle "Fail2Ban SSH Management" --title "Edit SSHD Jail Parameters" \
            --form "Times accept: N, Nm, Nh, Nd, Nw (e.g., 300, 10m, 2h). Booleans: true/false/yes/no/on/off/1/0." 18 74 6 \
            "maxretry:"           1 2  "$MAXRETRY"  1 22  12  0 \
            "findtime:"           2 2  "$FINDTIME"  2 22  12  0 \
            "bantime:"            3 2  "$BANTIME"   3 22  12  0 \
            "bantime.increment:"  4 2  "$INC"       4 22  12  0 \
            "bantime.factor:"     5 2  "$FACTOR"    5 22  12  0 \
            2>"$tmp" >/dev/tty; rc=$?; set -e
        fi
        [[ $rc -ne 0 ]] && { rm -f "$tmp"; continue; }
        form_out="$(cat "$tmp")"; rm -f "$tmp"

        # split safely
        local __F=(); while IFS= read -r line; do __F+=("$(sanitize "$line")"); done < <(printf '%s\n' "$form_out")
        while ((${#__F[@]} < 5)); do __F+=(""); done

        MAXRETRY="${__F[0]}"; FINDTIME="${__F[1]}"; BANTIME="${__F[2]}"; INC="${__F[3]}"; FACTOR="${__F[4]}"

        local err="" FINDTIME_S BANTIME_S INC_NORM
        is_int "$MAXRETRY" || err+="\n- maxretry must be an integer"
        if is_timespec "$FINDTIME"; then FINDTIME_S="$(parse_timespec "$FINDTIME")"; else err+="\n- findtime must be N with optional unit (s/m/h/d/w)"; fi
        if is_timespec "$BANTIME";   then BANTIME_S="$(parse_timespec "$BANTIME")";   else err+="\n- bantime must be N with optional unit (s/m/h/d/w)"; fi
        if INC_NORM="$(normalize_bool "$INC")"; then INC="$INC_NORM"; else err+="\n- bantime.increment must be true/false (yes/no/on/off/1/0)"; fi
        is_float "$FACTOR" || err+="\n- bantime.factor must be a number (e.g. 2 or 1.5)"

        if [[ -n "$err" ]]; then dlg --title "Validation Errors" --msgbox "Please fix:$err" 14 74; continue; fi

        set +e; dlg --title "Confirm Changes" --yesno "Apply these settings to $SSHD_LOCAL_FILE?\n
maxretry:          $MAXRETRY
findtime:          $FINDTIME  -> ${FINDTIME_S}s
bantime:           $BANTIME   -> ${BANTIME_S}s
bantime.increment: $INC
bantime.factor:    $FACTOR" 16 64; rc=$?; set -e
        [[ $rc -ne 0 ]] && continue
        write_sshd_config "$MAXRETRY" "$FINDTIME_S" "$BANTIME_S" "$INC" "$FACTOR"
        dlg --title "Saved" --msgbox "Configuration saved.\nYou can reload Fail2Ban next." 7 50
        ;;
      2)
        if systemctl is-active --quiet fail2ban; then
          if fail2ban-client reload >/dev/null 2>&1; then
            dlg --title "Reloaded" --msgbox "Fail2Ban reloaded successfully." 6 40
          else
            dlg --title "Error" --msgbox "Reload failed.\nTrying to restart service instead..." 7 60
            systemctl restart fail2ban >/dev/null 2>&1 && dlg --title "Restarted" --msgbox "Fail2Ban restarted successfully." 6 45 || \
              dlg --title "Error" --msgbox "Fail2Ban restart failed. See: journalctl -u fail2ban" 8 70
          fi
        else
          set +e; dlg --title "Service Inactive" --yesno "Fail2Ban is not active.\nStart it now?" 7 50; rc=$?; set -e
          [[ $rc -ne 0 ]] || { systemctl start fail2ban && dlg --title "Started" --msgbox "Fail2Ban started." 6 30 || dlg --title "Error" --msgbox "Failed to start Fail2Ban.\nSee: journalctl -u fail2ban" 8 70;
 }
        fi
        ;;
      3) show_status_box ;;
      4) show_recent_bans ;;
      5) unban_ip ;;
      6) manual_edit_sshd_local ;;
      7) "$DIALOG" --clear; clear; /root/.servman/ServiceMan fail2ban.service || true ;;
      0) break ;;
    esac
  done

  return 0
}
manage_fail2ban_ssh
