#!/usr/bin/env bash

#=========== CHRONY MENU + FUNCTIONS (DIALOG) ===========

# Pick default RHEL/Rocky path, fall back to Debian path
CONF="/etc/chrony.conf"
[[ -f "$CONF" ]] || CONF="/etc/chrony/chrony.conf"
LOG="/tmp/chrony_ntp_edit.log"

#--- common helpers ------------------------------------------------
_log(){ echo "$(date '+%F %T') - $*" >>"$LOG"; }
_die(){ dialog --backtitle "Chrony Config" --title "Error" --msgbox "$*" 7 80; return 1; }
_need_root(){ [[ $EUID -eq 0 ]] || { echo "Please run as root."; exit 1; }; }
_need_dialog(){ command -v dialog >/dev/null || { echo "dialog is required"; exit 1; }; }
_need_tools(){
  : >"$LOG"
  # always required
  for t in chronyc systemctl sed awk stat; do
    command -v "$t" >/dev/null || { echo "Missing tool: $t"; exit 1; }
  done
  # need at least one DNS tool for guided validation
  if ! command -v host >/dev/null 2>&1 && ! command -v dig >/dev/null 2>&1; then
    echo "Need either 'host' or 'dig' installed for hostname validation."; exit 1
  fi
}
_is_ip(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$1" =~ ^[0-9A-Fa-f:]+$ ]]; }

_restart_chrony(){
  ( echo 10; sleep 0.3; echo 35; sleep 0.5; echo 60; sleep 0.6;
    systemctl restart chronyd >/dev/null 2>&1; rc=$?;
    echo 85; sleep 0.4; echo 100; sleep 0.3; exit $rc ) \
  | dialog --backtitle "Chrony Config" --title "Restarting chronyd" --gauge "Applying changes..." 7 70
  return ${PIPESTATUS[0]}
}

_validate_sync(){
  local attempt=1 ok=0 tracking sources
  while (( attempt <= 5 )); do
    dialog --backtitle "Chrony Config" --title "Validating Time Sync" \
      --infobox "Checking chronyc tracking... (attempt $attempt/5)" 6 70
    sleep 4
    tracking="$(chronyc tracking 2>&1)"; _log "$tracking"
    if echo "$tracking" | grep -qE 'Leap status[[:space:]]*:[[:space:]]*Normal'; then
      ok=1; break
    fi
    ((attempt++))
  done
  sources="$(chronyc -n sources 2>&1)"; _log "$sources"
  if (( ok == 1 )); then
    dialog --backtitle "Chrony Config" --title "Time Synchronized" \
      --msgbox "Tracking:\n\n$tracking\n\nSources:\n\n$sources" 20 100
    return 0
  else
    dialog --backtitle "Chrony Config" --title "Not Yet Synchronized" \
      --yesno "chronyc tracking did not show 'Leap status: Normal' after retries.\n\nShow current status and re-enter servers?" 10 90
    return $?
  fi
}

_show_status(){
  dialog --backtitle "Chrony Config" --title "Current Chrony Status" \
    --msgbox "Tracking:\n\n$(chronyc tracking 2>&1)\n\nSources:\n\n$(chronyc -n sources 2>&1)" 20 110
}

#--- Option 1: guided servers edit (always iburst) ------------------
ntp_set_servers_dialog() {
  local INPUT
  local SERVERS=() BAD_PARSE=() BAD_RESOLVE=()

  _parse_servers(){ # -> SERVERS[]
    local raw="$1" s; SERVERS=()
    declare -A _seen=()
    IFS=',' read -r -a _tok <<<"$raw"
    for s in "${_tok[@]}"; do
      s="$(echo "$s" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
      [[ -z "$s" ]] && continue
      if [[ "$s" =~ ^([0-9A-Za-z._-]+|[0-9A-Fa-f:]+)$ ]]; then
        [[ -z "${_seen[$s]}" ]] && { SERVERS+=("$s"); _seen[$s]=1; }
      else
        BAD_PARSE+=("$s")
      fi
    done
    [[ ${#SERVERS[@]} -gt 0 ]]
  }

  _validate_resolve(){ # only host/dig; IPs are OK
    BAD_RESOLVE=(); local fail=0 host out rc
    for host in "${SERVERS[@]}"; do
      if _is_ip "$host"; then _log "IP literal ok: $host"; continue; fi
      if command -v host >/dev/null 2>&1; then
        out="$(host -W 3 "$host" 2>&1)"; rc=$?; _log "host -W 3 $host -> rc=$rc | $out"
        [[ $rc -eq 0 ]] && continue
      fi
      if command -v dig >/dev/null 2>&1; then
        out="$(dig +time=2 +tries=1 +short "$host" 2>&1)"; rc=$?; _log "dig +time=2 +tries=1 $host -> rc=$rc | $out"
        [[ -n "$out" ]] && continue
      fi
      BAD_RESOLVE+=("$host"); fail=1
    done
    return $fail
  }

  _write_config(){
    cp -a "$CONF" "${CONF}.bak.$(date +%F-%H%M%S)" || return 1
    sed -i -E '/^[[:space:]]*(server|pool)[[:space:]]+\S+/d' "$CONF"
    {
      echo "# --- Managed by ntp_set_servers_dialog on $(date) ---"
      for h in "${SERVERS[@]}"; do
        printf "server %s iburst\n" "$h"
      done
    } >>"$CONF"
  }

  # Flow
  while true; do
    INPUT=$(dialog --backtitle "Chrony Config" --title "NTP Servers (Guided)" \
      --inputbox $'Enter NTP servers (comma-separated). All will be configured with **iburst**.\n\nExamples:\n  192.168.110.1, 192.168.120.1\n  time1.example.com, time2.example.com' 12 90 \
      3>&1 1>&2 2>&3)
    local exit_status=$?
    [[ $exit_status -ne 0 ]] && { dialog --infobox "Cancelled." 3 20; sleep 1; return 1; }

    BAD_PARSE=()
    if ! _parse_servers "$INPUT"; then
      local msg="Please enter at least one valid server (comma-separated)."
      ((${#BAD_PARSE[@]})) && msg+="\n\nUnrecognized entries:\n  ${BAD_PARSE[*]}"
      dialog --backtitle "Chrony Config" --title "Invalid Input" --msgbox "$msg" 10 90
      continue
    fi

    if ! _validate_resolve; then
      dialog --backtitle "Chrony Config" --title "Resolution Warning" \
        --yesno "These servers did not resolve via host/dig: ${BAD_RESOLVE[*]}\n\nContinue anyway?\n\n(See $LOG for resolver output.)" 11 90
      [[ $? -ne 0 ]] && continue
    fi

    # Review
    local list=""; for h in "${SERVERS[@]}"; do list+="server $h iburst\n"; done
    dialog --backtitle "Chrony Config" --title "Review Servers" \
      --yesno "We'll write the following lines to $CONF:\n\n$(printf "%s" "$list")\nProceed?" 15 90
    [[ $? -ne 0 ]] && { dialog --infobox "OK, let's re-enter them..." 3 40; sleep 1; continue; }

    if ! _write_config; then
      _die "Failed to update $CONF (backup left in place)."; return 1
    fi

    if ! _restart_chrony; then
      _die "chronyd failed to restart. Check $LOG and journalctl -u chronyd."; return 1
    fi

    if _validate_sync; then
      dialog --backtitle "Chrony Config" --title "Done" --infobox "Chrony servers updated successfully." 4 60
      sleep 2; return 0
    else
      dialog --backtitle "Chrony Config" --title "Current Status" \
        --msgbox "Tracking:\n\n$(chronyc tracking 2>&1)\n\nSources:\n\n$(chronyc -n sources 2>&1)" 20 100
      dialog --backtitle "Chrony Config" --title "Retry" \
        --yesno "Would you like to adjust the server list and try again?" 7 70
      [[ $? -eq 0 ]] && continue
      return 1
    fi
  done
}

#--- Option 2: manual editor for chrony.conf ------------------------
manual_edit_chrony_dialog() {
  [[ -f "$CONF" ]] || { _die "chrony.conf not found at /etc/chrony.conf or /etc/chrony/chrony.conf"; return 1; }

  dialog --backtitle "Chrony Config" --title "Manual Edit" \
    --yesno "You are about to manually edit:\n\n$CONF\n\nA backup will be created automatically.\nProceed?" 10 70
  [[ $? -ne 0 ]] && { dialog --infobox "Cancelled." 3 20; sleep 1; return 1; }

  local TMP rc mode owner group
  TMP="$(mktemp)"
  dialog --backtitle "Chrony Config" --title "Editing $CONF" \
    --editbox "$CONF" 25 100 2>"$TMP"
  rc=$?
  [[ $rc -ne 0 ]] && { rm -f "$TMP"; dialog --infobox "No changes made." 3 30; sleep 1; return 1; }

  if cmp -s "$CONF" "$TMP"; then
    rm -f "$TMP"
    dialog --infobox "No changes detected." 3 30; sleep 1; return 0
  fi

  cp -a "$CONF" "${CONF}.bak.$(date +%F-%H%M%S)" || { rm -f "$TMP"; _die "Backup failed."; return 1; }
  mode=$(stat -c "%a" "$CONF"); owner=$(stat -c "%u" "$CONF"); group=$(stat -c "%g" "$CONF")
  cat "$TMP" > "$CONF" || { rm -f "$TMP"; _die "Write failed."; return 1; }
  chmod "$mode" "$CONF"; chown "$owner":"$group" "$CONF"
  rm -f "$TMP"

  dialog --backtitle "Chrony Config" --title "Saved" \
    --yesno "Saved changes to $CONF.\n\nDo you want to restart chronyd now?" 9 70
  if [[ $? -eq 0 ]]; then
    if ! _restart_chrony; then
      _die "chronyd failed to restart. Check journalctl -u chronyd."; return 1
    fi
    dialog --backtitle "Chrony Config" --title "Restarted" --infobox "chronyd restarted." 4 40
    sleep 1
    _show_status
  fi
  return 0
}

#--- NEW Option 3: manage 'allow' statements ------------------------
ntp_set_allow_dialog() {
  [[ -f "$CONF" ]] || { _die "chrony.conf not found."; return 1; }

  # Read current allow lines (non-commented)
  local CURRENT
  CURRENT="$(awk '/^[[:space:]]*allow([[:space:]]|$)/{sub(/^[[:space:]]*allow[[:space:]]*/,""); print}' "$CONF")"
  [[ -z "$CURRENT" ]] && CURRENT="(none)"

  dialog --backtitle "Chrony Config" --title "Allowed NTP Clients" \
    --yesno "This edits chrony 'allow' directives.\n\nCurrent entries:\n$CURRENT\n\nNOTE: Adding 'allow' makes this host serve NTP to those subnets/hosts.\n\nProceed?" 15 90
  [[ $? -ne 0 ]] && { dialog --infobox "Cancelled." 3 20; sleep 1; return 1; }

  local INPUT
  INPUT=$(dialog --backtitle "Chrony Config" --title "Set Allowed Clients" \
    --inputbox $'Enter comma-separated CIDRs or IPs to **allow** (e.g. 192.168.1.0/24,10.10.0.0/16,192.168.2.5).\n\nLeave BLANK to **remove all** allow directives.' 12 90 \
    3>&1 1>&2 2>&3)
  local exit_status=$?
  [[ $exit_status -ne 0 ]] && { dialog --infobox "Cancelled." 3 20; sleep 1; return 1; }

  # Parse & validate
  local ALLOWS=() BAD=()
  if [[ -n "$INPUT" ]]; then
    local t
    IFS=',' read -r -a _tok <<<"$INPUT"
    for t in "${_tok[@]}"; do
      t="$(echo "$t" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
      [[ -z "$t" ]] && continue
      if [[ "$t" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$t" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
        ALLOWS+=("$t")
      else
        BAD+=("$t")
      fi
    done
    if ((${#BAD[@]})); then
      dialog --backtitle "Chrony Config" --title "Invalid Entries" \
        --msgbox "These entries are not valid IPv4 or IPv4/CIDR:\n\n${BAD[*]}\n\nPlease try again." 12 90
      return 1
    fi
  fi

  # Review summary
  local summary
  if ((${#ALLOWS[@]})); then
    summary="Will set the following allow lines:\n"
    for a in "${ALLOWS[@]}"; do summary+="  allow $a\n"; done
  else
    summary="Will REMOVE all 'allow' lines (chronyd will not serve NTP to others)."
  fi

  dialog --backtitle "Chrony Config" --title "Review Allow Settings" \
    --yesno "$summary\n\nApply changes to $CONF?" 15 90
  [[ $? -ne 0 ]] && { dialog --infobox "No changes applied." 3 30; sleep 1; return 1; }

  # Write config
  cp -a "$CONF" "${CONF}.bak.$(date +%F-%H%M%S)" || { _die "Backup failed."; return 1; }
  # Remove existing non-commented allow lines
  sed -i -E '/^[[:space:]]*allow([[:space:]]|$)/d' "$CONF"
  if ((${#ALLOWS[@]})); then
    {
      echo "# --- Managed by ntp_set_allow_dialog on $(date) ---"
      for a in "${ALLOWS[@]}"; do
        printf "allow %s\n" "$a"
      done
    } >>"$CONF"
  fi

  # Ask to restart
  dialog --backtitle "Chrony Config" --title "Restart chronyd?" \
    --yesno "Config updated.\n\nDo you want to restart chronyd now?" 9 70
  if [[ $? -eq 0 ]]; then
    if ! _restart_chrony; then
      _die "chronyd failed to restart. Check journalctl -u chronyd."; return 1
    fi
    dialog --backtitle "Chrony Config" --title "Restarted" --infobox "chronyd restarted." 4 40
    sleep 1
    _show_status
  fi
  return 0
}

#--- Main menu ------------------------------------------------------
chrony_menu_dialog() {
  # ignore any per-user dialogrc; use built-in defaults (black text)
  export DIALOGRC=/dev/null
  unset DIALOGOPTS

  local ITEMS=(
    1 "Guided: set NTP servers (iburst) and validate"
    2 "Manual: edit chrony.conf"
    3 "Allowed clients: manage chrony 'allow' entries"
    4 "View current Chrony status"
    5 "Service Management"
    6 "Quit"
  )

  while true; do
    CHOICE=$(dialog --backtitle "Chrony Config" --title "Chrony Menu" \
      --menu "Choose an action" 20 80 10 "${ITEMS[@]}" \
      3>&1 1>&2 2>&3)

    case "$CHOICE" in
      1) ntp_set_servers_dialog ;;
      2) manual_edit_chrony_dialog ;;
      3) ntp_set_allow_dialog ;;
      4) _show_status ;;
      5)
       # hand off to ServiceMan focused on chronyd.service, then return here
       dialog --clear; clear
       /root/.servman/ServiceMan chronyd.service
       ;;
      6|"") clear; break ;;
    esac
  done
}

# --- Run the menu if executed directly ---
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  chrony_menu_dialog
fi
