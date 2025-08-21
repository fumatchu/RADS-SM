#!/bin/bash
# ===============================
# Samba DC Restore — stage (local/remote) + version checks + checklist + restore
# with scrollable logs after each action
# ===============================
set -euo pipefail

TEXTRESET=$(tput sgr0); RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)

FQDN=$(hostname -f)
LOCAL_DEFAULT="/root/samba-dc-backups"
REMOTE_DEFAULT="/root/samba-dc-backup"
STAGING_ROOT="/tmp/samba-dc-restore"   # where backups are staged locally

TMP_ERR=$(mktemp)
TMP_WORK=$(mktemp -d)
REPORT=$(mktemp)

cleanup(){ rm -f "$TMP_ERR" "$REPORT" 2>/dev/null || true; rm -rf "$TMP_WORK" 2>/dev/null || true; }
trap cleanup EXIT

# ---------- helpers ----------
ensure_root(){ if [ "$(id -u)" -ne 0 ]; then echo -e "${RED}This script must be run as root!${TEXTRESET}"; exit 1; fi; }

pick_source_menu(){ dialog --stdout --title "Restore Source" --menu "Where are the backups stored?" 12 70 2 \
  local  "Backups are on THIS server" \
  remote "Backups are on an SSH server"; }

prompt_local_root(){ dialog --title "Local Backup Root" --inputbox \
  "Enter the local backup ROOT directory to search (backups live directly under here):" 10 70 "$LOCAL_DEFAULT" 3>&1 1>&2 2>&3; }

list_local_backups(){ local root="$1"; find "$root" -maxdepth 1 -mindepth 1 -type d -name "${FQDN}_backup-*" 2>/dev/null | sort -r; }

menu_select_backup(){
  mapfile -t matches
  [[ ${#matches[@]} -eq 0 ]] && { echo ""; return 1; }
  local items=() i; for i in "${!matches[@]}"; do items+=($((i+1)) "${matches[$i]}"); done
  local tag; tag=$(dialog --clear --stdout --title "$1" --menu "$2" 22 100 15 "${items[@]}") || return 1
  echo "${matches[$((tag-1))]}"
}

ensure_sshpass(){ command -v sshpass >/dev/null 2>&1 || { echo -e "${YELLOW}Installing sshpass...${TEXTRESET}"; dnf -y install sshpass >/dev/null 2>&1 || yum -y install sshpass >/dev/null 2>&1 || true; }; }
accept_host_key(){ local host="$1"; mkdir -p ~/.ssh && chmod 700 ~/.ssh; ssh-keyscan -H "$host" >> ~/.ssh/known_hosts 2>/dev/null || true; }
validate_remote_dir(){ local user="$1" host="$2" dir="$3" pass="$4"; sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$host" "test -d '$dir'" 2>"$TMP_ERR"; }
list_remote_backups(){ local user="$1" host="$2" dir="$3" pass="$4"; sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$host" \
  "find '$dir' -maxdepth 1 -mindepth 1 -type d -name '${FQDN}_backup-*' 2>/dev/null | sort -r"; }

# Normalize (strip CR in case of CRLF)
normalize_text_file(){ local f="$1"; [[ -f "$f" ]] || return 0; sed -i 's/\r$//' "$f" 2>/dev/null || true; }

# Show a scrollable log (PgUp/PgDn, arrows)
# Show a scrollable log (PgUp/PgDn) without polluting stdout
show_scrollback() {
  local title="$1" file="$2"
  local TTYDEV
  TTYDEV="$(tty 2>/dev/null || echo /dev/tty)"
  dialog --title "$title — Scrollback (PgUp/PgDn)" \
         --textbox "$file" 26 100 > "$TTYDEV" 2>&1
}

# -------- staging via rsync (LOCAL) --------
stage_local_backup() {
  local source_dir="$1"
  mkdir -p "$STAGING_ROOT"
  local base dest
  base="$(basename "$source_dir")"
  dest="$STAGING_ROOT/$base"
  mkdir -p "$dest"

  local TTYDEV PIPE LOGFILE
  TTYDEV="$(tty 2>/dev/null || echo /dev/tty)"
  PIPE="$(mktemp -u)"
  LOGFILE="$TMP_WORK/rsync_stage_local.log"
  mkfifo "$PIPE"

  (
    set -o pipefail
    {
      rsync -aAX --human-readable --info=name1,stats1 \
        -- "$source_dir/" "$dest/" 2>&1
      RSYNC_RC=$?

      echo
      if [[ $RSYNC_RC -eq 0 ]]; then
        echo "----- Staging complete -----"
      else
        echo "----- Staging FAILED (rsync rc=$RSYNC_RC) -----"
      fi
      echo "Source : $source_dir/"
      echo "Dest   : $dest/"
      echo "Time   : $(date '+%Y-%m-%d %H:%M:%S')"

      return $RSYNC_RC
    } \
    | stdbuf -oL sed -u -e 's/\r/\n/g' -e 's/\x1B\[[0-9;]*[A-Za-z]//g' \
    | tee "$LOGFILE" > "$PIPE"
    exit ${PIPESTATUS[0]}
  ) &
  local prod_pid=$!

  dialog --title "Staging local backup via rsync" --programbox 22 100 < "$PIPE" > "$TTYDEV" 2>&1
  wait "$prod_pid" || { rm -f "$PIPE"; show_scrollback "Staging log" "$LOGFILE"; return 1; }
  rm -f "$PIPE"

  # Show scrollable log
  show_scrollback "Staging log" "$LOGFILE"
  echo "$dest"
}

# -------- staging via rsync (REMOTE) --------
stage_remote_backup() {
  local user="$1" host="$2" pass="$3" remote_dir="$4"

  mkdir -p "$STAGING_ROOT"
  local base dest
  base="$(basename "$remote_dir")"
  dest="$STAGING_ROOT/$base"
  mkdir -p "$dest"

  local TTYDEV PIPE LOGFILE
  TTYDEV="$(tty 2>/dev/null || echo /dev/tty)"
  PIPE="$(mktemp -u)"
  LOGFILE="$TMP_WORK/rsync_stage_remote.log"
  mkfifo "$PIPE"

  (
    set -o pipefail
    {
      sshpass -p "$pass" rsync -aAX --human-readable --info=name1,stats1 \
        -e "ssh -o StrictHostKeyChecking=no" \
        -- "$user@$host:$remote_dir/" "$dest/" 2>&1
      RSYNC_RC=$?

      echo
      if [[ $RSYNC_RC -eq 0 ]]; then
        echo "----- Download complete -----"
      else
        echo "----- Download FAILED (rsync rc=$RSYNC_RC) -----"
      fi
      echo "Source : $user@$host:$remote_dir/"
      echo "Dest   : $dest/"
      echo "Time   : $(date '+%Y-%m-%d %H:%M:%S')"

      return $RSYNC_RC
    } \
    | stdbuf -oL sed -u -e 's/\r/\n/g' -e 's/\x1B\[[0-9;]*[A-Za-z]//g' \
    | tee "$LOGFILE" > "$PIPE"
    exit ${PIPESTATUS[0]}
  ) &
  local prod_pid=$!

  dialog --title "Downloading backup via rsync" --programbox 22 100 < "$PIPE" > "$TTYDEV" 2>&1
  wait "$prod_pid" || { rm -f "$PIPE"; show_scrollback "Download log" "$LOGFILE"; return 1; }
  rm -f "$PIPE"

  # Show scrollable log
  show_scrollback "Download log" "$LOGFILE"
  echo "$dest"
}

extract_field(){ local key="$1" file="$2"; sed -n -E "s/^${key}[[:space:]]*:[[:space:]]*(.*)\$/\1/p" "$file" | head -n1 | xargs; }

parse_local_os(){ local pretty="unknown" id="" ver_id="" kernel="$(uname -r)"; if [[ -f /etc/os-release ]]; then . /etc/os-release; pretty="${PRETTY_NAME:-$pretty}"; id="${ID:-}"; ver_id="${VERSION_ID:-}"; fi; echo "$pretty|$id|$ver_id|$kernel"; }
parse_local_samba(){ local s="unknown"; if command -v samba >/dev/null 2>&1; then s="$(samba -V 2>/dev/null || true)"; elif command -v smbd >/dev/null 2>&1; then s="$(smbd -V 2>/dev/null || true)"; fi; local ver; ver="$(echo "$s" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1 || true)"; echo "$s|$ver"; }

parse_backup_os(){ local f="$1"; normalize_text_file "$f"; local pretty id ver_id kernel; pretty="$(extract_field 'PRETTY_NAME' "$f")"; id="$(extract_field 'ID' "$f")"; ver_id="$(extract_field 'VERSION_ID' "$f")"; kernel="$(extract_field 'KERNEL' "$f")"; echo "$pretty|$id|$ver_id|$kernel"; }
parse_backup_samba(){ local f="$1"; normalize_text_file "$f"; local line pkg ver; line="$(extract_field 'Samba' "$f")"; pkg="$(extract_field 'Package' "$f")"; ver="$(echo "$line" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1 || true)"; echo "$line|$ver|$pkg"; }

# --------- Checklist mapping ----------
tag_to_triplet(){  # echo "kind|src_rel|dst_abs"
  case "$1" in
    etc_samba)      echo "dir|etc/samba|/etc/samba" ;;
    varlib_samba)   echo "dir|var/lib/samba|/var/lib/samba" ;;
    samba_private)  echo "dir|var/lib/samba/private|/var/lib/samba/private" ;;
    sysvol)         echo "dir|var/lib/samba/sysvol|/var/lib/samba/sysvol" ;;
    ntp_signd)      echo "dir|var/lib/samba/ntp_signd|/var/lib/samba/ntp_signd" ;;
    bind_dns)       echo "dir|var/lib/samba/bind-dns|/var/lib/samba/bind-dns" ;;
    var_named)      echo "dir|var/named|/var/named" ;;
    krb5_conf)      echo "file|etc/krb5.conf|/etc/krb5.conf" ;;
    nsswitch_conf)  echo "file|etc/nsswitch.conf|/etc/nsswitch.conf" ;;
    named_conf)     echo "file|etc/named.conf|/etc/named.conf" ;;
    *) return 1 ;;
  esac
}
tag_label(){
  case "$1" in
    etc_samba) echo "/etc/samba → /etc/samba (dir)";;
    varlib_samba) echo "/var/lib/samba → /var/lib/samba (dir)";;
    samba_private) echo "/var/lib/samba/private (dir)";;
    sysvol) echo "/var/lib/samba/sysvol (dir)";;
    ntp_signd) echo "/var/lib/samba/ntp_signd (dir)";;
    bind_dns) echo "/var/lib/samba/bind-dns (dir)";;
    var_named) echo "/var/named → /var/named (dir)";;
    krb5_conf) echo "/etc/krb5.conf (file)";;
    nsswitch_conf) echo "/etc/nsswitch.conf (file)";;
    named_conf) echo "/etc/named.conf (file)";;
  esac
}

select_restore_items(){
  local staged="$1"
  local -a items=()
  add_if_present_dir(){ local tag="$1" rel="$2"; [[ -d "$staged/$rel" ]] && items+=("$tag" "$(tag_label "$tag")" "on"); }
  add_if_present_file(){ local tag="$1" rel="$2"; [[ -f "$staged/$rel" ]] && items+=("$tag" "$(tag_label "$tag")" "on"); }

  add_if_present_dir  etc_samba       "etc/samba"
  add_if_present_dir  varlib_samba    "var/lib/samba"
  add_if_present_dir  samba_private   "var/lib/samba/private"
  add_if_present_dir  sysvol          "var/lib/samba/sysvol"
  add_if_present_dir  ntp_signd       "var/lib/samba/ntp_signd"
  add_if_present_dir  bind_dns        "var/lib/samba/bind-dns"
  add_if_present_dir  var_named       "var/named"
  add_if_present_file krb5_conf       "etc/krb5.conf"
  add_if_present_file nsswitch_conf   "etc/nsswitch.conf"
  add_if_present_file named_conf      "etc/named.conf"

  if [[ ${#items[@]} -eq 0 ]]; then
    dialog --title "Nothing to Restore" --msgbox "No known Samba/DC paths found in the staged backup:\n$staged" 10 80
    return 1
  fi

  local selection
  selection=$(dialog --stdout --separate-output --checklist \
    "Select the items to restore\n(Staged at: $staged)\n\nTip: Space = toggle, Enter = confirm" \
    22 100 15 "${items[@]}") || return 1

  echo "$selection"
}

# Show validation, return 0 = proceed with restore, 1 = abort
compare_versions(){
  local los="$1" bos="$2" lsb="$3" bsb="$4"
  IFS='|' read -r L_PRETTY L_ID L_VER_ID L_KERNEL <<<"$los"
  IFS='|' read -r B_PRETTY B_ID B_VER_ID B_KERNEL <<<"$bos"
  IFS='|' read -r L_SMB_STR L_SMB_VER <<<"$lsb"
  IFS='|' read -r B_SMB_LINE B_SMB_VER B_PKG_LINE <<<"$bsb"

  local OS_MATCH="FAIL" SAMBA_MATCH="FAIL"
  [[ -n "$L_ID" && -n "$L_VER_ID" && "$L_ID" == "$B_ID" && "$L_VER_ID" == "$B_VER_ID" ]] && OS_MATCH="PASS"
  [[ -n "$L_SMB_VER" && -n "$B_SMB_VER" && "$L_SMB_VER" == "$B_SMB_VER" ]] && SAMBA_MATCH="PASS"

  {
    echo "Selected backup:"
    echo "  $SELECTED_BACKUP_DISPLAY"
    echo
    echo "=== OS Version Check ==="
    echo "Local : ${L_PRETTY}  (ID=${L_ID}  VERSION_ID=${L_VER_ID}  KERNEL=${L_KERNEL})"
    echo "Backup: ${B_PRETTY}      (ID=${B_ID}     VERSION_ID=${B_VER_ID}     KERNEL=${B_KERNEL})"
    echo "Result: ${OS_MATCH}"
    echo
    echo "=== Samba Version Check ==="
    echo "Local : ${L_SMB_STR} (parsed: ${L_SMB_VER:-unknown})"
    echo "Backup: ${B_SMB_LINE}     (parsed: ${B_SMB_VER:-unknown})"
    [[ -n "$B_PKG_LINE" ]] && echo "Package: ${B_PKG_LINE}"
    echo "Result: ${SAMBA_MATCH}"
    echo
    if [[ "$OS_MATCH" == "PASS" && "$SAMBA_MATCH" == "PASS" ]]; then
      echo "All checks PASSED."
    else
      echo "One or more checks FAILED. Review discrepancies below."
    fi
  } > "$REPORT"

  dialog --title "Version Validation Results" --textbox "$REPORT" 26 120

  local PROCEED=1
  if [[ "$OS_MATCH" != "PASS" || "$SAMBA_MATCH" != "PASS" ]]; then
    local DIFF_MSG="The following versions do not match:\n\n"
    [[ "$L_ID"     != "$B_ID"     ]] && DIFF_MSG+="• OS ID: local='${L_ID:-unknown}' vs backup='${B_ID:-unknown}'\n"
    [[ "$L_VER_ID" != "$B_VER_ID" ]] && DIFF_MSG+="• OS VERSION_ID: local='${L_VER_ID:-unknown}' vs backup='${B_VER_ID:-unknown}'\n"
    [[ -n "$L_KERNEL" && -n "$B_KERNEL" && "$L_KERNEL" != "$B_KERNEL" ]] && DIFF_MSG+="• Kernel (info): local='${L_KERNEL}' vs backup='${B_KERNEL}'\n"
    [[ "$L_SMB_VER" != "$B_SMB_VER" ]] && DIFF_MSG+="• Samba version: local='${L_SMB_VER:-unknown}' vs backup='${B_SMB_VER:-unknown}'\n"
    DIFF_MSG+="\nProceed with restore anyway?"
    dialog --title "Version Mismatch – Continue?" --yesno "$DIFF_MSG" 18 100 && PROCEED=0
  else
    dialog --title "Proceed?" --yesno "OS and Samba versions match.\n\nProceed with restore now?" 9 60 && PROCEED=0
  fi
  return $PROCEED
}

# Optional integrity check for staged backup (md5sum -c), excluding md5sums.txt itself
verify_staged_md5(){
  local staged="$1"
  local mdfile="$staged/md5sums.txt"
  [[ -f "$mdfile" ]] || return 0

  local checklist="$TMP_WORK/md5sums.checklist"
  local log="$TMP_WORK/md5check.log"
  grep -v -E '(^|[[:space:]])(\./)?md5sums\.txt$' "$mdfile" > "$checklist" || true

  local TTYDEV; TTYDEV="$(tty 2>/dev/null || echo /dev/tty)"
  dialog --title "Verifying backup checksums" --infobox "Running md5sum -c on staged backup..." 6 60
  (
    cd "$staged"
    md5sum -c "$checklist" 2>&1 | tee "$log"
  ) | dialog --title "Checksum verification" --programbox 22 100 > "$TTYDEV" 2>&1

  # Show scrollable log
  show_scrollback "Checksum verification log" "$log"

  if grep -q "FAILED$" "$log"; then
    dialog --title "Checksum Warnings" --yesno "One or more checksum entries reported FAILED.\n\nContinue with restore anyway?" 10 70 || return 1
  fi
  return 0
}

# Run rsyncs (dry-run or actual) for chosen targets
rsync_restore(){
  local staged="$1" dryrun="$2" targets="$3"
  local TTYDEV PIPE LOGFILE
  TTYDEV="$(tty 2>/dev/null || echo /dev/tty)"
  PIPE="$(mktemp -u)"
  LOGFILE="$TMP_WORK/restore_rsync.log"
  mkfifo "$PIPE"

  (
    set -o pipefail
    {
      echo "Starting restore (dry-run=$dryrun) from: $staged"
      echo
      local tag trip kind src dst

      for tag in $targets; do
        trip=$(tag_to_triplet "$tag") || continue
        IFS='|' read -r kind src dst <<<"$trip"

        if [[ "$kind" == "dir" && -d "$staged/$src" ]]; then
          echo ">>> DIR  $src  ->  $dst"
          mkdir -p "$dst"
          if [[ "$dryrun" == "yes" ]]; then
            rsync -aAX --delete -n --human-readable --info=name1,stats1 -- "$staged/$src/" "$dst/" 2>&1
          else
            rsync -aAX --delete    --human-readable --info=name1,stats1 -- "$staged/$src/" "$dst/" 2>&1
          fi
          echo
        elif [[ "$kind" == "file" && -f "$staged/$src" ]]; then
          echo ">>> FILE $src  ->  $dst"
          mkdir -p "$(dirname "$dst")"
          if [[ "$dryrun" == "yes" ]]; then
            rsync -aAX -n --human-readable --info=name1,stats1 -- "$staged/$src" "$dst" 2>&1
          else
            rsync -aAX    --human-readable --info=name1,stats1 -- "$staged/$src" "$dst" 2>&1
          fi
          echo
        fi
      done

      echo "Restore phase complete (dry-run=$dryrun)."
      return 0
    } | stdbuf -oL sed -u -e 's/\r/\n/g' -e 's/\x1B\[[0-9;]*[A-Za-z]//g' \
      | tee "$LOGFILE" > "$PIPE"
    exit ${PIPESTATUS[0]}
  ) &
  local prod_pid=$!

  local title="Restore (dry-run)"
  [[ "$dryrun" == "no" ]] && title="Restoring files"
  dialog --title "$title" --programbox 22 100 < "$PIPE" > "$TTYDEV" 2>&1
  wait "$prod_pid" || { rm -f "$PIPE"; show_scrollback "$title log" "$LOGFILE"; return 1; }
  rm -f "$PIPE"

  # Show scrollable log
  show_scrollback "$title log" "$LOGFILE"
  return 0
}

perform_restore(){
  local staged="$1" targets="$2"

  if [[ -f "$staged/md5sums.txt" ]]; then
    dialog --title "Verify Checksums?" --yesno "Run checksum verification on the staged backup before restoring?\n(Recommended)" 9 70
    if [[ $? -eq 0 ]]; then
      verify_staged_md5 "$staged" || {
        dialog --title "Aborted" --msgbox "Restore cancelled due to checksum warnings." 7 50
        return 1
      }
    fi
  fi

  {
    echo "You selected the following restore targets:"
    echo
    for tag in $targets; do
      printf " • %s\n" "$(tag_label "$tag")"
    done
    echo
  } > "$REPORT"
  dialog --title "Selected Restore Targets" --textbox "$REPORT" 20 100

  dialog --title "Dry-run first?" --yesno "Perform an rsync dry-run to preview changes for the selected items?" 9 70
  if [[ $? -eq 0 ]]; then
    rsync_restore "$staged" "yes" "$targets" || true
  fi

  dialog --title "Confirm Restore" --yesno "Apply the restore now?\n\nThis will overwrite system files in /etc and /var for the selected items." 10 80 || return 1

  dialog --title "Stopping services" --infobox "Stopping samba (and named if present)..." 6 60
  systemctl stop samba 2>/dev/null || true
  systemctl stop named 2>/dev/null || true
  sleep 0.8

  rsync_restore "$staged" "no" "$targets" || {
    dialog --title "Restore Error" --msgbox "One or more rsync operations failed." 7 60
    return 1
  }

  if command -v restorecon >/dev/null 2>&1; then
    dialog --title "SELinux" --infobox "Relabeling contexts on restored paths..." 6 60
    restorecon -RFv /etc/samba /var/lib/samba /var/named 2>/dev/null || true
  fi

  # Start services back
dialog --title "Starting services" --infobox "Starting samba (and named if present)..." 6 60
systemctl start named 2>/dev/null || true
systemctl start samba
sleep 1

if systemctl is-active --quiet samba; then
  # Optional: run your IP/DNS drift fix here if you added it earlier
  # ip_drift_check_and_fix "$(hostname -f)"

  dialog --title "Run AD/DC Validation?" \
         --yesno "Restore finished and samba is active.\n\nRun AD/DC validation tests now?" 10 70
  if [[ $? -eq 0 ]]; then
    post_restore_validations || dialog --title "Validation" --msgbox "Some validation steps failed. Review the dialogs above." 8 70
  fi

  dialog --title "Restore Complete" --msgbox "Tests Completed successfully." 6 40
  return 0
else
  dialog --title "Warning" --msgbox "Files restored, but samba is not active.\nCheck 'journalctl -u samba' for details." 10 70
  return 1
fi


}

# --- IP/DNS helpers ----------------------------------------------------------
get_current_ipv4s() {
  ip -4 -o addr show up scope global \
  | awk '{print $4}' | cut -d/ -f1 | LC_ALL=C sort -u
}

get_dns_a_for_fqdn() {
  local fqdn="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short @127.0.0.1 "$fqdn" A | LC_ALL=C sort -u
  elif command -v host >/dev/null 2>&1; then
    host "$fqdn" 127.0.0.1 | awk '/has address/ {print $4}' | LC_ALL=C sort -u
  else
    getent ahostsv4 "$fqdn" | awk '{print $1}' | LC_ALL=C sort -u
  fi
}

rev_zone_for_ip() {  # 10.20.30.40 -> 30.20.10.in-addr.arpa
  local a b c d; IFS=. read -r a b c d <<<"$1"; echo "$c.$b.$a.in-addr.arpa"
}
rev_ptr_for_ip() {  # 10.20.30.40 -> 40
  local a b c d; IFS=. read -r a b c d <<<"$1"; echo "$d"
}

scan_config_for_fixed_ips() {
  local cur_ips="$1"
  local rpt="$TMP_WORK/ip_drift_configs.txt"
  : > "$rpt"

  # smb.conf: interfaces =
  if [[ -f /etc/samba/smb.conf ]]; then
    local line
    line=$(awk -v IGNORECASE=1 '/^[[:space:]]*interfaces[[:space:]]*=/{print; exit}' /etc/samba/smb.conf)
    if [[ -n "$line" ]]; then
      local ips; ips=$(echo "$line" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | xargs -n1 | sort -u)
      if [[ -n "$ips" ]]; then
        {
          echo "smb.conf contains literal IPs in 'interfaces =' :"
          echo "  $line"
          echo
          echo "Current host IPs:"
          echo "$cur_ips" | sed 's/^/  - /'
          echo
          echo "Consider switching to interface names (e.g. 'interfaces = lo eth0')"
          echo "or update the IP list to match current."
          echo
        } >> "$rpt"
      fi
    fi
  fi

  # named.conf: listen-on { ... };
  if [[ -f /etc/named.conf ]]; then
    local listens; listens=$(awk '/listen-on[[:space:]]*\{/{fl=1}fl; /\}/{if(fl){print; fl=0}}' /etc/named.conf | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    if [[ -n "$listens" ]]; then
      {
        echo "named.conf contains literal IPs in 'listen-on { ... };' :"
        echo "$listens" | sed 's/^/  - /'
        echo
        echo "If this DC IP changed, update that list or use 'any;'."
        echo
      } >> "$rpt"
    fi
  fi

  [[ -s "$rpt" ]] && show_scrollback "Config warnings" "$rpt"
}

ip_drift_check_and_fix() {
  local fqdn="$1"
  local zone host; zone=$(hostname -d); host=$(hostname -s)

  local cur_ips dns_ips
  cur_ips="$(get_current_ipv4s)"
  dns_ips="$(get_dns_a_for_fqdn "$fqdn")"

  local cur_file dns_file; cur_file="$TMP_WORK/cur_ips.txt"; dns_file="$TMP_WORK/dns_ips.txt"
  printf "%s\n" $cur_ips >"$cur_file"; printf "%s\n" $dns_ips >"$dns_file"

  # Compute set diffs
  local missing stale
  missing=$(comm -13 "$dns_file" "$cur_file")  # present locally but missing in DNS
  stale=$(comm -23 "$dns_file" "$cur_file")    # present in DNS but not local

  # Build report
  {
    echo "FQDN: $fqdn"
    echo
    echo "Current IP(s):"
    [[ -n "$cur_ips" ]] && echo "$cur_ips" | sed 's/^/  - /' || echo "  (none)"
    echo
    echo "DNS A records @127.0.0.1:"
    [[ -n "$dns_ips" ]] && echo "$dns_ips" | sed 's/^/  - /' || echo "  (none)"
    echo
    echo "Missing in DNS (will ADD):"
    [[ -n "$missing" ]] && echo "$missing" | sed 's/^/  + /' || echo "  (none)"
    echo
    echo "Stale in DNS (can DELETE):"
    [[ -n "$stale" ]] && echo "$stale" | sed 's/^/  - /' || echo "  (none)"
  } > "$REPORT"
  dialog --title "IP/DNS Drift Summary" --textbox "$REPORT" 24 90

  # Nothing to do?
  if [[ -z "$missing" && -z "$stale" ]]; then
    scan_config_for_fixed_ips "$cur_ips"
    return 0
  fi

  # Offer auto-repair
  dialog --title "Auto-repair DNS?" --yesno "Run automatic DNS repair now?\n\n• Add missing A + PTR for current IPs\n• Offer to delete stale A records" 12 70 || { scan_config_for_fixed_ips "$cur_ips"; return 0; }

  local log="$TMP_WORK/dns_repair.log"
  : > "$log"

  # 1) Re-register using samba_dnsupdate
  {
    echo "== samba_dnsupdate =="
    samba_dnsupdate --verbose 2>&1 || true
    echo
  } | tee -a "$log" >/dev/null

  # 2) Add missing A + PTR
  if [[ -n "$missing" ]]; then
    {
      echo "== Adding missing A(+PTR) records for zone:$zone host:$host =="
      for ip in $missing; do
        echo "-- A $host.$zone -> $ip"
        samba-tool dns add 127.0.0.1 "$zone" "$host" A "$ip" -k yes 2>&1 || echo "  (A add failed for $ip)"
        local revz ptr; revz=$(rev_zone_for_ip "$ip"); ptr=$(rev_ptr_for_ip "$ip")
        echo "   PTR $ptr.$revz -> $fqdn."
        samba-tool dns add 127.0.0.1 "$revz" "$ptr" PTR "$fqdn." -k yes 2>&1 || echo "  (PTR add failed for $ip — reverse zone may not exist)"
      done
      echo
    } | tee -a "$log" >/dev/null
  fi

  # 3) Choose stale A records to delete
  if [[ -n "$stale" ]]; then
    # Build checklist items
    local items=() i=1 ip
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      items+=("old$i" "Delete A $host.$zone → $ip" "on")
      eval "STALE_IP_$i='$ip'"
      i=$((i+1))
    done <<< "$stale"

    local sel
    sel=$(dialog --stdout --separate-output --checklist \
      "Choose stale A records to delete from $zone:\n(FQDN: $host.$zone)" \
      18 90 10 "${items[@]}") || sel=""

    if [[ -n "$sel" ]]; then
      {
        echo "== Deleting selected stale A records =="
        for tag in $sel; do
          n=${tag#old}
          ip_var="STALE_IP_$n"
          ip="${!ip_var}"
          echo "-- delete A $host.$zone -> $ip"
          samba-tool dns delete 127.0.0.1 "$zone" "$host" A "$ip" -k yes 2>&1 || echo "  (delete failed for $ip)"
        done
        echo
      } | tee -a "$log" >/dev/null
    fi
  fi

  # Show the repair log (scrollable)
  show_scrollback "DNS repair log" "$log"

  # Re-summarize after changes
  dns_ips="$(get_dns_a_for_fqdn "$fqdn")"
  printf "%s\n" $dns_ips >"$dns_file"
  missing=$(comm -13 "$dns_file" "$cur_file")
  stale=$(comm -23 "$dns_file" "$cur_file")

  {
    echo "Post-repair DNS A records @127.0.0.1:"
    [[ -n "$dns_ips" ]] && echo "$dns_ips" | sed 's/^/  - /' || echo "  (none)"
    echo
    echo "Still missing: "; [[ -n "$missing" ]] && echo "$missing" | sed 's/^/  + /' || echo "  none"
    echo "Still stale  : "; [[ -n "$stale"   ]] && echo "$stale"   | sed 's/^/  - /' || echo "  none"
  } > "$REPORT"
  dialog --title "IP/DNS Drift — After Repair" --textbox "$REPORT" 16 90

  # Config warnings (interfaces/listen-on)
  scan_config_for_fixed_ips "$cur_ips"
}
#===========VALIDATE AD SERVER AND EXPORT=============
validate_ad_server() {
  local TTYDEV
  TTYDEV="$(tty 2>/dev/null || echo /dev/tty)"

  while true; do
    # --- Determine local FQDN (lowercased), with fallbacks ---
    # NOTE: ADDC is intentionally NOT 'local' so it persists after export
    # NOTE: DOMAIN is also NOT 'local' so it persists after export
    local FQDN SHORT DOM
    FQDN="$(hostname -f 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    if [[ -z "$FQDN" || "$FQDN" != *.* ]]; then
      SHORT="$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]')"
      DOM="$(dnsdomainname 2>/dev/null | tr '[:upper:]' '[:lower:]')"
      if [[ -n "$SHORT" && -n "$DOM" && "$DOM" != "(none)" ]]; then
        FQDN="${SHORT}.${DOM}"
      fi
    fi
    if [[ -z "$FQDN" || "$FQDN" != *.* ]]; then
      dialog --backtitle "AD Server Validation" \
             --msgbox "Unable to determine this server's FQDN.\nEnsure hostname and domain are configured." 9 70 > "$TTYDEV" 2>&1
      return 1
    fi
    ADDC="$FQDN"   # <-- not local

    # Derive DOMAIN (lowercase) with resilient fallbacks
    DOMAIN="${ADDC#*.}"   # <-- not local
    if [[ -z "$DOMAIN" || "$DOMAIN" == "(none)" ]]; then
      if [[ -f /etc/samba/smb.conf ]]; then
        DOMAIN="$(awk -F= 'tolower($1) ~ /^[[:space:]]*realm[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print tolower($2)}' /etc/samba/smb.conf)"
      fi
    fi
    if [[ -z "$DOMAIN" || "$DOMAIN" == "(none)" ]]; then
      DOMAIN="$(dnsdomainname 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    fi
    if [[ -z "$DOMAIN" || "$DOMAIN" == "(none)" || "$DOMAIN" != *.* ]]; then
      dialog --backtitle "AD Server Validation" \
             --msgbox "Could not determine the DNS domain for this host." 7 70 > "$TTYDEV" 2>&1
      return 1
    fi

    # --- Initialize results ---
    local DNS_RESULT="DNS resolution failed"
    local PING_RESULT="Ping failed"
    local LDAP_RESULT="LDAP SRV record not found"
    local KRB_RESULT="Kerberos SRV record not found"
    local ALL_OK=true

    # Resolve A record (prefer local DNS @127.0.0.1)
    local IP_ADDRESS=""
    if command -v dig >/dev/null 2>&1; then
      IP_ADDRESS="$(dig +short @127.0.0.1 "$ADDC" A | head -n 1)"
      [[ -z "$IP_ADDRESS" ]] && IP_ADDRESS="$(dig +short "$ADDC" A | head -n 1)"
    fi
    if [[ -z "$IP_ADDRESS" ]]; then
      IP_ADDRESS="$(getent hosts "$ADDC" | awk '{print $1}' | head -n1)"
    fi
    if [[ -n "$IP_ADDRESS" ]]; then
      DNS_RESULT="DNS resolved to $IP_ADDRESS"
    else
      ALL_OK=false
    fi

    # Ping
    if [[ -n "$IP_ADDRESS" ]] && ping -c 1 -W 2 "$IP_ADDRESS" &>/dev/null; then
      PING_RESULT="Ping successful to $IP_ADDRESS"
    else
      ALL_OK=false
    fi

    # SRV checks (prefer dig)
    local LDAP_SRV_OUT="" KRB_SRV_OUT=""
    if command -v dig >/dev/null 2>&1; then
      LDAP_SRV_OUT="$(dig +short @127.0.0.1 _ldap._tcp."$DOMAIN" SRV | awk '{print $4}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
      [[ -z "$LDAP_SRV_OUT" ]] && LDAP_SRV_OUT="$(dig +short _ldap._tcp."$DOMAIN" SRV | awk '{print $4}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
      KRB_SRV_OUT="$(dig +short @127.0.0.1 _kerberos._udp."$DOMAIN" SRV | awk '{print $4}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
      [[ -z "$KRB_SRV_OUT" ]] && KRB_SRV_OUT="$(dig +short _kerberos._udp."$DOMAIN" SRV | awk '{print $4}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
    else
      LDAP_SRV_OUT="$(host -t SRV _ldap._tcp."$DOMAIN" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
      KRB_SRV_OUT="$(host -t SRV _kerberos._udp."$DOMAIN" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
    fi

    if echo "$LDAP_SRV_OUT" | grep -q -F "$ADDC"; then
      LDAP_RESULT="LDAP SRV record found for $ADDC"
    else
      ALL_OK=false
    fi
    if echo "$KRB_SRV_OUT" | grep -q -F "$ADDC"; then
      KRB_RESULT="Kerberos SRV record found for $ADDC"
    else
      ALL_OK=false
    fi

    # Result window
    local RESULT_MSG
    RESULT_MSG=$(cat <<EOF
AD Server (auto-detected): $ADDC
Domain: $DOMAIN

$DNS_RESULT
$PING_RESULT
$LDAP_RESULT
$KRB_RESULT
EOF
)
    if $ALL_OK; then
      dialog --backtitle "AD Server Validation" --msgbox "$RESULT_MSG

All checks passed." 16 72 > "$TTYDEV" 2>&1

      # Export for subsequent functions
      DC_IP_ADDRESS="$IP_ADDRESS"   # set then export
      export ADDC DC_IP_ADDRESS DOMAIN
      # Optional extras
      export REALM="$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')"
      if [[ -f /etc/samba/smb.conf ]]; then
        export WORKGROUP="$(awk -F= 'tolower($1) ~ /^[[:space:]]*workgroup[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print toupper($2)}' /etc/samba/smb.conf)"
      fi
      clear
      return 0
    else
      dialog --backtitle "AD Server Validation" --yesno "$RESULT_MSG

One or more checks failed. Retry?" 19 72 > "$TTYDEV" 2>&1
      [[ $? -ne 0 ]] && clear && return 1
    fi
  done
}




#===========VALIDATE ADMIN PASSWORD AND EXPORT=============
validate_ad_admin_password() {
  while true; do
    ADMINPASS=$(dialog --clear --backtitle "Validate Administrator Password" \
      --insecure --passwordbox "Enter the password for 'Administrator@$DOMAIN'" 10 60 3>&1 1>&2 2>&3 3>&-)

    [ $? -ne 0 ] && clear && return 1

    if [ -z "$ADMINPASS" ]; then
      dialog --backtitle "Validate Administrator Password" \
        --msgbox "Password cannot be blank. Please try again." 6 50
      continue
    fi

    # Try secure bind using LDAPS with relaxed cert validation
    LDAPTLS_REQCERT=never ldapwhoami -x -H "ldaps://$DC_IP_ADDRESS" \
      -D "Administrator@$DOMAIN" -w "$ADMINPASS" >/tmp/ldap_test.out 2>&1

    if [ $? -eq 0 ]; then
      dialog --backtitle "Validate Administrator Password" \
        --infobox "Administrator credentials validated successfully." 5 60
      sleep 2
      export ADMINPASS
      clear
      return 0
    else
      ERROR_MSG=$(cat /tmp/ldap_test.out | tail -n 1)
      dialog --backtitle "Validate Administrator Password" \
        --msgbox "Authentication failed:\n\n$ERROR_MSG" 10 60
      dialog --backtitle "Validate Administrator Password" \
        --yesno "Would you like to try again?" 7 50
      [ $? -ne 0 ] && clear && return 1
    fi
  done
}


#===========ANONYMOUS LOGIN TEST=============
test_anonymous_login() {
  dialog --backtitle "Samba Validation" --title "Anonymous SMB Login Test" --infobox "Testing anonymous login to the Samba server..." 5 60
  sleep 2

  output=$(smbclient -L localhost -N 2>&1)

  if echo "$output" | grep -q "Anonymous login successful"; then
    dialog --backtitle "Samba Validation" --title "Anonymous Login Success" --infobox "Success: Anonymous login successful." 6 60
    sleep 2
  else
    dialog --backtitle "Samba Validation" --title "Anonymous Login Failed" --msgbox "Error: Anonymous logins are not available.\n\n$output" 15 70
    return 1
  fi

  return 0
}



#===========DNS SRV RECORD CHECK=============
check_dns_srv_records() {
  FQDN=$(hostname -f)
  DOMAIN=$(echo "$FQDN" | cut -d'.' -f2-)
  HOSTNAME_PART=$(echo "$FQDN" | cut -d'.' -f1)
  TIMEOUT=5

  dialog --backtitle "Samba Validation" --backtitle "SRV Records Check" --title "DNS SRV Record Check" --infobox "Querying SRV records for domain $DOMAIN..." 5 60
  sleep 1

  # Perform SRV lookups with timeout
  ldap_srv=$(timeout $TIMEOUT host -t SRV _ldap._tcp."$DOMAIN" 2>/dev/null)
  kerberos_srv=$(timeout $TIMEOUT host -t SRV _kerberos._udp."$DOMAIN" 2>/dev/null)
  fqdn_check=$(timeout $TIMEOUT host -t A "$FQDN" 2>/dev/null)

  # Handle timeout or failure
  if [[ -z "$ldap_srv" || -z "$kerberos_srv" || -z "$fqdn_check" ]]; then
    dialog --backtitle "Samba Validation" --title "DNS Query Timeout" --msgbox "Error: One or more DNS queries timed out after ${TIMEOUT}s.\n\nLDAP SRV:\n$ldap_srv\n
\nKerberos SRV:\n$kerberos_srv\n\nFQDN A record:\n$fqdn_check" 20 75
    return 1
  fi

  # Extract and normalize target FQDNs from SRV responses
  get_srv_hostnames() {
    local srv_records="$1"
    echo "$srv_records" | awk '/SRV record/ {print tolower($NF)}' | sed 's/\.$//'
  }

  ldap_targets=$(get_srv_hostnames "$ldap_srv")
  kerberos_targets=$(get_srv_hostnames "$kerberos_srv")

  # Combine and check if any match our full FQDN
  all_targets="$ldap_targets $kerberos_targets"
  match_found=0
  for t in $all_targets; do
    if [[ "$t" == "$FQDN" ]]; then
      match_found=1
      break
    fi
  done

  if [[ $match_found -eq 1 ]]; then
    dialog --backtitle "Samba Validation" --backtitle "SRV Records Check" --title "DNS SRV Check Passed" --infobox "Success: SRV record matches found for $FQDN\n\nLDAP SRV:\n$ldap_srv\n\nKerberos SRV:\n$kerberos_srv\n\nA Record:\n$fqdn_check" 20 75
    sleep 3
    return 0
  else
    # Check Samba service status
    samba_status=$(systemctl is-active samba)
    dns_entry=$(nmcli dev show | grep 'IP4.DNS')

    dialog  --backtitle "Samba Validation" --title "DNS SRV Record Check Failed" --msgbox "Error: No matching SRV hostnames.\n\nSamba
 status: $samba_status\n\nDNS entries:\n$dns_entry" 20 75
    return 1
  fi
}

#===========KERBEROS LOGIN AND TICKET CHECK=============
check_kerberos_ticket() {
  dialog --backtitle "Samba Validation" --title "Kerberos Login" --infobox "Attempting Kerberos login using Administrator credentials..." 5 80
  sleep 2

  # Attempt kinit with password from variable
  echo "$ADMINPASS" | kinit Administrator 2>/tmp/kinit_error.log

  if [[ $? -ne 0 ]]; then
    ERROR_MSG=$(< /tmp/kinit_error.log)
    dialog --backtitle "Samba Validation" --title "Kerberos Login Failed" --msgbox "Kerberos login failed:\n$ERROR_MSG" 10 80
    return 1
  fi

  # Run klist and capture output
  klist_output=$(klist 2>&1)

  if echo "$klist_output" | grep -q "Valid starting.*Service principal"; then
    dialog --backtitle "Samba Validation" --title "Kerberos Login Success" --infobox "Kerberos ticket successfully acquired for Administrator.\n\nTicket Details:\n\n$klist_output" 20 80
    sleep 3
  else
    dialog --backtitle "Samba Validation" --title "Kerberos Ticket Check Failed" --msgbox "Kerberos login succeeded, but no valid ticket found.\n\n$klist_output" 10 80
    return 1
  fi

  return 0
}

#===========LDAP BIND AND TEST=============
test_ldap_secure_connection() {
  LOG="/var/log/samba-ldap-cert-setup.log"
  IPADDR=$(hostname -I | awk '{print $1}')

  LDAP_ADMIN_DN=$(samba-tool user show Administrator | awk -F': ' '/^dn: / {print $2}')
  if [[ -z "$LDAP_ADMIN_DN" ]]; then
    dialog --backtitle "Samba Validation" --title "LDAP Test Error" --msgbox "Failed to retrieve Administrator DN from samba-tool output." 7 60
    return 1
  fi

  LDAP_BASEDN=$(echo "$LDAP_ADMIN_DN" | grep -oE 'DC=[^,]+(,DC=[^,]+)*')

  dialog --backtitle "Samba Validation" --infobox "Testing StartTLS on port 389..." 5 50
  sleep 2
  LDAPTLS_REQCERT=never \
  ldapsearch -x -H ldap://$IPADDR -ZZ \
    -D "$LDAP_ADMIN_DN" \
    -w "$ADMINPASS" \
    -b "$LDAP_BASEDN" dn >> "$LOG" 2>&1

  if grep -q "^dn: " "$LOG"; then
    dialog --backtitle "Samba Validation" --infobox "StartTLS (389) test passed." 5 50
    sleep 2
  else
    dialog --backtitle "Samba Validation" --msgbox "StartTLS (389) test failed — see $LOG for details." 7 60
  fi

  dialog --backtitle "Samba Validation" --infobox "Testing LDAPS on port 636..." 5 50
  sleep 2
  LDAPTLS_REQCERT=never \
  ldapsearch -x -H ldaps://$IPADDR \
    -D "$LDAP_ADMIN_DN" \
    -w "$ADMINPASS" \
    -b "$LDAP_BASEDN" dn >> "$LOG" 2>&1

  if grep -q "^dn: " "$LOG"; then
    dialog --backtitle "Samba Validation" --infobox "LDAPS (636) test passed." 5 50
    sleep 2
  else
    dialog --backtitle "Samba Validation" --msgbox "LDAPS test failed — see $LOG for details." 7 60
  fi

  dialog --backtitle "Samba Validation" --title "LDAP Secure Setup Complete" --infobox "StartTLS and LDAPS tested." 7 60
  sleep 3
  return 0
}



# ---------- post-restore validations ----------
post_restore_validations() {
  # Run these in order; do not subshell them so exported vars persist
  validate_ad_server || return 1
  validate_ad_admin_password || return 1
  test_anonymous_login || true
  check_dns_srv_records || true
  check_kerberos_ticket || true
  test_ldap_secure_connection || true
  return 0
}

# ---------- main ----------
main(){
  ensure_root

  local SRC_CHOICE; SRC_CHOICE=$(pick_source_menu) || { clear; exit 0; }

  if [[ "$SRC_CHOICE" == "local" ]]; then
    local ROOT_DIR; ROOT_DIR=$(prompt_local_root) || { clear; exit 0; }
    mapfile -t MATCHES < <(list_local_backups "$ROOT_DIR")
    [[ ${#MATCHES[@]} -eq 0 ]] && { dialog --title "No Backups Found" --msgbox "No directories matching:\n${FQDN}_backup-*\n\nUnder:\n$ROOT_DIR" 12 70; clear; exit 1; }

    local SELECTED; SELECTED=$(printf "%s\n" "${MATCHES[@]}" | menu_select_backup "Select Backup (Local)" "Choose a backup for $FQDN\nRoot: $ROOT_DIR") || { clear; exit 0; }

    local STAGED
    if ! STAGED=$(stage_local_backup "$SELECTED"); then
      dialog --title "Staging Error" --msgbox "Failed to stage local backup from:\n$SELECTED" 8 70
      clear; exit 1
    fi
    SELECTED_BACKUP_LOCAL="$STAGED"
    SELECTED_BACKUP_DISPLAY="$SELECTED  (staged → $SELECTED_BACKUP_LOCAL)"

  else
    local REMOTE_HOST REMOTE_USER REMOTE_DIR REMOTE_PASS
    REMOTE_HOST=$(dialog --title "Remote Host" --inputbox "Enter SSH server IP or hostname:" 8 60 3>&1 1>&2 2>&3) || { clear; exit 0; }
    REMOTE_USER=$(dialog --title "Remote User" --inputbox "Enter SSH username:" 8 60 "" 3>&1 1>&2 2>&3) || { clear; exit 0; }
    REMOTE_DIR=$(dialog --title "Remote Backup Root" --inputbox "Enter REMOTE backup ROOT directory to search:" 8 70 "$REMOTE_DEFAULT" 3>&1 1>&2 2>&3) || { clear; exit 0; }
    REMOTE_PASS=$(dialog --insecure --title "SSH Password" --passwordbox "Enter SSH password for $REMOTE_USER@$REMOTE_HOST:" 10 60 3>&1 1>&2 2>&3) || { clear; exit 0; }

    dialog --title "Testing SSH Access" --infobox "Validating SSH login and directory..." 6 60
    ensure_sshpass; accept_host_key "$REMOTE_HOST"
    validate_remote_dir "$REMOTE_USER" "$REMOTE_HOST" "$REMOTE_DIR" "$REMOTE_PASS" || { dialog --title "Remote Dir Error" --msgbox "Could not access remote directory:\n$REMOTE_DIR\n\nDetails:\n$(< "$TMP_ERR")" 14 100; clear; exit 1; }

    local REMOTE_LIST; REMOTE_LIST=$(list_remote_backups "$REMOTE_USER" "$REMOTE_HOST" "$REMOTE_DIR" "$REMOTE_PASS" || true)
    [[ -z "$REMOTE_LIST" ]] && { dialog --title "No Backups Found (Remote)" --msgbox "No directories matching:\n${FQDN}_backup-*\n\nUnder remote root:\n$REMOTE_DIR\n\nOn host:\n$REMOTE_USER@$REMOTE_HOST" 14 80; clear; exit 1; }
    mapfile -t REMOTE_MATCHES <<<"$REMOTE_LIST"

    local SELECTED_REMOTE; SELECTED_REMOTE=$(printf "%s\n" "${REMOTE_MATCHES[@]}" | menu_select_backup "Select Backup (Remote)" "Choose a backup for $FQDN\nRoot: $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR") || { clear; exit 0; }

    local STAGED; if ! STAGED=$(stage_remote_backup "$REMOTE_USER" "$REMOTE_HOST" "$REMOTE_PASS" "$SELECTED_REMOTE"); then
      dialog --title "Rsync Error" --msgbox "Failed to download backup via rsync from:\n$REMOTE_USER@$REMOTE_HOST:$SELECTED_REMOTE" 10 80; clear; exit 1
    fi
    SELECTED_BACKUP_LOCAL="$STAGED"
    SELECTED_BACKUP_DISPLAY="$REMOTE_USER@$REMOTE_HOST:$SELECTED_REMOTE  (staged → $SELECTED_BACKUP_LOCAL)"
  fi

  # Validate using the staged backup dir
  local B_OS_FILE="$SELECTED_BACKUP_LOCAL/os_version.txt"
  local B_SAMBA_FILE="$SELECTED_BACKUP_LOCAL/samba_version.txt"
  [[ -f "$B_OS_FILE" && -f "$B_SAMBA_FILE" ]] || { dialog --title "Missing Version Files" --msgbox "Could not find os_version.txt and/or samba_version.txt in:\n$SELECTED_BACKUP_LOCAL" 12 90; clear; exit 1; }
  normalize_text_file "$B_OS_FILE"; normalize_text_file "$B_SAMBA_FILE"

  local LOS BOS LSB BSB
  LOS=$(parse_local_os)
  LSB=$(parse_local_samba)
  BOS=$(parse_backup_os "$B_OS_FILE")
  BSB=$(parse_backup_samba "$B_SAMBA_FILE")

  if compare_versions "$LOS" "$BOS" "$LSB" "$BSB"; then
    local chosen
    chosen=$(select_restore_items "$SELECTED_BACKUP_LOCAL") || { clear; exit 0; }
    chosen=$(echo "$chosen" | xargs echo)
    perform_restore "$SELECTED_BACKUP_LOCAL" "$chosen"
  else
    clear; exit 0
  fi
}
main "$@"
