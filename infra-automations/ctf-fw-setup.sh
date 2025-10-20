#!/usr/bin/env bash
set -euo pipefail

# Default configuration values
BACKEND="iptables"
SSH_PORT=22
SERVICES=""
SERVICES_FILE="/etc/ctf_services"
ADMIN_IPS=""
TEAM_NET=""
DRY_RUN="no"
RATE_LIMIT_SSH="<depends>/min"
RATE_LIMIT_SERVICE="<depends>/min"
LOG_LIMIT="5/min"
IPTABLES_SAVE_V4="/etc/iptables/rules.v4"
IPTABLES_SAVE_V6="/etc/iptables/rules.v6"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend) BACKEND="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --services) SERVICES="$2"; shift 2 ;;
    --services-file) SERVICES_FILE="$2"; shift 2 ;;
    --admins) ADMIN_IPS="$2"; shift 2 ;;
    --team-net) TEAM_NET="$2"; shift 2 ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    -h|--help)
      cat <<EOF
Usage: $0 [options]
  --backend <ufw|iptables>
  --ssh-port <port>
  --services <p1,p2,...>
  --services-file <path>
  --admins <ip1,ip2,...>
  --team-net <CIDR>
  --dry-run
EOF
      exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Read services from file if provided
if [[ -f "$SERVICES_FILE" && -s "$SERVICES_FILE" ]]; then
  SERVICES="$(tr -d ' \t\n' < "$SERVICES_FILE" || true)"
fi

# Convert comma-separated strings to arrays
IFS=',' read -r -a SERVICE_PORTS <<< "${SERVICES:-}"
IFS=',' read -r -a ADMIN_IPS_ARR <<< "${ADMIN_IPS:-}"

# Function: run a command or just print it if dry-run mode is on
run() {
  if [[ "$DRY_RUN" == "yes" ]]; then
    echo "[DRY RUN] $*"
  else
    echo "[RUN] $*"
    eval "$@"
  fi
}

# Function: check if the user is root
is_root() { [[ "$(id -u)" -eq 0 ]]; }

# Function: automatically detect currently connected SSH client IPs
detect_ssh_client_ips() {
  local ips=""
  ips="$ips $(who | awk '{print $5}' | tr -d '()')"
  if command -v ss >/dev/null 2>&1; then
    ips="$ips $(ss -tnp 2>/dev/null | awk '/sshd/ && /ESTAB/ {print $5}' | sed 's/:.*//')"
  fi
  ips="$ips $(last -i | awk '/still logged in/ {print $3}')"
  echo "$ips" | tr ' ' '\n' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' 2>/dev/null | sort -u || true
}

# Function: check if a port number is valid
is_valid_port() { local p="$1"; [[ "$p" =~ ^[0-9]+$ ]] && (( p >=1 && p <= 65535 )); }

# Function: create a backup of current firewall rules for safety
backup_firewall() {
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local backup_path="/root/iptables-backup-$ts.rules"
  if command -v iptables-save >/dev/null 2>&1; then
    echo "Creating firewall backup at $backup_path..."
    iptables-save > "$backup_path" || echo "Warning: could not save iptables rules."
  fi
}

# Function: install required packages (iptables or ufw)
install_pkgs() {
  if [[ "$BACKEND" == "ufw" ]]; then
    if [[ -f /etc/debian_version ]]; then
      run apt-get update -y
      run apt-get install -y ufw
    elif [[ -f /etc/redhat-release ]]; then
      if command -v dnf >/dev/null 2>&1; then
        run dnf install -y epel-release || true
      else
        run yum install -y epel-release || true
      fi
      run yum install -y ufw || true
    else
      echo "Cannot auto-install ufw." >&2
    fi
  else
    if [[ -f /etc/debian_version ]]; then
      run apt-get update -y
      run apt-get install -y iptables iptables-persistent
    elif [[ -f /etc/redhat-release ]]; then
      if command -v dnf >/dev/null 2>&1; then
        run dnf install -y iptables-services
      else
        run yum install -y iptables-services
      fi
    else
      echo "Cannot auto-install iptables." >&2
    fi
  fi
}

# Function: setup firewall using UFW backend
setup_ufw() {
  run ufw --force reset
  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw allow in on lo
  run ufw allow "${SSH_PORT}/tcp"
  for p in "${SERVICE_PORTS[@]}"; do
    [[ -n "$p" ]] && is_valid_port "$p" && run ufw allow "$p" || true
  done
  for ip in "${ADMIN_IPS_ARR[@]}"; do
    [[ -n "$ip" ]] && run ufw allow from "$ip" to any port "$SSH_PORT" proto tcp || true
  done
  if [[ -n "$TEAM_NET" ]]; then run ufw allow from "$TEAM_NET"; fi
  for ip in $(detect_ssh_client_ips); do
    [[ -n "$ip" ]] && run ufw allow from "$ip" to any port "$SSH_PORT" proto tcp || true
  done
  run ufw logging on
  run ufw --force enable
  run ufw status numbered
}

# Function: setup firewall using iptables backend
setup_iptables() {
  backup_firewall
  run iptables -F
  run iptables -X
  run iptables -Z
  run iptables -t nat -F
  run iptables -t mangle -F
  run iptables -A INPUT -i lo -j ACCEPT
  run iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  for ip in "${ADMIN_IPS_ARR[@]}"; do
    [[ -n "$ip" ]] && run iptables -I INPUT -s "$ip" -j ACCEPT
  done
  for ip in $(detect_ssh_client_ips); do
    [[ -n "$ip" ]] && run iptables -I INPUT -s "$ip" -p tcp --dport "$SSH_PORT" \
      -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  done
  if [[ -n "$TEAM_NET" ]]; then run iptables -I INPUT -s "$TEAM_NET" -j ACCEPT; fi
  run iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
    -m limit --limit "$RATE_LIMIT_SSH" --limit-burst 6 -j ACCEPT
  for p in "${SERVICE_PORTS[@]}"; do
    [[ -n "$p" ]] && is_valid_port "$p" && \
      run iptables -A INPUT -p tcp --dport "$p" -m conntrack --ctstate NEW \
      -m limit --limit "$RATE_LIMIT_SERVICE" --limit-burst 20 -j ACCEPT
  done
  run iptables -A INPUT -p icmp -m limit --limit 20/sec -j ACCEPT || true
  run iptables -N CTF_LOGGING || true
  run iptables -A CTF_LOGGING -m limit --limit "$LOG_LIMIT" \
    -j LOG --log-prefix "CTF-DROP: " --log-level 4 || true
  run iptables -A CTF_LOGGING -j DROP
  run iptables -A INPUT -j CTF_LOGGING
  if [[ -f /etc/debian_version ]]; then
    run mkdir -p "$(dirname "$IPTABLES_SAVE_V4")"
    if [[ "$DRY_RUN" == "yes" ]]; then
      echo "[DRY RUN] iptables-save > $IPTABLES_SAVE_V4"
    else
      iptables-save > "$IPTABLES_SAVE_V4"
      if command -v netfilter-persistent >/dev/null 2>&1; then
        run netfilter-persistent save || true
      fi
    fi
  fi
  if [[ -f /etc/redhat-release ]]; then
    if [[ "$DRY_RUN" == "yes" ]]; then
      echo "[DRY RUN] iptables-save > /etc/sysconfig/iptables"
    else
      iptables-save > /etc/sysconfig/iptables || true
      if command -v systemctl >/dev/null 2>&1; then
        run systemctl enable --now iptables || true
      fi
    fi
  fi
}

# Main installation and setup logic
if ! is_root; then
  echo "Please run as root (sudo)." >&2
  exit 1
fi

echo "CTF Firewall installer"
echo "Backend: $BACKEND"
echo "SSH port: $SSH_PORT"
echo "Service ports: ${SERVICE_PORTS[*]:-NONE}"
echo "Admin IPs: ${ADMIN_IPS_ARR[*]:-NONE}"
echo "Team net: ${TEAM_NET:-NONE}"
echo "Dry run: $DRY_RUN"
echo

install_pkgs
if [[ "$BACKEND" == "ufw" ]]; then
  setup_ufw
else
  setup_iptables
fi

echo
if [[ "$BACKEND" == "ufw" ]]; then
  echo "ufw status verbose"
else
  echo "iptables -L -n -v"
fi
