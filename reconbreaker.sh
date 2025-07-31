#!/bin/bash

# ================================
#   ReconBreaker v0.1 by h3st4k3r
# ================================

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

clear
echo -e "${BLUE}"
echo "==============================="
echo "     ReconBreaker v0.1"
echo "        by h3st4k3r"
echo "==============================="
echo -e "${NC}"

read -p "Enter target IP or domain: " TARGET

# Create target structure
mkdir -p "$TARGET"/{1_recon,2_scan,3_enum,4_attacks}

# ------------ FASE 1: Passive Recon ------------
passive_recon() {
    echo -e "${YELLOW}[*] Starting Phase 1: Passive Recon on ${TARGET}${NC}"

    echo -e "${BLUE}[+] Running WHOIS...${NC}"
    whois $TARGET > "$TARGET/1_recon/whois.txt"

    echo -e "${BLUE}[+] Running NSLOOKUP...${NC}"
    nslookup $TARGET > "$TARGET/1_recon/nslookup.txt"

    echo -e "${BLUE}[+] Running DIG...${NC}"
    dig $TARGET ANY +noall +answer > "$TARGET/1_recon/dig.txt"

    echo -e "${GREEN}[✔] Passive recon completed. Output saved in: $TARGET/1_recon${NC}"
}

# ------------ FASE 2: Port Scanning ------------
port_scanning() {
    echo -e "${YELLOW}[*] Phase 2: Port Scanning (coming soon)${NC}"
}

# ------------ FASE 3: Service Enumeration ------------
service_enum() {
    echo -e "${YELLOW}[*] Phase 3: Service Enumeration (coming soon)${NC}"
}

# ------------ FASE 4: Automated Attacks ------------
auto_attacks() {
    echo -e "${YELLOW}[*] Phase 4: Automated Attacks (coming soon)${NC}"
}

# ------------ MAIN MENU LOOP ------------
while true; do
    echo
    echo -e "${BLUE}==== Select a phase to run ====${NC}"
    echo "1. Passive Recon"
    echo "2. Port Scanning"
    echo "3. Service Enumeration"
    echo "4. Automated Attacks"
    echo "5. Run ALL phases"
    echo "0. Exit"
    read -p "Choice: " OPTION

    case $OPTION in
        1) passive_recon ;;
        2) port_scanning ;;
        3) service_enum ;;
        4) auto_attacks ;;
        5)
            passive_recon
            port_scanning
            service_enum
            auto_attacks
            ;;
        0)
            echo -e "${RED}Exiting ReconBreaker...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
done
