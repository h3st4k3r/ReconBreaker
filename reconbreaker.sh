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
    echo -e "${YELLOW}[*] Starting Phase 2: Port Scanning on ${TARGET}${NC}"
    
    SCAN_DIR="$TARGET/2_scan"
    FULL_SCAN="$SCAN_DIR/nmap_full.txt"
    SERVICE_SCAN="$SCAN_DIR/nmap_services.txt"

    echo -e "${BLUE}[+] Running full TCP port scan (-p-)...${NC}"
    nmap -sS -Pn -T4 -p- --min-rate=5000 $TARGET -oN "$FULL_SCAN"

    echo -e "${BLUE}[+] Extracting open ports...${NC}"
    OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$FULL_SCAN" | cut -d'/' -f1 | paste -sd, -)

    if [ -z "$OPEN_PORTS" ]; then
        echo -e "${RED}[!] No open ports found. Skipping service scan.${NC}"
    else
        echo -e "${BLUE}[+] Open ports found: ${OPEN_PORTS}${NC}"
        echo -e "${BLUE}[+] Running service/version detection...${NC}"
        nmap -sC -sV -p$OPEN_PORTS $TARGET -oN "$SERVICE_SCAN"
    fi

    echo -e "${GREEN}[✔] Port scanning completed. Output saved in: $SCAN_DIR${NC}"
}

# ------------ FASE 3: Service Enumeration ------------
service_enum() {
    echo -e "${YELLOW}[*] Starting Phase 3: Service Enumeration${NC}"

    ENUM_DIR="$TARGET/3_enum"
    SERVICE_FILE="$TARGET/2_scan/nmap_services.txt"

    if [ ! -f "$SERVICE_FILE" ]; then
        echo -e "${RED}[!] Service scan not found. Please run Phase 2 first.${NC}"
        return
    fi

    echo -e "${BLUE}[+] Parsing services from nmap_services.txt...${NC}"

    # HTTP/HTTPS enum with gobuster
    if grep -E "http|https" "$SERVICE_FILE" | grep -q "open"; then
        echo -e "${BLUE}[+] Web service detected. Running gobuster...${NC}"
        mkdir -p "$ENUM_DIR/web"
        gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -t 20 -o "$ENUM_DIR/web/gobuster_http.txt"
    fi

    # SMB enum with enum4linux
    if grep -E "microsoft-ds|netbios-ssn|smb" "$SERVICE_FILE" | grep -q "open"; then
        echo -e "${BLUE}[+] SMB service detected. Running enum4linux...${NC}"
        mkdir -p "$ENUM_DIR/smb"
        enum4linux-ng -A $TARGET > "$ENUM_DIR/smb/enum4linux.txt"
    fi

    # FTP enum
    if grep -q "ftp" "$SERVICE_FILE"; then
        echo -e "${BLUE}[+] FTP service detected. Running basic anonymous login test...${NC}"
        mkdir -p "$ENUM_DIR/ftp"
        echo -e "open $TARGET\nuser anonymous\npass ftp@\nls\nquit" | ftp -n > "$ENUM_DIR/ftp/ftp_anonymous_test.txt"
    fi

    echo -e "${GREEN}[✔] Service enumeration completed. Output saved in: $ENUM_DIR${NC}"
}

# ------------ FASE 4: Offensive Checks ------------
auto_attacks() {
    echo -e "${YELLOW}[*] Starting Phase 4: Offensive Checks${NC}"

    ATTACK_DIR="$TARGET/4_attacks"
    SERVICE_FILE="$TARGET/2_scan/nmap_services.txt"

    if [ ! -f "$SERVICE_FILE" ]; then
        echo -e "${RED}[!] Service scan not found. Please run Phase 2 first.${NC}"
        return
    fi

    mkdir -p "$ATTACK_DIR"

    # Nikto web scan
    if grep -E "http|https" "$SERVICE_FILE" | grep -q "open"; then
        echo -e "${BLUE}[+] Web service detected. Running nikto...${NC}"
        nikto -h http://$TARGET -output "$ATTACK_DIR/nikto_web.txt"
    fi

    # Searchsploit lookup
    echo -e "${BLUE}[+] Extracting service versions for searchsploit...${NC}"
    grep -E "open\s+[^ ]+\s+[0-9]*/tcp" "$SERVICE_FILE" | while read -r line; do
        SERVICE_NAME=$(echo "$line" | awk '{print $3}')
        VERSION=$(echo "$line" | cut -d ' ' -f 4-)
        if [[ ! -z "$VERSION" ]]; then
            echo -e "${YELLOW}[*] Searching exploits for $SERVICE_NAME $VERSION...${NC}"
            echo "Service: $SERVICE_NAME $VERSION" >> "$ATTACK_DIR/searchsploit_results.txt"
            searchsploit "$SERVICE_NAME $VERSION" >> "$ATTACK_DIR/searchsploit_results.txt"
            echo "------------------------------------------------" >> "$ATTACK_DIR/searchsploit_results.txt"
        fi
    done

    echo -e "${GREEN}[✔] Offensive checks completed. Output saved in: $ATTACK_DIR${NC}"
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
