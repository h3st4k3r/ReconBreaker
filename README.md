# ReconBreaker

Tool for performing pentesting, CTFs, eJPT, and OSCP prep in an automated way (initial phases).

> Made by **h3st4k3r** for fast and modular recon, scan & enum workflows in Kali Linux.

---

## Features

- Menu-driven execution (choose 1 phase, ALL, or Smart Mode)
- Creates structured folders per target
- Stores all outputs per phase as evidences
- Context-aware logic (SMART mode)
- Includes user fuzzing, CVE matching, nuclei, searchsploit, etc.
- Modular & hackable Bash code
- NEW: Exploit Launch Helper for fast post-recon actions

---

## Quick Start

```bash
chmod +x reconbreaker.sh
./reconbreaker.sh
```

You’ll be prompted to enter a target (IP or domain), then shown a menu:

```
1. Passive Recon
2. Port Scanning
3. Service Enumeration
4. Offensive Checks
5. User Fuzzing
6. Run ALL previous phases
--------------------------
7. Smart Auto Mode (recommended)
--------------------------
8. Exploit Launch Helper (suggestions)
--------------------------
0. Exit
```

---

## Output Structure

```
<TARGET>/
├── 1_recon/
│   ├── whois.txt
│   ├── nslookup.txt
│   └── dig.txt
├── 2_scan/
│   ├── nmap_full.txt
│   └── nmap_services.txt
├── 3_enum/
│   ├── web/
│   │   ├── gobuster_http.txt
│   │   ├── whatweb.txt
│   │   └── headers.txt
│   ├── smb/enum4linux.txt
│   └── ftp/ftp_anonymous_test.txt
├── 4_attacks/
│   ├── nikto_web.txt
│   ├── searchsploit_results.txt
│   ├── nmap_cve_match.txt
│   └── nuclei_results.txt
└── 5_creds/
    └── fuzz/
        ├── ftp_user_fuzz.txt
        ├── ssh_user_fuzz.txt
        └── ...
```

---

## Dependencies

Make sure these tools are installed in Kali:

- `nmap`
- `whois`
- `dnsutils` (for `nslookup`, `dig`)
- `gobuster`
- `enum4linux-ng`
- `ftp`
- `nikto`
- `searchsploit`
- `hydra`
- `whatweb`
- `curl`
- `nuclei` + templates

Install base tools:

```bash
sudo apt update && sudo apt install nmap whois dnsutils gobuster enum4linux-ng ftp nikto exploitdb hydra whatweb curl
```

Install nuclei manually (recommended):

```bash
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
mv ~/go/bin/nuclei /usr/local/bin/
nuclei -update-templates
```

---

## Intended Use

This tool is designed for:

- CTFs & HackTheBox challenges
- eJPT / OSCP lab automation
- Recon workflows in internal pentests

> Use only in **authorized** and ethical environments.

---

## Disclaimer

This tool is provided for **educational and lawful use only**. Any misuse is the sole responsibility of the user.

---

## Author

**h3st4k3r**

Built with ❤️ for learning, hacking, and speed.

> "The quieter you become, the more you are able to hear."

