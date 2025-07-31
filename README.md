# ReconBreaker

Tool for performing pentesting, CTFs, eJPT, and OSCP prep in an automated way (initial phases).

> Made by **h3st4k3r** for fast and modular recon, scan & enum workflows in Kali Linux.

---

## Features

- Menu-driven execution (choose 1 phase or all)
- Creates target-based folders
- Stores all outputs as evidence per phase
- Context-aware: decides next actions based on open ports/services
- Modular & hackable Bash code

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
5. Run ALL Phases
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
│   ├── web/gobuster_http.txt
│   ├── smb/enum4linux.txt
│   └── ftp/ftp_anonymous_test.txt
└── 4_attacks/
    ├── nikto_web.txt
    └── searchsploit_results.txt
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

To install them:

```bash
sudo apt update && sudo apt install nmap whois dnsutils gobuster enum4linux-ng ftp nikto exploitdb
```

---

## Intended Use

For:

- CTF challenges
- eJPT/OSCP practice labs
- Internal pentest automation

Use only in **authorized** environments.

---

## Disclaimer

This tool is provided for educational and lawful use only. Any misuse is the sole responsibility of the user.

---

## Author

**h3st4k3r**

Built with ❤️ for learning, hacking, and speed.

> “The quieter you become, the more you are able to hear.”

