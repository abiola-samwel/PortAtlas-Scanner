# 🚀 PortAtlas – Advanced Network Port Scanner

PortAtlas is a **fast, efficient, and extensible port scanner** written in Python.  
It supports comprehensive port scanning, service detection, banner grabbing, OS guessing, and stealth scanning techniques (SYN, FIN, NULL).  

Designed for **security professionals, researchers, and developers**, PortAtlas provides both a **CLI tool** and a **REST API (FastAPI)** interface.

---

## ✨ Core Features

- 🔍 **Comprehensive Scanning** – Supports full range (1–65535) TCP & UDP ports  
- 🛰 **Service Detection** – Identifies common services & versions (HTTP, SSH, DNS, PostgreSQL, Redis, MongoDB, etc.)  
- 📜 **Banner Grabbing** – Fetches raw service banners for fingerprinting  
- 🖥 **OS Guessing** – Lightweight OS inference from banners & service data  
- 🕵 **Stealth Scans** – SYN, FIN, NULL scan modes to bypass firewalls/IDS  
- ⚡ **Optimized Performance** – Asynchronous scanning for speed  
- 🔐 **Security** – API key support, audit logging, and local/secure modes  
- 📊 **Rich Output** – JSON results + colored table CLI view  
- 🛠 **Error Handling** – Gracefully handles timeouts, filtered ports, and unreachable hosts  

---

## 📦 Installation

### Requirements
- Python **3.9+**

Install dependencies:
```bash
pip install -r requirements.txt
```

### Clone & Setup
```bash
git clone https://github.com/abiola-samwel/PortAtlas-Scanner
cd PortAtlas-Scanner
pip install -r requirements.txt
```

---

## 🚀 Usage

### Using the CLI (`test_scan.py`)

PortAtlas includes a command-line tool (`test_scan.py`) for scanning hosts directly from your terminal.  

#### Basic Syntax
```bash
python test_scan.py <target> <ports> [OPTIONS]
```

#### Arguments
- `<target>` → Host/IP to scan (e.g., `8.8.8.8`)  
- `<ports>` → Port(s) or range (e.g., `22`, `80,443`, `1-1000`)  

#### Options
- `--type` → Scan type (`tcp_connect`, `syn`, `fin`, `null`, `udp`)  
- `--banner` → Enable banner grabbing  
- `--all` → Scan all 65535 ports  
- `--no-json` → Show only table output (no JSON)  
- `--ignore-errors` → Suppress warnings/errors in output  
- `--api-key` → Use API key (if backend hosted)  
- `--debug` → Verbose debug mode  

#### Examples
```bash
# Scan a single port
python test_scan.py 8.8.8.8 22

# Scan multiple ports
python test_scan.py 8.8.8.8 22,80,443

# Scan a range of ports
python test_scan.py 8.8.8.8 1-1000

# Enable banner grabbing
python test_scan.py 8.8.8.8 22,80 --banner

# Perform a stealth SYN scan
python test_scan.py 8.8.8.8 22,80 --type syn
```


### CLI Mode
```bash
python test_scan.py <target> <ports> [OPTIONS]
```

**Arguments:**
- `<target>` – Host/IP to scan (e.g., `8.8.8.8`)  
- `<ports>` – Ports/range (e.g., `22,80,443` or `1-1000`)  

**Options:**
- `--type` – Scan type (`tcp_connect | syn | fin | null | udp`)  
- `--banner` – Enable banner grabbing  
- `--all` – Scan all 65535 ports  
- `--no-json` – Suppress JSON output, table view only  
- `--ignore-errors` – Suppress warnings/errors in output  
- `--api-key` – Use secure mode with API key (if backend hosted)  
- `--debug` – Verbose debug mode  

**Example:**
```bash
python test_scan.py 8.8.8.8 22,80 --banner
```

---

### API Mode
Run the backend:
```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Example API request:
```bash
curl -X POST "http://127.0.0.1:8000/scan"   -H "Content-Type: application/json"   -d '{"target":"8.8.8.8","ports":"22,80","type":"tcp_connect","banner":true}'
```

---

## ⚠️ Legal Disclaimer
This tool is for **educational and authorized testing purposes only**.  
Do not scan networks or systems without explicit permission. Unauthorized scanning is **illegal**.

---

## 📂 Project Structure
```
backend/
  app/
    main.py       # FastAPI backend
    scanner.py    # Core scanning logic
test_scan.py      # CLI tool
docs/             # Documentation & cheat sheets

```

---

## 📝 License
This project is released under the **MIT License**.

---

## 👨‍💻 Author
Developed by **Abiola Samwel** – Contributions welcome!
