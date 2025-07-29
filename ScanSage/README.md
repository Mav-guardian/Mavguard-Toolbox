# ScanSage

**ScanSage** is a lightweight, modular Python-based parser and reporting system designed to correlate results from Nmap and OpenVAS scans. It parses raw results, stores findings in a local SQLite database, and visualizes them via an interactive Streamlit dashboard.

> ⚡ Ideal for Vulnerability Managers who want a fast, local vulnerability correlation tool without a full SIEM or dashboard stack.

---

## 🔧 Features

- Parses Nmap vulnerability `.txt` files (e.g. `_vuln.txt`)
- Parses OpenVAS `.xml` reports with CVEs and metadata
- Automatically builds and updates an SQLite database
- Streamlit dashboard for live interactive exploration:
  - Total hosts/services/vulnerabilities
  - CVE search
  - Vulnerability drilldown per host

---

## 🧪 Setup & Usage

### 1. Requirements
```bash
pip install -r requirements.txt
```

### 2. Run the Parser
```bash
python scansage.py --internal ./internal --openvas ./openvas_scans --db ./output/vuln01_data.db
```

You can customize paths via CLI flags:
- `--internal` → folder with Nmap `_vuln.txt` results
- `--openvas` → folder with OpenVAS `.xml` files
- `--db` → path to SQLite DB

### 3. Launch Dashboard

If you're using WSL or Kali:
```bash
streamlit run strmltdashboard.py
```

Make sure the dashboard script has the correct relative path to the DB:
```python
DB_PATH = "../output/vuln01_data.db"
```

---

## 🧱 Database Schema
- **hosts** (`ip`, `hostname`)
- **services** (`ip`, `port`, `protocol`, `service_name`, `version`)
- **vulnerabilities** (`ip`, `port`, `cve`, `severity`, `description`, `solution`)
- **parsed_files** (tracks parsed OpenVAS XML filenames)

---

## 📁 Project Structure
```
ScanSage/
├── scansage.py            ← Main parser
├── strmltdashboard.py     ← Streamlit app
├── requirements.txt       ← Python dependencies
├── README.md              ← You're reading it
├── .gitignore             ← Clean repo hygiene
└── /output                ← Where SQLite DB will be created
```

---

## ⚠️ Disclaimer
This tool is for authorized security assessments and educational use only. The author assumes no responsibility for misuse.

---

## 📄 License
MIT License — Free to use, modify, and distribute.

---

## 👤 Author
The Mavguardian — Cybersecurity Automation & Recon Tools
