  GNU nano 8.4                                                                                                                                                                                                                                                                                                        scansage01.py                                                                                                                                                                                                                                                                                                                  # scansage.py

# This tool parses Nmap and OpenVAS scan results and stores them in SQLite.
# Streamlit is used to create visual dashboards.

import os
import glob
import re
import sqlite3
import argparse
import xml.etree.ElementTree as ET

# === Argument Parser ===
parser = argparse.ArgumentParser(description="ScanSage Parser")
parser.add_argument('--internal', type=str, default="./internal", help="Root folder with Nmap txt results")
parser.add_argument('--openvas', type=str, default="./openvas_scans", help="Path to OpenVAS scan folder")
parser.add_argument('--db', type=str, default="./output/vuln01_data.db", help="Path to SQLite DB file")
args = parser.parse_args()

ROOT_FOLDER = args.internal
OPENVAS_FOLDER = args.openvas
DB_FILE = args.db

# === DB Setup ===
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                        ip TEXT PRIMARY KEY,
                        hostname TEXT
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS services (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         ip TEXT,
                         port INTEGER,
                         protocol TEXT,
                         service_name TEXT,
                         version TEXT,
                         FOREIGN KEY (ip) REFERENCES hosts (ip)
                        )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       ip TEXT,
                       port INTEGER,
                       cve TEXT,
                       severity TEXT,
                       description TEXT,
                       solution TEXT,
                       FOREIGN KEY (ip) REFERENCES hosts (ip)
                       )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS parsed_files (
                       filename TEXT PRIMARY KEY
                     )''')
    conn.commit()
    return conn

# === Nmap result parser ===
def parse_nmap_file(file_path, conn):
    with open(file_path, "r") as file:
        content = file.read()

    hosts = re.findall(r"Nmap scan report .*?\n", content)
    for host in hosts:
        ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", host)
        ip = ip_match.group(0) if ip_match else None
        hostname = host.strip() if ip != host.strip() else None

        if ip:
            conn.execute("INSERT OR IGNORE INTO hosts (ip, hostname) VALUES (?, ?)", (ip, hostname))

        port_sections = re.findall(rf"{re.escape(host)}.*?(\n\d+/\w+.+?)(?=\n\n|Nmap scan report|$)", content, re.DOTALL)
        for section in port_sections:
            for line in section.splitlines():
                parts = line.split()
                if len(parts) >= 3 and "/" in parts[0]:
                    port_proto = parts[0].split("/")
                    port = int(port_proto[0])
                    protocol = port_proto[1]
                    service_name = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    conn.execute('''INSERT INTO services (ip, port, protocol, service_name, version)
                                    VALUES (?, ?, ?, ?, ?)''', (ip, port, protocol, service_name, version))
    conn.commit()

# === Recursive Nmap txt discovery ===
def parse_all_vuln_txt_files(ROOT_FOLDER, conn):
    for dirpath, dirnames, filenames in os.walk(ROOT_FOLDER):
        if dirpath.endswith("_results"):
            for filename in filenames:
                if filename.endswith("_vuln.txt"):
                    file_path = os.path.join(dirpath, filename)
                    print(f"[+] Parsing {file_path}")
                    parse_nmap_file(file_path, conn)

# === OpenVAS XML Parser ===
def parse_openvas_file(file_path, conn):
    filename = os.path.basename(file_path)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM parsed_files WHERE filename = ?", (filename,))
    if cur.fetchone():
        print(f"[-] Skipping already parsed file: {filename}")
        return

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for result in root.findall(".//result"):
            ip_elem = result.find(".//host")
            ip = ip_elem.text if ip_elem is not None else None

            port_str = result.findtext("port")
            port = None
            if port_str:
                port_num = port_str.split("/")[0]
                if port_num.isdigit():
                    port = int(port_num)

            cve = result.findtext(".//nvt/cve")
            if not cve:
                for ref in result.findall(".//nvt/refs/ref[@type='cve']"):
                    cve = ref.attrib.get("id")
                    if cve:
                        break

            severity = result.findtext("severity")
            description = result.findtext("description")
            solution = result.findtext(".//nvt/solution") or result.findtext("solution")

            if ip and (cve or description):
                conn.execute('''INSERT INTO vulnerabilities (ip, port, cve, severity, description, solution)
                                VALUES (?, ?, ?, ?, ?, ?)''', (ip, port, cve, severity, description, solution))

        conn.execute("INSERT INTO parsed_files (filename) VALUES (?)", (filename,))
        conn.commit()
    except Exception as e:
        print(f"[!] Failed to parse OpenVAS file {file_path}: {e}")

# === Main logic ===
def main():
    conn = init_db()
    print("[!] Initialised database")

    parse_all_vuln_txt_files(ROOT_FOLDER, conn)

    for root, _, files in os.walk(OPENVAS_FOLDER):
        for filename in files:
            if filename.endswith(".xml"):
                path = os.path.join(root, filename)
                print(f"[+] Parsing OpenVAS: {filename}")
                parse_openvas_file(path, conn)

    conn.close()
    print("[:)] All data stored in SQLite")

# === Entry Point ===
if __name__ == "__main__":
    main()

#First commit for ScanSage module
