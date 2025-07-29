# Kebercon 🛡️

**Kerberoasting Recon Tool for Active Directory**  
A PowerShell-based tool to automate reconnaissance of Kerberoastable accounts across trusted domains.

## 🔍 Features

- Enumerates trusted AD domains
- Detects roastable accounts (SPNs + RC4)
- Detects AS-REP roastable users
- Identifies stale accounts (180+ days)
- Checks for weak password hygiene (e.g. `PasswordNeverExpires`)
- Optional integration with Rubeus for ticket extraction

## ⚙️ Usage

```powershell
.\kebercon.ps1

Optional flags:

-NonDomainMode — skip domain enumeration (fallback to local domain)

-ExfilMode — enables Rubeus module (you must add the binary)

📂 Output
Results are saved in the Kebercon-Results folder.

🧠 Notes
You must run this from a domain-joined system with AD PowerShell module installed. Use with appropriate permissions.

🔐 Ethical Use
This tool is for educational and authorized testing only. Unauthorized use is prohibited.

📜 License
MIT license
