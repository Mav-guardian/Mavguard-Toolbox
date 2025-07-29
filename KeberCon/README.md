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
