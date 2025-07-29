# HealthCheck

**HealthCheck** is a modular C# system diagnostic and behavior analysis utility.

> ⚠️ Disclaimer: This is *not* a real health check tool. It is a **security research utility** intended for lab use to analyze how security software (like EDRs) behaves when various benign or suspicious system actions are performed.

### ⚙️ Purpose

- Help analysts observe what Windows actions are flagged by EDRs
- Learn what is baseline system behavior vs. flagged activities
- Enable modular and safe expansion to simulate recon or attack patterns

### 📦 Current Modules

- Basic system info dump
- List non-Microsoft, non-running services
- Attempt to read sensitive registry hives (read-only)
- Dump scheduled tasks (via `schtasks`)
- Show current user’s group memberships

### 🔒 Safety Notes

- This tool does **not** perform any malicious actions.
- Write operations are **commented out by default**.
- No persistence, exfiltration, or privilege escalation is included.
- Future modules (like simulated registry writes or process spawning) can be added carefully for *lab only* usage.

### 🧰 Requirements

- .NET-compatible compiler (like `csc.exe`)
- Local user privileges (some actions may require elevation to observe access errors)

### 🚧 Disclaimer

This tool is under development and is meant for educational/research purposes **only**. You are responsible for its use.
