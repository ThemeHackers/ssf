# Security Policy

## 🚨 Critical Disclaimer: Authorized Use Only

**ssf (Supabase Security Framework)** is a dual-purpose security tool designed for **defensive auditing** and **offensive verification**.

- **You must have explicit, written authorization** from the project owner before running this tool against any Supabase instance.
- **Unauthorized use is illegal.** The developers assume no liability and are not responsible for any misuse or damage caused by this program.
- This tool includes features that **actively exploit** vulnerabilities (e.g., SQL Injection verification, Exploit Runner). Use with extreme caution.

## Supported Versions

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 4.x     | :white_check_mark: | Active Development |
| 3.x     | :x:                | End of Life |

## Reporting a Vulnerability

We take the security of `ssf` seriously. If you discover a vulnerability in the framework itself (e.g., it leaks your API keys locally, executes arbitrary code from a server response, or has a dependency vulnerability), please report it immediately.

### ❌ NOT a Vulnerability
The following are **features**, not bugs, and should not be reported as vulnerabilities:
- The tool finding a vulnerability in *your* Supabase project (that's the point!).
- The tool executing RPCs that delete data (if you ran it against a production DB with a dangerous RPC exposed).
- The AI suggesting an exploit that works.

### ✅ How to Report
Please email security findings to **security@kpltgroup.com** (replace with actual email) or open a **Private GitHub Advisory**.

**DO NOT** open a public issue for sensitive security vulnerabilities in the tool itself.

### What to Include
- Description of the vulnerability in `ssf`.
- Steps to reproduce (e.g., "Malicious Supabase server can crash `ssf` client via X").
- Potential impact.

## Tool Safety & Active Testing

`ssf` is **NOT** a passive scanner. It performs active testing that can modify state or degrade performance.

### 1. RPC Execution (`--scan-rpc`)
- The scanner **executes** exposed RPCs (Remote Procedure Calls) using placeholder data.
- **Risk**: If you have an RPC like `delete_all_users()` exposed to `anon`, **this tool will execute it**.
- **Mitigation**: Run against a **staging/development** environment first.

### 2. SQL Injection Fuzzing
- The tool injects SQL payloads (e.g., `' OR 1=1`, `pg_sleep()`) into RPC parameters to test for injection flaws.
- **Risk**: Potential data corruption or performance degradation (DoS) if the database is weak.

### 3. Brute-Force (`--brute`)
- Performs high-frequency HTTP requests to guess hidden table names.
- **Risk**: Can trigger rate limits or WAFs.

### 4. Exploit Runner (`core/exploit.py`)
- This module **executes** generated exploits.
- **Risk**: High. This is an offensive capability intended for Red Teaming. **Never run this with auto-confirm against production.**

## Data Privacy (AI Analysis)

When using the `--agent` flag, `ssf` integrates with Google Gemini.

- **Data Transmitted**:
    - Target URL.
    - Summary of findings (table names, RPC names, row counts).
    - **Sample Data**: The tool sends snippets of leaked data (first 5 rows) to the AI to assess business impact (e.g., "Does this look like PII?").
- **Opt-Out**: Do not use the `--agent` flag. The core scanning logic works entirely locally.
- **Data Retention**: Data is processed by Google according to their API terms.

## Responsible Disclosure

We commit to acknowledging your report within 48 hours and providing a timeline for a fix. We ask that you refrain from public disclosure until a patch has been released.
