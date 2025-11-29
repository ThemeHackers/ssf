# Supabase Security Framework (ssf) v2.0

![Banner](https://img.shields.io/badge/Supabase-Security-green) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![License](https://img.shields.io/badge/License-MIT-yellow) ![Status](https://img.shields.io/badge/Maintained-Yes-brightgreen)

**ssf** is an enterprise-grade, asynchronous security auditing framework for Supabase projects. It goes beyond simple configuration checks to **actively test** for vulnerabilities like SQL Injection, IDOR, and Information Leakage.

## 🌟 Why ssf?

- **🛡️ Active Verification**: Don't just guess; verify. `ssf` attempts safe exploits (e.g., time-based SQLi) to confirm risks.
- **🤖 AI-Powered Context**: Integrates with **Google Gemini** to understand *your* specific schema and business logic for deeper insights.
- **⚙️ CI/CD Ready**: JSON output and diffing capabilities (`--diff`) make it perfect for automated security pipelines.
- **🧠 Smart Fuzzing**: Uses context-aware payloads to detect hidden data leaks in RPCs.

## ⚡ Key Capabilities

| Feature | Description |
| :--- | :--- |
| **RLS Analysis** | Detects tables with missing or permissive Row Level Security policies. |
| **Auth Leaks** | Identifies public tables exposing user data (PII). |
| **RPC Security** | Enumerates and **fuzzes** executable Remote Procedure Calls for SQLi and leaks. |
| **Storage Buckets** | Checks for public write access and listing capabilities. |
| **Realtime Channels** | Detects open WebSocket channels and **sniffs** for sensitive events (`--sniff`). |
| **PostgREST Config** | Checks for dangerous configuration like unlimited `max_rows` (`--check-config`). |
| **Edge Functions** | Enumerates public Edge Functions. |
| **Database Extensions** | Detects 30+ extensions (e.g., `pg_cron`, `pg_net`) and assesses security risks. |
| **GraphQL** | Checks for introspection leaks, **Query Depth**, and **Field Fuzzing**. |

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ThemeHackers/ssf
   cd ssf
   ```

2. **Install dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip3 install -r requirements.txt
   ```

## 🛠️ Usage

### Basic Scan
```bash
python3 ssf.py <SUPABASE_URL> <ANON_KEY>
```

### Advanced Scan (Recommended)
Enable AI analysis, brute-forcing, and HTML reporting:
```bash
# Using Gemini (Cloud)
python3 ssf.py <URL> <KEY> --agent-provider gemini --agent gemini-2.0-flash --agent-key "YOUR_API_KEY" --brute --html --json

# Using OpenAI (GPT-4)
python3 ssf.py <URL> <KEY> --agent-provider openai --agent gpt-4-turbo --agent-key "sk-..." --brute --html --json

# Using Anthropic (Claude)
python3 ssf.py <URL> <KEY> --agent-provider anthropic --agent claude-3-5-sonnet-20240620 --agent-key "sk-ant-..." --brute --html --json

# Using DeepSeek (DeepSeek-V3)
python3 ssf.py <URL> <KEY> --agent-provider deepseek --agent deepseek-chat --agent-key "sk-..." --brute --html --json

# Using Ollama (Local)
python3 ssf.py <URL> <KEY> --agent-provider ollama --agent llama3 --brute --html --json
```

> [!TIP]
> For Gemini, you can set the `GEMINI_API_KEY` environment variable instead of passing `--agent-key`.

### Continuous Integration (CI) Mode
Block regressions by comparing against a baseline:
```bash
# 1. Generate baseline
python3 ssf.py <URL> <KEY> --json > baseline.json

# 2. Compare in CI
python3 ssf.py <URL> <KEY> --json --diff baseline.json
```

### 🧠 Static Code Analysis
Scan your local source code for Supabase-specific vulnerabilities (e.g., hardcoded keys, weak RLS definitions in migrations):
```bash
python3 ssf.py <URL> <KEY> --agent-provider gemini --agent-key "KEY" --analyze ./supabase/migrations
```

### 🛠️ Automated Remediation
Generate a SQL script to fix identified vulnerabilities:
```bash
python3 ssf.py <URL> <KEY> --agent-provider gemini --agent-key "KEY" --gen-fixes
```

### 🎭 Multi-Role Testing
Test for vertical escalation by providing multiple role tokens:
```bash
# roles.json: {"user1": "eyJ...", "admin": "eyJ..."}
python3 ssf.py <URL> <KEY> --roles roles.json
```

### 🤖 Automated Threat Modeling
Generate a comprehensive threat model (DFD, Attack Paths) using AI:
```bash
python3 ssf.py <URL> <KEY> --agent-provider gemini --agent-key "KEY" --threat-model
```
## Managing Accepted Risks
Create a knowledge.json file to ignore known safe patterns:
```bash
{
  "accepted_risks": [
    {
      "pattern": "public_stats",
      "type": "rls",
      "reason": "Intentionally public dashboard data"
    }
  ]
}
```


### ✅ Advanced Risk Acceptance
Verify if accepted risks have been remediated and update the knowledge base:
```bash
python3 ssf.py <URL> <KEY> --knowledge knowledge.json --verify-fix
```

## 📊 Sample Output

```text
[*] Testing RPC: get_user_data
    [!] DATA LEAK via RPC 'get_user_data' → 5 rows
    [!] Potential SQL Injection in get_user_data (param: id) - Verifying...
    [!!!] CONFIRMED Time-Based SQL Injection in get_user_data (5.02s)
```

## 🛡️ Security & Liability

> [!WARNING]
> **Active Testing Warning**: This tool performs active exploitation verification (e.g., SQL Injection fuzzing, RPC execution).

- **Authorized Use Only**: You must have explicit permission to scan the target.
- **Data Privacy**: Using `--agent` sends scan summaries to Google Gemini.

👉 **Read our full [Security Policy](SECURITY.md) before use.**

### Local AI Support (Ollama)
Run scans using local LLMs (e.g., Llama 3) for privacy and offline usage:
```bash
# Ensure Ollama is running (ollama serve)
python3 ssf.py <URL> <KEY> --agent-provider ollama --agent llama3
```

### 🎭 Tamper Scripts (WAF Bypass)
Use built-in tamper scripts or custom ones to bypass WAFs:
```bash
# Use built-in tamper
python3 ssf.py <URL> <KEY> --tamper randomcase

# Available built-ins:
# - randomcase: SeLECt * fRoM...
# - charencode: URL encode
# - doubleencode: Double URL encode
# - unionall: UNION SELECT -> UNION ALL SELECT
# - space2plus: space -> +
# - version_comment: space -> /*!50000*/
```

## 📝 Arguments

| Argument | Description |
|----------|-------------|
| `url` | Target Supabase Project URL |
| `key` | Public Anon Key |
| `--agent-provider <NAME>` | AI Provider: `gemini` (default), `ollama`, `openai`, `deepseek`, `anthropic` |
| `--agent <MODEL>` | AI Model Name (e.g., `gemini-3-pro-preview`, `llama3`, `gpt-4`) |
| `--agent-key <KEY>` | AI API Key (for Gemini/OpenAI/DeepSeek/Anthropic) |
| `--brute` | Enable dictionary attack for hidden tables |
| `--html` | Generate a styled HTML report |
| `--json` | Save raw results to JSON |
| `--diff <FILE>` | Compare current scan vs previous JSON report |
| `--knowledge <FILE>` | Path to accepted risks JSON file |
| `--ci` | Exit with non-zero code on critical issues (for CI/CD) |
| `--fail-on <LEVEL>` | Risk level to fail on (default: HIGH) |
| `--ci-format <FMT>` | CI Output format (text/github) |
| `--proxy <URL>` | Route traffic through an HTTP proxy |
| `--exploit` | **DANGER**: Auto-run generated exploits |
| `--gen-fixes` | Generate SQL fix script from AI analysis |
| `--analyze <PATH>` | Perform static analysis on local code files |
| `--edge_rpc <FILE>`| Custom wordlist for Edge Functions |
| `--roles <FILE>` | JSON file with role tokens for vertical escalation testing |
| `--threat-model` | Generate Automated Threat Model (requires --agent) |
| `--verify-fix` | Verify remediation of accepted risks |
| `--compile` | Compile tool to standalone executable |
| `--verbose` | Enable debug logging |
| `--dump-all` | Dump all data from the database |
| `--sniff [SEC]` | Enable Realtime Sniffer for N seconds (default: 10) |
| `--check-config` | Check PostgREST configuration (max_rows) |
| `--update` | Update the tool to the latest version |
| `--wizard` | Run in wizard mode for beginners |
| `--random-agent` | Use a random User-Agent header |
| `--level <LEVEL>` | Level of tests to perform (1-5, default 1) |
| `--tamper <NAME>` | Tamper script name (built-in) or path to file |

## ⚠️ Disclaimer

The developers assume no liability and are not responsible for any misuse or damage caused by this program. Use responsibly.
