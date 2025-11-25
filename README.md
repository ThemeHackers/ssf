# Supabase Security Framework (ssf) v4.0

![Banner](https://img.shields.io/badge/Supabase-Security-green) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![License](https://img.shields.io/badge/License-MIT-yellow)

**ssf** is an enterprise-grade, asynchronous security auditing framework for Supabase projects. It proactively identifies misconfigurations, exposed data, and insecure functions before attackers can exploit them.

## 🚀 Key Features

- **🛡️ Comprehensive Scanning**:
    - **RLS Analysis**: Detects tables with missing or permissive Row Level Security policies.
    - **Auth Leaks**: Identifies public tables exposing user data (PII).
    - **RPC Security**: Enumerates and tests executable Remote Procedure Calls.
    - **Storage Buckets**: Checks for public write access and listing capabilities.
    - **Realtime Channels**: Detects open WebSocket channels broadcasting sensitive events.
    - **Edge Functions**: Enumerates public Edge Functions.
    - **GraphQL**: Checks for introspection leaks.

- **🤖 AI-Powered Assessment**:
    - Integrates with **Google Gemini 1.5 Pro** (8k context).
    - Provides **Business Impact Analysis**, **Technical Risk Assessment**, and **Step-by-Step Remediation**.
    - Injects a specialized **Supabase Security Knowledge Base** for context-aware advice.

- **🧠 Knowledge Framework**:
    - Define **Accepted Risks** via a JSON file (`--knowledge`).
    - Automatically filters known safe findings from reports.

- **📊 Enterprise Reporting**:
    - **HTML Reports**: Beautiful, interactive dashboards.
    - **JSON Reports**: Machine-readable output for CI/CD.
    - **Diff Engine**: Compare scans to detect regressions (`--diff`).
    - **Structured Console Output**: Clean, professional terminal UI.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/supa-sniffer.git
   cd supa-sniffer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Usage

### Basic Scan
```bash
python3 ssf.py <SUPABASE_URL> <ANON_KEY>
```

### Advanced Scan (Recommended)
Enable AI analysis, brute-forcing, and HTML reporting:
```bash
python3 ssf.py <URL> <KEY> --agent "YOUR_GEMINI_API_KEY" --brute --html --json
```

### Continuous Integration (CI) Mode
Compare current results with a previous baseline to block regressions:
```bash

python3 ssf.py <URL> <KEY> --json > baseline.json


python3 ssf.py <URL> <KEY> --json --diff baseline.json
```

### Managing Accepted Risks
Create a `knowledge.json` file to ignore known safe patterns:
```json
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
Run with:
```bash
python3 ssf.py <URL> <KEY> --knowledge knowledge.json
```

## 📝 Arguments

| Argument | Description |
|----------|-------------|
| `url` | Target Supabase Project URL |
| `key` | Public Anon Key |
| `--agent <KEY>` | Google Gemini API Key for AI Analysis |
| `--brute` | Enable dictionary attack for hidden tables |
| `--html` | Generate a styled HTML report |
| `--json` | Save raw results to JSON |
| `--diff <FILE>` | Compare current scan vs previous JSON report |
| `--knowledge <FILE>` | Path to accepted risks JSON file |
| `--verbose` | Enable debug logging |

## ⚠️ Disclaimer

This tool is for **authorized security auditing only**. Usage against targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.