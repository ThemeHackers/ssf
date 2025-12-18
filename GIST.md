# SSF (Supabase Security Framework) - Quick Reference Gist

> A shareable reference for the **ssf** security auditing framework for Supabase projects.

## 📦 Quick Installation

```bash
# Install from PyPI
pip3 install supabase-audit-framework --upgrade

# Or run with Docker
docker run -it ghcr.io/themehackers/ssf --help
```

## 🚀 Basic Usage

```bash
# Basic scan
ssf <SUPABASE_URL> <ANON_KEY>

# Advanced scan with AI analysis and HTML report
ssf <URL> <KEY> --agent-provider gemini --agent gemini-2.0-flash --agent-key "YOUR_API_KEY" --brute --html --json

# CI/CD mode with SARIF output
ssf <URL> <KEY> --ci --sarif --json --fail-on HIGH
```

## 📋 Common Scan Options

| Flag | Description |
|------|-------------|
| `--brute` | Enable dictionary attack for hidden tables |
| `--html` | Generate HTML report |
| `--json` | Save results to JSON |
| `--sarif` | Generate SARIF report for GitHub Security |
| `--ci` | Exit with non-zero code on critical issues |
| `--stealth` | Enable JA3 spoofing for WAF bypass |
| `--webui` | Launch Web Management Dashboard |

## 🔗 Links

- **GitHub**: [ThemeHackers/ssf](https://github.com/ThemeHackers/ssf)
- **PyPI**: [supabase-audit-framework](https://pypi.org/project/supabase-audit-framework/)
- **Documentation**: See [README.md](https://github.com/ThemeHackers/ssf#readme)

---
*This gist is a quick reference for the SSF project. For full documentation, visit the GitHub repository.*
