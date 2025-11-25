# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 4.x     | :white_check_mark: |
| 3.x     | :x:                |

## Reporting a Vulnerability

We take the security of this framework seriously. If you discover a vulnerability in **ssf** itself (e.g., it leaks your API keys or executes unsafe code), please report it immediately.

### How to Report
Please email security findings to **security@example.com** (replace with actual email) or open a **Private GitHub Advisory**.

**DO NOT** open a public issue for sensitive security vulnerabilities.

### What to Include
- Description of the vulnerability.
- Steps to reproduce.
- Potential impact.

## Responsible Disclosure
We commit to acknowledging your report within 48 hours and providing a timeline for a fix. We ask that you refrain from public disclosure until a patch has been released.

## Tool Safety
**ssf** is a read-heavy auditing tool, but it does perform some active testing (e.g., RPC execution, Brute-force).
- **Production Use**: Use with caution. While `ssf` attempts to be non-destructive, executing unknown RPCs can have side effects.
- **AI Data Privacy**: When using `--agent`, scan summaries are sent to Google Gemini. Do not use this feature if your schema names or finding details are considered strictly confidential/proprietary and cannot be shared with a third-party LLM processor.
