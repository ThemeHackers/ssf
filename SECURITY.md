# Security Policy

This file explains the security policy of ssf.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Reporting a Vulnerability
If you discover a security vulnerability within ssf, please send an e-mail to **tigerzaza5678@gmail.com**.

### What to include in your report

Please include as much detail as possible to help us reproduce the issue:
- A description of the vulnerability.
- Steps to reproduce the issue.
- Potential impact of the vulnerability.
- Any proof-of-concept code or screenshots.

### False Positives vs. Vulnerabilities

Since `ssf` is a security scanning tool, you may encounter:
1.  **False Positives in Scan Results**: If the tool reports a vulnerability in your target that isn't real, please open a GitHub Issue instead of a security report.
2.  **Vulnerabilities in the Tool Itself**: If you find a flaw in `ssf` that could compromise the user running it (e.g., RCE via malicious target), please report it via email.

### Response Timeline

We are committed to addressing security issues promptly.
- We will acknowledge receipt of your report within 48 hours.
- We will provide a status update every 5 business days.
- We aim to fix critical vulnerabilities within 14 days.

## Disclosure Policy

- Please do not disclose the vulnerability publicly until we have had a chance to fix it.
- We will credit you for your discovery if you wish.
- We generally follow a 90-day disclosure deadline, meaning we will publish details of the vulnerability 90 days after the initial report, or sooner if a fix is released.

## Scope

This policy applies to the ssf codebase hosted in this repository.
External dependencies are out of scope, but if you find an issue in a dependency that affects ssf, please let us know.

Thank you for helping keep ssf secure!
