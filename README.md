# 🔍 Secret & API Key Detector

A lightweight, zero-dependency Python tool that scans your codebase for hardcoded secrets, API keys, tokens, and passwords — before they end up on GitHub.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-6366f1?style=flat-square)

---

## ✨ Features

- 🛡 **50+ detection patterns** — AWS, GitHub, Stripe, OpenAI, JWT, database URIs, and more
- 🎯 **Severity levels** — CRITICAL / HIGH / MEDIUM / LOW with color-coded terminal output
- 🌐 **HTML report** — beautiful dark-theme visual report with interactive severity filters
- 💾 **JSON report** — structured output for CI/CD pipelines and integrations
- 🔒 **Privacy-safe** — personal paths (username, OneDrive, Desktop) are never written to reports
- ⚡ **Zero dependencies** — pure Python standard library, nothing to install
- 🚀 **CI/CD ready** — `--exit-code` flag returns exit code 1 when secrets are found

---

## 📦 Files

| File | Description |
|------|-------------|
| `secret_detector.py` | Main scanner — run this |
| `index.html` | Visual dashboard — load your `report.json` to explore findings |

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/your-username/secret-detector.git
cd secret-detector

# Scan current directory
python secret_detector.py .
```

No pip install needed. Works with Python 3.10+.

---

## 📖 Usage

```bash
python secret_detector.py [PATH] [OPTIONS]
```

### Examples

```bash
# Scan a single file
python secret_detector.py config.py

# Scan an entire project folder
python secret_detector.py ./my-project

# Only show HIGH and CRITICAL findings (reduce noise)
python secret_detector.py . --severity HIGH

# Generate visual HTML report
python secret_detector.py . --html report.html

# Generate JSON report
python secret_detector.py . --output report.json

# Generate both at once
python secret_detector.py . --html report.html --output report.json

# Show exact line of code for each finding
python secret_detector.py . --verbose

# CI/CD mode — exits with code 1 if secrets found
python secret_detector.py . --exit-code

# Combine flags
python secret_detector.py . --severity HIGH --html report.html --exit-code
```

### All Options

| Flag | Description |
|------|-------------|
| `path` | File or directory to scan (default: `.`) |
| `--severity LEVEL` | Minimum severity: `CRITICAL` `HIGH` `MEDIUM` `LOW` (default: `LOW`) |
| `--html FILE` | Export findings to an HTML report |
| `--output FILE` | Export findings to a JSON report |
| `-v, --verbose` | Show line context for each finding in terminal |
| `--no-color` | Disable colored terminal output |
| `--exit-code` | Exit with code `1` if secrets are found |
| `--list-patterns` | List all 50+ detection patterns and exit |

---

## 🔎 What It Detects

| Category | Patterns |
|----------|----------|
| ☁️ Cloud | AWS Access/Secret Keys, GCP API Keys, Azure Connection Strings |
| 🐙 Version Control | GitHub Tokens, GitLab Tokens, GitHub OAuth |
| 💳 Payments | Stripe, PayPal/Braintree, Square, Shopify |
| 📡 Communication | Slack Tokens & Webhooks, Twilio, SendGrid, Mailgun |
| 🗄️ Databases | MongoDB, PostgreSQL, MySQL, Redis URIs |
| 🤖 AI / ML | OpenAI, Anthropic, Hugging Face tokens |
| 🔐 Auth | JWT Tokens, OAuth Client Secrets, Private Key Blocks |
| 🛠️ Dev Tools | NPM, PyPI, Heroku, Cloudflare, Discord, Telegram |
| 🔑 Generic | API Keys, Secrets, Tokens, Passwords, High-Entropy Strings |

---

## 📊 Output Examples

### Terminal
```
🔍  SECRET DETECTOR SCAN REPORT
════════════════════════════════════════
  Scanned path  : DESKTOP/FILES/my-project
  Files scanned : 24
  Findings      : 5

  config/settings.py
    [CRITICAL] Line 5:  AWS Access Key
    [HIGH]     Line 9:  PostgreSQL URI
    [HIGH]     Line 12: Stripe Secret Key

  Severity Breakdown:
    CRITICAL : 1
    HIGH     : 2
    MEDIUM   : 2
```

### HTML Report
Open `report.html` in any browser — dark-themed, interactive, filterable by severity.

### JSON Report
```json
{
  "meta": {
    "scan_path": "DESKTOP/FILES/my-project",
    "scan_time": "2026-02-19 12:25:07",
    "scanned_files": 24,
    "total_findings": 5
  },
  "severity_breakdown": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 0 },
  "findings": [
    {
      "file": "config/settings.py",
      "line": 5,
      "pattern": "AWS Access Key",
      "severity": "CRITICAL",
      "match": "AKIAIOSFODNN7EXAMPLE",
      "context": "AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\""
    }
  ]
}
```

---

## 🔒 Privacy & Safety

Paths in all reports are automatically anonymized — your username, OneDrive folder, Desktop, and locale-specific folder names (e.g. `Masaüstü`, `Bureau`) are never written to any output file.

```
# What you have on disk:
C:\Users\yourname\OneDrive\Desktop\my-project\config.py

# What appears in reports:
DESKTOP/FILES/my-project/config.py
```

---

## 🚦 CI/CD Integration

Add to your GitHub Actions workflow to block commits with exposed secrets:

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Secret Detector
        run: python secret_detector.py . --severity HIGH --exit-code
```

---

## 🙈 .gitignore

Add these to your `.gitignore` before pushing:

```gitignore
report.json
report.html
test_secrets.py
*.env
.env*
```

---

## 📋 Requirements

- Python **3.10** or newer
- No external packages — uses only the standard library

---

## 📄 License
- This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2026 Space Weather Forecasting Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including, without limitation, the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🤝 Contributing
- Contributions welcome!
- Feel free to contribute to what parts need to be changed. 
