"""
Secret & API Key Detector
Scans files or directories for hardcoded secrets, API keys, and tokens.
"""

import re
import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

# ─────────────────────────────────────────────
# Pattern definitions
# ─────────────────────────────────────────────

PATTERNS = {
    "Generic API Key":          r'(?i)(api[_\-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
    "Generic Secret":           r'(?i)(secret[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9\-_/+]{20,})["\']?',
    "Generic Token":            r'(?i)(access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[:=]\s*["\']?([A-Za-z0-9\-_\.]{20,})["\']?',
    "Generic Password":         r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',
    "Private Key Block":        r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "High Entropy String":      r'(?i)(secret|key|token|pass|pwd|auth)\s*[:=]\s*["\']([A-Za-z0-9+/]{32,}={0,2})["\']',
    "AWS Access Key":           r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])',
    "AWS Secret Key":           r'(?i)aws[_\-]?secret[_\-]?(access[_\-]?)?key\s*[:=]\s*["\']?([A-Za-z0-9/+]{40})["\']?',
    "GCP API Key":              r'AIza[0-9A-Za-z\-_]{35}',
    "GCP Service Account":      r'"type"\s*:\s*"service_account"',
    "Azure Connection String":  r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
    "Azure SAS Token":          r'sv=\d{4}-\d{2}-\d{2}&s[a-z]=\w+&sig=[A-Za-z0-9%]+',
    "GitHub Token":             r'gh[pousr]_[A-Za-z0-9]{36,}',
    "GitHub OAuth":             r'[Gg][Ii][Tt][Hh][Uu][Bb][_\-]?[Oo][Aa][Uu][Tt][Hh]\s*[:=]\s*["\']?([0-9a-f]{40})["\']?',
    "GitLab Token":             r'glpat-[A-Za-z0-9\-_]{20}',
    "Slack Token":              r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    "Slack Webhook":            r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Twilio API Key":           r'SK[0-9a-fA-F]{32}',
    "Twilio Account SID":       r'AC[0-9a-fA-F]{32}',
    "SendGrid API Key":         r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43}',
    "Mailgun API Key":          r'key-[0-9a-zA-Z]{32}',
    "Stripe Secret Key":        r'sk_(live|test)_[0-9a-zA-Z]{24,}',
    "Stripe Publishable Key":   r'pk_(live|test)_[0-9a-zA-Z]{24,}',
    "PayPal/Braintree Token":   r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    "Square OAuth Token":       r'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    "Shopify Token":            r'shpat_[a-fA-F0-9]{32}',
    "MongoDB URI":              r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\']+',
    "PostgreSQL URI":           r'postgres(ql)?://[^:]+:[^@]+@[^\s"\']+',
    "MySQL URI":                r'mysql://[^:]+:[^@]+@[^\s"\']+',
    "Redis URI":                r'redis://:[^@]+@[^\s"\']+',
    "JWT Token":                r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    "OAuth Client Secret":      r'(?i)client[_\-]?secret\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?',
    "Facebook Token":           r'EAACEdEose0cBA[0-9A-Za-z]+',
    "Twitter Bearer Token":     r'AAAA[A-Za-z0-9%]{80,}',
    "Heroku API Key":           r'[hH]eroku[_\-]?[aA][pP][iI][_\-]?[kK][eE][yY]\s*[:=]\s*["\']?([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})["\']?',
    "NPM Token":                r'npm_[A-Za-z0-9]{36}',
    "PyPI Token":               r'pypi-[A-Za-z0-9\-_]{40,}',
    "Cloudflare API Key":       r'(?i)cloudflare[_\-]?api[_\-]?key\s*[:=]\s*["\']?([A-Za-z0-9]{37})["\']?',
    "OpenAI API Key":           r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}',
    "Anthropic API Key":        r'sk-ant-[A-Za-z0-9\-_]{40,}',
    "Hugging Face Token":       r'hf_[A-Za-z0-9]{30,}',
    "Telegram Bot Token":       r'[0-9]{8,10}:[A-Za-z0-9\-_]{35}',
    "Discord Bot Token":        r'(Bot\s)?[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
}

# ─────────────────────────────────────────────
# Path anonymization
# ─────────────────────────────────────────────

def anonymize_path(path_str: str) -> str:
    # Strips home dir, cloud folder (OneDrive etc.) and locale desktop names.
    # Always outputs: DESKTOP/FILES/<your-project-and-file>
    # e.g. C:/Users/melis/OneDrive/Masaustu/MyProject/app.py -> DESKTOP/FILES/MyProject/app.py
    CLOUD_PREFIXES = {
        "onedrive", "onedrive - personal", "onedrive - business",
        "icloud drive", "dropbox", "google drive", "my drive", "box",
        "desktop", "masaüstü", "bureau", "escritorio", "schreibtisch",
        "bureaublad", "skrivbord", "skrivebord", "documents", "my documents", "belgeler",
    }
    rel = path_str
    try:
        home = Path.home()
        p = Path(path_str)
        rel = p.relative_to(home).as_posix()
    except ValueError:
        # Fallback: Windows path regex  C:\Users\<n>\...
        m = re.match(r'^[A-Za-z]:[/\\\\][Uu]sers[/\\\\][^/\\\\]+[/\\\\]?(.*)', path_str)
        if m:
            rel = m.group(1).replace("\\\\", "/")
        else:
            return path_str
    parts = rel.split('/')
    while parts and parts[0].lower() in CLOUD_PREFIXES:
        parts.pop(0)
    meaningful = "/".join(parts) if parts else path_str
    return f"DESKTOP/FILES/{meaningful}"

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pdf", ".docx", ".xlsx", ".pptx", ".lock", ".sum",
}

SKIP_DIRS = {
    ".git", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".env", "dist", "build", ".idea", ".vscode",
}

# ─────────────────────────────────────────────
# Severity
# ─────────────────────────────────────────────

SEVERITY_MAP = {
    "AWS Access Key":          "CRITICAL",
    "AWS Secret Key":          "CRITICAL",
    "Private Key Block":       "CRITICAL",
    "Azure Connection String": "CRITICAL",
    "MongoDB URI":             "HIGH",
    "PostgreSQL URI":          "HIGH",
    "MySQL URI":               "HIGH",
    "Redis URI":               "HIGH",
    "Stripe Secret Key":       "HIGH",
    "GitHub Token":            "HIGH",
    "GitLab Token":            "HIGH",
    "Slack Token":             "HIGH",
    "SendGrid API Key":        "HIGH",
    "OpenAI API Key":          "HIGH",
    "Anthropic API Key":       "HIGH",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def get_severity(pattern_name: str) -> str:
    return SEVERITY_MAP.get(pattern_name, "MEDIUM")

# ─────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────

@dataclass
class Finding:
    file: str
    line_number: int
    pattern_name: str
    matched_text: str
    line_content: str

@dataclass
class ScanResult:
    scanned_files: int = 0
    skipped_files: int = 0
    scan_path: str = ""
    scan_time: str = ""
    findings: list = field(default_factory=list)

# ─────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────

class SecretDetector:
    def __init__(self, patterns: dict = PATTERNS, max_line_length: int = 1000):
        self.compiled = {name: re.compile(pat) for name, pat in patterns.items()}
        self.max_line_length = max_line_length

    def scan_line(self, line: str, line_number: int, filepath: str) -> list[Finding]:
        findings = []
        if len(line) > self.max_line_length:
            return findings
        for name, regex in self.compiled.items():
            match = regex.search(line)
            if match:
                findings.append(Finding(
                    file=filepath,
                    line_number=line_number,
                    pattern_name=name,
                    matched_text=match.group(0)[:80],
                    line_content=line.strip()[:120],
                ))
        return findings

    def scan_file(self, filepath: str | Path) -> tuple[list[Finding], bool]:
        path = Path(filepath)
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return [], False
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                findings = []
                for i, line in enumerate(f, 1):
                    findings.extend(self.scan_line(line, i, str(path)))
                return findings, True
        except (PermissionError, IsADirectoryError):
            return [], False

    def scan_path(self, target: str | Path) -> ScanResult:
        result = ScanResult(
            scan_path=anonymize_path(str(Path(target).resolve())),
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        target = Path(target)
        if target.is_file():
            findings, scanned = self.scan_file(target)
            if scanned:
                result.scanned_files += 1
                # Anonymize file path in every finding
                for f in findings:
                    f.file = anonymize_path(f.file)
                result.findings.extend(findings)
            else:
                result.skipped_files += 1
            return result

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                findings, scanned = self.scan_file(fpath)
                if scanned:
                    result.scanned_files += 1
                    for f in findings:
                        f.file = anonymize_path(f.file)
                    result.findings.extend(findings)
                else:
                    result.skipped_files += 1
        return result

# ─────────────────────────────────────────────
# Filtering
# ─────────────────────────────────────────────

def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 2)
    return [f for f in findings if SEVERITY_ORDER.get(get_severity(f.pattern_name), 2) <= threshold]

# ─────────────────────────────────────────────
# Terminal output
# ─────────────────────────────────────────────

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[36m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "GREEN":    "\033[32m",
}

def colorize(text: str, color: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"

def print_report(result: ScanResult, no_color: bool = False, verbose: bool = False, min_severity: str = "LOW"):
    findings = filter_by_severity(result.findings, min_severity)
    total = len(findings)
    print()
    print(colorize("═" * 62, "BOLD", no_color))
    print(colorize("  🔍  SECRET DETECTOR SCAN REPORT", "BOLD", no_color))
    print(colorize("═" * 62, "BOLD", no_color))
    print(f"  Scanned path  : {result.scan_path}")
    print(f"  Scan time     : {result.scan_time}")
    print(f"  Files scanned : {result.scanned_files}")
    print(f"  Files skipped : {result.skipped_files}")
    print(f"  Min severity  : {colorize(min_severity.upper(), min_severity.upper(), no_color)}")
    print(f"  Findings      : {colorize(str(total), 'CRITICAL' if total else 'GREEN', no_color)}")
    print(colorize("─" * 62, "DIM", no_color))

    if not findings:
        print(colorize("  ✅  No secrets detected at this severity level!", "GREEN", no_color))
        print()
        return

    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath, file_findings in sorted(by_file.items()):
        print(f"\n  {colorize(filepath, 'BOLD', no_color)}")
        for f in file_findings:
            severity = get_severity(f.pattern_name)
            sev_label = colorize(f"[{severity}]", severity, no_color)
            print(f"    {sev_label} Line {f.line_number}: {colorize(f.pattern_name, 'BOLD', no_color)}")
            print(f"      Match   : {colorize(f.matched_text, 'DIM', no_color)}")
            if verbose:
                print(f"      Context : {f.line_content}")

    print()
    print(colorize("─" * 62, "DIM", no_color))
    print("  Severity Breakdown:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for f in findings if get_severity(f.pattern_name) == sev)
        if count:
            print(f"    {colorize(sev, sev, no_color)}: {count}")
    print()

# ─────────────────────────────────────────────
# JSON export
# ─────────────────────────────────────────────

def export_json(result: ScanResult, output_path: str, min_severity: str = "LOW"):
    findings = filter_by_severity(result.findings, min_severity)
    data = {
        "meta": {
            "scan_path": result.scan_path,
            "scan_time": result.scan_time,
            "scanned_files": result.scanned_files,
            "skipped_files": result.skipped_files,
            "total_findings": len(findings),
            "min_severity_filter": min_severity.upper(),
        },
        "severity_breakdown": {
            sev: sum(1 for f in findings if get_severity(f.pattern_name) == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "findings": [
            {
                "file": f.file,
                "line": f.line_number,
                "pattern": f.pattern_name,
                "severity": get_severity(f.pattern_name),
                "match": f.matched_text,
                "context": f.line_content,
            }
            for f in findings
        ],
    }
    with open(output_path, "w") as fp:
        json.dump(data, fp, indent=2)
    print(f"  💾 JSON report  → {output_path}")

# ─────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────

def export_html(result: ScanResult, output_path: str, min_severity: str = "LOW"):
    findings = filter_by_severity(result.findings, min_severity)
    sev_counts = {
        sev: sum(1 for f in findings if get_severity(f.pattern_name) == sev)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    rows_html = ""
    for f in findings:
        sev = get_severity(f.pattern_name)
        safe_match = f.matched_text.replace("<", "&lt;").replace(">", "&gt;")
        safe_ctx   = f.line_content.replace("<", "&lt;").replace(">", "&gt;")
        safe_file  = f.file.replace("<", "&lt;").replace(">", "&gt;")
        rows_html += f"""
        <tr data-severity="{sev}">
          <td><span class="badge badge-{sev.lower()}">{sev}</span></td>
          <td class="file-cell" title="{safe_file}">{safe_file}</td>
          <td class="line-num">{f.line_number}</td>
          <td>{f.pattern_name}</td>
          <td><code class="match-code">{safe_match}</code></td>
          <td><code class="ctx-code">{safe_ctx}</code></td>
        </tr>"""

    file_cards = ""
    for filepath, file_findings in sorted(by_file.items()):
        worst = min(file_findings, key=lambda x: SEVERITY_ORDER.get(get_severity(x.pattern_name), 99))
        worst_sev = get_severity(worst.pattern_name)
        safe_fp = filepath.replace("<", "&lt;").replace(">", "&gt;")
        file_cards += f"""
        <div class="file-card severity-border-{worst_sev.lower()}">
          <div class="file-card-header">
            <span class="file-icon">📄</span>
            <span class="file-path">{safe_fp}</span>
            <span class="file-count">{len(file_findings)} finding{"s" if len(file_findings)!=1 else ""}</span>
          </div>
          <div class="file-findings">
            {"".join(f'<span class="finding-pill badge-{get_severity(f.pattern_name).lower()}">{f.pattern_name} L{f.line_number}</span>' for f in file_findings)}
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Secret Detector Report</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@300;400;600;700&display=swap');
    :root {{
      --bg:#0a0e1a;--surface:#111827;--surface2:#1a2236;--border:#1e2d45;
      --text:#e2e8f0;--muted:#64748b;
      --critical:#ff3b3b;--critical-bg:#2a0a0a;
      --high:#f97316;--high-bg:#2a1200;
      --medium:#eab308;--medium-bg:#2a1f00;
      --low:#22d3ee;--low-bg:#00161a;
      --green:#22c55e;--accent:#6366f1;
    }}
    *{{box-sizing:border-box;margin:0;padding:0;}}
    body{{font-family:'Sora',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;}}
    .header{{background:linear-gradient(135deg,#0d1424 0%,#111827 60%,#0a1020 100%);border-bottom:1px solid var(--border);padding:2rem 2.5rem;position:relative;overflow:hidden;}}
    .header::before{{content:'';position:absolute;top:-60px;left:-60px;width:300px;height:300px;background:radial-gradient(circle,rgba(99,102,241,.12) 0%,transparent 70%);pointer-events:none;}}
    .header-top{{display:flex;align-items:center;gap:1rem;margin-bottom:.5rem;}}
    .header-icon{{font-size:2rem;}}
    .header h1{{font-size:1.6rem;font-weight:700;letter-spacing:-.02em;color:#fff;}}
    .header-meta{{font-size:.8rem;color:var(--muted);font-family:'JetBrains Mono',monospace;display:flex;gap:2rem;flex-wrap:wrap;}}
    .stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;padding:1.5rem 2.5rem;background:var(--surface);border-bottom:1px solid var(--border);}}
    .stat-card{{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:1.1rem 1.2rem;position:relative;overflow:hidden;transition:transform .2s;}}
    .stat-card:hover{{transform:translateY(-2px);}}
    .stat-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;}}
    .stat-card.critical::before{{background:var(--critical);}}
    .stat-card.high::before{{background:var(--high);}}
    .stat-card.medium::before{{background:var(--medium);}}
    .stat-card.low::before{{background:var(--low);}}
    .stat-card.total::before{{background:var(--accent);}}
    .stat-card.files::before{{background:var(--green);}}
    .stat-label{{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:.4rem;}}
    .stat-value{{font-size:2rem;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1;}}
    .stat-card.critical .stat-value{{color:var(--critical);}}
    .stat-card.high .stat-value{{color:var(--high);}}
    .stat-card.medium .stat-value{{color:var(--medium);}}
    .stat-card.low .stat-value{{color:var(--low);}}
    .stat-card.total .stat-value{{color:var(--accent);}}
    .stat-card.files .stat-value{{color:var(--green);}}
    .main{{padding:2rem 2.5rem;display:flex;flex-direction:column;gap:2rem;}}
    .section-title{{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:1rem;}}
    .file-cards{{display:flex;flex-direction:column;gap:.6rem;}}
    .file-card{{background:var(--surface2);border:1px solid var(--border);border-left:4px solid transparent;border-radius:8px;padding:.9rem 1.1rem;}}
    .severity-border-critical{{border-left-color:var(--critical);}}
    .severity-border-high{{border-left-color:var(--high);}}
    .severity-border-medium{{border-left-color:var(--medium);}}
    .severity-border-low{{border-left-color:var(--low);}}
    .file-card-header{{display:flex;align-items:center;gap:.6rem;margin-bottom:.5rem;}}
    .file-path{{font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#a5b4fc;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
    .file-count{{font-size:.7rem;color:var(--muted);white-space:nowrap;}}
    .file-findings{{display:flex;flex-wrap:wrap;gap:.4rem;}}
    .finding-pill{{font-size:.67rem;padding:.15rem .5rem;border-radius:4px;font-family:'JetBrains Mono',monospace;}}
    .badge{{display:inline-block;font-size:.65rem;font-weight:700;padding:.2rem .55rem;border-radius:4px;letter-spacing:.05em;text-transform:uppercase;font-family:'JetBrains Mono',monospace;white-space:nowrap;}}
    .badge-critical{{background:var(--critical-bg);color:var(--critical);border:1px solid rgba(255,59,59,.3);}}
    .badge-high{{background:var(--high-bg);color:var(--high);border:1px solid rgba(249,115,22,.3);}}
    .badge-medium{{background:var(--medium-bg);color:var(--medium);border:1px solid rgba(234,179,8,.3);}}
    .badge-low{{background:var(--low-bg);color:var(--low);border:1px solid rgba(34,211,238,.3);}}
    .filter-bar{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;}}
    .filter-label{{font-size:.72rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.08em;}}
    .filter-btn{{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:.35rem .9rem;border-radius:6px;font-size:.75rem;font-family:'Sora',sans-serif;cursor:pointer;transition:all .15s;}}
    .filter-btn:hover{{background:var(--border);}}
    .filter-btn.active-all{{border-color:var(--accent);color:#a5b4fc;background:rgba(99,102,241,.1);}}
    .filter-btn.active-critical{{border-color:var(--critical);color:var(--critical);background:var(--critical-bg);}}
    .filter-btn.active-high{{border-color:var(--high);color:var(--high);background:var(--high-bg);}}
    .filter-btn.active-medium{{border-color:var(--medium);color:var(--medium);background:var(--medium-bg);}}
    .filter-btn.active-low{{border-color:var(--low);color:var(--low);background:var(--low-bg);}}
    .table-wrap{{overflow-x:auto;border-radius:10px;border:1px solid var(--border);}}
    table{{width:100%;border-collapse:collapse;font-size:.8rem;}}
    thead{{background:var(--surface2);}}
    th{{padding:.8rem 1rem;text-align:left;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;}}
    tbody tr{{border-bottom:1px solid var(--border);transition:background .1s;}}
    tbody tr:last-child{{border-bottom:none;}}
    tbody tr:hover{{background:var(--surface2);}}
    td{{padding:.75rem 1rem;vertical-align:top;}}
    .file-cell{{font-family:'JetBrains Mono',monospace;font-size:.72rem;color:#a5b4fc;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
    .line-num{{font-family:'JetBrains Mono',monospace;color:var(--muted);text-align:right;width:60px;}}
    .match-code{{font-family:'JetBrains Mono',monospace;font-size:.72rem;background:rgba(255,255,255,.04);padding:.15rem .4rem;border-radius:4px;color:#fca5a5;word-break:break-all;display:block;max-width:260px;}}
    .ctx-code{{font-family:'JetBrains Mono',monospace;font-size:.68rem;color:var(--muted);word-break:break-all;display:block;max-width:280px;}}
    .empty-state{{text-align:center;padding:4rem 2rem;color:var(--muted);}}
    .empty-state .icon{{font-size:3rem;margin-bottom:1rem;}}
    .empty-state h2{{color:var(--green);font-size:1.2rem;margin-bottom:.5rem;}}
    .footer{{text-align:center;padding:1.5rem;border-top:1px solid var(--border);font-size:.72rem;color:var(--muted);font-family:'JetBrains Mono',monospace;}}
    @media(max-width:640px){{.header,.stats-grid,.main{{padding-left:1rem;padding-right:1rem;}}}}
  </style>
</head>
<body>
<header class="header">
  <div class="header-top">
    <span class="header-icon">🔍</span>
    <h1>Secret Detector Report</h1>
  </div>
  <div class="header-meta">
    <span>📁 {result.scan_path}</span>
    <span>🕐 {result.scan_time}</span>
    <span>📄 {result.scanned_files} files scanned</span>
    <span>⏭ {result.skipped_files} skipped</span>
    <span>🔎 Filter: {min_severity.upper()}+</span>
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card total"><div class="stat-label">Total Findings</div><div class="stat-value">{len(findings)}</div></div>
  <div class="stat-card critical"><div class="stat-label">Critical</div><div class="stat-value">{sev_counts["CRITICAL"]}</div></div>
  <div class="stat-card high"><div class="stat-label">High</div><div class="stat-value">{sev_counts["HIGH"]}</div></div>
  <div class="stat-card medium"><div class="stat-label">Medium</div><div class="stat-value">{sev_counts["MEDIUM"]}</div></div>
  <div class="stat-card low"><div class="stat-label">Low</div><div class="stat-value">{sev_counts["LOW"]}</div></div>
  <div class="stat-card files"><div class="stat-label">Files Affected</div><div class="stat-value">{len(by_file)}</div></div>
</div>

<main class="main">
{'<section><div class="section-title">📂 Affected Files</div><div class="file-cards">' + file_cards + '</div></section><section><div class="section-title">🔎 All Findings</div><div class="filter-bar"><span class="filter-label">Filter:</span><button class="filter-btn active-all" onclick="filterTable(\'ALL\')">All (' + str(len(findings)) + ')</button><button class="filter-btn" onclick="filterTable(\'CRITICAL\')">Critical (' + str(sev_counts["CRITICAL"]) + ')</button><button class="filter-btn" onclick="filterTable(\'HIGH\')">High (' + str(sev_counts["HIGH"]) + ')</button><button class="filter-btn" onclick="filterTable(\'MEDIUM\')">Medium (' + str(sev_counts["MEDIUM"]) + ')</button><button class="filter-btn" onclick="filterTable(\'LOW\')">Low (' + str(sev_counts["LOW"]) + ')</button></div><br/><div class="table-wrap"><table id="findings-table"><thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Pattern</th><th>Match</th><th>Context</th></tr></thead><tbody>' + rows_html + '</tbody></table></div></section>' if findings else '<div class="empty-state"><div class="icon">✅</div><h2>No secrets detected!</h2><p>Your codebase is clean at this severity level.</p></div>'}
</main>

<footer class="footer">Generated by Secret Detector &nbsp;·&nbsp; {result.scan_time}</footer>

<script>
function filterTable(severity) {{
  document.querySelectorAll('#findings-table tbody tr').forEach(row => {{
    row.style.display = (severity === 'ALL' || row.dataset.severity === severity) ? '' : 'none';
  }});
  const map = {{'ALL':'active-all','CRITICAL':'active-critical','HIGH':'active-high','MEDIUM':'active-medium','LOW':'active-low'}};
  document.querySelectorAll('.filter-btn').forEach(btn => btn.className = 'filter-btn');
  const labels = {{'ALL':'All','CRITICAL':'Critical','HIGH':'High','MEDIUM':'Medium','LOW':'Low'}};
  [...document.querySelectorAll('.filter-btn')].find(b => b.textContent.startsWith(labels[severity]))?.classList.add(map[severity]);
}}
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html)
    print(f"  🌐 HTML report  → {output_path}")

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Secret & API Key Detector — scan files for hardcoded secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python secret_detector.py .
  python secret_detector.py ./src --verbose
  python secret_detector.py . --severity HIGH
  python secret_detector.py . --output report.json --html report.html
  python secret_detector.py . --severity CRITICAL --exit-code
        """
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show line context in terminal output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--output", metavar="FILE", help="Export findings to a JSON file")
    parser.add_argument("--html", metavar="FILE", help="Export findings to an HTML report")
    parser.add_argument(
        "--severity", metavar="LEVEL", default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity to include: CRITICAL | HIGH | MEDIUM | LOW  (default: LOW)"
    )
    parser.add_argument("--exit-code", action="store_true", help="Exit with code 1 if secrets found (CI mode)")
    parser.add_argument("--list-patterns", action="store_true", help="List all detection patterns and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_patterns:
        print(f"\n{'Pattern Name':<35} {'Severity':<10} Regex")
        print("─" * 100)
        for name, pat in PATTERNS.items():
            sev = get_severity(name)
            print(f"  {name:<33} {sev:<10} {pat[:55]}")
        print()
        return

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path '{target}' does not exist.")
        sys.exit(2)

    nc = args.no_color
    print(f"\n  Scanning: {colorize(anonymize_path(str(target.resolve())), 'BOLD', nc)}")

    detector = SecretDetector()
    result = detector.scan_path(target)

    print_report(result, no_color=nc, verbose=args.verbose, min_severity=args.severity)

    if args.output:
        export_json(result, args.output, min_severity=args.severity)
    if args.html:
        export_html(result, args.html, min_severity=args.severity)
    if args.output or args.html:
        print()

    filtered = filter_by_severity(result.findings, args.severity)
    if args.exit_code and filtered:
        sys.exit(1)


if __name__ == "__main__":
    main()