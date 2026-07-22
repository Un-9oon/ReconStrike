import html
import os
from datetime import datetime, timezone

from scanner.core import ScanSession, Severity


def generate_html_report(session: ScanSession, output_path: str, compliance_data: dict = None) -> str:
    findings = sorted(session.findings, key=lambda f: f.severity.score, reverse=True)

    severity_counts = {}
    for s in Severity:
        severity_counts[s.value] = sum(1 for f in findings if f.severity == s)

    total = len(findings)
    confirmed = sum(1 for f in findings if f.confirmed)
    duration = (session.end_time or 0) - (session.start_time or 0)
    urls_scanned = len(session.crawled_urls)
    forms_found = len(session.forms)

    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
        "INFO": "#6b7280",
    }

    findings_html = ""
    for i, f in enumerate(findings):
        color = severity_colors[f.severity.value]
        conf_badge = (
            '<span style="background:#16a34a;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">Confirmed</span>'
            if f.confirmed else
            '<span style="background:#d97706;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">Tentative</span>'
        )
        findings_html += f"""
        <div class="finding" style="border-left:4px solid {color};">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color};">{f.severity.value}</span>
                <span class="finding-title">{html.escape(f.title)}</span>
                {conf_badge}
            </div>
            <div class="finding-meta">
                <span>Module: {html.escape(f.module)}</span>
                {f'<span>CWE: <a href="https://cwe.mitre.org/data/definitions/{html.escape(f.cwe.replace("CWE-", ""))}.html" target="_blank">{html.escape(f.cwe)}</a></span>' if f.cwe else ''}
                <span>URL: <a href="{html.escape(f.url)}">{html.escape(f.url[:80])}</a></span>
            </div>
            <div class="finding-body">
                <h4>Description</h4>
                <p>{html.escape(f.description)}</p>
                <h4>Evidence</h4>
                <pre>{html.escape(f.evidence)}</pre>
                <h4>Remediation</h4>
                <p>{html.escape(f.remediation)}</p>
            </div>
        </div>
        """

    risk_score = _calculate_risk_score(findings)
    risk_label, risk_color = _risk_label(risk_score)

    compliance_section = ""
    if compliance_data:
        from scanner.compliance import generate_compliance_html
        compliance_section = generate_compliance_html(compliance_data, session.config.target)

    modules_scanned = ", ".join(session.config.scan_modules) if session.config.scan_modules else "all"

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconStrike Report - {html.escape(session.config.target)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,-apple-system,sans-serif; background:#0f172a; color:#e2e8f0; line-height:1.6; }}
.container {{ max-width:1100px; margin:0 auto; padding:20px; }}
.header {{ background:linear-gradient(135deg,#1e293b,#334155); border-radius:12px; padding:30px; margin-bottom:24px; position:relative; overflow:hidden; }}
.header::after {{ content:''; position:absolute; top:0; right:0; width:200px; height:100%; background:linear-gradient(135deg,transparent,rgba(99,102,241,0.1)); }}
.header h1 {{ font-size:28px; font-weight:700; color:#f8fafc; margin-bottom:4px; }}
.header .subtitle {{ color:#94a3b8; font-size:14px; }}
.toc {{ background:#1e293b; border-radius:8px; padding:16px 20px; margin-bottom:24px; }}
.toc h3 {{ color:#94a3b8; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; }}
.toc a {{ color:#60a5fa; text-decoration:none; display:inline-block; margin-right:16px; margin-bottom:4px; font-size:14px; }}
.toc a:hover {{ text-decoration:underline; }}
.meta-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:20px 0; }}
.meta-card {{ background:#1e293b; border-radius:8px; padding:16px; }}
.meta-card .label {{ color:#94a3b8; font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
.meta-card .value {{ font-size:24px; font-weight:700; color:#f8fafc; margin-top:4px; }}
.risk-meter {{ background:#1e293b; border-radius:12px; padding:24px; margin-bottom:24px; text-align:center; }}
.risk-score {{ font-size:64px; font-weight:800; }}
.risk-label {{ font-size:18px; margin-top:4px; }}
.risk-bar {{ height:8px; background:#334155; border-radius:4px; margin:16px auto; max-width:400px; overflow:hidden; }}
.risk-fill {{ height:100%; border-radius:4px; transition:width 0.5s; }}
.severity-summary {{ display:flex; gap:12px; justify-content:center; flex-wrap:wrap; margin-top:16px; }}
.severity-pill {{ padding:6px 16px; border-radius:20px; font-size:14px; font-weight:600; color:#fff; }}
.section-title {{ font-size:20px; font-weight:700; color:#f8fafc; margin:24px 0 12px; padding-bottom:8px; border-bottom:1px solid #334155; }}
.finding {{ background:#1e293b; border-radius:8px; margin-bottom:16px; overflow:hidden; }}
.finding-header {{ display:flex; align-items:center; gap:12px; padding:16px; background:#0f172a; }}
.severity-badge {{ color:#fff; padding:4px 12px; border-radius:4px; font-size:12px; font-weight:700; letter-spacing:0.5px; }}
.finding-title {{ font-size:16px; font-weight:600; color:#f8fafc; flex:1; }}
.finding-meta {{ display:flex; gap:16px; padding:8px 16px; background:#1a2744; font-size:13px; color:#94a3b8; flex-wrap:wrap; }}
.finding-meta a {{ color:#60a5fa; }}
.finding-body {{ padding:16px; }}
.finding-body h4 {{ color:#cbd5e1; font-size:14px; margin:12px 0 6px; text-transform:uppercase; letter-spacing:0.5px; }}
.finding-body h4:first-child {{ margin-top:0; }}
.finding-body p {{ color:#94a3b8; }}
.finding-body pre {{ background:#0f172a; padding:12px; border-radius:6px; overflow-x:auto; font-size:13px; color:#a5f3fc; white-space:pre-wrap; word-break:break-all; }}
.footer {{ text-align:center; color:#64748b; font-size:13px; padding:24px; margin-top:24px; border-top:1px solid #1e293b; }}
.no-findings {{ text-align:center; padding:60px; color:#94a3b8; }}
.no-findings h2 {{ color:#22c55e; font-size:24px; margin-bottom:8px; }}
table {{ border-collapse:collapse; width:100%; }}
table td, table th {{ padding:10px 16px; text-align:left; border-bottom:1px solid #334155; }}
table th {{ color:#94a3b8; font-size:13px; }}
table tr:hover {{ background:#1a2744; }}
@media print {{ body {{ background:#fff; color:#1e293b; }} .finding {{ border:1px solid #e2e8f0; }} }}
@media (max-width:768px) {{ .meta-grid {{ grid-template-columns:1fr 1fr; }} .finding-meta {{ flex-direction:column; gap:4px; }} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>ReconStrike Security Assessment Report</h1>
        <div class="subtitle">Target: {html.escape(session.config.target)}</div>
        <div class="subtitle">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        <div class="subtitle">Modules: {html.escape(modules_scanned[:100])}</div>
    </div>

    <div class="toc">
        <h3>Report Sections</h3>
        <a href="#summary">Executive Summary</a>
        <a href="#risk">Risk Assessment</a>
        <a href="#modules">Module Results</a>
        {'<a href="#compliance">Compliance</a>' if compliance_data else ''}
        <a href="#findings">Findings ({total})</a>
    </div>

    <div class="meta-grid">
        <div class="meta-card">
            <div class="label">Total Findings</div>
            <div class="value">{total}</div>
        </div>
        <div class="meta-card">
            <div class="label">Confirmed</div>
            <div class="value">{confirmed}</div>
        </div>
        <div class="meta-card">
            <div class="label">URLs Scanned</div>
            <div class="value">{urls_scanned}</div>
        </div>
        <div class="meta-card">
            <div class="label">Forms Found</div>
            <div class="value">{forms_found}</div>
        </div>
        <div class="meta-card">
            <div class="label">Scan Duration</div>
            <div class="value">{duration:.0f}s</div>
        </div>
        <div class="meta-card">
            <div class="label">Modules Run</div>
            <div class="value">{len(session.config.scan_modules)}</div>
        </div>
    </div>

    <div class="risk-meter" id="risk">
        <div class="risk-score" style="color:{risk_color};">{risk_score}/100</div>
        <div class="risk-label" style="color:{risk_color};">Overall Risk: {risk_label}</div>
        <div class="risk-bar"><div class="risk-fill" style="width:{risk_score}%;background:{risk_color};"></div></div>
        <div class="severity-summary">
            <span class="severity-pill" style="background:{severity_colors['CRITICAL']};">Critical: {severity_counts['CRITICAL']}</span>
            <span class="severity-pill" style="background:{severity_colors['HIGH']};">High: {severity_counts['HIGH']}</span>
            <span class="severity-pill" style="background:{severity_colors['MEDIUM']};">Medium: {severity_counts['MEDIUM']}</span>
            <span class="severity-pill" style="background:{severity_colors['LOW']};">Low: {severity_counts['LOW']}</span>
            <span class="severity-pill" style="background:{severity_colors['INFO']};">Info: {severity_counts['INFO']}</span>
        </div>
    </div>

    <h2 class="section-title" id="summary">Executive Summary</h2>
    <div style="background:#1e293b;border-radius:8px;padding:20px;margin-bottom:24px;color:#94a3b8;">
        <p>A comprehensive vulnerability assessment was conducted against
        <strong style="color:#f8fafc;">{html.escape(session.config.target)}</strong>
        scanning {urls_scanned} URLs and {forms_found} forms across {len(session.config.scan_modules)} security modules
        in {duration:.0f} seconds.</p>
        <p style="margin-top:12px;">The scan identified <strong style="color:#f8fafc;">{total} findings</strong>
        ({confirmed} confirmed) with an overall risk score of
        <strong style="color:{risk_color};">{risk_score}/100 ({risk_label})</strong>.
        {f'<span style="color:#dc2626;font-weight:700;">Immediate attention is required for {severity_counts["CRITICAL"]} critical finding(s).</span>' if severity_counts["CRITICAL"] else ''}
        {f'<span style="color:#ea580c;font-weight:600;"> {severity_counts["HIGH"]} high-severity issue(s) should be prioritized.</span>' if severity_counts["HIGH"] else ''}
        </p>
    </div>

    <h2 class="section-title" id="modules">Module Results</h2>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-bottom:24px;">
        {_module_summary_cards(findings, severity_colors)}
    </div>

    {'<div id="compliance">' + compliance_section + '</div>' if compliance_section else ''}

    <h2 class="section-title" id="findings">Findings ({total})</h2>
    {'<div class="no-findings"><h2>No vulnerabilities found</h2><p>The scan completed without finding any issues.</p></div>' if not findings else findings_html}

    <div class="footer">
        ReconStrike v3.0 Security Assessment Framework &mdash; For authorized testing only<br>
        Report generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}
    </div>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report)

    return output_path


def print_summary(session: ScanSession):
    findings = session.findings
    if not findings:
        print("\n  No vulnerabilities found.")
        return

    print(f"\n  {'='*60}")
    print(f"  SCAN SUMMARY")
    print(f"  {'='*60}")

    for severity in Severity:
        count = sum(1 for f in findings if f.severity == severity)
        if count:
            print(f"  {severity.color}{severity.value:10s}: {count}{'\033[0m'}")

    confirmed = sum(1 for f in findings if f.confirmed)
    print(f"  {'─'*60}")
    print(f"  Total: {len(findings)} ({confirmed} confirmed)")

    risk = _calculate_risk_score(findings)
    label, _ = _risk_label(risk)
    print(f"  Risk Score: {risk}/100 ({label})")


def _module_summary_cards(findings, severity_colors) -> str:
    modules = {}
    for f in findings:
        if f.module not in modules:
            modules[f.module] = {"count": 0, "max_severity": None}
        modules[f.module]["count"] += 1
        if modules[f.module]["max_severity"] is None or f.severity.score > modules[f.module]["max_severity"].score:
            modules[f.module]["max_severity"] = f.severity

    cards = ""
    for mod, data in sorted(modules.items(), key=lambda x: x[1]["max_severity"].score if x[1]["max_severity"] else 0, reverse=True):
        sev = data["max_severity"]
        color = severity_colors.get(sev.value, "#6b7280") if sev else "#6b7280"
        cards += (
            f'<div style="background:#1e293b;border-radius:6px;padding:12px;border-left:3px solid {color};">'
            f'<div style="color:#f8fafc;font-weight:600;font-size:14px;">{html.escape(mod)}</div>'
            f'<div style="color:#94a3b8;font-size:13px;">{data["count"]} finding(s) '
            f'<span style="color:{color};font-weight:600;">({sev.value})</span></div></div>'
        )
    return cards


def _calculate_risk_score(findings) -> int:
    if not findings:
        return 0
    weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
    score = 0
    for f in findings:
        w = weights[f.severity.value]
        if f.confirmed:
            w = int(w * 1.2)
        score += w
    return min(score, 100)


def _risk_label(score: int) -> tuple[str, str]:
    if score >= 75:
        return "CRITICAL", "#dc2626"
    if score >= 50:
        return "HIGH", "#ea580c"
    if score >= 25:
        return "MEDIUM", "#d97706"
    if score > 0:
        return "LOW", "#2563eb"
    return "NONE", "#22c55e"
