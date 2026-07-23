import json
import os
from datetime import datetime, timezone

from scanner.core import ScanSession


SCAN_HISTORY_DIR = os.path.expanduser("~/.reconstrike/history")


def save_scan_results(session: ScanSession):
    os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)
    from urllib.parse import urlparse
    domain = urlparse(session.config.target).netloc.replace(":", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.json"
    filepath = os.path.join(SCAN_HISTORY_DIR, filename)

    data = {
        "target": session.config.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration": (session.end_time or 0) - (session.start_time or 0),
        "urls_scanned": len(session.crawled_urls),
        "forms_found": len(session.forms),
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "url": f.url,
                "module": f.module,
                "cwe": f.cwe,
                "confirmed": f.confirmed,
                "location": f.location,
                "parameter": f.parameter,
                "payload": f.payload,
                "curl_command": f.curl_command,
                "reproduction_steps": f.reproduction_steps,
                "developer_fix": f.developer_fix,
                "affected_component": f.affected_component,
                "request_method": f.request_method,
                "response_status": f.response_status,
            }
            for f in session.findings
        ],
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)

    latest = os.path.join(SCAN_HISTORY_DIR, f"{domain}_latest.json")
    with open(latest, "w") as fh:
        json.dump(data, fh, indent=2)

    return filepath


def load_previous_scan(target: str) -> dict | None:
    from urllib.parse import urlparse
    domain = urlparse(target).netloc.replace(":", "_")
    latest = os.path.join(SCAN_HISTORY_DIR, f"{domain}_latest.json")
    if not os.path.exists(latest):
        return None
    with open(latest) as fh:
        return json.load(fh)


def compute_diff(previous: dict, current_session: ScanSession) -> dict:
    prev_findings = {
        (f["title"], f["url"], f["module"]): f
        for f in previous.get("findings", [])
    }
    curr_findings = {
        (f.title, f.url, f.module): f
        for f in current_session.findings
    }

    prev_keys = set(prev_findings.keys())
    curr_keys = set(curr_findings.keys())

    new_vulns = curr_keys - prev_keys
    fixed_vulns = prev_keys - curr_keys
    persistent = curr_keys & prev_keys

    return {
        "new": [curr_findings[k] for k in new_vulns],
        "fixed": [prev_findings[k] for k in fixed_vulns],
        "persistent": [curr_findings[k] for k in persistent],
        "previous_timestamp": previous.get("timestamp", "Unknown"),
        "previous_total": len(previous.get("findings", [])),
        "current_total": len(current_session.findings),
    }


def print_diff(diff: dict):
    from colorama import Fore, Style

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SCAN COMPARISON (vs {diff['previous_timestamp'][:19]}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"  Previous: {diff['previous_total']} findings")
    print(f"  Current:  {diff['current_total']} findings")

    if diff["new"]:
        print(f"\n  {Fore.RED}NEW VULNERABILITIES ({len(diff['new'])}){Style.RESET_ALL}")
        for f in diff["new"]:
            sev = f.severity.value if hasattr(f, "severity") else f.get("severity", "?")
            title = f.title if hasattr(f, "title") else f.get("title", "?")
            print(f"    {Fore.RED}[+]{Style.RESET_ALL} [{sev}] {title}")

    if diff["fixed"]:
        print(f"\n  {Fore.GREEN}FIXED VULNERABILITIES ({len(diff['fixed'])}){Style.RESET_ALL}")
        for f in diff["fixed"]:
            sev = f.get("severity", "?") if isinstance(f, dict) else f.severity.value
            title = f.get("title", "?") if isinstance(f, dict) else f.title
            print(f"    {Fore.GREEN}[-]{Style.RESET_ALL} [{sev}] {title}")

    if diff["persistent"]:
        print(f"\n  {Fore.YELLOW}PERSISTENT ({len(diff['persistent'])}){Style.RESET_ALL}")
