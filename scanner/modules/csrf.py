import re
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession


CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf", "xsrf_token",
    "_xsrf", "authenticity_token", "__requestverificationtoken",
    "antiforgerytoken", "csrfmiddlewaretoken",
}

STATE_CHANGING_INDICATORS = [
    "password", "delete", "remove", "update", "edit",
    "create", "save", "modify", "change",
    "transfer", "upload", "config", "setting",
]


def _is_state_changing_form(form: dict) -> bool:
    if form["method"] != "post":
        return False
    action_path = urlparse(form["action"]).path.lower()
    input_names = [i.get("name", "").lower() for i in form["inputs"]]
    all_text = action_path + " " + " ".join(input_names)
    return any(indicator in all_text for indicator in STATE_CHANGING_INDICATORS)


def _has_csrf_token(form: dict) -> bool:
    for inp in form["inputs"]:
        name = (inp.get("name") or "").lower()
        name_normalized = name.replace("-", "").replace("_", "")
        if name_normalized in CSRF_TOKEN_NAMES or any(t in name for t in ("csrf", "xsrf", "authenticity_token")):
            return True
    return False


def run(session: ScanSession) -> None:
    print("\n[*] Testing for CSRF vulnerabilities...")

    for form in session.forms:
        if not _is_state_changing_form(form):
            continue

        if _has_csrf_token(form):
            continue

        resp = session.get(session.config.target)
        has_samesite = False
        if resp:
            for cookie in resp.cookies:
                samesite = cookie.get_nonstandard_attr("SameSite") or ""
                if samesite.lower() in ("strict", "lax"):
                    has_samesite = True
                    break

        if has_samesite:
            continue

        input_names = [i.get("name", "") for i in form["inputs"] if i.get("name")]
        session.add_finding(Finding(
            title="Missing CSRF Protection on State-Changing Form",
            severity=Severity.MEDIUM,
            description=f"A POST form at {form['action']} performs state-changing operations without CSRF token protection.",
            evidence=f"Action: {form['action']}\nMethod: POST\nFields: {', '.join(input_names)}\nNo CSRF token or SameSite cookie found.",
            remediation="Add a CSRF token to all state-changing forms. Use SameSite=Strict cookies as defense-in-depth.",
            url=form.get("source_url", form["action"]),
            module="csrf",
            cwe="CWE-352",
            confirmed=True,
        ))
