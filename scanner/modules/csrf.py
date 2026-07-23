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
        source_url = form.get("source_url", form["action"])
        data_str = "&".join(f"{n}=test" for n in input_names)
        curl_cmd = f"curl -k -X POST '{form['action']}' -d '{data_str}'"

        session.add_finding(Finding(
            title="Missing CSRF Protection on State-Changing Form",
            severity=Severity.MEDIUM,
            description=(
                f"A POST form at {form['action']} performs state-changing operations (detected keywords: "
                f"{', '.join(ind for ind in STATE_CHANGING_INDICATORS if ind in (urlparse(form['action']).path.lower() + ' ' + ' '.join(input_names).lower()))}) "
                f"without CSRF token protection. An attacker can craft a malicious page that submits this form "
                f"on behalf of an authenticated user without their knowledge."
            ),
            evidence=(
                f"Form Action: {form['action']}\n"
                f"Method: POST\n"
                f"Fields: {', '.join(input_names)}\n"
                f"CSRF Token: Not found\n"
                f"SameSite Cookie: Not set"
            ),
            remediation=(
                "1. Add a CSRF token to all state-changing forms.\n"
                "2. Validate the token server-side on form submission.\n"
                "3. Set SameSite=Strict or SameSite=Lax on session cookies as defense-in-depth.\n"
                "4. Verify the Origin/Referer header matches your domain."
            ),
            url=source_url,
            module="csrf",
            cwe="CWE-352",
            confirmed=True,
            location=f"POST form at {form['action']}",
            request_method="POST",
            curl_command=curl_cmd,
            reproduction_steps=(
                f"1. Navigate to page containing the form: {source_url}\n"
                f"2. Inspect the form that submits to: {form['action']}\n"
                f"3. Note that no CSRF token (hidden input) is present in the form.\n"
                f"4. Create an HTML page with an auto-submitting form targeting {form['action']}:\n"
                f"   <form action=\"{form['action']}\" method=\"POST\">\n"
                + "".join(f"     <input type=\"hidden\" name=\"{n}\" value=\"attacker_value\">\n" for n in input_names)
                + f"   </form><script>document.forms[0].submit()</script>\n"
                f"5. When an authenticated user visits the attacker's page, the form auto-submits."
            ),
            developer_fix=(
                f"File: The template rendering the form at {form['action']} and its server-side handler.\n\n"
                f"1. Add a hidden CSRF token field to the form:\n"
                f"   <input type=\"hidden\" name=\"csrf_token\" value=\"{{{{ csrf_token }}}}\">\n\n"
                f"2. Validate the token server-side:\n"
                f"   Django: Uses {{% csrf_token %}} template tag automatically\n"
                f"   Flask: from flask_wtf.csrf import CSRFProtect; csrf = CSRFProtect(app)\n"
                f"   Express: Use csurf middleware\n"
                f"   PHP: Generate token with bin2hex(random_bytes(32)), store in session, validate on POST\n\n"
                f"3. Set SameSite on session cookies:\n"
                f"   Set-Cookie: session=value; SameSite=Strict; Secure; HttpOnly"
            ),
            affected_component=f"POST {form['action']}",
            references="https://owasp.org/www-community/attacks/csrf | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            detection_method="Identified POST forms performing state-changing operations (password, delete, update, etc.) and checked for CSRF token hidden fields and SameSite cookie attributes. Missing both protections confirms CSRF vulnerability.",
        ))
