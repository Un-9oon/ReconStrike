import re
from urllib.parse import urljoin

from scanner.core import Finding, Severity, ScanSession


COMMON_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
]


def run(session: ScanSession) -> None:
    print("\n[*] Checking authentication security...")

    _check_login_security(session)
    _check_session_security(session)
    _check_password_policy(session)
    _check_default_credentials(session)


def _check_login_security(session: ScanSession):
    login_paths = ["/login", "/signin", "/auth/login", "/user/login",
                   "/account/login", "/admin/login", "/admin"]

    for path in login_paths:
        url = urljoin(session.config.target, path)
        resp = session.get(url, allow_redirects=False)
        if not resp or resp.status_code not in (200, 301, 302):
            continue

        if resp.status_code in (301, 302):
            resp = session.get(url)
            if not resp:
                continue

        body = resp.text.lower()
        if not any(kw in body for kw in ["password", "login", "sign in", "username"]):
            continue

        if session.config.target.startswith("https"):
            form_actions = re.findall(r'<form[^>]*action=["\']?(http://[^"\'>\s]+)', body, re.IGNORECASE)
            for action in form_actions:
                if action.startswith("http://"):
                    session.add_finding(Finding(
                        title="Login Form Submits Over HTTP",
                        severity=Severity.HIGH,
                        description=f"Login form at {url} submits credentials over unencrypted HTTP.",
                        evidence=f"Form action: {action}",
                        remediation="Ensure login forms submit to HTTPS endpoints.",
                        url=url,
                        module="auth",
                        cwe="CWE-319",
                        confirmed=True,
                    ))

        if "autocomplete" not in body or 'autocomplete="off"' not in body:
            has_password = re.search(r'<input[^>]*type=["\']password["\'][^>]*>', body)
            if has_password and 'autocomplete="off"' not in has_password.group(0):
                pass  # Informational only, not worth a finding

        from scanner.crawler import extract_forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            has_pass = any("pass" in (i.get("name") or "").lower() for i in form["inputs"])
            if not has_pass:
                continue

            for cred_user, cred_pass in [("invalid_user_test", "invalid_pass_test")] * 1:
                post_data = {}
                for inp in form["inputs"]:
                    name = inp.get("name", "")
                    if not name:
                        continue
                    if "user" in name.lower() or "email" in name.lower() or "login" in name.lower():
                        post_data[name] = cred_user
                    elif "pass" in name.lower():
                        post_data[name] = cred_pass
                    elif inp.get("value"):
                        post_data[name] = inp["value"]

                if form["method"] == "post":
                    fail_resp = session.post(form["action"], data=post_data)
                else:
                    fail_resp = session.get(form["action"], params=post_data)

                if not fail_resp:
                    continue

                fail_body = fail_resp.text.lower()
                user_enum_patterns = [
                    "user not found", "username not found", "account not found",
                    "no account", "user does not exist", "invalid username",
                    "email not found", "email not registered",
                ]
                for pattern in user_enum_patterns:
                    if pattern in fail_body:
                        session.add_finding(Finding(
                            title="Username Enumeration via Login Error",
                            severity=Severity.MEDIUM,
                            description="Login error messages reveal whether a username exists.",
                            evidence=f"URL: {url}\nError message contains: '{pattern}'",
                            remediation="Use generic messages like 'Invalid credentials' that don't distinguish between invalid user and wrong password.",
                            url=url,
                            module="auth",
                            cwe="CWE-204",
                            confirmed=True,
                        ))
                        break
            break


def _check_session_security(session: ScanSession):
    resp = session.get(session.config.target)
    if not resp:
        return

    for cookie in resp.cookies:
        if len(cookie.value) < 10:
            continue
        if not cookie.secure and session.config.target.startswith("https"):
            pass  # Already covered by headers module
        if cookie.has_nonstandard_attr("SameSite"):
            pass


def _check_password_policy(session: ScanSession):
    register_paths = ["/register", "/signup", "/sign-up", "/create-account", "/join"]

    for path in register_paths:
        url = urljoin(session.config.target, path)
        resp = session.get(url)
        if not resp or resp.status_code != 200:
            continue

        body = resp.text.lower()
        if not any(kw in body for kw in ["register", "sign up", "create account", "password"]):
            continue

        from scanner.crawler import extract_forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            has_pass = any("pass" in (i.get("name") or "").lower() for i in form["inputs"])
            if not has_pass:
                continue

            for inp in form["inputs"]:
                if "pass" in (inp.get("name") or "").lower():
                    input_tag = re.search(
                        rf'<input[^>]*name=["\']?{re.escape(inp["name"])}[^>]*>',
                        resp.text, re.IGNORECASE
                    )
                    if input_tag:
                        tag_str = input_tag.group(0)
                        if 'minlength' not in tag_str.lower() and 'pattern' not in tag_str.lower():
                            session.add_finding(Finding(
                                title="No Client-Side Password Strength Validation",
                                severity=Severity.INFO,
                                description=f"Registration form at {url} doesn't enforce password requirements client-side.",
                                evidence=f"Password field lacks minlength/pattern attributes.",
                                remediation="Enforce password policy both client-side and server-side.",
                                url=url,
                                module="auth",
                                cwe="CWE-521",
                                confirmed=True,
                            ))
            break


def _check_default_credentials(session: ScanSession):
    if not session.config.auth_url:
        return

    resp = session.get(session.config.auth_url)
    if not resp:
        return

    from scanner.crawler import extract_forms
    forms = extract_forms(resp.text, session.config.auth_url)
    login_form = None
    for form in forms:
        if any("pass" in (i.get("name") or "").lower() for i in form["inputs"]):
            login_form = form
            break

    if not login_form:
        return

    fail_data = {}
    for inp in login_form["inputs"]:
        name = inp.get("name", "")
        if not name:
            continue
        if "user" in name.lower() or "email" in name.lower() or "login" in name.lower():
            fail_data[name] = "vulnscan_invalid_user_xz9"
        elif "pass" in name.lower():
            fail_data[name] = "vulnscan_invalid_pass_xz9"
        elif inp.get("value"):
            fail_data[name] = inp["value"]

    if login_form["method"] == "post":
        fail_resp = session.post(login_form["action"], data=fail_data, allow_redirects=True)
    else:
        fail_resp = session.get(login_form["action"], params=fail_data, allow_redirects=True)
    fail_text = fail_resp.text.lower() if fail_resp else ""

    from scanner.crawler import extract_forms
    fail_has_login_form = bool(extract_forms(fail_resp.text if fail_resp else "", login_form["action"]))

    print("  [*] Testing for default credentials...")
    for username, password in COMMON_CREDS:
        post_data = {}
        for inp in login_form["inputs"]:
            name = inp.get("name", "")
            if not name:
                continue
            if "user" in name.lower() or "email" in name.lower() or "login" in name.lower():
                post_data[name] = username
            elif "pass" in name.lower():
                post_data[name] = password
            elif inp.get("value"):
                post_data[name] = inp["value"]

        if login_form["method"] == "post":
            resp = session.post(login_form["action"], data=post_data, allow_redirects=True)
        else:
            resp = session.get(login_form["action"], params=post_data, allow_redirects=True)

        if not resp:
            continue

        body = resp.text.lower()
        success_forms = extract_forms(resp.text, login_form["action"])
        still_has_login = any(
            any("pass" in (i.get("name") or "").lower() for i in f["inputs"])
            for f in success_forms
        )

        if still_has_login:
            continue

        if body != fail_text and not still_has_login:
            session.add_finding(Finding(
                title=f"Default Credentials: {username}/{password}",
                severity=Severity.CRITICAL,
                description=f"The application accepts default credentials ({username}/{password}).",
                evidence=f"Login with {username}:{password} succeeded. "
                         f"Response no longer contains login form (login form present in failure response: {fail_has_login_form}).",
                remediation="Change default credentials. Enforce password change on first login.",
                url=session.config.auth_url,
                module="auth",
                cwe="CWE-798",
                confirmed=True,
            ))
            return
