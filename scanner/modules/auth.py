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
                    curl_cmd = f"curl -kI '{url}'"
                    session.add_finding(Finding(
                        title="Login Form Submits Over HTTP",
                        severity=Severity.HIGH,
                        description=f"Login form at {url} submits credentials over unencrypted HTTP to {action}. Credentials can be intercepted via network sniffing.",
                        evidence=f"Login Page: {url}\nForm action: {action}\nProtocol: HTTP (unencrypted)",
                        remediation="Ensure login forms submit to HTTPS endpoints only.",
                        url=url,
                        module="auth",
                        cwe="CWE-319",
                        confirmed=True,
                        location=f"Login form action attribute at {url}",
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Navigate to: {url}\n"
                            f"2. Inspect the login form's action attribute.\n"
                            f"3. The form action points to an HTTP (not HTTPS) URL: {action}\n"
                            f"4. Credentials are transmitted in cleartext."
                        ),
                        developer_fix=(
                            f"Change the form action from http:// to https://:\n"
                            f"  <form action=\"{action.replace('http://', 'https://')}\" method=\"POST\">\n"
                            f"Or use a relative URL: <form action=\"/login\" method=\"POST\">\n"
                            f"Also add HSTS header to prevent downgrade attacks."
                        ),
                        affected_component=f"Login form at {url}",
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
                        detection_method="Tested authentication mechanisms: checked login forms for HTTPS, tested for username enumeration via response differences, validated password policies, and attempted default credential combinations against common login endpoints.",
                    ))

        from scanner.crawler import extract_forms
        forms = extract_forms(resp.text, url)
        for form in forms:
            has_pass = any("pass" in (i.get("name") or "").lower() for i in form["inputs"])
            if not has_pass:
                continue

            post_data = {}
            for inp in form["inputs"]:
                name = inp.get("name", "")
                if not name:
                    continue
                if "user" in name.lower() or "email" in name.lower() or "login" in name.lower():
                    post_data[name] = "invalid_user_test"
                elif "pass" in name.lower():
                    post_data[name] = "invalid_pass_test"
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
                    data_str = "&".join(f"{k}={v}" for k, v in post_data.items())
                    curl_cmd = f"curl -k -X POST '{form['action']}' -d '{data_str}'"
                    session.add_finding(Finding(
                        title="Username Enumeration via Login Error",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Login error messages at {url} reveal whether a username/email exists in the system. "
                            f"The error message '{pattern}' distinguishes between invalid users and wrong passwords, "
                            f"allowing attackers to enumerate valid accounts."
                        ),
                        evidence=(
                            f"Login URL: {url}\n"
                            f"Error message contains: '{pattern}'\n"
                            f"Test credentials: invalid_user_test / invalid_pass_test"
                        ),
                        remediation="Use generic error messages like 'Invalid credentials' that don't reveal whether the username exists.",
                        url=url,
                        module="auth",
                        cwe="CWE-204",
                        confirmed=True,
                        location=f"Login error response at {form['action']}",
                        request_method="POST",
                        request_body=data_str,
                        response_status=fail_resp.status_code,
                        curl_command=curl_cmd,
                        reproduction_steps=(
                            f"1. Navigate to: {url}\n"
                            f"2. Enter a non-existent username and any password.\n"
                            f"3. Submit the login form.\n"
                            f"4. The error message contains '{pattern}', confirming the username doesn't exist.\n"
                            f"5. Compare with a valid username - the error message differs.\n"
                            f"6. Run: {curl_cmd}"
                        ),
                        developer_fix=(
                            f"File: Login handler at {form['action']}\n\n"
                            f"VULNERABLE: 'User not found' / 'Wrong password' (reveals which is wrong)\n"
                            f"SECURE: 'Invalid username or password' (same message for both cases)\n\n"
                            f"Also ensure response timing is consistent for both cases to prevent timing-based enumeration."
                        ),
                        affected_component=f"Login handler at {form['action']}",
                        references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account",
                        detection_method="Tested authentication mechanisms: checked login forms for HTTPS, tested for username enumeration via response differences, validated password policies, and attempted default credential combinations against common login endpoints.",
                    ))
                    break
            break


def _check_session_security(session: ScanSession):
    from scanner.modules import session_security
    session_security.run(session)


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
                                description=f"Registration form at {url} doesn't enforce password requirements client-side. Weak passwords may be accepted.",
                                evidence=f"Password field '{inp['name']}' lacks minlength/pattern attributes.\nForm action: {form['action']}",
                                remediation="Enforce password policy both client-side (minlength, pattern) and server-side.",
                                url=url,
                                module="auth",
                                cwe="CWE-521",
                                confirmed=True,
                                location=f"Password field '{inp['name']}' in registration form at {url}",
                                curl_command=f"curl -k '{url}'",
                                developer_fix=(
                                    f"Add client-side validation to the password field:\n"
                                    f"  <input type=\"password\" name=\"{inp['name']}\" minlength=\"8\" "
                                    f"pattern=\"(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{{8,}}\" required>\n\n"
                                    f"Also enforce server-side: minimum 8 chars, mixed case, numbers, special chars."
                                ),
                                affected_component=f"Registration form at {url}",
                                detection_method="Tested authentication mechanisms: checked login forms for HTTPS, tested for username enumeration via response differences, validated password policies, and attempted default credential combinations against common login endpoints.",
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
            data_str = "&".join(f"{k}={v}" for k, v in post_data.items())
            curl_cmd = f"curl -k -X POST '{login_form['action']}' -d '{data_str}'"
            session.add_finding(Finding(
                title=f"Default Credentials: {username}/{password}",
                severity=Severity.CRITICAL,
                description=(
                    f"The application accepts default credentials ({username}/{password}). "
                    f"This allows anyone with knowledge of common default passwords to gain unauthorized access."
                ),
                evidence=(
                    f"Login URL: {session.config.auth_url}\n"
                    f"Username: {username}\n"
                    f"Password: {password}\n"
                    f"Login succeeded - response no longer contains login form."
                ),
                remediation=(
                    "1. Change all default credentials immediately.\n"
                    "2. Force password change on first login.\n"
                    "3. Implement account lockout after failed attempts.\n"
                    "4. Use strong password policy."
                ),
                url=session.config.auth_url,
                module="auth",
                cwe="CWE-798",
                confirmed=True,
                location=f"Login form at {login_form['action']}",
                request_method="POST",
                request_body=data_str,
                response_status=resp.status_code,
                curl_command=curl_cmd,
                reproduction_steps=(
                    f"1. Navigate to: {session.config.auth_url}\n"
                    f"2. Enter username: {username}\n"
                    f"3. Enter password: {password}\n"
                    f"4. Submit the login form.\n"
                    f"5. Authentication succeeds.\n"
                    f"6. Run: {curl_cmd}"
                ),
                developer_fix=(
                    f"1. Remove or change all default accounts:\n"
                    f"   UPDATE users SET password = random_hash() WHERE username = '{username}';\n"
                    f"2. Force password change on first login.\n"
                    f"3. Add account lockout after 5 failed attempts."
                ),
                affected_component=f"Authentication system at {login_form['action']}",
                references="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials",
                detection_method="Tested authentication mechanisms: checked login forms for HTTPS, tested for username enumeration via response differences, validated password policies, and attempted default credential combinations against common login endpoints.",
            ))
            return
