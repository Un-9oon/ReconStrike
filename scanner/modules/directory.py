import os
from urllib.parse import urljoin, urlparse

from scanner.core import Finding, Severity, ScanSession

SENSITIVE_PATHS = [
    # Config & environment
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/config.php", "/config.yml", "/config.json", "/config.xml",
    "/wp-config.php", "/wp-config.php.bak",
    "/settings.py", "/settings.ini", "/application.properties",
    "/appsettings.json", "/web.config",
    # Version control
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.svn/entries", "/.hg/store",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/dump.sql", "/database.sql", "/site.tar.gz",
    # Admin interfaces
    "/admin", "/admin/", "/administrator/",
    "/wp-admin/", "/phpmyadmin/", "/adminer.php",
    "/cpanel", "/manager/html", "/_admin",
    "/admin/login", "/dashboard", "/panel",
    # Debug & info
    "/phpinfo.php", "/info.php", "/test.php",
    "/debug", "/debug/", "/_debug",
    "/server-status", "/server-info",
    "/elmah.axd", "/trace.axd",
    "/.well-known/security.txt",
    # API docs
    "/swagger-ui.html", "/swagger.json", "/api-docs",
    "/openapi.json", "/graphql", "/graphiql",
    "/api/v1/", "/api/v2/",
    # Docker / container
    "/Dockerfile", "/docker-compose.yml",
    "/.dockerenv",
    # Common files
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/favicon.ico", "/humans.txt",
    # Log files
    "/error.log", "/access.log", "/debug.log",
    "/logs/", "/log/",
    # Package managers
    "/package.json", "/composer.json", "/Gemfile",
    "/requirements.txt", "/Pipfile",
    # CI/CD
    "/.github/workflows/", "/.gitlab-ci.yml",
    "/Jenkinsfile", "/.circleci/config.yml",
]

DIRECTORY_LISTING_INDICATORS = [
    "Index of /", "Directory listing for", "Parent Directory",
    "<title>Directory listing", "Directory Listing",
]

SENSITIVE_CONTENT_PATTERNS = {
    "/.env": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "AWS_", "REDIS_"],
    "/.git/HEAD": ["ref: refs/"],
    "/.git/config": ["[remote", "[branch", "repositoryformatversion"],
    "/phpinfo.php": ["phpinfo()", "PHP Version", "php.ini"],
}


def _build_curl(url):
    return f"curl -k -s -o /dev/null -w '%{{http_code}}' '{url}'"


def run(session: ScanSession) -> None:
    print("\n[*] Scanning for sensitive files and directories...")

    soft404_resp = session.get(urljoin(session.config.target, "/vulnscan_nonexistent_page_404_test"))
    soft404_text = soft404_resp.text[:2000] if soft404_resp and soft404_resp.status_code == 200 else None

    target_parsed = urlparse(session.config.target)

    for path in SENSITIVE_PATHS:
        url = urljoin(session.config.target, path)
        resp = session.get(url, allow_redirects=False)
        if not resp:
            continue

        if resp.status_code == 200:
            content = resp.text[:5000]
            content_type = resp.headers.get("Content-Type", "")

            if soft404_text and path not in SENSITIVE_CONTENT_PATTERNS:
                from difflib import SequenceMatcher
                similarity = SequenceMatcher(None, content[:2000], soft404_text).ratio()
                if similarity > 0.85:
                    continue

            if any(ind in content for ind in DIRECTORY_LISTING_INDICATORS):
                snippet = content[:300].replace('\n', ' ').strip()
                session.add_finding(Finding(
                    title=f"Directory Listing Enabled: {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Directory listing is enabled at {path}, exposing the internal file structure "
                        f"of the web application. An attacker can browse all files in this directory, "
                        f"potentially discovering sensitive files, backup archives, configuration files, "
                        f"or source code that should not be publicly accessible."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Status: 200\n"
                        f"Content-Type: {content_type}\n"
                        f"Directory listing indicators found in response body.\n"
                        f"Response Snippet: {snippet}..."
                    ),
                    remediation=(
                        "1. Disable directory listing in the web server configuration.\n"
                        "2. For Apache: Remove 'Options Indexes' or add 'Options -Indexes' in httpd.conf or .htaccess.\n"
                        "3. For Nginx: Remove 'autoindex on;' from the location block.\n"
                        "4. Add a default index file (index.html) to prevent fallback to directory listing.\n"
                        "5. Audit directory contents and remove any files that should not be web-accessible."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-548",
                    confirmed=True,
                    location=f"Directory path '{path}' on {target_parsed.netloc}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        f"1. Open a browser or HTTP client.\n"
                        f"2. Navigate to: {url}\n"
                        f"3. Observe the directory listing showing file names, sizes, and modification dates.\n"
                        f"4. Click on any listed file to access it directly."
                    ),
                    developer_fix=(
                        f"File: Web server configuration (e.g., httpd.conf, nginx.conf, or .htaccess)\n"
                        f"Fix: Disable directory indexing for the '{path}' path.\n\n"
                        f"Apache (.htaccess or httpd.conf):\n"
                        f"  Options -Indexes\n\n"
                        f"Nginx (nginx.conf):\n"
                        f"  location {path} {{\n"
                        f"      autoindex off;\n"
                        f"  }}\n\n"
                        f"IIS (web.config):\n"
                        f"  <directoryBrowse enabled=\"false\" />"
                    ),
                    affected_component=f"Web server directory listing at {path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information | "
                        "https://cwe.mitre.org/data/definitions/548.html"
                    ),
                ))
                continue

            confirmed = False
            if path in SENSITIVE_CONTENT_PATTERNS:
                patterns = SENSITIVE_CONTENT_PATTERNS[path]
                if any(p in content for p in patterns):
                    confirmed = True

            if path.endswith((".env", ".env.bak", ".env.local", ".env.production")):
                if any(p in content for p in ["DB_", "SECRET", "API_KEY", "PASSWORD"]):
                    matched_vars = [p for p in ["DB_", "SECRET", "API_KEY", "PASSWORD"] if p in content]
                    # Extract first few lines as evidence (redact values)
                    env_lines = content.split('\n')[:10]
                    redacted = []
                    for line in env_lines:
                        if '=' in line and not line.strip().startswith('#'):
                            key = line.split('=', 1)[0]
                            redacted.append(f"{key}=<REDACTED>")
                        else:
                            redacted.append(line)
                    redacted_preview = '\n'.join(redacted)

                    session.add_finding(Finding(
                        title=f"Environment File Exposed: {path}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The environment configuration file at {path} is publicly accessible and "
                            f"contains sensitive configuration data including database credentials, API keys, "
                            f"and secret tokens. This is a critical information disclosure that can lead to "
                            f"full application and database compromise. Environment files should never be "
                            f"served by the web server."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Matched Patterns: {', '.join(matched_vars)}\n"
                            f"Content Preview (redacted values):\n{redacted_preview}"
                        ),
                        remediation=(
                            "1. Immediately rotate ALL credentials found in the exposed file.\n"
                            "2. Block access to .env files in the web server configuration.\n"
                            "3. Move .env files outside the web root directory.\n"
                            "4. Add .env to .gitignore to prevent committing to version control.\n"
                            "5. Audit access logs for any prior access to this file."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-538",
                        confirmed=True,
                        location=f"File '{path}' in web root on {target_parsed.netloc}",
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=f"curl -k -s '{url}'",
                        reproduction_steps=(
                            f"1. Open a browser or use curl.\n"
                            f"2. Request the URL: {url}\n"
                            f"3. Observe the response contains environment variables with sensitive values.\n"
                            f"4. Note database credentials, API keys, and secret tokens are exposed in plaintext."
                        ),
                        developer_fix=(
                            f"File: Web server configuration and deployment scripts\n"
                            f"Fix: Block all .env file access and move them outside web root.\n\n"
                            f"Apache (.htaccess):\n"
                            f"  <FilesMatch \"^\\.env\">\n"
                            f"      Order allow,deny\n"
                            f"      Deny from all\n"
                            f"  </FilesMatch>\n\n"
                            f"Nginx:\n"
                            f"  location ~ /\\.env {{\n"
                            f"      deny all;\n"
                            f"      return 404;\n"
                            f"  }}\n\n"
                            f"Additionally, move .env outside the web root:\n"
                            f"  # Instead of /var/www/html/.env\n"
                            f"  # Use /var/www/.env and reference with:\n"
                            f"  # require_once dirname(__DIR__) . '/.env';"
                        ),
                        affected_component=f"Environment configuration file at {path}",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information | "
                            "https://cwe.mitre.org/data/definitions/538.html"
                        ),
                    ))
                    continue

            if "/.git/" in path and confirmed:
                session.add_finding(Finding(
                    title=f"Git Repository Exposed: {path}",
                    severity=Severity.HIGH,
                    description=(
                        f"Git repository metadata is accessible at {path}. An attacker can reconstruct "
                        f"the entire source code of the application by downloading Git objects. This "
                        f"exposes source code, commit history, developer information, and potentially "
                        f"hardcoded credentials or API keys embedded in the code."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Status: {resp.status_code}\n"
                        f"Content matches Git repository file patterns.\n"
                        f"Content Preview: {content[:200]}"
                    ),
                    remediation=(
                        "1. Block access to the .git directory immediately.\n"
                        "2. Audit the repository for any hardcoded secrets and rotate them.\n"
                        "3. Review commit history for sensitive data and consider force-pushing a cleaned history.\n"
                        "4. Ensure .git is excluded from deployment artifacts.\n"
                        "5. Use server configuration to deny access to hidden files and directories."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-538",
                    confirmed=True,
                    location=f"Git metadata at '{path}' on {target_parsed.netloc}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=f"curl -k -s '{url}'",
                    reproduction_steps=(
                        f"1. Request the URL: {url}\n"
                        f"2. Observe Git metadata in the response.\n"
                        f"3. Use a tool like 'git-dumper' to reconstruct the full repository:\n"
                        f"   git-dumper {urljoin(session.config.target, '/.git/')} output_dir\n"
                        f"4. Browse the recovered source code and commit history."
                    ),
                    developer_fix=(
                        f"File: Web server configuration and deployment pipeline\n"
                        f"Fix: Block access to all hidden files/directories and exclude .git from deployments.\n\n"
                        f"Apache (.htaccess):\n"
                        f"  RedirectMatch 404 /\\.git\n\n"
                        f"Nginx:\n"
                        f"  location ~ /\\.git {{\n"
                        f"      deny all;\n"
                        f"      return 404;\n"
                        f"  }}\n\n"
                        f"Deployment: Use .dockerignore or .gitattributes export-ignore:\n"
                        f"  # .dockerignore\n"
                        f"  .git"
                    ),
                    affected_component=f"Version control metadata at {path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces | "
                        "https://cwe.mitre.org/data/definitions/538.html"
                    ),
                ))
                continue

            if path in ("/phpinfo.php", "/info.php", "/test.php") and confirmed:
                session.add_finding(Finding(
                    title=f"PHP Info Page Exposed: {path}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"A PHP information disclosure page is accessible at {path}. This page reveals "
                        f"detailed server configuration including PHP version, loaded modules, environment "
                        f"variables, file paths, database connection settings, and internal IP addresses. "
                        f"Attackers use this information to identify specific vulnerabilities and plan targeted attacks."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Status: {resp.status_code}\n"
                        f"Response contains phpinfo() output with server configuration details."
                    ),
                    remediation=(
                        "1. Delete phpinfo/test/info files from the production server immediately.\n"
                        "2. Add a deployment check to prevent debug files from reaching production.\n"
                        "3. If PHP info is needed for debugging, restrict access by IP or require authentication.\n"
                        "4. Audit for other debug/test files that may have been left behind."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=True,
                    location=f"Debug file '{path}' on {target_parsed.netloc}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=resp.status_code,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        f"1. Open a browser.\n"
                        f"2. Navigate to: {url}\n"
                        f"3. Observe the full PHP configuration page showing server details.\n"
                        f"4. Note exposed information: PHP version, loaded extensions, environment variables, file paths."
                    ),
                    developer_fix=(
                        f"File: {path} on the production server\n"
                        f"Fix: Remove the file and add a deployment safeguard.\n\n"
                        f"Remove:\n"
                        f"  rm {path}\n\n"
                        f"Add to deployment pipeline (e.g., Dockerfile):\n"
                        f"  RUN find /var/www -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' | xargs rm -f\n\n"
                        f"If access is needed, restrict by IP:\n"
                        f"  # Apache .htaccess\n"
                        f"  <Files \"phpinfo.php\">\n"
                        f"      Require ip 10.0.0.0/8\n"
                        f"  </Files>"
                    ),
                    affected_component=f"PHP debug/info page at {path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server | "
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ),
                ))
                continue

            admin_paths = ["/admin", "/admin/", "/administrator/", "/wp-admin/",
                           "/phpmyadmin/", "/adminer.php", "/admin/login", "/dashboard", "/panel"]
            if path in admin_paths and "text/html" in content_type:
                if any(kw in content.lower() for kw in ["login", "password", "sign in", "username"]):
                    session.add_finding(Finding(
                        title=f"Admin Interface Found: {path}",
                        severity=Severity.INFO,
                        description=(
                            f"An administrative or management interface was discovered at {path}. "
                            f"The page contains a login form, indicating it is an access-controlled area. "
                            f"While the interface requires authentication, its public discoverability allows "
                            f"attackers to focus brute-force or credential-stuffing attacks on this endpoint."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Content-Type: {content_type}\n"
                            f"Login-related keywords detected in response body."
                        ),
                        remediation=(
                            "1. Restrict access to admin interfaces by IP address using firewall rules.\n"
                            "2. Implement multi-factor authentication (MFA) for all admin accounts.\n"
                            "3. Consider renaming the admin path to a non-standard URL.\n"
                            "4. Implement account lockout after failed login attempts.\n"
                            "5. Add rate limiting to the login endpoint."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=True,
                        location=f"Admin interface at '{path}' on {target_parsed.netloc}",
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=_build_curl(url),
                        reproduction_steps=(
                            f"1. Open a browser.\n"
                            f"2. Navigate to: {url}\n"
                            f"3. Observe the admin login page is publicly accessible.\n"
                            f"4. Note any additional information disclosed (software name, version, etc.)."
                        ),
                        developer_fix=(
                            f"File: Web server configuration or application routing\n"
                            f"Fix: Restrict admin access to trusted networks only.\n\n"
                            f"Nginx:\n"
                            f"  location {path} {{\n"
                            f"      allow 10.0.0.0/8;\n"
                            f"      allow 192.168.0.0/16;\n"
                            f"      deny all;\n"
                            f"  }}\n\n"
                            f"Apache (.htaccess):\n"
                            f"  <Location \"{path}\">\n"
                            f"      Require ip 10.0.0.0/8 192.168.0.0/16\n"
                            f"  </Location>"
                        ),
                        affected_component=f"Administrative interface at {path}",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces | "
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ),
                    ))
                    continue

            api_paths = ["/swagger-ui.html", "/swagger.json", "/api-docs",
                         "/openapi.json", "/graphql", "/graphiql"]
            if path in api_paths and resp.status_code == 200:
                if "text/html" in content_type or "application/json" in content_type:
                    session.add_finding(Finding(
                        title=f"API Documentation Exposed: {path}",
                        severity=Severity.LOW,
                        description=(
                            f"API documentation or interactive interface is publicly accessible at {path}. "
                            f"This exposes the full API surface area including endpoints, parameters, data models, "
                            f"and authentication mechanisms. Attackers can use this information to identify "
                            f"vulnerabilities, craft targeted requests, and discover hidden functionality."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Content-Type: {content_type}\n"
                            f"Response contains API documentation/interface content."
                        ),
                        remediation=(
                            "1. Restrict API documentation access in production environments.\n"
                            "2. Require authentication to view API docs.\n"
                            "3. If public API docs are intended, ensure no internal-only endpoints are documented.\n"
                            "4. Disable interactive 'Try it out' features in production."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=confirmed,
                        location=f"API documentation at '{path}' on {target_parsed.netloc}",
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=_build_curl(url),
                        reproduction_steps=(
                            f"1. Open a browser.\n"
                            f"2. Navigate to: {url}\n"
                            f"3. Observe the API documentation listing all available endpoints.\n"
                            f"4. Note exposed endpoint paths, parameters, and authentication requirements."
                        ),
                        developer_fix=(
                            f"File: Application configuration (e.g., SpringBoot application.yml, Express middleware)\n"
                            f"Fix: Disable API docs in production or require authentication.\n\n"
                            f"Spring Boot (application.yml):\n"
                            f"  springdoc:\n"
                            f"    api-docs:\n"
                            f"      enabled: false  # or use security\n\n"
                            f"Express.js:\n"
                            f"  if (process.env.NODE_ENV !== 'production') {{\n"
                            f"      app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));\n"
                            f"  }}"
                        ),
                        affected_component=f"API documentation endpoint at {path}",
                        references=(
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ | "
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ),
                    ))

            if path == "/robots.txt" and resp.status_code == 200:
                disallowed = [line.split(":", 1)[1].strip()
                              for line in content.split("\n")
                              if line.strip().lower().startswith("disallow")]
                if disallowed:
                    disallowed_list = ', '.join(disallowed[:10])
                    session.add_finding(Finding(
                        title="Robots.txt Reveals Hidden Paths",
                        severity=Severity.INFO,
                        description=(
                            f"The robots.txt file discloses {len(disallowed)} restricted paths. While "
                            f"robots.txt is intended to guide search engine crawlers, it inadvertently "
                            f"creates a roadmap of sensitive paths for attackers. Disallowed paths often "
                            f"point to admin panels, internal APIs, or other restricted areas."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Status: {resp.status_code}\n"
                            f"Disallowed Paths: {disallowed_list}"
                        ),
                        remediation=(
                            "1. Review all disallowed paths and ensure they are protected by proper authentication.\n"
                            "2. Do not rely on robots.txt for security -- it is a suggestion, not an access control.\n"
                            "3. Consider removing sensitive paths from robots.txt and securing them at the server level.\n"
                            "4. Use 'noindex' meta tags instead for pages that should not appear in search results."
                        ),
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=True,
                        location=f"robots.txt at {target_parsed.netloc}",
                        parameter="",
                        payload="",
                        request_method="GET",
                        response_status=resp.status_code,
                        curl_command=f"curl -k -s '{url}'",
                        reproduction_steps=(
                            f"1. Request the URL: {url}\n"
                            f"2. Review the 'Disallow' directives listing restricted paths.\n"
                            f"3. Attempt to access each disallowed path to check for proper access control.\n"
                            f"4. Disallowed paths found: {disallowed_list}"
                        ),
                        developer_fix=(
                            f"File: robots.txt and web server configuration\n"
                            f"Fix: Protect sensitive paths with authentication rather than robots.txt.\n\n"
                            f"robots.txt (minimized):\n"
                            f"  User-agent: *\n"
                            f"  Disallow: /  # or just remove sensitive-path entries\n\n"
                            f"For pages that should not be indexed, use meta tags instead:\n"
                            f"  <meta name=\"robots\" content=\"noindex, nofollow\">\n\n"
                            f"Ensure authentication is enforced on restricted paths:\n"
                            f"  location /admin {{\n"
                            f"      auth_basic \"Restricted\";\n"
                            f"      auth_basic_user_file /etc/nginx/.htpasswd;\n"
                            f"  }}"
                        ),
                        affected_component="robots.txt information disclosure",
                        references=(
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage | "
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ),
                    ))

        elif resp.status_code == 403:
            interesting_403 = ["/.env", "/.git/", "/admin", "/phpmyadmin", "/config"]
            if any(path.startswith(p) for p in interesting_403):
                session.add_finding(Finding(
                    title=f"Forbidden Path Exists: {path}",
                    severity=Severity.INFO,
                    description=(
                        f"The path {path} returns HTTP 403 Forbidden, confirming the resource exists "
                        f"on the server but access is currently denied. While access is blocked, the "
                        f"403 response (instead of 404) reveals the existence of this path, which may "
                        f"help attackers map the application structure and identify targets for "
                        f"bypass attempts."
                    ),
                    evidence=(
                        f"URL: {url}\n"
                        f"Status: 403 Forbidden\n"
                        f"The server confirms the path exists but denies access."
                    ),
                    remediation=(
                        "1. Return 404 instead of 403 for paths that should be hidden.\n"
                        "2. If the resource should be accessible to certain users, implement proper authentication.\n"
                        "3. Review the server configuration to ensure the access restriction is intentional."
                    ),
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=True,
                    location=f"Path '{path}' on {target_parsed.netloc}",
                    parameter="",
                    payload="",
                    request_method="GET",
                    response_status=403,
                    curl_command=_build_curl(url),
                    reproduction_steps=(
                        f"1. Send a GET request to: {url}\n"
                        f"2. Observe the HTTP 403 Forbidden response.\n"
                        f"3. Compare with a non-existent path (which should return 404).\n"
                        f"4. The 403 confirms the path exists on the server."
                    ),
                    developer_fix=(
                        f"File: Web server configuration\n"
                        f"Fix: Return 404 for hidden paths to avoid confirming their existence.\n\n"
                        f"Nginx:\n"
                        f"  location {path} {{\n"
                        f"      return 404;\n"
                        f"  }}\n\n"
                        f"Apache:\n"
                        f"  <Location \"{path}\">\n"
                        f"      Redirect 404 /\n"
                        f"  </Location>"
                    ),
                    affected_component=f"Access control for {path}",
                    references=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information | "
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ),
                ))
