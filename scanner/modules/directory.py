import os
from urllib.parse import urljoin

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


def run(session: ScanSession) -> None:
    print("\n[*] Scanning for sensitive files and directories...")

    soft404_resp = session.get(urljoin(session.config.target, "/vulnscan_nonexistent_page_404_test"))
    soft404_text = soft404_resp.text[:2000] if soft404_resp and soft404_resp.status_code == 200 else None

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
                session.add_finding(Finding(
                    title=f"Directory Listing Enabled: {path}",
                    severity=Severity.MEDIUM,
                    description=f"Directory listing is enabled at {path}, exposing file structure.",
                    evidence=f"URL: {url}\nStatus: 200\nContent contains directory listing indicators.",
                    remediation="Disable directory listing in web server configuration.",
                    url=url,
                    module="directory",
                    cwe="CWE-548",
                    confirmed=True,
                ))
                continue

            confirmed = False
            if path in SENSITIVE_CONTENT_PATTERNS:
                patterns = SENSITIVE_CONTENT_PATTERNS[path]
                if any(p in content for p in patterns):
                    confirmed = True

            if path.endswith((".env", ".env.bak", ".env.local", ".env.production")):
                if any(p in content for p in ["DB_", "SECRET", "API_KEY", "PASSWORD"]):
                    session.add_finding(Finding(
                        title=f"Environment File Exposed: {path}",
                        severity=Severity.CRITICAL,
                        description=f"Environment file at {path} is publicly accessible and contains sensitive configuration.",
                        evidence=f"URL: {url}\nContains environment variable patterns.",
                        remediation="Block access to .env files in web server config. Move them outside the web root.",
                        url=url,
                        module="directory",
                        cwe="CWE-538",
                        confirmed=True,
                    ))
                    continue

            if "/.git/" in path and confirmed:
                session.add_finding(Finding(
                    title=f"Git Repository Exposed: {path}",
                    severity=Severity.HIGH,
                    description=f"Git repository metadata is accessible at {path}. Source code may be recoverable.",
                    evidence=f"URL: {url}\nContent matches git file patterns.",
                    remediation="Block access to .git directory. Add rules in web server config.",
                    url=url,
                    module="directory",
                    cwe="CWE-538",
                    confirmed=True,
                ))
                continue

            if path in ("/phpinfo.php", "/info.php", "/test.php") and confirmed:
                session.add_finding(Finding(
                    title=f"PHP Info Page Exposed: {path}",
                    severity=Severity.MEDIUM,
                    description=f"PHP info page at {path} reveals server configuration details.",
                    evidence=f"URL: {url}",
                    remediation="Remove info/debug PHP files from production.",
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=True,
                ))
                continue

            admin_paths = ["/admin", "/admin/", "/administrator/", "/wp-admin/",
                           "/phpmyadmin/", "/adminer.php", "/admin/login", "/dashboard", "/panel"]
            if path in admin_paths and "text/html" in content_type:
                if any(kw in content.lower() for kw in ["login", "password", "sign in", "username"]):
                    session.add_finding(Finding(
                        title=f"Admin Interface Found: {path}",
                        severity=Severity.INFO,
                        description=f"An admin/management interface was found at {path}.",
                        evidence=f"URL: {url}\nStatus: 200\nContains login form.",
                        remediation="Restrict admin interfaces by IP. Use MFA. Consider renaming the admin path.",
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=True,
                    ))
                    continue

            api_paths = ["/swagger-ui.html", "/swagger.json", "/api-docs",
                         "/openapi.json", "/graphql", "/graphiql"]
            if path in api_paths and resp.status_code == 200:
                if "text/html" in content_type or "application/json" in content_type:
                    session.add_finding(Finding(
                        title=f"API Documentation Exposed: {path}",
                        severity=Severity.LOW,
                        description=f"API documentation/interface is publicly accessible at {path}.",
                        evidence=f"URL: {url}\nStatus: 200",
                        remediation="Restrict API docs access in production. Require authentication.",
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=confirmed,
                    ))

            if path == "/robots.txt" and resp.status_code == 200:
                disallowed = [line.split(":", 1)[1].strip()
                              for line in content.split("\n")
                              if line.strip().lower().startswith("disallow")]
                if disallowed:
                    session.add_finding(Finding(
                        title="Robots.txt Reveals Hidden Paths",
                        severity=Severity.INFO,
                        description=f"robots.txt discloses {len(disallowed)} restricted paths.",
                        evidence=f"Disallowed: {', '.join(disallowed[:10])}",
                        remediation="Review robots.txt entries. Sensitive paths should be protected by auth, not obscurity.",
                        url=url,
                        module="directory",
                        cwe="CWE-200",
                        confirmed=True,
                    ))

        elif resp.status_code == 403:
            interesting_403 = ["/.env", "/.git/", "/admin", "/phpmyadmin", "/config"]
            if any(path.startswith(p) for p in interesting_403):
                session.add_finding(Finding(
                    title=f"Forbidden Path Exists: {path}",
                    severity=Severity.INFO,
                    description=f"Path {path} returns 403 Forbidden, confirming it exists but is protected.",
                    evidence=f"URL: {url}\nStatus: 403",
                    remediation="Ensure 403 paths return 404 to avoid information disclosure.",
                    url=url,
                    module="directory",
                    cwe="CWE-200",
                    confirmed=True,
                ))
