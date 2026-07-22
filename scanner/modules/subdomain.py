import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core import Finding, Severity, ScanSession

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "remote",
    "admin", "panel", "cp", "cpanel", "whm", "webmin",
    "api", "api2", "api-v2", "rest", "graphql",
    "dev", "development", "staging", "stage", "stg", "test", "testing",
    "uat", "qa", "sandbox", "demo", "beta", "alpha", "preview",
    "app", "application", "portal", "gateway",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "git", "gitlab", "github", "svn", "bitbucket",
    "ci", "jenkins", "travis", "drone", "build",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "nagios",
    "log", "logs", "syslog", "elk",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "private", "corp", "corporate",
    "auth", "login", "sso", "oauth", "identity",
    "docs", "doc", "documentation", "wiki", "help", "support",
    "blog", "forum", "community",
    "shop", "store", "cart", "payment", "pay",
    "proxy", "gateway", "lb", "loadbalancer",
    "docker", "k8s", "kubernetes", "rancher", "swarm",
    "status", "health", "ping",
    "crm", "erp", "hr",
    "s3", "storage", "minio",
    "rabbitmq", "kafka", "queue",
    "vault", "secrets",
    "prometheus", "alertmanager",
]

INTERESTING_SUBDOMAINS = {
    "admin", "panel", "cpanel", "whm", "webmin", "dev", "staging", "stage",
    "test", "testing", "uat", "qa", "sandbox", "internal", "intranet",
    "private", "backup", "bak", "old", "legacy", "git", "gitlab", "jenkins",
    "docker", "k8s", "kubernetes", "db", "database", "mysql", "postgres",
    "redis", "mongo", "elastic", "grafana", "kibana", "prometheus", "vault",
}


def _resolve_subdomain(subdomain: str, domain: str) -> tuple[str, str | None]:
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except socket.gaierror:
        return fqdn, None


def run(session: ScanSession) -> None:
    print("\n[*] Enumerating subdomains...")

    parsed = urlparse(session.config.target)
    domain = parsed.netloc.split(":")[0]

    parts = domain.split(".")
    if len(parts) > 2:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = domain

    found_subdomains = []

    wildcard_ip = None
    random_sub = "vulnscan-wildcard-check-xz9q7"
    _, wild_ip = _resolve_subdomain(random_sub, base_domain)
    if wild_ip:
        wildcard_ip = wild_ip
        print(f"  [!] Wildcard DNS detected (*.{base_domain} -> {wild_ip}), filtering results...")

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(_resolve_subdomain, sub, base_domain): sub
            for sub in COMMON_SUBDOMAINS
        }
        for future in as_completed(futures):
            fqdn, ip = future.result()
            if ip:
                if wildcard_ip and ip == wildcard_ip:
                    continue
                sub = futures[future]
                found_subdomains.append((fqdn, ip, sub))

    found_subdomains.sort(key=lambda x: x[0])

    if not found_subdomains:
        print("  [*] No subdomains found via DNS brute force.")
        return

    print(f"  [+] Found {len(found_subdomains)} subdomains:")
    for fqdn, ip, _ in found_subdomains:
        print(f"      {fqdn} -> {ip}")

    interesting = [(fqdn, ip, sub) for fqdn, ip, sub in found_subdomains if sub in INTERESTING_SUBDOMAINS]

    if interesting:
        interesting_list = ", ".join(f"{fqdn} ({ip})" for fqdn, ip, _ in interesting)
        session.add_finding(Finding(
            title="Sensitive Subdomains Discovered",
            severity=Severity.MEDIUM,
            description=f"Found {len(interesting)} potentially sensitive subdomains that may expose "
                        "internal services, development environments, or admin interfaces.",
            evidence=f"Subdomains: {interesting_list}",
            remediation="Review exposed subdomains. Internal/dev/staging services should not be publicly resolvable. "
                        "Use split-horizon DNS or restrict via firewall.",
            url=session.config.target,
            module="subdomain",
            cwe="CWE-200",
            confirmed=True,
        ))

    all_list = "\n".join(f"  {fqdn} -> {ip}" for fqdn, ip, _ in found_subdomains)
    session.add_finding(Finding(
        title=f"Subdomain Enumeration: {len(found_subdomains)} Found",
        severity=Severity.INFO,
        description=f"DNS brute force discovered {len(found_subdomains)} subdomains for {base_domain}.",
        evidence=f"Subdomains:\n{all_list}",
        remediation="Review all subdomains and ensure only intended services are publicly accessible.",
        url=session.config.target,
        module="subdomain",
        cwe="CWE-200",
        confirmed=True,
    ))
