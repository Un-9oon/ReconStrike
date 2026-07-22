import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core import Finding, Severity, ScanSession

COMMON_PORTS = {
    21: ("FTP", Severity.MEDIUM),
    22: ("SSH", Severity.INFO),
    23: ("Telnet", Severity.HIGH),
    25: ("SMTP", Severity.LOW),
    53: ("DNS", Severity.INFO),
    80: ("HTTP", Severity.INFO),
    110: ("POP3", Severity.LOW),
    111: ("RPCBind", Severity.MEDIUM),
    135: ("MSRPC", Severity.MEDIUM),
    139: ("NetBIOS", Severity.MEDIUM),
    143: ("IMAP", Severity.LOW),
    443: ("HTTPS", Severity.INFO),
    445: ("SMB", Severity.HIGH),
    993: ("IMAPS", Severity.INFO),
    995: ("POP3S", Severity.INFO),
    1433: ("MSSQL", Severity.HIGH),
    1521: ("Oracle", Severity.HIGH),
    2049: ("NFS", Severity.HIGH),
    2375: ("Docker API (unencrypted)", Severity.CRITICAL),
    2376: ("Docker API", Severity.MEDIUM),
    3306: ("MySQL", Severity.HIGH),
    3389: ("RDP", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.HIGH),
    5672: ("RabbitMQ", Severity.MEDIUM),
    5900: ("VNC", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    6443: ("Kubernetes API", Severity.HIGH),
    8080: ("HTTP Proxy/Alt", Severity.LOW),
    8443: ("HTTPS Alt", Severity.INFO),
    8888: ("HTTP Alt", Severity.LOW),
    9090: ("Management Console", Severity.MEDIUM),
    9200: ("Elasticsearch", Severity.HIGH),
    9300: ("Elasticsearch Transport", Severity.HIGH),
    11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    27018: ("MongoDB", Severity.HIGH),
}

DANGEROUS_SERVICES = {
    "Telnet", "SMB", "MSSQL", "Oracle", "MySQL", "PostgreSQL", "VNC",
    "Redis", "MongoDB", "Elasticsearch", "Memcached", "NFS",
    "Docker API (unencrypted)", "Kubernetes API", "NetBIOS", "RPCBind",
}

BANNER_GRAB_PORTS = {21, 22, 23, 25, 80, 110, 143, 3306, 6379, 11211, 27017}


def _scan_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool, str]:
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            if port in BANNER_GRAB_PORTS:
                try:
                    if port in (80, 443, 8080):
                        sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            sock.close()
            return port, True, banner
        sock.close()
    except Exception:
        pass
    return port, False, ""


def run(session: ScanSession) -> None:
    print("\n[*] Running port scan...")

    parsed = urlparse(session.config.target)
    hostname = parsed.netloc.split(":")[0]

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"  [!] Cannot resolve hostname: {hostname}")
        return

    print(f"  [*] Scanning {hostname} ({ip}) — {len(COMMON_PORTS)} ports...")

    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(_scan_port, ip, port): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service_name, _ = COMMON_PORTS[port]
                open_ports.append((port, service_name, banner))

    open_ports.sort(key=lambda x: x[0])

    if not open_ports:
        print("  [+] No commonly targeted ports found open.")
        return

    web_ports = {80, 443, 8080, 8443}
    target_port = parsed.port

    for port, service, banner in open_ports:
        _, default_severity = COMMON_PORTS[port]

        if port in web_ports or port == target_port:
            continue

        is_dangerous = service in DANGEROUS_SERVICES

        if is_dangerous:
            severity = Severity.HIGH
            if service == "Docker API (unencrypted)":
                severity = Severity.CRITICAL
        else:
            severity = default_severity

        evidence = f"Port: {port}\nService: {service}\nHost: {hostname} ({ip})"
        if banner:
            evidence += f"\nBanner: {banner[:200]}"

        if is_dangerous:
            session.add_finding(Finding(
                title=f"Exposed Service: {service} (port {port})",
                severity=severity,
                description=f"{service} service is exposed on port {port}. "
                            f"This service should not be publicly accessible.",
                evidence=evidence,
                remediation=f"Restrict access to {service} (port {port}) using firewall rules. "
                            f"Only allow connections from trusted IPs. Use VPN for remote access.",
                url=session.config.target,
                module="portscan",
                cwe="CWE-284",
                confirmed=True,
            ))
        elif severity != Severity.INFO:
            session.add_finding(Finding(
                title=f"Open Port: {service} ({port})",
                severity=severity,
                description=f"{service} is accessible on port {port}.",
                evidence=evidence,
                remediation=f"Review if port {port} ({service}) needs to be publicly accessible.",
                url=session.config.target,
                module="portscan",
                cwe="CWE-284",
                confirmed=True,
            ))

    port_list = ", ".join(f"{p}({s})" for p, s, _ in open_ports)
    print(f"  [+] Open ports: {port_list}")
