import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.core import Finding, Severity, ScanSession


WEAK_CIPHERS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}


def run(session: ScanSession) -> None:
    parsed = urlparse(session.config.target)
    if parsed.scheme != "https":
        session.add_finding(Finding(
            title="Site Not Using HTTPS",
            severity=Severity.HIGH,
            description="The target is served over plain HTTP. All traffic is transmitted unencrypted.",
            evidence=f"URL scheme: {parsed.scheme}",
            remediation="Enable HTTPS with a valid TLS certificate.",
            url=session.config.target,
            module="ssl",
            cwe="CWE-319",
            confirmed=True,
        ))
        return

    print("\n[*] Checking SSL/TLS configuration...")
    hostname = parsed.netloc.split(":")[0]
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=session.config.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                if protocol in ("TLSv1", "TLSv1.1"):
                    session.add_finding(Finding(
                        title=f"Deprecated TLS Version: {protocol}",
                        severity=Severity.HIGH,
                        description=f"Server supports {protocol} which is deprecated and vulnerable.",
                        evidence=f"Negotiated protocol: {protocol}",
                        remediation="Disable TLSv1.0 and TLSv1.1. Use TLSv1.2 or TLSv1.3 only.",
                        url=session.config.target,
                        module="ssl",
                        cwe="CWE-326",
                        confirmed=True,
                    ))

                if cert:
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (not_after - now).days

                    if days_left < 0:
                        session.add_finding(Finding(
                            title="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            description="The SSL certificate has expired.",
                            evidence=f"Expiry: {cert['notAfter']} ({abs(days_left)} days ago)",
                            remediation="Renew the SSL certificate immediately.",
                            url=session.config.target,
                            module="ssl",
                            cwe="CWE-295",
                            confirmed=True,
                        ))
                    elif days_left < 30:
                        session.add_finding(Finding(
                            title="SSL Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            description=f"The SSL certificate expires in {days_left} days.",
                            evidence=f"Expiry: {cert['notAfter']}",
                            remediation="Renew the SSL certificate before expiration.",
                            url=session.config.target,
                            module="ssl",
                            cwe="CWE-295",
                            confirmed=True,
                        ))

                    subject = dict(x[0] for x in cert.get("subject", []))
                    san = cert.get("subjectAltName", [])
                    cert_names = [subject.get("commonName", "")]
                    cert_names.extend(v for t, v in san if t == "DNS")
                    if not any(_match_hostname(hostname, n) for n in cert_names):
                        session.add_finding(Finding(
                            title="SSL Certificate Hostname Mismatch",
                            severity=Severity.HIGH,
                            description="The certificate does not match the target hostname.",
                            evidence=f"Hostname: {hostname}, Cert names: {cert_names}",
                            remediation="Obtain a certificate that covers the target hostname.",
                            url=session.config.target,
                            module="ssl",
                            cwe="CWE-295",
                            confirmed=True,
                        ))

                if cipher:
                    cipher_name = cipher[0]
                    for weak in WEAK_CIPHERS:
                        if weak in cipher_name.upper():
                            session.add_finding(Finding(
                                title=f"Weak SSL Cipher: {cipher_name}",
                                severity=Severity.HIGH,
                                description=f"Server negotiated a weak cipher suite.",
                                evidence=f"Cipher: {cipher_name}, Protocol: {protocol}",
                                remediation="Disable weak cipher suites and use only strong ciphers (AES-GCM, ChaCha20).",
                                url=session.config.target,
                                module="ssl",
                                cwe="CWE-326",
                                confirmed=True,
                            ))
                            break

    except ssl.SSLCertVerificationError as e:
        session.add_finding(Finding(
            title="SSL Certificate Verification Failed",
            severity=Severity.HIGH,
            description="The SSL certificate could not be verified.",
            evidence=str(e),
            remediation="Use a valid certificate from a trusted CA.",
            url=session.config.target,
            module="ssl",
            cwe="CWE-295",
            confirmed=True,
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"  [!] SSL check failed: {e}")

    _check_deprecated_protocols(session, hostname, port)


def _check_deprecated_protocols(session: ScanSession, hostname: str, port: int):
    for proto_name, proto_const in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto_const
            ctx.maximum_version = proto_const
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    session.add_finding(Finding(
                        title=f"Server Accepts Deprecated {proto_name}",
                        severity=Severity.MEDIUM,
                        description=f"Server accepts connections via deprecated {proto_name}.",
                        evidence=f"Successfully connected with {proto_name}",
                        remediation=f"Disable {proto_name} on the server.",
                        url=session.config.target,
                        module="ssl",
                        cwe="CWE-326",
                        confirmed=True,
                    ))
        except (ssl.SSLError, socket.error, OSError):
            pass


def _match_hostname(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return hostname == pattern
