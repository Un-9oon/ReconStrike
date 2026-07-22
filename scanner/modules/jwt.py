import base64
import json
import re
import hashlib
import hmac

from scanner.core import Finding, Severity, ScanSession


def _decode_jwt_part(part: str) -> dict | None:
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception:
        return None


def _extract_jwts(text: str) -> list[str]:
    pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    return re.findall(pattern, text)


def _forge_none_alg(header_b64: str, payload_b64: str) -> str:
    header = _decode_jwt_part(header_b64)
    if not header:
        return ""
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{new_header}.{payload_b64}."


def _forge_weak_secret(header_b64: str, payload_b64: str) -> list[tuple[str, str]]:
    weak_secrets = [
        "secret", "password", "123456", "key", "test", "admin",
        "jwt_secret", "changeme", "mysecret", "default",
        "your-256-bit-secret", "shhhhh", "supersecret",
    ]
    results = []
    for secret in weak_secrets:
        msg = f"{header_b64}.{payload_b64}".encode()
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        results.append((secret, f"{header_b64}.{payload_b64}.{sig}"))
    return results


def run(session: ScanSession) -> None:
    print("\n[*] Checking for JWT vulnerabilities...")

    all_jwts = set()
    jwt_locations = {}

    for url in session.crawled_urls:
        resp = session.get(url)
        if not resp:
            continue

        for header_name in ["Authorization", "Set-Cookie", "X-Auth-Token", "X-Access-Token"]:
            header_val = resp.headers.get(header_name, "")
            tokens = _extract_jwts(header_val)
            for t in tokens:
                all_jwts.add(t)
                jwt_locations[t] = f"Header: {header_name} @ {url}"

        body_tokens = _extract_jwts(resp.text)
        for t in body_tokens:
            all_jwts.add(t)
            jwt_locations.setdefault(t, f"Body @ {url}")

    if not all_jwts:
        return

    for token in all_jwts:
        parts = token.split(".")
        if len(parts) < 2:
            continue

        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        location = jwt_locations.get(token, "Unknown")

        if not header or not payload:
            continue

        alg = header.get("alg", "")
        if alg.lower() == "none":
            session.add_finding(Finding(
                title="JWT Algorithm Set to 'none'",
                severity=Severity.CRITICAL,
                description="A JWT token uses algorithm 'none', meaning the signature is not verified.",
                evidence=f"Location: {location}\nHeader: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
                remediation="Always enforce a strong algorithm (RS256, ES256). Reject 'none' algorithm.",
                url=location.split(" @ ")[-1] if " @ " in location else session.config.target,
                module="jwt",
                cwe="CWE-345",
                confirmed=True,
            ))

        if alg in ("HS256", "HS384", "HS512"):
            none_token = _forge_none_alg(parts[0], parts[1])
            if none_token:
                for url in list(session.crawled_urls)[:5]:
                    resp = session.get(url, headers={"Authorization": f"Bearer {none_token}"})
                    if resp and resp.status_code == 200:
                        resp_orig = session.get(url, headers={"Authorization": f"Bearer {token}"})
                        if resp_orig and resp.text == resp_orig.text:
                            session.add_finding(Finding(
                                title="JWT 'none' Algorithm Accepted",
                                severity=Severity.CRITICAL,
                                description="Server accepts JWT tokens with algorithm set to 'none', bypassing signature verification.",
                                evidence=f"Original token accepted, then forged 'none' alg token also accepted.\nForged: {none_token[:80]}...",
                                remediation="Reject 'none' algorithm in JWT verification. Use a whitelist of allowed algorithms.",
                                url=url,
                                module="jwt",
                                cwe="CWE-345",
                                confirmed=True,
                            ))
                            break

            for secret, forged in _forge_weak_secret(parts[0], parts[1]):
                if len(parts) >= 3 and parts[2]:
                    forged_sig = forged.split(".")[-1]
                    if forged_sig == parts[2]:
                        session.add_finding(Finding(
                            title=f"JWT Signed with Weak Secret: '{secret}'",
                            severity=Severity.CRITICAL,
                            description=f"JWT token is signed with guessable secret '{secret}'.",
                            evidence=f"Secret: {secret}\nLocation: {location}\nPayload: {json.dumps(payload)}",
                            remediation="Use a strong, randomly generated secret (256+ bits). Rotate secrets regularly.",
                            url=location.split(" @ ")[-1] if " @ " in location else session.config.target,
                            module="jwt",
                            cwe="CWE-321",
                            confirmed=True,
                        ))
                        break

        if payload:
            sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key"]
            found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
            if found_sensitive:
                session.add_finding(Finding(
                    title="JWT Contains Sensitive Data",
                    severity=Severity.MEDIUM,
                    description=f"JWT payload contains sensitive fields: {', '.join(found_sensitive)}. "
                                "JWT payloads are base64-encoded, not encrypted.",
                    evidence=f"Sensitive fields: {found_sensitive}\nLocation: {location}",
                    remediation="Don't store sensitive data in JWT payloads. Use encrypted JWTs (JWE) if needed.",
                    url=location.split(" @ ")[-1] if " @ " in location else session.config.target,
                    module="jwt",
                    cwe="CWE-311",
                    confirmed=True,
                ))

            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                import time
                if exp - time.time() > 86400 * 30:
                    session.add_finding(Finding(
                        title="JWT Has Excessive Expiration",
                        severity=Severity.LOW,
                        description=f"JWT token has expiration more than 30 days from now.",
                        evidence=f"Expiration: {exp} (>30 days)\nLocation: {location}",
                        remediation="Use short-lived tokens (15-60 minutes) with refresh token rotation.",
                        url=location.split(" @ ")[-1] if " @ " in location else session.config.target,
                        module="jwt",
                        cwe="CWE-613",
                        confirmed=True,
                    ))
            elif "exp" not in payload:
                session.add_finding(Finding(
                    title="JWT Missing Expiration Claim",
                    severity=Severity.MEDIUM,
                    description="JWT token has no 'exp' claim, meaning it never expires.",
                    evidence=f"No 'exp' field in payload.\nLocation: {location}",
                    remediation="Always include an 'exp' claim in JWT tokens.",
                    url=location.split(" @ ")[-1] if " @ " in location else session.config.target,
                    module="jwt",
                    cwe="CWE-613",
                    confirmed=True,
                ))
