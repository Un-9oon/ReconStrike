import time
import urllib3
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import requests
from colorama import Fore, Style

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self):
        return {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.CYAN,
            "INFO": Fore.BLUE,
        }[self.value]

    @property
    def score(self):
        return {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 2.0, "INFO": 0.0}[self.value]


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    url: str
    module: str
    cwe: str = ""
    confirmed: bool = False

    @property
    def confidence(self):
        return "Confirmed" if self.confirmed else "Tentative"


@dataclass
class ScanConfig:
    target: str
    threads: int = 10
    timeout: int = 10
    depth: int = 3
    user_agent: str = "ReconStrike/3.0 (Security Audit)"
    auth_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    verify_ssl: bool = False
    follow_redirects: bool = True
    scan_modules: list = field(default_factory=list)
    proxy: str = ""
    rate_limit: float = 0
    scope_include: str = ""
    scope_exclude: str = ""


class ScanSession:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers.update({
            "User-Agent": config.user_agent,
            **config.headers,
        })
        if config.cookies:
            self.session.cookies.update(config.cookies)
        self.findings: list[Finding] = []
        self.crawled_urls: set[str] = set()
        self.forms: list[dict] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self._last_request_time: float = 0
        self._request_count: int = 0

    def authenticate(self) -> bool:
        if not self.config.auth_url:
            return True
        try:
            resp = self.session.get(self.config.auth_url, timeout=self.config.timeout)
            from .crawler import extract_forms
            forms = extract_forms(resp.text, self.config.auth_url)
            login_form = None
            for form in forms:
                input_names = [i["name"].lower() for i in form["inputs"] if i.get("name")]
                has_password = any("pass" in n for n in input_names)
                if has_password:
                    login_form = form
                    break
            if not login_form:
                print(f"{Fore.YELLOW}[!] No login form found at {self.config.auth_url}{Style.RESET_ALL}")
                return False

            post_data = {}
            for inp in login_form["inputs"]:
                name = inp.get("name", "")
                if not name:
                    continue
                if "user" in name.lower() or "email" in name.lower() or "login" in name.lower():
                    post_data[name] = self.config.auth_username
                elif "pass" in name.lower():
                    post_data[name] = self.config.auth_password
                elif inp.get("value"):
                    post_data[name] = inp["value"]

            method = login_form.get("method", "post").lower()
            action = login_form.get("action", self.config.auth_url)

            if method == "post":
                resp = self.session.post(action, data=post_data, timeout=self.config.timeout)
            else:
                resp = self.session.get(action, params=post_data, timeout=self.config.timeout)

            if resp.status_code == 200 and "logout" in resp.text.lower():
                print(f"{Fore.GREEN}[+] Authentication successful{Style.RESET_ALL}")
                return True

            if resp.status_code in (301, 302, 303):
                print(f"{Fore.GREEN}[+] Authentication likely successful (redirect){Style.RESET_ALL}")
                return True

            print(f"{Fore.YELLOW}[!] Authentication result uncertain (status {resp.status_code}){Style.RESET_ALL}")
            return True

        except Exception as e:
            print(f"{Fore.RED}[-] Authentication failed: {e}{Style.RESET_ALL}")
            return False

    def add_finding(self, finding: Finding):
        for existing in self.findings:
            if existing.title == finding.title and existing.url == finding.url:
                return
        self.findings.append(finding)
        severity_color = finding.severity.color
        conf = f"{Fore.GREEN}CONFIRMED" if finding.confirmed else f"{Fore.YELLOW}TENTATIVE"
        print(
            f"  {severity_color}[{finding.severity.value}]{Style.RESET_ALL} "
            f"{finding.title} @ {finding.url} [{conf}{Style.RESET_ALL}]"
        )

    def _rate_limit(self):
        if self.config.rate_limit > 0:
            interval = 1.0 / self.config.rate_limit
            elapsed = time.time() - self._last_request_time
            if elapsed < interval:
                time.sleep(interval - elapsed)
        self._last_request_time = time.time()
        self._request_count += 1

    def _in_scope(self, url: str) -> bool:
        import re
        if self.config.scope_exclude:
            if re.search(self.config.scope_exclude, url):
                return False
        if self.config.scope_include:
            if not re.search(self.config.scope_include, url):
                return False
        return True

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            self._rate_limit()
            kwargs.setdefault("timeout", self.config.timeout)
            kwargs.setdefault("allow_redirects", self.config.follow_redirects)
            return self.session.get(url, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            self._rate_limit()
            kwargs.setdefault("timeout", self.config.timeout)
            return self.session.post(url, **kwargs)
        except requests.RequestException:
            return None

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            kwargs.setdefault("timeout", self.config.timeout)
            return self.session.head(url, **kwargs)
        except requests.RequestException:
            return None
