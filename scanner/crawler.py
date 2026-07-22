import re
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup
from colorama import Fore, Style


def extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        action = urljoin(base_url, action) if action else base_url
        method = form.get("method", "get").lower()
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            input_info = {
                "name": tag.get("name", ""),
                "type": tag.get("type", "text"),
                "value": tag.get("value", ""),
            }
            if tag.name == "select":
                input_info["type"] = "select"
                options = tag.find_all("option")
                if options:
                    input_info["value"] = options[0].get("value", "")
            inputs.append(input_info)
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def extract_links(html: str, base_url: str, scope_domain: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "link", "script", "img", "iframe", "frame"]):
        href = tag.get("href") or tag.get("src")
        if not href:
            continue
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc and parsed.netloc != scope_domain:
            continue
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        links.add(clean)
    return links


def extract_comments(html: str) -> list[str]:
    return re.findall(r"<!--(.*?)-->", html, re.DOTALL)


def extract_js_urls(html: str, base_url: str) -> set[str]:
    urls = set()
    patterns = [
        r'(?:href|src|action|url)\s*[=:]\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        for match in re.findall(pattern, html):
            if match.startswith(("http://", "https://", "/")):
                urls.add(urljoin(base_url, match))
    return urls


class Crawler:
    def __init__(self, scan_session):
        self.session = scan_session
        self.config = scan_session.config
        self.visited = set()
        self.scope_domain = urlparse(self.config.target).netloc

    def crawl(self) -> None:
        print(f"\n{Fore.CYAN}[*] Starting crawler on {self.config.target}{Style.RESET_ALL}")
        self._crawl_url(self.config.target, depth=0)
        print(
            f"{Fore.GREEN}[+] Crawling complete: {len(self.session.crawled_urls)} URLs, "
            f"{len(self.session.forms)} forms{Style.RESET_ALL}"
        )

    def _crawl_url(self, url: str, depth: int) -> None:
        if depth > self.config.depth:
            return
        normalized = self._normalize(url)
        if normalized in self.visited:
            return
        self.visited.add(normalized)

        resp = self.session.get(url)
        if not resp:
            return

        self.session.crawled_urls.add(url)
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return

        html = resp.text
        forms = extract_forms(html, url)
        for form in forms:
            form["source_url"] = url
            self.session.forms.append(form)

        links = extract_links(html, url, self.scope_domain)
        js_urls = extract_js_urls(html, url)
        all_urls = links | js_urls

        for link in all_urls:
            parsed = urlparse(link)
            if parsed.netloc != self.scope_domain:
                continue
            skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
                        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf")
            if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
                self.session.crawled_urls.add(link)
                continue
            self._crawl_url(link, depth + 1)

    def _normalize(self, url: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        normalized_params = "&".join(f"{k}=" for k in sorted(params.keys()))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{normalized_params}"
