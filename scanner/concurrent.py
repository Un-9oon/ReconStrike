import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from colorama import Fore, Style

from scanner.core import ScanSession


class ConcurrentCrawler:
    """Thread-pool based crawler that's 5-10x faster than sequential."""

    def __init__(self, session: ScanSession):
        self.session = session
        self.config = session.config
        self.visited = set()
        self.scope_domain = urlparse(self.config.target).netloc
        self._lock = __import__("threading").Lock()

    def crawl(self):
        from scanner.crawler import extract_links, extract_forms, extract_js_urls

        print(f"\n{Fore.CYAN}[*] Starting concurrent crawler ({self.config.threads} threads)...{Style.RESET_ALL}")
        start = time.time()

        queue = [self.config.target]
        depth_map = {self.config.target: 0}

        while queue:
            batch = queue[:self.config.threads * 2]
            queue = queue[len(batch):]

            with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
                futures = {}
                for url in batch:
                    normalized = self._normalize(url)
                    with self._lock:
                        if normalized in self.visited:
                            continue
                        self.visited.add(normalized)
                    futures[pool.submit(self._fetch, url)] = url

                for future in as_completed(futures):
                    url = futures[future]
                    result = future.result()
                    if not result:
                        continue

                    resp, new_links, forms = result
                    self.session.crawled_urls.add(url)
                    for form in forms:
                        form["source_url"] = url
                        self.session.forms.append(form)

                    current_depth = depth_map.get(url, 0)
                    if current_depth < self.config.depth:
                        for link in new_links:
                            if self._normalize(link) not in self.visited:
                                depth_map[link] = current_depth + 1
                                queue.append(link)

        elapsed = time.time() - start
        print(
            f"{Fore.GREEN}[+] Crawling complete: {len(self.session.crawled_urls)} URLs, "
            f"{len(self.session.forms)} forms ({elapsed:.1f}s){Style.RESET_ALL}"
        )

    def _fetch(self, url):
        from scanner.crawler import extract_links, extract_forms, extract_js_urls

        resp = self.session.get(url)
        if not resp:
            return None

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return resp, set(), []

        html = resp.text
        forms = extract_forms(html, url)
        links = extract_links(html, url, self.scope_domain)
        js_urls = extract_js_urls(html, url)

        all_urls = set()
        skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
                    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf")
        for link in links | js_urls:
            parsed = urlparse(link)
            if parsed.netloc and parsed.netloc != self.scope_domain:
                continue
            if any(parsed.path.lower().endswith(ext) for ext in skip_ext):
                continue
            all_urls.add(link)

        return resp, all_urls, forms

    def _normalize(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        normalized_params = "&".join(f"{k}=" for k in sorted(params.keys()))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{normalized_params}"
