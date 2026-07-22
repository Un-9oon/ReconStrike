import re
from scanner.core import ScanSession

TECH_PATTERNS = {
    "frameworks": {
        "React": [r'data-reactroot', r'_reactRoot', r'__NEXT_DATA__'],
        "Angular": [r'ng-version="', r'ng-app', r'angular\.min\.js'],
        "Vue.js": [r'data-v-[a-f0-9]', r'__vue__', r'vue\.min\.js'],
        "jQuery": [r'jquery[\.-][\d\.]+\.min\.js', r'jquery\.js'],
        "Bootstrap": [r'bootstrap[\.-][\d\.]+\.min\.(css|js)'],
        "Next.js": [r'__NEXT_DATA__', r'/_next/static'],
        "Nuxt.js": [r'__NUXT__', r'/_nuxt/'],
        "Svelte": [r'svelte-[\w]+', r'__svelte'],
        "Django": [r'csrfmiddlewaretoken', r'__admin/'],
        "Laravel": [r'laravel_session', r'XSRF-TOKEN.*laravel'],
        "Rails": [r'csrf-token.*content', r'action_controller'],
        "Express": [r'X-Powered-By.*Express'],
        "Flask": [r'Werkzeug/', r'werkzeug\.debug'],
        "Spring": [r'JSESSIONID', r'spring-security'],
        "ASP.NET": [r'__VIEWSTATE', r'__EVENTVALIDATION', r'aspnet_sessionid'],
    },
    "servers": {
        "Nginx": [r'Server:.*nginx'],
        "Apache": [r'Server:.*Apache'],
        "IIS": [r'Server:.*IIS', r'X-Powered-By.*ASP\.NET'],
        "LiteSpeed": [r'Server:.*LiteSpeed'],
        "Caddy": [r'Server:.*Caddy'],
    },
    "cms": {
        "WordPress": [r'wp-content/', r'wp-includes/', r'wp-json'],
        "Drupal": [r'Drupal\.settings', r'sites/default/files'],
        "Joomla": [r'/media/jui/', r'Joomla!'],
        "Ghost": [r'ghost-api', r'content/themes/'],
    },
    "cdn": {
        "Cloudflare": [r'CF-RAY', r'cloudflare'],
        "AWS CloudFront": [r'X-Amz-Cf-Id', r'cloudfront\.net'],
        "Fastly": [r'X-Served-By.*cache', r'fastly'],
        "Akamai": [r'X-Akamai'],
    },
    "analytics": {
        "Google Analytics": [r'google-analytics\.com', r'ga\.js', r'gtag/js'],
        "Google Tag Manager": [r'googletagmanager\.com'],
        "Facebook Pixel": [r'connect\.facebook\.net/.*fbevents'],
        "Hotjar": [r'static\.hotjar\.com'],
    },
}


def analyze_tech_stack(session: ScanSession) -> dict:
    detected = {}
    resp = session.get(session.config.target)
    if not resp:
        return detected

    combined = resp.text
    headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    combined += "\n" + headers_str

    for category, techs in TECH_PATTERNS.items():
        for tech_name, patterns in techs.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.setdefault(category, [])
                    if tech_name not in detected[category]:
                        detected[category].append(tech_name)
                    break

    return detected


def print_tech_stack(stack: dict):
    from colorama import Fore, Style
    if not stack:
        print(f"  {Fore.YELLOW}[*] No technologies detected.{Style.RESET_ALL}")
        return

    for category, techs in stack.items():
        print(f"  {Fore.CYAN}{category.title()}: {Style.RESET_ALL}{', '.join(techs)}")
