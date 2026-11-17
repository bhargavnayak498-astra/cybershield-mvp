from __future__ import annotations

import hashlib
import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from app.config import settings
from app.ml_utils import get_model_status

COMMON_BRANDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "paypal",
    "github",
    "dropbox",
    "netflix",
    "adobe",
    "bankofamerica",
    "wellsfargo",
    "chase",
    "bank",
    "discord",
    "linkedin",
    "zoom",
]

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "top",
    "xyz",
    "bid",
    "loan",
    "click",
    "club",
    "loan",
    "download",
    "rest",
}

REDIRECT_KEYS = {
    "next",
    "redirect",
    "url",
    "return",
    "target",
    "destination",
    "continue",
    "goto",
    "go",
    "r",
    "redir",
}


def normalize_host(hostname: str) -> str:
    if not hostname:
        return ""
    hostname = hostname.strip().rstrip(".")
    hostname = hostname.lower()
    return hostname


def make_redacted_url(url: str) -> str:
    parsed = urlsplit(url)
    host = normalize_host(parsed.hostname or "")
    if not host:
        return "[invalid-url]"
    if host.count(".") >= 2:
        parts = host.split(".")
        if len(parts) > 2:
            host = ".".join([parts[0], "***", parts[-1]]) if len(parts) > 3 else "***." + parts[-1]
    return f"{parsed.scheme}://{host}{parsed.path or '/'}"


def make_url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("URL cannot be empty.")

    if any(value.lower().startswith(prefix) for prefix in ("javascript:", "data:", "file:", "ftp:")):
        raise ValueError("Unsupported scheme. Only http and https are accepted.")

    if "://" not in value:
        raise ValueError("URL must include a scheme and hostname.")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Unsupported scheme. Only http and https are accepted.")

    hostname = normalize_host(parsed.hostname or "")
    if not hostname:
        raise ValueError("URL does not include a valid hostname.")

    if " " in value:
        raise ValueError("URL contains spaces and is malformed.")

    port = parsed.port
    netloc = hostname if port is None else f"{hostname}:{port}"

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass

    normalized = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment))
    return normalized


def detect_typo_like_brand(hostname: str) -> list[str]:
    host = hostname.lower().split(":")[0]
    if not host:
        return []

    root = host.split(".")[:-1] if "." in host else [host]
    root_name = "".join(root)
    candidates: list[str] = []
    for brand in COMMON_BRANDS:
        if brand in host:
            continue
        similarity = SequenceMatcher(None, root_name, brand).ratio()
        if similarity >= 0.8:
            candidates.append(brand)
    return candidates


def analyze_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlsplit(url)
    hostname = normalize_host(parsed.hostname or "")
    path = parsed.path or "/"
    query = parsed.query
    score = 0
    reasons: list[str] = []

    if parsed.scheme != "https":
        score += 18
        reasons.append("The URL uses HTTP instead of HTTPS.")

    if hostname.startswith("xn--"):
        score += 8
        reasons.append("The hostname contains punycode/IDN encoding, which can be used for homograph confusion.")

    try:
        ipaddress.ip_address(hostname)
        score += 38
        reasons.append("The hostname is a raw IP address, which is uncommon for legitimate hosted websites.")
    except ValueError:
        pass

    if len(url) > 120:
        score += 16
        reasons.append("The full URL is unusually long for a typical benign site.")

    labels = hostname.split(".") if hostname else []
    if len(labels) > 5:
        score += 12
        reasons.append("The hostname has excessive subdomain nesting.")

    if re.search(r"(%[0-9A-Fa-f]{2}|[.@%+\\]+)", hostname):
        score += 10
        reasons.append("The hostname contains encoded or special characters that can obfuscate the true domain.")

    if any(token in hostname for token in ("-", "--", "..")):
        score += 8
        reasons.append("The domain contains suspicious separators or dot-based obfuscation.")

    if any(token in (path.lower() + " " + query.lower()) for token in ("redirect", "next", "return", "target", "go=")):
        score += 14
        reasons.append("The URL contains redirect-like parameters that often lead to external destination changes.")

    if "@" in parsed.netloc or "%40" in parsed.netloc.lower():
        score += 12
        reasons.append("Credential-like '@' usage was detected in the URL.")

    if any(char in url for char in ("%2f", "%5c", "%00", "%2e%2e")):
        score += 10
        reasons.append("Encoded path or traversal-like sequences were detected.")

    suspicious_tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""
    if suspicious_tld in SUSPICIOUS_TLDS:
        score += 22
        reasons.append(f"The top-level domain '.{suspicious_tld}' is often associated with opportunistic or low-trust phishing sites.")

    brand_like = detect_typo_like_brand(hostname)
    if brand_like:
        score += 28
        reasons.append(f"The domain resembles a trusted brand but is not an exact match: {', '.join(brand_like)}.")

    if len(query) > 80:
        score += 8
        reasons.append("The query string is unusually long for a simple_site request and may hide a redirect or payload.")

    if parsed.path and any(s in parsed.path.lower() for s in ("login", "signin", "verify", "reset", "account", "update")):
        score += 10
        reasons.append("The path resembles a credential collection or login flow.")

    if "http://" in raw_url.lower() and parsed.scheme == "http":
        score += 6
        reasons.append("The URL is using a plain HTTP connection to a potentially sensitive flow.")

    if re.search(r"[A-Za-z0-9-]{30,}", hostname):
        score += 6
        reasons.append("The hostname contains an unusually long label pattern that can be used for impersonation.")

    if not reasons:
        reasons.append("No major phishing heuristics were triggered. The URL remains advisory-only and is not considered safe with certainty.")

    score = max(0, min(100, score))
    if score < 25:
        verdict = "Safe"
    elif score < 70:
        verdict = "Suspicious"
    else:
        verdict = "Phishing"

    model_status = get_model_status(settings.model_path)

    return {
        "url": raw_url,
        "normalized_url": url,
        "redacted_url": make_redacted_url(url),
        "hash": make_url_hash(url),
        "score": int(score),
        "verdict": verdict,
        "reasons": reasons,
        "model_status": model_status,
    }


def demo_urls() -> list[str]:
    return [
        "https://www.google.com/",
        "https://secure-login-microsoft.com/",
        "http://192.168.0.5/login?next=https://evil.example/",
        "javascript:alert(1)",
    ]
