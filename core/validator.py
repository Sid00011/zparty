import re
import socket
import httpx
import logging

logger = logging.getLogger(__name__)

URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)


class ValidationError(Exception):
    pass


def validate_url_format(url: str) -> None:
    if not URL_RE.match(url):
        raise ValidationError(
            f"Invalid URL format: '{url}'. Must start with http:// or https://"
        )


def validate_dns(url: str) -> str:
    from urllib.parse import urlparse
    host = urlparse(url).hostname
    if not host:
        raise ValidationError(f"Cannot extract hostname from URL: {url}")
    try:
        ip = socket.gethostbyname(host)
        logger.info(f"DNS resolved: {host} -> {ip}")
        return ip
    except socket.gaierror as e:
        raise ValidationError(f"DNS resolution failed for '{host}': {e}")


def validate_reachability(url: str, timeout: int = 20) -> int:
    """Warn on timeout/5xx but never hard-fail — DNS success is enough to proceed."""
    try:
        # verify=False: pentest tool — must handle self-signed / mismatched certs
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 Zparty/1.0"})
        if resp.status_code >= 500:
            logger.warning(f"Target returned {resp.status_code} — may be unstable, continuing")
        logger.info(f"Reachability check: {url} -> HTTP {resp.status_code}")
        return resp.status_code
    except httpx.ConnectError as e:
        raise ValidationError(f"Cannot reach target '{url}': {e}")
    except (httpx.TimeoutException, httpx.ReadTimeout, httpx.ConnectTimeout):
        logger.warning(f"Reachability check timed out for '{url}' — DNS resolved, continuing anyway")
        return 0
    except Exception as e:
        logger.warning(f"Reachability check failed ({e}) — continuing anyway")
        return 0


def validate_target(url: str, timeout: int = 20) -> dict:
    """Run all three validation layers. Returns metadata on success."""
    validate_url_format(url)
    ip = validate_dns(url)
    status = validate_reachability(url, timeout=timeout)
    return {"url": url, "resolved_ip": ip, "http_status": status}
