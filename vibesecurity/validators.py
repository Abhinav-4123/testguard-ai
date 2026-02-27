"""
VibeSecurity - Input Validation & Security Utilities
SSRF protection, HTML sanitization, URL validation.
"""
import ipaddress
import socket
import logging
from html import escape
from urllib.parse import urlparse

logger = logging.getLogger("vibesecurity.validators")

# Private/reserved IP ranges that should never be scanned
BLOCKED_HOSTS = {"localhost", "0.0.0.0", "metadata.google.internal"}


def validate_scan_target(url: str) -> tuple[bool, str]:
    """
    Validate a URL is safe to scan. Blocks private IPs, loopback, link-local,
    cloud metadata endpoints, and non-HTTP schemes.
    Returns (is_valid, error_message).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are allowed"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a hostname"

    if hostname in BLOCKED_HOSTS:
        return False, "Scanning this host is not allowed"

    # Check if hostname is a direct IP
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            return False, "Scanning private or reserved IP addresses is not allowed"
    except ValueError:
        # It's a hostname, resolve and check all IPs
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for _, _, _, _, addr in resolved:
                ip = ipaddress.ip_address(addr[0])
                if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                    return False, "URL resolves to a private or reserved IP address"
        except socket.gaierror:
            return False, f"Could not resolve hostname: {hostname}"

    return True, ""


def sanitize_for_html(text: str) -> str:
    """Escape text for safe HTML rendering."""
    if text is None:
        return ""
    return escape(str(text), quote=True)


def validate_email(email: str) -> bool:
    """Basic email format validation."""
    if not email or "@" not in email or len(email) > 254:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return False
    return True
