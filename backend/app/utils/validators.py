"""Target URL & input validators."""
import ipaddress
import re
from urllib.parse import urlparse
import socket


# Private / reserved IP ranges to block (prevent SSRF)
BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Blocked hostnames
BLOCKED_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
}


def validate_target_url(url: str) -> tuple[bool, str]:
    """
    Validate a target URL for scanning.
    Returns (is_valid, error_message).
    """
    url = url.strip()

    # Must not be empty
    if not url:
        return False, "Target URL is required."

    # Must have valid scheme
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Target URL must use http:// or https:// scheme."

    # Must have a hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: missing hostname."

    # Block known dangerous hostnames
    if hostname.lower() in BLOCKED_HOSTS:
        return False, f"Scanning '{hostname}' is not allowed."

    # Try to resolve and check against blocked IP ranges
    try:
        # Check if hostname is already an IP
        try:
            ip = ipaddress.ip_address(hostname)
            for blocked in BLOCKED_RANGES:
                if ip in blocked:
                    return False, f"Scanning private/reserved IP addresses is not allowed."
            return True, ""
        except ValueError:
            pass  # Not an IP address, it's a hostname

        # Resolve hostname
        addrs = socket.getaddrinfo(hostname, None)
        for addr_info in addrs:
            ip_str = addr_info[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                for blocked in BLOCKED_RANGES:
                    if ip in blocked:
                        return False, f"Target resolves to a private/reserved IP address."
            except ValueError:
                continue

    except socket.gaierror:
        # Can't resolve — might be valid for nuclei to handle, allow it
        pass

    return True, ""
