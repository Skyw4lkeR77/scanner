"""OWASP Top 10 (2021) category mapper using CWE IDs and nuclei template tags."""

# OWASP Top 10 2021 definitions
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# CWE -> OWASP mapping (common CWEs)
CWE_TO_OWASP = {
    # A01: Broken Access Control
    "CWE-22": "A01", "CWE-23": "A01", "CWE-35": "A01",
    "CWE-59": "A01", "CWE-200": "A01", "CWE-201": "A01",
    "CWE-219": "A01", "CWE-264": "A01", "CWE-275": "A01",
    "CWE-276": "A01", "CWE-284": "A01", "CWE-285": "A01",
    "CWE-352": "A01", "CWE-359": "A01", "CWE-377": "A01",
    "CWE-402": "A01", "CWE-425": "A01", "CWE-441": "A01",
    "CWE-497": "A01", "CWE-538": "A01", "CWE-540": "A01",
    "CWE-548": "A01", "CWE-552": "A01", "CWE-566": "A01",
    "CWE-601": "A01", "CWE-639": "A01", "CWE-651": "A01",
    "CWE-668": "A01", "CWE-706": "A01", "CWE-862": "A01",
    "CWE-863": "A01", "CWE-913": "A01", "CWE-922": "A01",
    "CWE-1275": "A01",

    # A02: Cryptographic Failures
    "CWE-261": "A02", "CWE-296": "A02", "CWE-310": "A02",
    "CWE-319": "A02", "CWE-321": "A02", "CWE-322": "A02",
    "CWE-323": "A02", "CWE-324": "A02", "CWE-325": "A02",
    "CWE-326": "A02", "CWE-327": "A02", "CWE-328": "A02",
    "CWE-329": "A02", "CWE-330": "A02", "CWE-331": "A02",
    "CWE-335": "A02", "CWE-336": "A02", "CWE-337": "A02",
    "CWE-338": "A02", "CWE-340": "A02", "CWE-347": "A02",
    "CWE-523": "A02", "CWE-720": "A02", "CWE-757": "A02",
    "CWE-759": "A02", "CWE-760": "A02", "CWE-780": "A02",
    "CWE-818": "A02", "CWE-916": "A02",

    # A03: Injection
    "CWE-20": "A03", "CWE-74": "A03", "CWE-75": "A03",
    "CWE-77": "A03", "CWE-78": "A03", "CWE-79": "A03",
    "CWE-80": "A03", "CWE-83": "A03", "CWE-87": "A03",
    "CWE-88": "A03", "CWE-89": "A03", "CWE-90": "A03",
    "CWE-91": "A03", "CWE-93": "A03", "CWE-94": "A03",
    "CWE-95": "A03", "CWE-96": "A03", "CWE-97": "A03",
    "CWE-98": "A03", "CWE-99": "A03", "CWE-100": "A03",
    "CWE-113": "A03", "CWE-116": "A03", "CWE-138": "A03",
    "CWE-184": "A03", "CWE-470": "A03", "CWE-471": "A03",
    "CWE-564": "A03", "CWE-610": "A03", "CWE-643": "A03",
    "CWE-644": "A03", "CWE-652": "A03", "CWE-917": "A03",

    # A04: Insecure Design
    "CWE-73": "A04", "CWE-183": "A04", "CWE-209": "A04",
    "CWE-213": "A04", "CWE-235": "A04", "CWE-256": "A04",
    "CWE-257": "A04", "CWE-266": "A04", "CWE-269": "A04",
    "CWE-280": "A04", "CWE-311": "A04", "CWE-312": "A04",
    "CWE-313": "A04", "CWE-316": "A04", "CWE-419": "A04",
    "CWE-430": "A04", "CWE-434": "A04", "CWE-444": "A04",
    "CWE-451": "A04", "CWE-472": "A04", "CWE-501": "A04",
    "CWE-522": "A04", "CWE-525": "A04", "CWE-539": "A04",
    "CWE-579": "A04", "CWE-598": "A04", "CWE-602": "A04",
    "CWE-642": "A04", "CWE-646": "A04", "CWE-650": "A04",
    "CWE-653": "A04", "CWE-656": "A04", "CWE-657": "A04",
    "CWE-799": "A04", "CWE-807": "A04", "CWE-840": "A04",
    "CWE-841": "A04", "CWE-927": "A04", "CWE-1021": "A04",
    "CWE-1173": "A04",

    # A05: Security Misconfiguration
    "CWE-2": "A05", "CWE-11": "A05", "CWE-13": "A05",
    "CWE-15": "A05", "CWE-16": "A05", "CWE-260": "A05",
    "CWE-315": "A05", "CWE-520": "A05", "CWE-526": "A05",
    "CWE-537": "A05", "CWE-541": "A05", "CWE-547": "A05",
    "CWE-611": "A05", "CWE-614": "A05", "CWE-756": "A05",
    "CWE-776": "A05", "CWE-942": "A05", "CWE-1004": "A05",
    "CWE-1032": "A05", "CWE-1174": "A05",

    # A06: Vulnerable and Outdated Components
    "CWE-937": "A06", "CWE-1035": "A06", "CWE-1104": "A06",

    # A07: Identification and Authentication Failures
    "CWE-255": "A07", "CWE-259": "A07", "CWE-287": "A07",
    "CWE-288": "A07", "CWE-290": "A07", "CWE-294": "A07",
    "CWE-295": "A07", "CWE-297": "A07", "CWE-300": "A07",
    "CWE-302": "A07", "CWE-304": "A07", "CWE-306": "A07",
    "CWE-307": "A07", "CWE-346": "A07", "CWE-384": "A07",
    "CWE-521": "A07", "CWE-613": "A07", "CWE-620": "A07",
    "CWE-640": "A07", "CWE-798": "A07", "CWE-940": "A07",
    "CWE-1216": "A07",

    # A08: Software and Data Integrity Failures
    "CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08",
    "CWE-494": "A08", "CWE-502": "A08", "CWE-565": "A08",
    "CWE-784": "A08", "CWE-829": "A08", "CWE-830": "A08",
    "CWE-915": "A08",

    # A09: Security Logging and Monitoring Failures
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09",
    "CWE-778": "A09",

    # A10: Server-Side Request Forgery (SSRF)
    "CWE-918": "A10",
}

# Tag-based heuristic mapping (nuclei template tags -> OWASP)
TAG_TO_OWASP = {
    # A01
    "idor": "A01", "lfi": "A01", "rfi": "A01",
    "path-traversal": "A01", "traversal": "A01",
    "directory-listing": "A01", "exposure": "A01",
    "open-redirect": "A01", "redirect": "A01",
    "cors": "A01", "csrf": "A01",
    "unauthorized": "A01", "unauth": "A01",

    # A02
    "ssl": "A02", "tls": "A02", "weak-crypto": "A02",
    "cleartext": "A02", "http": "A02",

    # A03
    "sqli": "A03", "xss": "A03", "injection": "A03",
    "rce": "A03", "command-injection": "A03",
    "code-injection": "A03", "ssti": "A03",
    "template-injection": "A03", "xxe": "A03",
    "ldap": "A03", "xpath": "A03", "nosql": "A03",
    "crlf": "A03", "header-injection": "A03",

    # A04
    "insecure-design": "A04", "file-upload": "A04",

    # A05
    "misconfig": "A05", "misconfiguration": "A05",
    "default-login": "A05", "default-credentials": "A05",
    "debug": "A05", "config": "A05", "exposed": "A05",
    "panel": "A05", "admin": "A05",

    # A06
    "cve": "A06", "outdated": "A06", "eol": "A06",
    "wordpress": "A06", "joomla": "A06", "drupal": "A06",
    "apache": "A06", "nginx": "A06", "iis": "A06",

    # A07
    "auth-bypass": "A07", "authentication": "A07",
    "brute-force": "A07", "weak-password": "A07",
    "login": "A07", "session": "A07", "token": "A07",

    # A08
    "deserialization": "A08",

    # A09
    "log": "A09", "logging": "A09", "monitoring": "A09",

    # A10
    "ssrf": "A10",
}


def map_cwe_to_owasp(cwe_id: str | None) -> tuple[str | None, str | None]:
    """
    Map a CWE ID to OWASP Top 10 category.
    Returns (category_code, category_name) or (None, None).
    """
    if not cwe_id:
        return None, None

    # Normalize: accept "79", "CWE-79", "cwe-79"
    cwe_str = cwe_id.upper().strip()
    if not cwe_str.startswith("CWE-"):
        cwe_str = f"CWE-{cwe_str}"

    code = CWE_TO_OWASP.get(cwe_str)
    if code:
        return code, OWASP_CATEGORIES.get(code)
    return None, None


def map_tags_to_owasp(tags: list[str] | None) -> tuple[str | None, str | None]:
    """
    Map nuclei template tags to OWASP Top 10 category (heuristic).
    Returns (category_code, category_name) or (None, None).
    """
    if not tags:
        return None, None

    for tag in tags:
        tag_lower = tag.lower().strip()
        code = TAG_TO_OWASP.get(tag_lower)
        if code:
            return code, OWASP_CATEGORIES.get(code)
    return None, None


def get_owasp_category(
    cwe_id: str | None = None,
    tags: list[str] | None = None,
) -> tuple[str | None, str | None]:
    """
    Determine OWASP category from CWE or tags.
    Priority: CWE mapping > tag heuristic.
    """
    code, name = map_cwe_to_owasp(cwe_id)
    if code:
        return code, name

    code, name = map_tags_to_owasp(tags)
    if code:
        return code, name

    return None, None
