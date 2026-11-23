"""CWE -> (canonical name, OWASP Top 10 2021, OWASP Top 10 2025, default severity).

Used by validate_findings.py to fill / normalise classification fields. The agent may override
severity with justification (e.g. unauthenticated reachability raises it, admin-only lowers it).
Mappings follow the official OWASP Top 10 CWE lists where a CWE is listed there, otherwise the
closest category ("best fit").
"""

A21 = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery",
    "NA": "Not in Top 10 (see CWE Top 25)",
}
A25 = {
    "A01": "A01:2025-Broken Access Control",
    "A02": "A02:2025-Security Misconfiguration",
    "A03": "A03:2025-Software Supply Chain Failures",
    "A04": "A04:2025-Cryptographic Failures",
    "A05": "A05:2025-Injection",
    "A06": "A06:2025-Insecure Design",
    "A07": "A07:2025-Authentication Failures",
    "A08": "A08:2025-Software or Data Integrity Failures",
    "A09": "A09:2025-Security Logging and Alerting Failures",
    "A10": "A10:2025-Mishandling of Exceptional Conditions",
    "NA": "Not in Top 10 (see CWE Top 25)",
}

# cwe: (name, 2021 key, 2025 key, default severity)
CWE = {
    "CWE-20": ("Improper Input Validation", "A04", "A06", "Medium"),
    "CWE-22": ("Path Traversal", "A01", "A01", "High"),
    "CWE-23": ("Relative Path Traversal", "A01", "A01", "High"),
    "CWE-73": ("External Control of File Name or Path", "A04", "A01", "High"),
    "CWE-77": ("Command Injection", "A03", "A05", "Critical"),
    "CWE-78": ("OS Command Injection", "A03", "A05", "Critical"),
    "CWE-79": ("Cross-Site Scripting (XSS)", "A03", "A05", "Medium"),
    "CWE-80": ("Basic XSS", "A03", "A05", "Medium"),
    "CWE-88": ("Argument Injection", "A03", "A05", "High"),
    "CWE-89": ("SQL Injection", "A03", "A05", "High"),
    "CWE-90": ("LDAP Injection", "A03", "A05", "High"),
    "CWE-91": ("XML Injection", "A03", "A05", "Medium"),
    "CWE-93": ("CRLF Injection", "A03", "A05", "Medium"),
    "CWE-94": ("Code Injection", "A03", "A05", "Critical"),
    "CWE-95": ("Eval Injection", "A03", "A05", "Critical"),
    "CWE-98": ("File Inclusion (PHP Remote/Local File Inclusion)", "A03", "A05", "Critical"),
    "CWE-113": ("HTTP Response Splitting / Header Injection", "A03", "A05", "Medium"),
    "CWE-117": ("Log Injection", "A09", "A09", "Low"),
    "CWE-119": ("Memory Buffer Errors", "NA", "NA", "High"),
    "CWE-120": ("Classic Buffer Overflow", "NA", "NA", "High"),
    "CWE-125": ("Out-of-bounds Read", "NA", "NA", "High"),
    "CWE-134": ("Format String Vulnerability", "A03", "A05", "High"),
    "CWE-190": ("Integer Overflow or Wraparound", "NA", "NA", "Medium"),
    "CWE-200": ("Exposure of Sensitive Information", "A01", "A01", "Medium"),
    "CWE-209": ("Information Exposure Through Error Messages", "A04", "A10", "Low"),
    "CWE-242": ("Use of Inherently Dangerous Function / Unsafe Code", "NA", "NA", "Medium"),
    "CWE-248": ("Uncaught Exception", "A04", "A10", "Low"),
    "CWE-250": ("Execution with Unnecessary Privileges", "A05", "A02", "Medium"),
    "CWE-256": ("Plaintext Storage of Password", "A04", "A04", "High"),
    "CWE-257": ("Storing Passwords in a Recoverable Format", "A04", "A04", "High"),
    "CWE-259": ("Hard-coded Password", "A07", "A07", "High"),
    "CWE-269": ("Improper Privilege Management", "A04", "A01", "High"),
    "CWE-276": ("Incorrect Default Permissions", "A01", "A01", "Medium"),
    "CWE-284": ("Improper Access Control", "A01", "A01", "High"),
    "CWE-285": ("Improper Authorization", "A01", "A01", "High"),
    "CWE-287": ("Improper Authentication", "A07", "A07", "High"),
    "CWE-288": ("Authentication Bypass Using an Alternate Path", "A07", "A07", "High"),
    "CWE-295": ("Improper Certificate Validation (TLS verification disabled)", "A07", "A04", "Medium"),
    "CWE-306": ("Missing Authentication for Critical Function", "A07", "A07", "High"),
    "CWE-307": ("Missing Brute-force / Rate Limiting on Authentication", "A07", "A07", "Medium"),
    "CWE-311": ("Missing Encryption of Sensitive Data", "A04", "A04", "Medium"),
    "CWE-312": ("Cleartext Storage of Sensitive Information", "A04", "A04", "Medium"),
    "CWE-319": ("Cleartext Transmission of Sensitive Information", "A02", "A04", "Medium"),
    "CWE-321": ("Hard-coded Cryptographic Key", "A02", "A04", "High"),
    "CWE-326": ("Inadequate Encryption Strength", "A02", "A04", "Medium"),
    "CWE-327": ("Use of Broken or Risky Cryptographic Algorithm", "A02", "A04", "Medium"),
    "CWE-328": ("Use of Weak Hash", "A02", "A04", "Medium"),
    "CWE-330": ("Use of Insufficiently Random Values", "A02", "A04", "Medium"),
    "CWE-338": ("Use of Cryptographically Weak PRNG", "A02", "A04", "Medium"),
    "CWE-345": ("Insufficient Verification of Data Authenticity", "A08", "A08", "Medium"),
    "CWE-347": ("Improper Verification of Cryptographic Signature (JWT)", "A02", "A04", "High"),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)", "A01", "A01", "Medium"),
    "CWE-362": ("Race Condition", "A04", "A06", "Medium"),
    "CWE-367": ("TOCTOU Race Condition", "A04", "A06", "Medium"),
    "CWE-377": ("Insecure Temporary File", "A01", "A01", "Low"),
    "CWE-384": ("Session Fixation", "A07", "A07", "Medium"),
    "CWE-400": ("Uncontrolled Resource Consumption", "A04", "A06", "Medium"),
    "CWE-416": ("Use After Free", "NA", "NA", "High"),
    "CWE-434": ("Unrestricted File Upload", "A04", "A06", "High"),
    "CWE-470": ("Unsafe Reflection", "A03", "A05", "High"),
    "CWE-476": ("NULL Pointer Dereference", "NA", "A10", "Medium"),
    "CWE-489": ("Debug Mode / Active Debug Code in Production", "A05", "A02", "Medium"),
    "CWE-502": ("Insecure Deserialization", "A08", "A08", "Critical"),
    "CWE-521": ("Weak Password Requirements", "A07", "A07", "Medium"),
    "CWE-522": ("Insufficiently Protected Credentials", "A04", "A07", "High"),
    "CWE-532": ("Sensitive Information in Log Files", "A09", "A09", "Medium"),
    "CWE-546": ("Suspicious Comment (security TODO)", "A04", "A06", "Info"),
    "CWE-548": ("Directory Listing Enabled", "A05", "A02", "Low"),
    "CWE-601": ("Open Redirect", "A01", "A01", "Medium"),
    "CWE-611": ("XML External Entity (XXE)", "A05", "A02", "High"),
    "CWE-613": ("Insufficient Session Expiration", "A07", "A07", "Medium"),
    "CWE-614": ("Sensitive Cookie Without Secure/HttpOnly Flag", "A05", "A02", "Low"),
    "CWE-617": ("Reachable Assertion Used for Security Check", "A04", "A10", "Medium"),
    "CWE-620": ("Unverified Password Change", "A07", "A07", "High"),
    "CWE-639": ("Insecure Direct Object Reference (IDOR)", "A01", "A01", "High"),
    "CWE-640": ("Weak Password Recovery Mechanism", "A07", "A07", "High"),
    "CWE-643": ("XPath Injection", "A03", "A05", "High"),
    "CWE-693": ("Protection Mechanism Failure (missing security headers)", "A05", "A02", "Low"),
    "CWE-697": ("Incorrect Comparison (type juggling)", "A07", "A07", "High"),
    "CWE-732": ("Incorrect Permission Assignment", "A01", "A01", "Medium"),
    "CWE-754": ("Improper Check for Unusual or Exceptional Conditions", "A04", "A10", "Low"),
    "CWE-755": ("Improper Handling of Exceptional Conditions", "A04", "A10", "Low"),
    "CWE-770": ("Allocation of Resources Without Limits (no rate limiting)", "A04", "A06", "Medium"),
    "CWE-776": ("XML Entity Expansion (Billion Laughs)", "A05", "A02", "Medium"),
    "CWE-787": ("Out-of-bounds Write", "NA", "NA", "High"),
    "CWE-798": ("Hard-coded Credentials / Secret", "A07", "A07", "High"),
    "CWE-829": ("Inclusion of Functionality from Untrusted Control Sphere", "A08", "A03", "Medium"),
    "CWE-840": ("Business Logic Error", "A04", "A06", "Medium"),
    "CWE-862": ("Missing Authorization", "A01", "A01", "High"),
    "CWE-863": ("Incorrect Authorization", "A01", "A01", "High"),
    "CWE-915": ("Mass Assignment", "A08", "A08", "High"),
    "CWE-916": ("Password Hash With Insufficient Computational Effort", "A02", "A04", "High"),
    "CWE-917": ("Expression Language Injection", "A03", "A05", "Critical"),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "A10", "A01", "High"),
    "CWE-942": ("Permissive CORS Policy", "A05", "A02", "Medium"),
    "CWE-943": ("NoSQL Injection", "A03", "A05", "High"),
    "CWE-1004": ("Sensitive Cookie Without HttpOnly", "A05", "A02", "Low"),
    "CWE-1021": ("Clickjacking (missing frame protection)", "A04", "A02", "Low"),
    "CWE-1022": ("Reverse Tabnabbing", "A05", "A02", "Low"),
    "CWE-1104": ("Use of Unmaintained Third-Party Component", "A06", "A03", "Medium"),
    "CWE-1188": ("Insecure Default Initialization (Electron)", "A05", "A02", "High"),
    "CWE-1236": ("CSV / Formula Injection", "A03", "A05", "Low"),
    "CWE-1321": ("Prototype Pollution", "A08", "A08", "High"),
    "CWE-1327": ("Binding to Unrestricted IP Address", "A05", "A02", "Low"),
    "CWE-1333": ("Regular Expression Denial of Service (ReDoS)", "A04", "A06", "Medium"),
    "CWE-1336": ("Server-Side Template Injection (SSTI)", "A03", "A05", "Critical"),
    "CWE-1395": ("Dependency on Vulnerable Third-Party Component", "A06", "A03", "High"),
    "CWE-1427": ("Prompt Injection (LLM)", "A03", "A05", "Medium"),
}

# Category-based overrides of the 2021/2025 mapping (when a CWE spans several contexts).
CATEGORY_OWASP = {
    "ci-script-injection": ("A08", "A03"),
    "ci-misconfiguration": ("A08", "A03"),
    "vulnerable-dependency": ("A06", "A03"),
    "container-misconfiguration": ("A05", "A02"),
    "cloud-misconfiguration": ("A05", "A02"),
}

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
CONFIDENCES = ["High", "Medium", "Low"]


def classify(cwe, category=None):
    cwe = normalise_cwe(cwe)
    name, k21, k25, sev = CWE.get(cwe, (None, "NA", "NA", "Medium"))
    if category in CATEGORY_OWASP:
        k21, k25 = CATEGORY_OWASP[category]
    return {"cwe": cwe, "cwe_name": name, "owasp_2021": A21[k21], "owasp_2025": A25[k25],
            "default_severity": sev}


def normalise_cwe(cwe):
    if cwe is None:
        return ""
    s = str(cwe).strip().upper().replace("_", "-").replace(" ", "")
    if s.isdigit():
        return "CWE-" + s
    if s.startswith("CWE") and not s.startswith("CWE-"):
        return "CWE-" + s[3:]
    return s
