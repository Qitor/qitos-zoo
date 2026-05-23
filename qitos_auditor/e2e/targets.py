"""Target definitions for auditor e2e testing.

Each target is a GitHub repository (or local directory) with known
vulnerability patterns. These are source-code repositories analyzed
locally -- no Docker required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AuditTarget:
    """A source-code repository for audit testing.

    Attributes
    ----------
    name : str
        Unique identifier (e.g., "dvwa-src").
    repo_url : str
        Git clone URL. Empty for synthetic local targets.
    local_path : str
        Relative path under playground/ where the repo is cloned.
    languages : list[str]
        Primary programming languages.
    known_vulnerabilities : dict
        Ground truth: vulnerability_type -> list of {file, line, description}.
    description : str
        Human-readable description.
    min_tier : int
        Minimum test tier (1=smoke, 3=deep vuln discovery).
    max_tier : int
        Maximum test tier supported.
    """

    name: str
    repo_url: str = ""
    local_path: str = ""
    languages: List[str] = field(default_factory=list)
    known_vulnerabilities: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    description: str = ""
    min_tier: int = 1
    max_tier: int = 3


# ── Synthetic Flask target ────────────────────────────────────────

SYNTHETIC_FLASK = AuditTarget(
    name="synthetic-flask",
    repo_url="",
    local_path="synthetic-flask",  # Under playground/
    languages=["python"],
    known_vulnerabilities={
        "sql_injection": [
            {"file": "app.py", "line": 29, "description": "String-interpolated SQL query in login route"},
        ],
        "xss": [
            {"file": "app.py", "line": 36, "description": "Unescaped user input in HTML response"},
        ],
        "command_injection": [
            {"file": "app.py", "line": 41, "description": "os.system with user-controlled host parameter"},
        ],
        "path_traversal": [
            {"file": "app.py", "line": 47, "description": "Open file with unsanitized filename parameter"},
        ],
        "hardcoded_secret": [
            {"file": "app.py", "line": 8, "description": "Hardcoded Flask secret key"},
        ],
    },
    description="Synthetic Flask app with SQLi, XSS, cmd injection, path traversal, hardcoded secret",
    min_tier=1,
    max_tier=3,
)

# ── Real GitHub targets ───────────────────────────────────────────

VULNERABLE_FLASK = AuditTarget(
    name="vulnerable-flask-app",
    repo_url="https://github.com/avgituoso/vulnerable-flask-app.git",
    local_path="vulnerable-flask-app",
    languages=["python"],
    known_vulnerabilities={
        "sql_injection": [
            {"file": "app.py", "description": "Multiple SQLi via string interpolation"},
        ],
        "xss": [
            {"file": "templates/", "description": "Reflected and stored XSS in templates"},
        ],
        "hardcoded_secret": [
            {"file": "app.py", "description": "Hardcoded database credentials and secret key"},
        ],
    },
    description="Deliberately vulnerable Flask web application",
    min_tier=1,
    max_tier=3,
)

DVWA_SRC = AuditTarget(
    name="dvwa-src",
    repo_url="https://github.com/digininja/DVWA.git",
    local_path="dvwa-src",
    languages=["php"],
    known_vulnerabilities={
        "sql_injection": [
            {"file": "vulnerabilities/sqli/", "description": "SQL injection in user ID lookup"},
        ],
        "xss": [
            {"file": "vulnerabilities/xss_r/", "description": "Reflected XSS in name field"},
            {"file": "vulnerabilities/xss_s/", "description": "Stored XSS in message field"},
        ],
        "command_injection": [
            {"file": "vulnerabilities/exec/", "description": "OS command injection via ping"},
        ],
        "file_upload": [
            {"file": "vulnerabilities/upload/", "description": "Unrestricted file upload"},
        ],
        "csrf": [
            {"file": "vulnerabilities/csrf/", "description": "Cross-site request forgery"},
        ],
    },
    description="Damn Vulnerable Web Application source code",
    min_tier=1,
    max_tier=3,
)

SECURITY_VULN_LAB = AuditTarget(
    name="security-vuln-lab",
    repo_url="https://github.com/zendy0x/security-vuln-lab.git",
    local_path="security-vuln-lab",
    languages=["python", "javascript", "php"],
    known_vulnerabilities={
        "ssrf": [
            {"file": "ssrf/", "description": "Server-side request forgery patterns"},
        ],
        "deserialization": [
            {"file": "deserialization/", "description": "Insecure deserialization patterns"},
        ],
        "race_condition": [
            {"file": "race_condition/", "description": "Race condition patterns"},
        ],
    },
    description="Security vulnerability lab with SSRF, deserialization, race condition patterns",
    min_tier=2,
    max_tier=3,
)

JUICE_SHOP_SRC = AuditTarget(
    name="juice-shop-src",
    repo_url="https://github.com/juice-shop/juice-shop.git",
    local_path="juice-shop-src",
    languages=["javascript", "typescript"],
    known_vulnerabilities={
        "sql_injection": [
            {"file": "routes/search.ts", "description": "SQL injection in search endpoint"},
        ],
        "xss": [
            {"file": "routes/basket.ts", "description": "DOM-based XSS"},
        ],
        "auth_bypass": [
            {"file": "routes/login.ts", "description": "Authentication bypass via SQLi"},
        ],
    },
    description="OWASP Juice Shop source code",
    min_tier=2,
    max_tier=3,
)

# Registry
TARGETS: Dict[str, AuditTarget] = {
    "synthetic-flask": SYNTHETIC_FLASK,
    "vulnerable-flask-app": VULNERABLE_FLASK,
    "dvwa-src": DVWA_SRC,
    "security-vuln-lab": SECURITY_VULN_LAB,
    "juice-shop-src": JUICE_SHOP_SRC,
}


def get_targets_for_tier(tier: int) -> List[AuditTarget]:
    """Return all targets that support the given tier."""
    return [t for t in TARGETS.values() if t.min_tier <= tier <= t.max_tier]
