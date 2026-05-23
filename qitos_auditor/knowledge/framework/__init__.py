"""Framework security knowledge modules — aggregate all docs."""

from .fastapi import FASTAPI_SECURITY
from .django import DJANGO_SECURITY
from .flask import FLASK_SECURITY
from .express import EXPRESS_SECURITY
from .react import REACT_SECURITY
from .supabase import SUPABASE_SECURITY

ALL_FRAMEWORK_DOCS = [
    FASTAPI_SECURITY,
    DJANGO_SECURITY,
    FLASK_SECURITY,
    EXPRESS_SECURITY,
    REACT_SECURITY,
    SUPABASE_SECURITY,
]

# Map from framework keywords to canonical document IDs
FRAMEWORK_ALIASES = {
    "flask": "framework_flask",
    "django": "framework_django",
    "fastapi": "framework_fastapi",
    "express": "framework_express",
    "node": "framework_express",
    "nodejs": "framework_express",
    "react": "framework_react",
    "nextjs": "framework_react",
    "next": "framework_react",
    "supabase": "framework_supabase",
}

__all__ = [
    "ALL_FRAMEWORK_DOCS",
    "FRAMEWORK_ALIASES",
    "FASTAPI_SECURITY",
    "DJANGO_SECURITY",
    "FLASK_SECURITY",
    "EXPRESS_SECURITY",
    "REACT_SECURITY",
    "SUPABASE_SECURITY",
]
