"""Decode JWT payload claims found in JavaScript (decode only, never verify).

A JWT found in a bundle is usually a hardcoded or example token. Its
payload segment is just base64url JSON, so the top-level claim names
(``sub``, ``exp``, ``role``, ...) can be listed without any key and
without trusting the token: the signature is never checked, and the
decoded claims are reported as *claimed* by the token, not as verified
facts. Tokens whose payload is not base64url JSON, or not a JSON
object, yield ``None`` — the secret finding is still reported, just
without a claim list.
"""

import base64
import binascii
import json


def decode_jwt_claims(token):
    """Return the top-level claim names of *token*'s payload, or None.

    The payload is the middle ``header.payload.signature`` segment.
    Claim names keep their payload order. Returns ``None`` for
    malformed tokens, undecodable payloads, non-JSON payloads, and
    JSON payloads that are not objects (a list or scalar has no claim
    names to list).
    """
    try:
        parts = token.split(".")
        if len(parts) != 3 or not parts[1]:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload)
        claims = json.loads(raw.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    return list(claims)
