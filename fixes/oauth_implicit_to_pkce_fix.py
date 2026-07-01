"""
Fix for Issue #204 — OAuth 2.0 Implicit Grant Flow → Authorization Code Interception.

Root cause
----------
The Implicit Grant (`response_type=token`) returns the access token directly in
the redirect URI fragment. This is unsafe because:

  1. Tokens leak via browser history, Referer headers, proxy/CDN logs, and
     malicious apps that register the same custom URI scheme (mobile).
  2. There is no client authentication and no code-to-token exchange, so a
     network attacker who intercepts the redirect gets the token immediately.
  3. Authorization Code Interception (RFC 7636 §1) is trivially exploitable
     against public clients using plain Authorization Code without PKCE, and
     Implicit provides no equivalent defense at all.

Per OAuth 2.0 Security BCP (RFC 9700 / draft-ietf-oauth-security-topics) and
OAuth 2.1, the Implicit Grant is **deprecated and MUST NOT be used**. All
clients — including SPAs and native/mobile apps — MUST use the Authorization
Code Flow with PKCE (RFC 7636), plus exact-match redirect URI validation and
short-lived, single-use authorization codes bound to the PKCE verifier.

This module provides:

  * `AuthorizationServer` — refuses `response_type=token` (Implicit), requires
    PKCE with S256 for public clients, enforces exact redirect_uri match,
    single-use codes, code<->client<->redirect_uri binding, and a 60-second
    code TTL.
  * `verify_pkce` — constant-time verification of `code_verifier` against the
    stored `code_challenge` (S256 only; `plain` is rejected).
  * Self-tests demonstrating that all known interception paths are blocked.

Drop-in usage: replace any Implicit endpoint with `AuthorizationServer.authorize`
+ `AuthorizationServer.exchange_code`. No token is ever returned via the
front-channel.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Constants (RFC 7636 / RFC 9700)
# ---------------------------------------------------------------------------

CODE_TTL_SECONDS = 60          # short-lived auth codes
MIN_VERIFIER_LEN = 43          # RFC 7636 §4.1
MAX_VERIFIER_LEN = 128
ALLOWED_RESPONSE_TYPES = frozenset({"code"})   # Implicit ("token") is banned
ALLOWED_CHALLENGE_METHODS = frozenset({"S256"})  # "plain" is banned


# ---------------------------------------------------------------------------
# Errors — mirror RFC 6749 §4.1.2.1 error codes so clients get a spec response
# ---------------------------------------------------------------------------

class OAuthError(Exception):
    """Base OAuth error. `code` is the RFC 6749 error identifier."""

    def __init__(self, code: str, description: str) -> None:
        super().__init__(f"{code}: {description}")
        self.code = code
        self.description = description


class InvalidRequest(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__("invalid_request", description)


class UnsupportedResponseType(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__("unsupported_response_type", description)


class InvalidGrant(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__("invalid_grant", description)


class UnauthorizedClient(OAuthError):
    def __init__(self, description: str) -> None:
        super().__init__("unauthorized_client", description)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Client:
    client_id: str
    # Redirect URIs are compared with EXACT match (RFC 9700 §2.1); no wildcards,
    # no scheme-only match, no path prefix match.
    registered_redirect_uris: Tuple[str, ...]
    # Public clients (SPA / native) have no secret; PKCE is mandatory for them,
    # and — per RFC 9700 — recommended for confidential clients too.
    is_public: bool = True


@dataclass
class _CodeRecord:
    client_id: str
    redirect_uri: str
    code_challenge: str
    scope: str
    subject: str
    expires_at: float
    used: bool = False


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------

def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_code_verifier(num_bytes: int = 32) -> str:
    """Return a fresh RFC 7636-compliant code_verifier (43–128 chars)."""
    if num_bytes < 32:
        raise ValueError("code_verifier entropy must be >= 256 bits")
    return _b64url_nopad(secrets.token_bytes(num_bytes))


def derive_code_challenge_s256(verifier: str) -> str:
    """S256 challenge = BASE64URL(SHA256(ASCII(verifier)))."""
    if not (MIN_VERIFIER_LEN <= len(verifier) <= MAX_VERIFIER_LEN):
        raise InvalidRequest("code_verifier length out of range (43..128)")
    return _b64url_nopad(hashlib.sha256(verifier.encode("ascii")).digest())


def verify_pkce(verifier: str, expected_challenge: str) -> bool:
    """Constant-time S256 verifier check. Rejects short/long verifiers."""
    if not (MIN_VERIFIER_LEN <= len(verifier) <= MAX_VERIFIER_LEN):
        return False
    derived = derive_code_challenge_s256(verifier)
    return hmac.compare_digest(derived, expected_challenge)


# ---------------------------------------------------------------------------
# Redirect URI validation (RFC 9700 §2.1 — exact string match)
# ---------------------------------------------------------------------------

def _validate_redirect_uri(client: Client, redirect_uri: str) -> None:
    if not redirect_uri:
        raise InvalidRequest("redirect_uri is required")
    # Reject anything but an absolute URI with a safe scheme. `javascript:`,
    # `data:`, relative URIs, and URIs containing fragments are all refused —
    # fragments in redirect_uri are the primary Implicit-flow leak vector.
    parts = urlsplit(redirect_uri)
    if parts.scheme.lower() not in ("https", "http") and ":" not in parts.scheme:
        raise InvalidRequest("redirect_uri must be an absolute URI")
    if parts.fragment:
        raise InvalidRequest("redirect_uri must not contain a fragment")
    # Exact-match check — no normalization, no wildcards.
    if redirect_uri not in client.registered_redirect_uris:
        raise InvalidRequest("redirect_uri does not match a registered value")


# ---------------------------------------------------------------------------
# Authorization Server
# ---------------------------------------------------------------------------

@dataclass
class AuthorizationServer:
    clients: Dict[str, Client] = field(default_factory=dict)
    _codes: Dict[str, _CodeRecord] = field(default_factory=dict)
    _clock: callable = field(default=time.time)

    # ---- Authorization endpoint --------------------------------------------

    def authorize(
        self,
        *,
        client_id: str,
        response_type: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str,
        subject: str,
        state: Optional[str] = None,
    ) -> str:
        """
        Handle the authorization request. Returns the redirect URL containing
        `code` (and echoed `state`) in the query string — NEVER in the
        fragment, and NEVER containing an access token.
        """
        client = self.clients.get(client_id)
        if client is None:
            raise UnauthorizedClient("unknown client_id")

        # 1. Ban Implicit outright. This is the core of the fix.
        if response_type != "code":
            raise UnsupportedResponseType(
                "Implicit and hybrid flows are disabled; use response_type=code with PKCE"
            )
        if response_type not in ALLOWED_RESPONSE_TYPES:
            raise UnsupportedResponseType("only response_type=code is supported")

        # 2. Validate redirect_uri with exact match.
        _validate_redirect_uri(client, redirect_uri)

        # 3. PKCE is mandatory. Only S256 is accepted; `plain` is refused
        #    because it is trivially replayable if the code is intercepted.
        if code_challenge_method not in ALLOWED_CHALLENGE_METHODS:
            raise InvalidRequest("code_challenge_method must be S256")
        # A valid S256 challenge is 43 chars of base64url (SHA-256 => 32 bytes).
        if len(code_challenge) != 43 or not _is_b64url(code_challenge):
            raise InvalidRequest("malformed code_challenge")

        # 4. Mint a single-use, high-entropy authorization code bound to the
        #    client, the redirect_uri, and the PKCE challenge.
        code = _b64url_nopad(os.urandom(32))
        self._codes[code] = _CodeRecord(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            scope=scope,
            subject=subject,
            expires_at=self._clock() + CODE_TTL_SECONDS,
        )

        # 5. Return the code in the QUERY (not the fragment). The fragment is
        #    what leaks in Implicit; putting the code in ?code=... keeps it out
        #    of Referer headers when the RP follows the top-level redirect,
        #    and out of browser history for the token itself (there is no
        #    token here).
        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={code}"
        if state is not None:
            location += f"&state={_percent(state)}"
        return location

    # ---- Token endpoint ----------------------------------------------------

    def exchange_code(
        self,
        *,
        client_id: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> Dict[str, str]:
        """
        Exchange a one-time authorization code for a token. Enforces PKCE,
        code<->client<->redirect_uri binding, single-use, and TTL.
        """
        record = self._codes.get(code)
        if record is None:
            raise InvalidGrant("unknown or already-consumed code")

        # Single-use: burn the code on first lookup regardless of validity to
        # prevent brute-force / replay of a stolen code.
        if record.used:
            # Defense in depth: an attacker replaying a code should also cause
            # all previously-issued tokens for that code to be revoked. We
            # signal that via `invalid_grant` here.
            self._codes.pop(code, None)
            raise InvalidGrant("authorization code already used")
        record.used = True

        try:
            if self._clock() > record.expires_at:
                raise InvalidGrant("authorization code expired")
            if not hmac.compare_digest(record.client_id, client_id):
                raise InvalidGrant("client_id does not match code")
            if not hmac.compare_digest(record.redirect_uri, redirect_uri):
                raise InvalidGrant("redirect_uri does not match code")
            if not verify_pkce(code_verifier, record.code_challenge):
                raise InvalidGrant("PKCE verification failed")
        finally:
            # Always burn on any exit path so a code cannot be retried.
            self._codes.pop(code, None)

        # In real code you would mint a signed access token bound to
        # (client_id, subject, scope). For this fix module we return an opaque
        # placeholder so the caller wires in their own token service.
        return {
            "access_token": _b64url_nopad(os.urandom(32)),
            "token_type": "Bearer",
            "expires_in": "3600",
            "scope": record.scope,
            "subject": record.subject,
        }


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _is_b64url(s: str) -> bool:
    return bool(s) and all(c in _B64URL_ALPHABET for c in s)


def _percent(s: str) -> str:
    # Minimal percent-encoder for the `state` echo. state should be opaque.
    from urllib.parse import quote

    return quote(s, safe="")


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def _run_self_tests() -> None:
    client = Client(
        client_id="spa-1",
        registered_redirect_uris=("https://app.example.com/cb",),
        is_public=True,
    )
    server = AuthorizationServer(clients={client.client_id: client})

    verifier = generate_code_verifier()
    challenge = derive_code_challenge_s256(verifier)

    # 1. Implicit flow is refused.
    try:
        server.authorize(
            client_id="spa-1",
            response_type="token",
            redirect_uri="https://app.example.com/cb",
            code_challenge=challenge,
            code_challenge_method="S256",
            scope="read",
            subject="user-1",
        )
    except UnsupportedResponseType:
        pass
    else:
        raise AssertionError("Implicit flow must be rejected")

    # 2. Hybrid (`code token`) is refused.
    try:
        server.authorize(
            client_id="spa-1",
            response_type="code token",
            redirect_uri="https://app.example.com/cb",
            code_challenge=challenge,
            code_challenge_method="S256",
            scope="read",
            subject="user-1",
        )
    except UnsupportedResponseType:
        pass
    else:
        raise AssertionError("Hybrid flow must be rejected")

    # 3. PKCE `plain` is refused.
    try:
        server.authorize(
            client_id="spa-1",
            response_type="code",
            redirect_uri="https://app.example.com/cb",
            code_challenge=verifier,
            code_challenge_method="plain",
            scope="read",
            subject="user-1",
        )
    except InvalidRequest:
        pass
    else:
        raise AssertionError("plain PKCE must be rejected")

    # 4. Non-registered redirect_uri is refused (exact match).
    try:
        server.authorize(
            client_id="spa-1",
            response_type="code",
            redirect_uri="https://app.example.com/cb/extra",
            code_challenge=challenge,
            code_challenge_method="S256",
            scope="read",
            subject="user-1",
        )
    except InvalidRequest:
        pass
    else:
        raise AssertionError("non-exact redirect_uri must be rejected")

    # 5. Happy path: code exchange works with correct verifier.
    location = server.authorize(
        client_id="spa-1",
        response_type="code",
        redirect_uri="https://app.example.com/cb",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope="read",
        subject="user-1",
        state="xyz",
    )
    assert "#" not in location, "auth response must not use URI fragment"
    assert "access_token" not in location, "no token in front-channel"
    code = location.split("code=")[1].split("&")[0]

    tok = server.exchange_code(
        client_id="spa-1",
        code=code,
        redirect_uri="https://app.example.com/cb",
        code_verifier=verifier,
    )
    assert tok["access_token"]

    # 6. Wrong verifier fails (code interception without the verifier is useless).
    location = server.authorize(
        client_id="spa-1",
        response_type="code",
        redirect_uri="https://app.example.com/cb",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope="read",
        subject="user-1",
    )
    code = location.split("code=")[1].split("&")[0]
    try:
        server.exchange_code(
            client_id="spa-1",
            code=code,
            redirect_uri="https://app.example.com/cb",
            code_verifier=generate_code_verifier(),  # attacker's guess
        )
    except InvalidGrant:
        pass
    else:
        raise AssertionError("PKCE mismatch must fail")

    # 7. Code is single-use even after failure.
    try:
        server.exchange_code(
            client_id="spa-1",
            code=code,
            redirect_uri="https://app.example.com/cb",
            code_verifier=verifier,
        )
    except InvalidGrant:
        pass
    else:
        raise AssertionError("burned code must not be reusable")

    # 8. Expired code fails.
    server2 = AuthorizationServer(
        clients={client.client_id: client}, _clock=lambda: 1000.0
    )
    loc = server2.authorize(
        client_id="spa-1",
        response_type="code",
        redirect_uri="https://app.example.com/cb",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope="read",
        subject="user-1",
    )
    code = loc.split("code=")[1].split("&")[0]
    server2._clock = lambda: 1000.0 + CODE_TTL_SECONDS + 1
    try:
        server2.exchange_code(
            client_id="spa-1",
            code=code,
            redirect_uri="https://app.example.com/cb",
            code_verifier=verifier,
        )
    except InvalidGrant:
        pass
    else:
        raise AssertionError("expired code must be rejected")

    print("All 8 OAuth Implicit → PKCE fix self-tests passed.")


if __name__ == "__main__":
    _run_self_tests()
