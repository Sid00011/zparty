"""
core/auth.py — Authentication manager
Supports: none | cookie | bearer | basic | apikey | form
"""
import base64
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Manages authentication state for a scan session.

    Supported auth types
    --------------------
    none    — no authentication (default)
    cookie  — raw cookie string, e.g. "session=abc123; csrf=xyz"
    bearer  — Authorization: Bearer <token>
    basic   — HTTP Basic auth (username + password → Authorization header)
    apikey  — custom header name + key value
    form    — POST credentials to login_url, store returned session cookies
    """

    def __init__(self) -> None:
        self.auth_type: str = "none"
        self.is_authenticated: bool = False
        self._cookies: dict = {}
        self._headers: dict = {}

    # ------------------------------------------------------------------ #
    # Factory                                                              #
    # ------------------------------------------------------------------ #

    @classmethod
    async def from_config(cls, cfg: dict, ctx: dict) -> "AuthManager":
        """Build and return a ready-to-use AuthManager from config.yaml values."""
        mgr = cls()
        auth_cfg: dict = cfg.get("auth", {}) or {}
        auth_type: str = str(auth_cfg.get("type", "none")).lower()
        mgr.auth_type = auth_type

        if auth_type == "none" or not auth_type:
            logger.info("Auth: none — scanning without authentication")
            return mgr

        if auth_type == "cookie":
            raw: str = auth_cfg.get("cookie", "") or ""
            if raw:
                mgr._cookies = _parse_cookie_string(raw)
                mgr.is_authenticated = True
                logger.info(f"Auth: cookie — {len(mgr._cookies)} cookie(s) loaded")
            else:
                logger.warning("Auth: cookie type specified but no cookie string provided")

        elif auth_type == "bearer":
            token: str = auth_cfg.get("bearer", "") or ""
            if token:
                mgr._headers["Authorization"] = f"Bearer {token}"
                mgr.is_authenticated = True
                logger.info("Auth: bearer token loaded")
            else:
                logger.warning("Auth: bearer type specified but no token provided")

        elif auth_type == "basic":
            basic_cfg: dict = auth_cfg.get("basic", {}) or {}
            username: str = basic_cfg.get("username", "") or ""
            password: str = basic_cfg.get("password", "") or ""
            if username:
                encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
                mgr._headers["Authorization"] = f"Basic {encoded}"
                mgr.is_authenticated = True
                logger.info(f"Auth: basic — user '{username}'")
            else:
                logger.warning("Auth: basic type specified but no username provided")

        elif auth_type == "apikey":
            apikey_cfg: dict = auth_cfg.get("apikey", {}) or {}
            header_name: str = apikey_cfg.get("header", "X-API-Key") or "X-API-Key"
            key_value: str = apikey_cfg.get("key", "") or ""
            if key_value:
                mgr._headers[header_name] = key_value
                mgr.is_authenticated = True
                logger.info(f"Auth: apikey — header '{header_name}'")
            else:
                logger.warning("Auth: apikey type specified but no key provided")

        elif auth_type == "form":
            form_cfg: dict = auth_cfg.get("form", {}) or {}
            await mgr._do_form_login(form_cfg)

        else:
            logger.warning(f"Auth: unknown auth type '{auth_type}' — treating as none")

        return mgr

    # ------------------------------------------------------------------ #
    # Public accessors                                                     #
    # ------------------------------------------------------------------ #

    def get_cookies(self) -> dict:
        """Return a copy of the auth cookies dict."""
        return dict(self._cookies)

    def get_headers(self) -> dict:
        """Return a copy of the auth headers dict."""
        return dict(self._headers)

    # ------------------------------------------------------------------ #
    # Form login helper                                                    #
    # ------------------------------------------------------------------ #

    async def _do_form_login(self, form_cfg: dict) -> None:
        login_url: str = form_cfg.get("login_url", "") or ""
        username_field: str = form_cfg.get("username_field", "username") or "username"
        password_field: str = form_cfg.get("password_field", "password") or "password"
        username: str = form_cfg.get("username", "") or ""
        password: str = form_cfg.get("password", "") or ""
        success_indicator: str = form_cfg.get("success_indicator", "") or ""

        if not login_url:
            logger.warning("Auth: form type specified but no login_url provided")
            return
        if not username:
            logger.warning("Auth: form type specified but no username provided")
            return

        payload = {
            username_field: username,
            password_field: password,
        }

        logger.info(f"Auth: form — attempting login at {login_url}")
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=15.0, read=30.0, write=10.0, pool=8.0),
                http2=False,
                verify=False,
                follow_redirects=True,
            ) as client:
                resp = await client.post(login_url, data=payload)

            if success_indicator and success_indicator not in resp.text:
                logger.error(
                    f"Auth: form login failed — success_indicator '{success_indicator}' "
                    f"not found in response (HTTP {resp.status_code})"
                )
                return

            # Store all cookies returned by the server (including redirect chain cookies)
            for name, value in resp.cookies.items():
                self._cookies[name] = value

            if self._cookies:
                self.is_authenticated = True
                logger.info(
                    f"Auth: form login succeeded — {len(self._cookies)} session cookie(s) stored"
                )
            else:
                logger.warning(
                    f"Auth: form login returned HTTP {resp.status_code} "
                    "but no session cookies were set"
                )

        except Exception as exc:
            logger.error(f"Auth: form login request failed: {type(exc).__name__}: {exc}")


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _parse_cookie_string(raw: str) -> dict:
    """Parse a raw cookie string like 'session=abc123; csrf=xyz' into a dict."""
    cookies: dict = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _, value = part.partition("=")
            cookies[name.strip()] = value.strip()
        else:
            # Flag-style cookie with no value
            cookies[part] = ""
    return cookies
