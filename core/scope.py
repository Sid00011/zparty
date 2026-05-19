"""
core/scope.py — Scope control for Zparty scans.

Prevents sending attack payloads to out-of-scope URLs or destructive
paths (e.g. /logout which would invalidate the session under test).
"""
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ScopeManager:
    """
    Controls which URLs are in-scope for vulnerability testing.

    Rules applied in order
    ----------------------
    1. out_of_scope domains/paths → always excluded
    2. exclude_paths prefixes      → excluded (default: /logout, /signout, ...)
    3. include_paths prefixes      → if non-empty, only URLs matching one of these
                                     are included; URLs not matching are excluded
    4. Everything else             → in-scope
    """

    # Paths that, if probed, would log the scanner out and break the session.
    _DEFAULT_EXCLUDE = {"/logout", "/signout", "/sign-out", "/log-out", "/signoff"}

    def __init__(self, cfg: dict | None = None) -> None:
        scope_cfg: dict = (cfg or {}).get("scope", {}) if cfg else {}

        raw_oos: list = scope_cfg.get("out_of_scope", []) or []
        self._out_of_scope: list[str] = [str(x).lower().rstrip("/") for x in raw_oos if x]

        raw_excl: list = scope_cfg.get("exclude_paths", []) or []
        self._exclude_paths: list[str] = list(self._DEFAULT_EXCLUDE)
        for p in raw_excl:
            p = str(p).rstrip("/")
            if p and p not in self._exclude_paths:
                self._exclude_paths.append(p)

        raw_incl: list = scope_cfg.get("include_paths", []) or []
        self._include_paths: list[str] = [str(p).rstrip("/") for p in raw_incl if p]

        logger.debug(
            f"ScopeManager: exclude_paths={self._exclude_paths} "
            f"include_paths={self._include_paths} "
            f"out_of_scope={self._out_of_scope}"
        )

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def is_in_scope(self, url: str) -> bool:
        """Return True if this URL should be tested."""
        if not url:
            return False

        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        path = parsed.path.rstrip("/") or "/"

        # Rule 1: explicit out-of-scope list (domain or full URL prefix)
        for oos in self._out_of_scope:
            if host == oos or host.endswith("." + oos):
                logger.debug(f"OOS (domain): {url}")
                return False
            if url.lower().startswith(oos):
                logger.debug(f"OOS (prefix): {url}")
                return False

        # Rule 2: excluded paths (session-breaking, etc.)
        for excl in self._exclude_paths:
            if path == excl or path.startswith(excl + "/"):
                logger.debug(f"Excluded path: {url}")
                return False

        # Rule 3: include_paths whitelist (if configured)
        if self._include_paths:
            for incl in self._include_paths:
                if path == incl or path.startswith(incl + "/"):
                    return True
            logger.debug(f"Not in include_paths whitelist: {url}")
            return False

        return True

    def filter(self, urls: list[str]) -> list[str]:
        """Return only the URLs that are in-scope."""
        result = [u for u in urls if self.is_in_scope(u)]
        removed = len(urls) - len(result)
        if removed:
            logger.info(f"ScopeManager: filtered out {removed} out-of-scope URL(s)")
        return result
