"""Privacy policy for target HTTP headers included in AI prompts.

Only sanitize copies used for AI context. Target requests and the AI provider's
own transport Authorization header must retain their original credentials.
This is header filtering, not general anonymization of URLs or bodies.
"""

SENSITIVE_HEADERS = frozenset({
    "host", "cookie", "cookie2", "set-cookie", "set-cookie2",
    "authorization", "proxy-authorization", "authentication-info",
    "proxy-authentication-info", "x-api-key", "api-key", "apikey",
    "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token",
    "csrf-token", "xsrf-token",
})


def sanitize_headers(headers: dict | None) -> dict:
    """Remove sensitive headers case-insensitively without mutating input."""
    return {
        name: value for name, value in (headers or {}).items()
        if str(name).strip().lower() not in SENSITIVE_HEADERS
    }
