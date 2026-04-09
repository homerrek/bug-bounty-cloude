#!/usr/bin/env python3
"""
Burp Suite MCP Client — startup connectivity check.

Verifies that Burp Suite is running and its REST API is reachable at
http://localhost:8080 before registering any MCP tools.  If Burp is not
detected the client prints a warning and exits cleanly without raising an
unhandled exception; the rest of Claude Code continues to start normally.

Usage (called automatically by Claude Code MCP integration):
    python3 mcp/burp-mcp-client/client.py
"""

import http.client
import os
import socket
import sys

BURP_HOST = "localhost"
BURP_PORT = int(os.environ.get("BURP_REST_PORT", "8080"))
BURP_TIMEOUT = 3  # seconds


def _burp_is_reachable() -> bool:
    """Return True if the Burp REST API responds at BURP_HOST:BURP_PORT."""
    try:
        conn = http.client.HTTPConnection(BURP_HOST, BURP_PORT, timeout=BURP_TIMEOUT)
        conn.request("GET", "/")
        resp = conn.getresponse()
        conn.close()
        # Any HTTP response (even 401/404) means Burp is up.
        return resp.status is not None
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def main() -> None:
    if not _burp_is_reachable():
        print(
            f"WARNING: Burp Suite not detected at {BURP_HOST}:{BURP_PORT}"
            " — Burp MCP tools disabled"
        )
        # Exit cleanly — do not register tools, do not raise an exception.
        sys.exit(0)

    # Burp is up: proceed with normal tool registration / MCP server startup.
    print(f"[+] Burp Suite detected at {BURP_HOST}:{BURP_PORT} — Burp MCP tools enabled")


if __name__ == "__main__":
    main()
