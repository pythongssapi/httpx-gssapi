#!/usr/bin/env python
"""Tests for httpx_gssapi."""

from os import getenv

if getenv("HTTPX") == "httpx2":
    import httpx2 as httpx
else:
    import httpx  # type: ignore[no-redef]
import pytest

import httpx_gssapi


def test_end_to_end(http_server, http_creds, krb_realm, http_server_port):
    auth = httpx_gssapi.HTTPSPNEGOAuth(creds=http_creds)
    with httpx.Client(auth=auth, timeout=500) as client:
        for i in range(2):
            resp = client.get(f'http://localhost:{http_server_port}/')
            assert resp.status_code == 200


if __name__ == '__main__':
    pytest.main()
