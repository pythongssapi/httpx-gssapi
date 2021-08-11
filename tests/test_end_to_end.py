#!/usr/bin/env python
"""Tests for httpx_gssapi."""

import httpx
import pytest

import httpx_gssapi


@pytest.mark.usefixtures('http_server', 'krb_realm')
def test_end_to_end(http_creds, http_server_port):
    auth = httpx_gssapi.HTTPSPNEGOAuth(creds=http_creds)
    with httpx.Client(auth=auth, timeout=500) as client:
        for i in range(2):
            resp = client.get(f'http://localhost:{http_server_port}/')
            assert resp.status_code == 200


@pytest.mark.usefixtures('http_server', 'krb_realm')
def test_mutual_auth(http_creds, http_server_port):
    auth = httpx_gssapi.HTTPSPNEGOAuth(
        creds=http_creds,
        mutual_authentication=True,
    )
    with httpx.Client(auth=auth, timeout=500) as client:
        for i in range(2):
            resp = client.get(f'http://localhost:{http_server_port}/')
            assert resp.status_code == 200


if __name__ == '__main__':
    pytest.main()
