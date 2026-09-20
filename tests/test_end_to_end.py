#!/usr/bin/env python
"""Tests for httpx_gssapi."""
import gssapi
import httpx
import k5test
import pytest

import httpx_gssapi


def test_end_to_end(
    http_server: str,
    http_creds: gssapi.Credentials,
    krb_realm: k5test.K5Realm,
) -> None:
    auth = httpx_gssapi.HTTPSPNEGOAuth(creds=http_creds)
    with httpx.Client(auth=auth, timeout=500) as client:
        for i in range(2):
            resp = client.get(http_server)
            assert resp.status_code == 200


if __name__ == '__main__':
    pytest.main()
