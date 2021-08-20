#!/usr/bin/env python
"""Tests for httpx_gssapi proxy support."""

import os
import re
import multiprocessing as mp
from base64 import b64decode, b64encode
from time import sleep
from typing import Optional

import httpx
import pytest
import k5test
import gssapi

from proxy import main as proxy_main
from proxy.http.parser import HttpParser
from proxy.http.codes import httpStatusCodes
from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.exception import ProxyAuthenticationFailed
from proxy.common.flag import flags
from proxy.common.utils import build_http_response
from proxy.common.constants import \
    PROXY_AGENT_HEADER_VALUE, PROXY_AGENT_HEADER_KEY

import httpx_gssapi

AUTHENTICATE = b'Proxy-Authenticate'
AUTHORIZATION = b'Proxy-Authorization'
NEGOTIATE = b'Negotiate'

_find_auth = re.compile(rb'Negotiate\s*([^,]*)', re.I).search

flags.add_argument(
    '--krb5-realm',
    type=str,
    default='KRBTEST.COM',
    help='Kerberos realm for GSSAPI auth.',
)


class GSSAPIProxyAuthFailed(ProxyAuthenticationFailed):
    """
    Exception raised when Http Proxy GSSAPI auth is enabled and
    incoming request fails authentication.
    """

    def __init__(self, neg_token: bytes = None):
        self.neg_token = neg_token

    def response(self, _request: HttpParser) -> memoryview:
        return memoryview(build_http_response(
            httpStatusCodes.PROXY_AUTH_REQUIRED,
            reason=b'Proxy Authentication Required',
            headers={
                PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
                AUTHENTICATE: _format_neg(self.neg_token),
            },
            body=b'Proxy Authentication Required',
        ))


class GSSAPIAuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication."""

    def before_upstream_connection(self,
                                   request: HttpParser) -> Optional[HttpParser]:
        if self.flags.krb5_realm:
            in_token = _get_auth_header(request)
            if not in_token:
                raise GSSAPIProxyAuthFailed()

            ctx = self._get_context()
            out_token = ctx.step(in_token)
            if not ctx.complete:
                raise GSSAPIProxyAuthFailed(b64encode(out_token))

            request.add_header(AUTHENTICATE, _format_neg(out_token))
        return request

    def _get_context(self):
        service_name = gssapi.Name(
            f'HTTP/localhost@{self.flags.krb5_realm}'
        )
        server_cred = gssapi.Credentials(name=service_name, usage='accept')
        return gssapi.SecurityContext(creds=server_cred)

    def handle_client_request(self,
                              request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass


def _get_auth_header(request: HttpParser) -> Optional[bytes]:
    auth_key = AUTHORIZATION.lower()
    if auth_key not in request.headers:
        return
    match = _find_auth(request.headers[auth_key][1])
    if match:
        return b64decode(match.group(1))


def _format_neg(token: bytes = None) -> bytes:
    header = NEGOTIATE
    if token:
        header += b' ' + token
    return header


def start_proxy(realm: k5test.K5Realm,
                host: str = '127.0.0.1',
                port: int = 8080):
    princ = f'HTTP/localhost@{realm.realm}'
    realm.addprinc(princ)
    realm.extract_keytab(princ, realm.keytab)
    realm.ccache = realm.env['KRB5CCNAME'] \
        = os.path.join(realm.tmpdir, 'service_ccache')
    realm.kinit(princ, flags=['-k', '-t', realm.keytab])

    os.environ.update(realm.env)

    proxy_main([
        f'--krb5-realm={realm.realm}',
        f'--hostname={host}',
        f'--port={port}',
    ], plugins=[GSSAPIAuthPlugin])


@pytest.fixture
def proxy_port(free_port_factory) -> int:
    return free_port_factory()


@pytest.fixture
def proxy(request, krb_realm, proxy_port):
    ps = mp.Process(
        target=start_proxy,
        args=(krb_realm,),
        kwargs={'port': proxy_port},
    )
    ps.start()

    sleep(1)

    @request.addfinalizer
    def cleanup():
        if ps.is_alive():
            ps.terminate()


@pytest.fixture
@pytest.mark.usefixtures('proxy', 'http_server')
def client(http_creds, proxy_port) -> httpx.Client:
    auth = httpx_gssapi.HTTPSPNEGOAuth(creds=http_creds)
    with httpx.Client(
            auth=auth,
            timeout=500,
            proxies={'http://': f'http://localhost:{proxy_port}'},
    ) as client:
        yield client


@pytest.mark.xfail(reason="Can't determine the proper proxy host")
@pytest.mark.usefixtures('proxy')
def test_proxy_external(client):
    for i in range(2):
        # Use neverssl.com to avoid worrying about SSL with the proxy
        resp = client.get('http://neverssl.com/')
        assert resp.status_code == 200


@pytest.mark.usefixtures('proxy', 'http_server')
def test_proxy_local(client, http_server_port):
    for i in range(2):
        resp = client.get(f'http://localhost:{http_server_port}/')
        assert resp.status_code == 200


if __name__ == '__main__':
    pytest.main()
