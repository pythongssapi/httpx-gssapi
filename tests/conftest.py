# TODO: Provide this through k5test?
import copy
import multiprocessing as mp
import os
import re
import threading as th
from base64 import b64decode
from contextlib import contextmanager
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Generator, cast

import gssapi.exceptions
import k5test  # type: ignore[import-untyped]
import pytest

WWW_AUTHENTICATE = 'WWW-Authenticate'
AUTHORIZATION = 'Authorization'
NEGOTIATE = 'Negotiate'

_find_auth = re.compile(r'Negotiate\s*([^,]*)', re.IGNORECASE).search


class KrbRequestHandler(BaseHTTPRequestHandler):
    """
    Simple HTTP Request Handler which implements kerberos authentication
    and responds with "Authenticated!" on success and "Unauthorized!" on
    failure.
    """

    def do_GET(self):
        in_token = self._get_auth_header()
        if not in_token:
            return self._unauthorized()
        ctx = self._get_context()
        out_token = ctx.step(in_token)
        if ctx.complete:
            return self._authorized(out_token)
        else:
            return self._unauthorized()

    def _get_auth_header(self):
        auth = self.headers.get(AUTHORIZATION)
        if not auth:
            return
        match_obj = _find_auth(auth)
        if match_obj:
            return b64decode(match_obj.group(1))

    def _authorized(self, neg_token=None):
        self._respond(200, 'Authorized!', neg_token)

    def _unauthorized(self, neg_token=None):
        self._respond(401, 'Unauthorized!', neg_token)

    def _respond(self, code, msg, neg_token=None):
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self._set_www_auth(neg_token)
        self.end_headers()
        self.wfile.write(msg.encode())

    def _set_www_auth(self, token=None):
        www_auth = f'{NEGOTIATE} {token}' if token else NEGOTIATE
        self.send_header(WWW_AUTHENTICATE, www_auth)

    def _get_context(self):
        service_name = gssapi.Name(
            f'HTTP/{self.server.server_name}@{self.server.krb5_realm.realm}'
        )
        server_cred = gssapi.Credentials(name=service_name, usage='accept')
        return gssapi.SecurityContext(creds=server_cred)


@contextmanager
def start_http_server(
    realm: k5test.K5Realm,
    host: str = 'localhost',
    port: int = 0,
) -> Generator[HTTPServer, None, None]:
    princ = f'HTTP/{host}@{realm.realm}'
    realm.addprinc(princ)
    realm.extract_keytab(princ, realm.keytab)
    realm.ccache = realm.env['KRB5CCNAME'] \
        = os.path.join(realm.tmpdir, 'service_ccache')
    realm.kinit(princ, flags=['-k', '-t', realm.keytab])

    with HTTPServer(
        server_address=(host, port),
        RequestHandlerClass=KrbRequestHandler,
    ) as httpd:
        httpd.krb5_realm = realm  # type: ignore[attr-defined]
        thread = th.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        yield httpd
        thread.join(timeout=5)


@pytest.fixture(scope='session')
def krb_realm() -> k5test.K5Realm:
    realm = k5test.K5Realm()
    env = copy.deepcopy(os.environ)
    os.environ.update(realm.env)
    yield realm
    realm.stop()
    os.environ = env # noqa: B003


@pytest.fixture(scope='session')
def http_server(krb_realm: k5test.K5Realm) -> Generator[str, None, None]:
    with start_http_server(krb_realm) as httpd:
        host, port = cast(tuple[str, int], httpd.server_address)
        yield f"http://{host}:{port}/"
        httpd.shutdown()


@pytest.fixture
def http_creds(
    krb_realm: k5test.K5Realm,
) -> Generator[gssapi.Credentials, None, None]:
    yield gssapi.Credentials(usage='initiate', name=gssapi.Name('user'))
