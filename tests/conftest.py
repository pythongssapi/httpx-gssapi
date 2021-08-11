# TODO: Provide this through k5test?
import os
import re
import copy
import socket
import contextlib
import multiprocessing as mp
from time import sleep
from base64 import b64decode, b64encode
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable

import pytest
import k5test

import gssapi.exceptions

WWW_AUTHENTICATE = 'WWW-Authenticate'
AUTHORIZATION = 'Authorization'
NEGOTIATE = 'Negotiate'

_find_auth = re.compile(r'Negotiate\s*([^,]*)', re.I).search


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
        # Required to work around proxy test issue
        # https://github.com/abhinavsingh/proxy.py/issues/398
        self.send_header('Content-Length', str(len(msg.encode())))
        self._set_www_auth(neg_token)
        self.end_headers()
        self.wfile.write(msg.encode())

    def _set_www_auth(self, token=None):
        www_auth = NEGOTIATE
        if token:
            www_auth += f' {b64encode(token).decode()}'
        self.send_header(WWW_AUTHENTICATE, www_auth)

    def _get_context(self):
        service_name = gssapi.Name(
            f'HTTP/{self.server.server_name}@{self.server.krb5_realm.realm}'
        )
        server_cred = gssapi.Credentials(name=service_name, usage='accept')
        return gssapi.SecurityContext(creds=server_cred)


def start_http_server(realm: k5test.K5Realm,
                      host: str = 'localhost',
                      port: int = 8080):
    princ = f'HTTP/{host}@{realm.realm}'
    realm.addprinc(princ)
    realm.extract_keytab(princ, realm.keytab)
    realm.ccache = realm.env['KRB5CCNAME'] \
        = os.path.join(realm.tmpdir, 'service_ccache')
    realm.kinit(princ, flags=['-k', '-t', realm.keytab])

    os.environ.update(realm.env)

    with HTTPServer(server_address=(host, port),
                    RequestHandlerClass=KrbRequestHandler) as httpd:
        httpd.krb5_realm = realm
        httpd.serve_forever()


@pytest.fixture(scope='session')
def krb_realm() -> k5test.K5Realm:
    realm = k5test.K5Realm()
    env = copy.deepcopy(os.environ)
    os.environ.update(realm.env)
    yield realm
    realm.stop()
    os.environ = env


@pytest.fixture(scope='session')
def free_port_factory() -> Callable[[], int]:
    def _get_free_port() -> int:
        with contextlib.closing(socket.socket()) as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]
    return _get_free_port


@pytest.fixture
def free_port(free_port_factory) -> int:
    return free_port_factory()


@pytest.fixture(scope='session')
def http_server_port(free_port_factory) -> int:
    return free_port_factory()


@pytest.fixture(scope='session')
def http_server(request, krb_realm: k5test.K5Realm, http_server_port: int):
    ps = mp.Process(
        target=start_http_server,
        args=(krb_realm,),
        kwargs={'port': http_server_port},
    )
    ps.start()

    sleep(1)

    @request.addfinalizer
    def cleanup():
        if ps.is_alive():
            ps.terminate()


@pytest.fixture
def http_creds(krb_realm: k5test.K5Realm):
    yield gssapi.Credentials(usage='initiate', name=gssapi.Name('user'))
