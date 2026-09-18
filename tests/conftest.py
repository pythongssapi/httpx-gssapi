# TODO: Provide this through k5test?
import os
import re
import copy
import socket
import contextlib
import multiprocessing as mp
from time import sleep
from base64 import b64decode
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest
import k5test  # type: ignore[import-untyped]

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
        self._set_www_auth(neg_token)
        self.end_headers()
        self.wfile.write(msg.encode())

    def _set_www_auth(self, token=None):
        www_auth = f'{NEGOTIATE} {token}' if token else NEGOTIATE
        self.send_header(WWW_AUTHENTICATE, www_auth)

    def _get_context(self):
        service_name = gssapi.Name(
            f'HTTP/{self.server.server_name}@{self.server.krb5_realm_name}'
        )
        server_cred = gssapi.Credentials(name=service_name, usage='accept')
        return gssapi.SecurityContext(creds=server_cred)


def start_http_server(realm_name: str,
                      env: dict,
                      host: str = 'localhost',
                      port: int = 8080):
    # Runs in the worker process. Everything it needs is passed as picklable
    # data (a realm-name ``str`` and a ``dict[str, str]`` of environment
    # variables) so this works under the ``spawn``/``forkserver`` start
    # methods, which pickle the target's arguments. The KDC-side setup
    # (addprinc/extract_keytab/kinit) has already run in the parent, and the
    # acceptor credentials resolve from the keytab via ``env`` (KRB5_KTNAME).
    os.environ.update(env)

    with HTTPServer(server_address=(host, port),
                    RequestHandlerClass=KrbRequestHandler) as httpd:
        httpd.krb5_realm_name = realm_name  # type: ignore[attr-defined]
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
def http_server_port() -> int:
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='session')
def http_server(request, krb_realm: k5test.K5Realm, http_server_port: int):
    host = 'localhost'
    # Do the KDC-side setup in the parent, where the realm object lives, then
    # hand the worker only picklable data. This keeps the suite correct under
    # Python 3.14+, where the default POSIX start method changed from "fork"
    # to "forkserver" (a fresh interpreter that pickles the target's args --
    # the ``k5test.K5Realm`` object holds an unpicklable ``threading.Lock``).
    princ = f'HTTP/{host}@{krb_realm.realm}'
    krb_realm.addprinc(princ)
    krb_realm.extract_keytab(princ, krb_realm.keytab)
    krb_realm.ccache = krb_realm.env['KRB5CCNAME'] \
        = os.path.join(krb_realm.tmpdir, 'service_ccache')
    krb_realm.kinit(princ, flags=['-k', '-t', krb_realm.keytab])

    ctx = mp.get_context('forkserver')
    ps = ctx.Process(
        target=start_http_server,
        kwargs={
            'realm_name': krb_realm.realm,
            'env': dict(krb_realm.env),
            'host': host,
            'port': http_server_port,
        },
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
