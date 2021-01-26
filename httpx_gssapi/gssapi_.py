import re
import logging
from itertools import chain
from functools import wraps
from typing import Generator, Optional, List, Any

from base64 import b64encode, b64decode

import gssapi
from gssapi import SecurityContext
from gssapi.exceptions import GSSError

import httpx
from httpx import Auth, Request, Response

from .exceptions import MutualAuthenticationError, SPNEGOExchangeError

log = logging.getLogger(__name__)
FlowGen = Generator[Request, Response, None]

# Different types of mutual authentication:
#  with mutual_authentication set to REQUIRED, all responses will be
#   authenticated with the exception of errors. Errors will have their contents
#   and headers stripped. If a non-error response cannot be authenticated, a
#   MutualAuthenticationError exception will be raised.
# with mutual_authentication set to OPTIONAL, mutual authentication will be
#   attempted if supported, and if supported and failed, a
#   MutualAuthenticationError exception will be raised. Responses which do not
#   support mutual authentication will be returned directly to the user.
# with mutual_authentication set to DISABLED, mutual authentication will not be
#   attempted, even if supported.
REQUIRED = 1
OPTIONAL = 2
DISABLED = 3

_find_auth = re.compile(r'Negotiate\s*([^,]*)', re.I).search


def _negotiate_value(response: Response) -> Optional[bytes]:
    """Extracts the gssapi authentication token from the appropriate header"""
    authreq = response.headers.get('www-authenticate', None)
    if authreq:
        match_obj = _find_auth(authreq)
        if match_obj:
            return b64decode(match_obj.group(1))


def _sanitize_response(response: Response):
    """
    When mutual authentication is required and an HTTP error is to be
    returned, this method is used to sanitize the response which cannot
    be trusted.
    """
    response.is_stream_consumed = True
    response._content = b""
    response._cookies = httpx.Cookies()
    headers = response.headers
    response.headers = httpx.Headers({'content-length': '0'})
    for header in ('date', 'server'):
        if header in headers:
            response.headers[header] = headers[header]


def _handle_gsserror(*, gss_stage: str, result: Any = ...):
    """
    Decorator to handle GSSErrors and properly log them against the decorated
    function's name.

    :param gss_stage:
        Name of GSS stage that the function is handling. Typically either
        'initializing' or 'stepping'.
    :param result:
        The result to return if a GSSError is raised. If the result is a
        callable, it will be called first with the message and all args
        and kwargs.
    """

    def _decor(func):
        @wraps(func)
        def _wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except GSSError as error:
                msg = f"{gss_stage} context failed: {error.gen_message()}"
                log.exception(f"{func.__name__}(): {msg}")
                if callable(result):
                    return result(msg, *args, **kwargs)
                return result

        return _wrapper

    return _decor


def _gss_to_spnego_error(message: str, *args: Any, **kwargs: Any):
    """Helper function to _handle_gsserror to raise SPNEGOExchangeErrors."""
    try:
        request = next(
            a for a in chain(args, kwargs.values())
            if isinstance(a, Request)
        )
    except StopIteration:  # sanity check
        raise RuntimeError("No request in arguments!")
    raise SPNEGOExchangeError(message, request=request)


class HTTPSPNEGOAuth(Auth):
    """
    Attaches HTTP GSSAPI Authentication to the given Request object.

    `mutual_authentication` controls whether GSSAPI should attempt mutual
    authentication.  It may be `REQUIRED`, `OPTIONAL`, or `DISABLED`
    (default).

    `target_name` specifies the remote principal name.  It may be either a
    GSSAPI name type or a string (default: "HTTP" at the DNS host).

    `delegate` indicates whether we should attempt credential delegation.
    Default is `False`.

    `opportunistic_auth` indicates whether we should assume the server will
    ask for Negotiation.  Defaut is `False`.

    `creds` is GSSAPI credentials (gssapi.Credentials) to use for negotiation.
    Default is `None`.

    `mech` is GSSAPI Mechanism (gssapi.Mechanism) to use for negotiation.
    Default is `None`

    `sanitize_mutual_error_response` controls whether we should clean up
    server responses.  See the `SanitizedResponse` class.

    """

    def __init__(self,
                 mutual_authentication: int = DISABLED,
                 target_name: Optional[str] = "HTTP",
                 delegate: bool = False,
                 opportunistic_auth: bool = False,
                 creds: gssapi.Credentials = None,
                 mech: bytes = None,
                 sanitize_mutual_error_response: bool = True):
        self.mutual_authentication = mutual_authentication
        self.target_name = target_name
        self.delegate = delegate
        self.opportunistic_auth = opportunistic_auth
        self.creds = creds
        self.mech = mech
        self.sanitize_mutual_error_response = sanitize_mutual_error_response

    def auth_flow(self, request: Request) -> FlowGen:
        if self.opportunistic_auth:
            # add Authorization header before we receive a 401
            ctx = self.set_auth_header(request)
        else:
            ctx = None

        response = yield request
        yield from self.handle_response(response, ctx)

    def handle_response(self,
                        response: Response,
                        ctx: SecurityContext = None) -> FlowGen:
        num_401s = 0
        while response.status_code == 401 and num_401s < 2:
            num_401s += 1
            log.debug(f"Handling 401 response, total seen: {num_401s}")

            if _negotiate_value(response) is None:
                log.debug("GSSAPI is not supported")
                break

            log.debug("Generating user authentication header")
            try:
                ctx = self.set_auth_header(response.request, response)
            except SPNEGOExchangeError:
                log.debug("Failed to generate authentication header")

            # Try request again, hopefully with a new auth header
            response = yield response.request

        if response.status_code == 401 or ctx is None:
            log.debug("Failed to authenticate, returning 401 response")
            return

        self.handle_mutual_auth(response, ctx)

    def handle_mutual_auth(self, response: Response, ctx: SecurityContext):
        """
        Handles all responses with the exception of 401s.

        This is necessary so that we can authenticate responses if requested
        """
        log.debug(f"handle_mutual_auth(): Handling {response.status_code}")

        if self.mutual_authentication == DISABLED:
            log.debug("handle_mutual_auth(): Mutual auth disabled, ignoring")
            return

        is_http_error = response.status_code >= 400

        if _negotiate_value(response) is not None:
            log.debug("handle_mutual_auth(): Authenticating the server")
            if not self.authenticate_server(response, ctx):
                # Mutual authentication failure when mutual auth is wanted,
                # raise an exception so the user doesn't use an untrusted
                # response.
                log.error("handle_mutual_auth(): Mutual authentication failed")
                raise MutualAuthenticationError(response=response)

            # Authentication successful
            log.debug("handle_other(): authentication successful")
        elif is_http_error or self.mutual_authentication == OPTIONAL:
            if response.status_code != httpx.codes.OK:
                log.error(
                    f"handle_mutual_auth(): Mutual authentication unavailable "
                    f"on {response.status_code} response"
                )
            if (self.mutual_authentication == REQUIRED
                    and self.sanitize_mutual_error_response):
                _sanitize_response(response)
        else:
            # Unable to attempt mutual authentication when mutual auth is
            # required, raise an exception so the user doesn't use an
            # untrusted response.
            log.error("handle_other(): Mutual authentication failed")
            raise MutualAuthenticationError(response=response)

    @_handle_gsserror(gss_stage='stepping', result=_gss_to_spnego_error)
    def set_auth_header(self,
                        request: Request,
                        response: Response = None) -> SecurityContext:
        """
        Create a new security context, generate the GSSAPI authentication
        token, and insert it into the request header. The new security context
        will be returned.

        If any GSSAPI step fails, raise SPNEGOExchangeError with failure detail.
        """
        ctx = self._make_context(request)

        token = _negotiate_value(response) if response is not None else None
        gss_resp = ctx.step(token or None)
        auth_header = f"Negotiate {b64encode(gss_resp).decode()}"
        log.debug(
            f"add_request_header(): "
            f"{'Preemptive ' if token is None else ''}"
            f"Authorization header: {auth_header}"
        )

        request.headers['Authorization'] = auth_header
        return ctx

    @_handle_gsserror(gss_stage="stepping", result=False)
    def authenticate_server(self,
                            response: Response,
                            ctx: SecurityContext) -> bool:
        """
        Uses GSSAPI to authenticate the server by extracting the negotiate
        value from the response and stepping the security context.

        Returns True on success, False on failure.
        """
        auth_header = _negotiate_value(response)
        log.debug(f"authenticate_server(): Authenticate header: {auth_header}")

        # If the handshake isn't complete here, nothing we can do
        ctx.step(auth_header)

        log.debug("authenticate_server(): authentication successful")
        return True

    @_handle_gsserror(gss_stage='initializing', result=_gss_to_spnego_error)
    def _make_context(self, request: Request) -> SecurityContext:
        """
        Create a GSSAPI security context for handling the authentication.

        :param request:
            Request to make the context for. The hostname from it is
            used if it isn't included in :py:attr:`target_name`.
        """
        name = self.target_name
        if type(name) != gssapi.Name:  # type(name) is str
            if '@' not in name:
                name += f"@{request.url.host}"
            name = gssapi.Name(name, gssapi.NameType.hostbased_service)

        return SecurityContext(
            usage="initiate",
            flags=self._gssflags,
            name=name,
            creds=self.creds,
            mech=self.mech,
        )

    @property
    def _gssflags(self) -> List[gssapi.RequirementFlag]:
        """List of configured GSSAPI requirement flags."""
        flags = [gssapi.RequirementFlag.out_of_sequence_detection]
        if self.delegate:
            flags.append(gssapi.RequirementFlag.delegate_to_peer)
        if self.mutual_authentication != DISABLED:
            flags.append(gssapi.RequirementFlag.mutual_authentication)
        return flags
