"""
Compatibility library for older versions of python and requests_kerberos
"""
import gssapi
from gssapi.exceptions import GSSError

from httpx import Response

from .gssapi_ import DISABLED, HTTPSPNEGOAuth, SPNEGOExchangeError, log


class HTTPKerberosAuth(HTTPSPNEGOAuth):
    """Deprecated compat shim; see HTTPSPNEGOAuth instead."""
    def __init__(self,
                 mutual_authentication: int = DISABLED,
                 service: str = "HTTP",
                 delegate: bool = False,
                 force_preemptive: bool = False,
                 principal: str = None,
                 hostname_override: str = None,
                 sanitize_mutual_error_response: bool = True):
        # put these here for later
        self.principal = principal
        self.service = service
        self.hostname_override = hostname_override

        super().__init__(
            mutual_authentication=mutual_authentication,
            target_name=None,
            delegate=delegate,
            opportunistic_auth=force_preemptive,
            creds=None,
            sanitize_mutual_error_response=sanitize_mutual_error_response,
        )

    def generate_request_header(self,
                                host: str,
                                response: Response = None) -> str:
        # This method needs to be shimmed because `host` isn't exposed to
        # __init__() and we need to derive things from it.  Also, __init__()
        # can't fail, in the strictest compatability sense.
        gss_stage = "start"
        try:
            if self.principal is not None:
                gss_stage = "acquiring credentials"
                name = gssapi.Name(
                    self.principal,
                    gssapi.NameType.hostbased_service,
                )
                self.creds = gssapi.Credentials(name=name, usage="initiate")

            # contexts still need to be stored by host, but hostname_override
            # allows use of an arbitrary hostname for the GSSAPI exchange (eg,
            # in cases of aliased hosts, internal vs external, CNAMEs w/
            # name-based HTTP hosting)
            if self.service is not None:
                gss_stage = "initiating context"
                kerb_host = host
                if self.hostname_override:
                    kerb_host = self.hostname_override

                kerb_spn = f"{self.service}@{kerb_host}"
                self.target_name = gssapi.Name(
                    kerb_spn,
                    gssapi.NameType.hostbased_service,
                )

            return super().generate_request_header(host, response)
        except GSSError as error:
            msg = f"{gss_stage} failed: {error.gen_message()}"
            log.exception(f"generate_request_header(): {msg}")
            raise SPNEGOExchangeError(msg)
