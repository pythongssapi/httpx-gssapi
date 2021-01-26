"""
httpx_gssapi.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of exceptions.

"""
from httpx import HTTPError, Request, Response


class MutualAuthenticationError(HTTPError):
    """Mutual Authentication Error"""

    def __init__(self, *,
                 request: Request = None,
                 response: Response):
        self.response = response
        super().__init__(
            f"Unable to authenticate {self.response}",
            request=request or self.response.request,
        )


class SPNEGOExchangeError(HTTPError):
    """SPNEGO Exchange Failed Error"""
