"""
httpx_gssapi.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of exceptions.

"""
from httpx import RequestError, Request, Response


class MutualAuthenticationError(RequestError):
    """Mutual Authentication Error"""

    def __init__(self, *,
                 request: Request = None,
                 response: Response):
        self.response = response
        super().__init__(
            f"Unable to authenticate {self.response}",
            request=request or self.response.request,
        )


class SPNEGOExchangeError(RequestError):
    """SPNEGO Exchange Failed Error"""
