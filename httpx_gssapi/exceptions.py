"""
httpx_gssapi.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of exceptions.

"""
from __future__ import annotations

from httpx import Request, RequestError, Response


class MutualAuthenticationError(RequestError):
    """Mutual Authentication Error"""

    def __init__(self, *,
                 request: Request | None = None,
                 response: Response):
        self.response = response
        super().__init__(
            f"Unable to authenticate {self.response}",
            request=request or self.response.request,
        )


class SPNEGOExchangeError(RequestError):
    """SPNEGO Exchange Failed Error"""
