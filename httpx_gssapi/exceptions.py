"""
httpx_gssapi.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of exceptions.

"""

from os import getenv
from typing import Optional

if getenv("HTTPX") == "httpx2":
    from httpx2 import RequestError, Request, Response
else:
    from httpx import RequestError, Request, Response  # type: ignore[assignment]


class MutualAuthenticationError(RequestError):
    """Mutual Authentication Error"""

    def __init__(self, *,
                 request: Optional[Request] = None,
                 response: Response):
        self.response = response
        super().__init__(
            f"Unable to authenticate {self.response}",
            request=request or self.response.request,
        )


class SPNEGOExchangeError(RequestError):
    """SPNEGO Exchange Failed Error"""
