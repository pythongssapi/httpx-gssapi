"""
httpx_gssapi.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of exceptions.

"""
from httpx import HTTPError


class MutualAuthenticationError(HTTPError):
    """Mutual Authentication Error"""
    def __str__(self):
        return f"Unable to authenticate {self.response}"

    def __repr__(self):
        return f"{__class__.__name__}('{self}')"


class SPNEGOExchangeError(HTTPError):
    """SPNEGO Exchange Failed Error"""
