"""
HTTPX GSSAPI authentication library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTPX is a full featured Python HTTP library with both sync and async APIs
designed to be a next generation HTTP client for Python. This library is a port
of requests_gssapi to HTTPX and adds optional GSSAPI authentication support and
supports mutual authentication. Basic GET usage:

    >>> import httpx
    >>> from httpx_gssapi import HTTPSPNEGOAuth
    >>> r = httpx.get("http://example.org", auth=HTTPSPNEGOAuth())

Both the sync and async HTTPX APIs should be fully supported.
"""
__all__ = (
    'DISABLED',
    'OPTIONAL',
    'REQUIRED',
    'SPNEGO',
    'HTTPSPNEGOAuth',
    'MutualAuthenticationError',
)

import logging
import os

from ._version import get_versions
from .exceptions import MutualAuthenticationError
from .gssapi_ import DISABLED, OPTIONAL, REQUIRED, SPNEGO, HTTPSPNEGOAuth

__version__ = get_versions()['version']
del get_versions

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
logger.setLevel(os.environ.get(f'{__name__.upper()}_LOG_LEVEL') or 'WARNING')
