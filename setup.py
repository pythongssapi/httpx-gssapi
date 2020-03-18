#!/usr/bin/env python
import re
from pathlib import Path
from setuptools import setup

path = Path(__file__).parent
readme = path / 'README.rst'
history = path / 'HISTORY.rst'

long_desc = readme.read_text() if readme.exists() else ''
if history.exists():
    long_desc = '\n\n'.join([long_desc, history.read_text()])


def get_version():
    """Get current version using regex to avoid import."""
    reg = re.compile(r'__version__ = [\'"]([^\'"]*)[\'"]')
    with (path / 'httpx_gssapi' / '__init__.py').open() as fd:
        match = next(filter(None, map(reg.match, fd)), None)

    if match is None:
        raise RuntimeError('Could not find the version for httpx_gssapi')
    return match.group(1)


setup(
    long_description=long_desc,
    version=get_version(),
)
