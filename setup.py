#!/usr/bin/env python
from pathlib import Path
from setuptools import setup
import versioneer

path = Path(__file__).parent
readme = path / 'README.rst'
history = path / 'HISTORY.rst'

long_desc = readme.read_text() if readme.exists() else ''
if history.exists():
    long_desc = '\n\n'.join([long_desc, history.read_text()])

setup(
    long_description=long_desc,
    long_description_content_type='text/x-rst',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
)
