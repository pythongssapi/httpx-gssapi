srpm:
	dnf install -y python3
	sed "s/name='httpx-gssapi'/name='python-httpx-gssapi'/" setup.py > .copr/setup.py
	python3 .copr/setup.py bdist_rpm --source-only --dist-dir "$(outdir)" --build-requires=python-setuptools
