# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM python:3.11-slim AS test
WORKDIR /src
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
COPY tests tests
COPY scripts scripts
COPY demo demo
RUN pip install --no-cache-dir ".[dev]" && pytest

FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
# The demo, and with it idpCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch. Rebuild after running the
# install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the relying
# party's key, certificate or the IdP metadata). A COPY of the demo DIRECTORY
# succeeds with or without it, so a fresh clone and CI still build; naming the
# file, or a glob that matches nothing, fails the build in both builders. It
# comes after the install, so a new chain does not reinstall the library.
COPY demo ./demo
COPY scripts ./scripts
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','3000')).read()" || exit 1
CMD ["python", "demo/app.py"]
