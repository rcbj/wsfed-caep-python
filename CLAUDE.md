<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Python port of the server-side WS-Federation relying party. Import `wsfed_caep`. Distribution name `wsfed-caep`. Version 0.1.0. License MIT (`LICENSE`). A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A version already on PyPI stays there; the next release is a new `version` in `pyproject.toml` (and `VERSION`). When this tree is published, `develop` and `main` are the same commit.

## Usage

`RelyingParty.from_file("wsfed.json")`, then `login(relay_state=...)` and `handle_reply({"method", "url", "body"}, request_id)`. JSON keys are the Node keys. Methods are snake_case: `from_file`, `login`, `handle_reply`, `resolve_config`, `read_config_file`.

The party accepts SAML 2.0 assertions with bearer confirmation `urn:oasis:names:tc:SAML:2.0:cm:bearer`. It reads IdP metadata, writes RP metadata, verifies XML signatures (rsa-sha256 is `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), decrypts encrypted elements, and caches assertion ids. Status success is `urn:oasis:names:tc:SAML:2.0:status:Success`. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`. `wsfed-caep generate-keys` writes a self-signed RSA key pair.

## signals

Omitted or `true` means on. The resolved configuration omits `signals` in that case. `false` does not start the receiver and does not require transmitter metadata. The relying party never starts the receiver itself; `SignalsReceiver` is separate. Sign-in does not change when signals are off, because WS-Federation does not send OAuth scopes. A non-boolean raises a config error: `signals must be true or false`. The shipped demo omits the key.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `pip install --no-cache-dir ".[dev]" && pytest` in `python:3.11-slim`. GitHub Actions uses that command. Do not run pytest on the host. The demo image does not run the suite.

Pytest covers the stub IdP (a signed SAML assertion the library accepts), replay, metadata, the self-signed certificate, the SSF poll receiver, the setup script's plan, and the demo handler. Those tests do not start iya-sts.

`python3 scripts/live_iya_sts.py` runs the install script inside the demo image against a scratch copy of this checkout (writing the `idpCa` chain), then builds the demo image again (which carries the chain), starts it with no CA mount, signs it in to iya-sts and checks credential-change and session-revoked on `GET /live-status`. The nightly workflow (06:35 UTC) runs the unit suite and that script once every 24 hours. Neither binds port 3000, 8081 or 18481-18495; the live defaults are 18556 and 18656. Secrets reach docker as `-e NAME`, and sign-in requests are logged by fixed labels, never URLs. `tests/test_trust_chain.py`: the install script writes the whole chain to `idpCa`'s path every run; the library trusts an HTTPS IdP through that file, refuses a forged leaf followed by the real CA certificates, and refuses the right chain under the wrong host name; a generated password goes to a 0600 file and is not printed. `tests/test_password_file.py`: that file is opened with mode 0600 (never wider, even for a moment), an existing wider file is narrowed to 0600, and a user name that is not a file name is refused.

## Layout

`src/wsfed_caep/` library (`ssf/` is the poll receiver). `tests/` pytest. `demo/app.py` stdlib server. `scripts/configure_iya_sts.py` registers the demo with iya-sts and writes the `idpCa` chain (`scripts/trust_chain.py`); the container `PORT` wins over the shell `PORT`. `scripts/live_iya_sts.py` is the live sign-in. `.github/workflows/nightly.yml` runs the unit suite and that script once every 24 hours. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`. The live script never binds 3000, 8081 or 18481-18495.

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/wsfed.json` names the iya-sts TLS listener CA trust chain the library trusts for the IdP metadata URL and the Shared Signals transmitter. The default is `file:generated/idp-ca.pem`, relative to `demo/`. The value may also be a plain path, `env:<NAME>`, or the PEM itself. The library loads every certificate in it as a trust anchor (`ssl` `load_verify_locations(cadata=...)`), so the whole chain works and OpenSSL ends the path at the self-signed Root. The presented leaf must still verify to one of those anchors (a forged leaf followed by the real CA certificates is refused), and the host name is checked against the leaf's subject alternative names (a DNS name, or an IP literal such as `127.0.0.1`).

`scripts/configure_iya_sts.py`, the install script, writes that file on every run (`scripts/trust_chain.py`, `save_trust_chain()`). It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page. A password iya-sts generates for the test user is never printed: it goes to `demo/generated/<user>.password`, mode 0600.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image, and rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`: the relying party's key, certificate and the IdP metadata stay out of the image (compose still mounts `demo/generated` read-only for them). A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo ./demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, both BuildKit and the classic builder fail. A directory COPY of `demo/` (which always exists) succeeds in both. `python scripts/trust_chain.py --config demo/wsfed.json --idp <iya-sts URL>` refreshes the file by hand.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. `GET /live-status` is JSON: `signedIn`, `subject`, the receiver state, and accepted Shared Signals events (`type` and `jti` only). Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.
