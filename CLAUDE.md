<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Python port of the server-side WS-Federation relying party. Import `wsfed_caep`. Distribution name `wsfed-caep`. Version 0.1.0. License MIT (`LICENSE`). Publishing to PyPI is not set up. When this tree is published, `develop` and `main` are the same commit.

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

`python3 scripts/live_iya_sts.py` signs the demo in to iya-sts and checks credential-change and session-revoked on `GET /live-status`. The nightly workflow runs the unit suite and that script once every 24 hours. Neither binds port 3000 or 8081.

## Layout

`src/wsfed_caep/` library (`ssf/` is the poll receiver). `tests/` pytest. `demo/app.py` stdlib server. `scripts/configure_iya_sts.py` registers the demo with iya-sts; the container `PORT` wins over the shell `PORT`. `scripts/live_iya_sts.py` is the live sign-in. `.github/workflows/nightly.yml` runs the unit suite and that script once every 24 hours. `Dockerfile` and comment-free `docker-compose.yml` use `network_mode: host`, `ENV PORT=3000`, and a health check of `http://127.0.0.1:${PORT}/healthz`. The live script never binds 3000 or 8081.

## Demo

`PORT` defaults to 3000. Loopback realm and reply URLs follow the running port. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `200` and `ok`. The page links to `/login`, which redirects with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL handles the POST and sign-out cleanup. `POST /logout` signs out. `GET /live-status` is JSON: `signedIn`, `subject`, the receiver state, and accepted Shared Signals events (`type` and `jti` only). Demo JSON uses `file:` placeholders. Do not commit `demo/generated`.
