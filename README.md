<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Python. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

Version 0.1.0. License: MIT. Publishing to PyPI is not set up. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

## Usage

```python
from wsfed_caep import RelyingParty

rp = RelyingParty.from_file("wsfed.json")
request = rp.login(relay_state="/")
who = rp.handle_reply({"method": "POST", "url": "/wsfed", "body": body}, request.id)
```

JSON keys match the Node configuration: `realm`, `replyUrl`, `idpMetadata`, `privateKey`, `certificate`, `idpCa`, `idpEntityId`, `clockSkewSeconds`, `wantAssertionsEncrypted`, `allowUnsolicited`, `requestTokenType`, `signals`, `ssf`. `file:` and `env:` prefixes are accepted. The default subject attribute is `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`.

`signals` omitted or `true` is on. The resolved configuration omits the key in that case. `false` is kept, does not start a receiver, and does not require transmitter metadata. Sign-in is unchanged either way: WS-Federation does not send OAuth scopes. Any other value raises a config error whose message is `signals must be true or false`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-python-demo \
  wsfed-caep generate-keys --config demo/wsfed.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  wsfed-caep-python-demo \
  wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The suite includes a stub identity provider. Those tests do not start iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It builds this demo image, uses iya-sts (the latest main branch, in memory mode, when `IYA_STS_URL` is unset), registers the demo, signs in through `GET /login`, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It uses the host's Python and Docker and does not import this library. It binds high ports and never binds 3000 or 8081. The nightly workflow runs the unit suite and this script once every 24 hours.

## Layout

- `src/wsfed_caep/` library
- `tests/` pytest, fixtures, stub identity provider
- `demo/app.py` stdlib HTTP demo
- `scripts/configure_iya_sts.py` registration plan for iya-sts
- `scripts/live_iya_sts.py` live sign-in against iya-sts
- `.github/workflows/nightly.yml` unit suite and live script, once every 24 hours
- `Dockerfile`, `docker-compose.yml` (`network_mode: host`, `PORT=3000`)

## Demo

`PORT` defaults to 3000. A loopback realm and reply URL follow that port. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `GET /healthz` returns `200` and the body `ok` even when generated keys are absent. `GET /login` redirects to the identity provider with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL accepts the sign-in POST and `wsignoutcleanup1.0`. `POST /logout` signs out, including at the identity provider. `GET /live-status` is JSON: `signedIn`, `subject`, the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). No token is in that body.

Demo JSON uses `file:` paths under `demo/generated/`. Those keys are not in the tree. `"signals"` is omitted, so the receiver is on when a transmitter is configured.

```sh
PORT=40123 docker compose up --build
```
