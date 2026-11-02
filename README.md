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
wsfed-caep generate-keys --config demo/wsfed.json
wsfed-caep metadata --config demo/wsfed.json
```

The generated certificate's common name defaults to `wsfed-caep-nodejs relying party` plus the realm, cut at 64 characters.

## Tests

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The suite includes a stub identity provider. It does not need a live iya-sts.

## Layout

- `src/wsfed_caep/` library
- `tests/` pytest, fixtures, stub identity provider
- `demo/app.py` stdlib HTTP demo
- `scripts/configure_iya_sts.py` registration plan for iya-sts
- `Dockerfile`, `docker-compose.yml` (`network_mode: host`, `PORT=3000`)

## Demo

`PORT` defaults to 3000. A loopback realm and reply URL follow that port. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `GET /healthz` returns `200` and the body `ok` even when generated keys are absent. `GET /login` redirects to the identity provider with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL accepts the sign-in POST and `wsignoutcleanup1.0`. `POST /logout` signs out, including at the identity provider.

Demo JSON uses `file:` paths under `demo/generated/`. Those keys are not in the tree. `"signals"` is omitted, so the receiver is on when a transmitter is configured.

```sh
PORT=40123 python demo/app.py
```
