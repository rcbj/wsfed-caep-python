<!--
SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
SPDX-License-Identifier: MIT
-->

# wsfed-caep

Server-side WS-Federation relying party for Python. It accepts SAML 2.0 bearer assertions, reads identity-provider federation metadata, writes relying-party metadata, verifies XML signatures, decrypts encrypted assertions, and remembers assertion ids so a bearer token cannot be replayed. A Shared Signals poll receiver for CAEP and RISC is included. The relying party does not start that receiver.

License: MIT. A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published. `develop` and `main` are the same commit when this tree is published; nothing here creates a remote.

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

**Plain http (#13).** Federation metadata from a URL and every Shared Signals transmitter call (configuration, JWKS, stream and poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys and Shared Signals carry SETs and the bearer token. A URL with userinfo is never loopback, and a URL with whitespace or a control character is refused. The `WsFedError` keeps the fetch's code (`metadata`, `ssf`) and names the scheme and host only. There is no opt-out. The relying party's own realm and reply URL may stay http; they are never fetched.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The suite includes a stub identity provider. Those tests do not start iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It uses iya-sts (the latest main branch, in memory mode with persistence and clustering off, when `IYA_STS_URL` is unset; `IYA_STS_IMAGE` starts a fresh container from an image), copies this checkout to a scratch build context, builds the demo image, runs the install script inside it (which registers the demo, generates the key pair and writes the `idpCa` chain), then builds the demo image again so it carries the chain, checks the image holds the chain and no key, starts the demo with no CA mount, signs in through `GET /login`, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It uses the host's Python and Docker and does not import this library. It uses two high ports (defaults 18556 and 18656, `LIVE_STS_PORT` and `LIVE_DEMO_PORT`) and never binds 3000, 8081 or 18481-18495. No secret appears on a docker command line, and sign-in requests are logged by fixed labels, not URLs. The nightly workflow (06:35 UTC) runs the unit suite and this script once every 24 hours.

## Layout

- `src/wsfed_caep/` library
- `tests/` pytest, fixtures, stub identity provider
- `demo/app.py` stdlib HTTP demo
- `scripts/configure_iya_sts.py` registers the demo with iya-sts and writes the listener CA trust chain to the file `idpCa` names
- `scripts/trust_chain.py` holds `save_trust_chain()` and refreshes that file
- `scripts/live_iya_sts.py` live sign-in against iya-sts
- `.github/workflows/nightly.yml` unit suite and live script, once every 24 hours
- `Dockerfile`, `docker-compose.yml` (`network_mode: host`, `PORT=3000`)

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/wsfed.json` names the iya-sts TLS listener CA trust chain the library trusts for the IdP metadata URL and the Shared Signals transmitter. The default is `file:generated/idp-ca.pem`, relative to `demo/`. The value may also be a plain path, `env:<NAME>`, or the PEM itself. The library loads every certificate in it as a trust anchor (`ssl` `load_verify_locations(cadata=...)`), so the whole chain works and OpenSSL ends the path at the self-signed Root. The presented leaf must still verify to one of those anchors (a forged leaf followed by the real CA certificates is refused), and the host name is checked against the leaf's subject alternative names (a DNS name, or an IP literal such as `127.0.0.1`).

`scripts/configure_iya_sts.py`, the install script, writes that file on every run (`scripts/trust_chain.py`, `save_trust_chain()`). It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page. A password iya-sts generates for the test user is never printed: it goes to `demo/generated/<user>.password`, mode 0600.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image, and rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`: the relying party's key, certificate and the IdP metadata stay out of the image (compose still mounts `demo/generated` read-only for them). A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo ./demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, both BuildKit and the classic builder fail. A directory COPY of `demo/` (which always exists) succeeds in both. `python scripts/trust_chain.py --config demo/wsfed.json --idp <iya-sts URL>` refreshes the file by hand.

## Demo

`PORT` defaults to 3000. A loopback realm and reply URL follow that port. Any other host stays as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `GET /healthz` returns `200` and the body `ok` even when generated keys are absent. `GET /login` redirects to the identity provider with `wa=wsignin1.0`, `wtrealm`, `wreply`, and `wctx`. The reply URL accepts the sign-in POST and `wsignoutcleanup1.0`. `POST /logout` signs out, including at the identity provider. `GET /live-status` is JSON: `signedIn`, `subject`, the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). No token is in that body.

Demo JSON uses `file:` paths under `demo/generated/`. Those keys are not in the tree. `"signals"` is omitted, so the receiver is on when a transmitter is configured.

```sh
PORT=40123 docker compose up --build
```
