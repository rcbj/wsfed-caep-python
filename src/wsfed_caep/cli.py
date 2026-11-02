# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""wsfed-caep command line: generate-keys and metadata."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from wsfed_caep.config import resolve_config
from wsfed_caep.relying_party import RelyingParty
from wsfed_caep.x509util import create_self_signed_key_pair

USAGE = """Usage:
  wsfed-caep generate-keys --config <wsfed.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  wsfed-caep generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The key decrypts encrypted assertions and can authenticate the Shared Signals receiver (mutual
      TLS); WS-Federation itself signs nothing. The common name defaults to one naming the realm.

  wsfed-caep metadata --config <wsfed.json> [--out <file>]
      This relying party's federation metadata, from the configuration (and its certificate, when it
      has one): give it to the identity provider. Written to --out, or to standard output."""


def parse_args(argv: list[str]) -> tuple[str | None, dict]:
    if not argv:
        return None, {}
    command, rest = argv[0], argv[1:]
    args: dict = {}
    i = 0
    while i < len(rest):
        item = rest[i]
        if not item.startswith("--"):
            raise SystemExit(f"unexpected argument {item}\n\n{USAGE}")
        key = item[2:]
        if key in ("force", "help"):
            args[key] = True
        else:
            if i + 1 >= len(rest) or rest[i + 1].startswith("--"):
                raise SystemExit(f"--{key} needs a value\n\n{USAGE}")
            args[key] = rest[i + 1]
            i += 1
        i += 1
    return command, args


def _strip_file(value: str) -> str:
    return value[5:] if value.startswith("file:") else value


def key_paths(args: dict) -> tuple[str, str, str]:
    config_path = args.get("config") if isinstance(args.get("config"), str) else None
    key = args.get("key") if isinstance(args.get("key"), str) else None
    cert = args.get("cert") if isinstance(args.get("cert"), str) else None
    common_name = args.get("cn") if isinstance(args.get("cn"), str) else None
    if config_path:
        raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
        base = Path(config_path).resolve().parent

        def at(value, what):
            if not value or "-----BEGIN " in value:
                raise SystemExit(f"{config_path}'s {what} must be a file path for generate-keys to write to")
            value = _strip_file(value)
            path = Path(value)
            return path if path.is_absolute() else base / path

        if key is None and raw.get("privateKey"):
            key = str(at(raw.get("privateKey"), "privateKey"))
        if cert is None and raw.get("certificate"):
            cert = str(at(raw.get("certificate"), "certificate"))
        if not common_name and raw.get("realm"):
            common_name = f"wsfed-caep-nodejs relying party {raw['realm']}"[:64]
    if not key or not cert:
        raise SystemExit(f"generate-keys needs --config, or --key and --cert\n\n{USAGE}")
    return str(Path(key).resolve()), str(Path(cert).resolve()), common_name or "wsfed-caep-nodejs relying party"


def main(argv: list[str] | None = None, out=None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    if out is None:
        out = sys.stdout.write
    command, args = parse_args(list(argv))
    if not command or args.get("help") or command == "help":
        out(USAGE + "\n")
        return
    if command == "generate-keys":
        key, cert, common_name = key_paths(args)
        if not args.get("force") and (os.path.exists(key) or os.path.exists(cert)):
            which = key if os.path.exists(key) else cert
            raise SystemExit(
                f"{which} already exists; pass --force to replace the key pair.\n"
                "Replacing it means giving the identity provider the new metadata before it next encrypts to this relying party."
            )
        days = int(args["days"]) if isinstance(args.get("days"), str) else None
        bits = int(args["bits"]) if isinstance(args.get("bits"), str) else None
        if days is not None and days <= 0:
            raise SystemExit("--days must be a positive whole number")
        if bits is not None and bits not in (2048, 3072, 4096):
            raise SystemExit("--bits must be 2048, 3072 or 4096")
        pair = create_self_signed_key_pair(common_name, days=days or 1095, bits=bits or 3072)
        Path(key).parent.mkdir(parents=True, exist_ok=True)
        Path(cert).parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, pair.private_key_pem.encode())
        finally:
            os.close(fd)
        Path(cert).write_text(pair.certificate_pem, encoding="utf-8")
        os.chmod(cert, 0o644)
        out(f"Wrote the private key  {key} (mode 600)\n")
        out(f"Wrote the certificate  {cert}\n")
        out(f"  subject   {pair.certificate.subject.rfc4514_string()}\n")
        return
    if command == "metadata":
        config_path = args.get("config") if isinstance(args.get("config"), str) else None
        if not config_path:
            raise SystemExit(f"metadata needs --config\n\n{USAGE}")
        raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
        raw.pop("idpCa", None)
        xml = RelyingParty(resolve_config(raw, str(Path(config_path).resolve().parent)), None).metadata()
        target = args.get("out") if isinstance(args.get("out"), str) else None
        if target:
            path = Path(target).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(xml, encoding="utf-8")
            out(f"Wrote the relying party metadata to {path}\n")
        else:
            out(xml)
        return
    raise SystemExit(f"unknown command {command}\n\n{USAGE}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as err:
        if err.code not in (None, 0):
            sys.stderr.write(f"{err.code if isinstance(err.code, str) else err}\n" if False else (f"{err.code}\n" if isinstance(err.code, str) else ""))
            if isinstance(err.code, str):
                sys.exit(1)
        raise
    except Exception as err:
        sys.stderr.write(f"{err}\n")
        sys.exit(1)
