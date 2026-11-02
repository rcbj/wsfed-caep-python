# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The setup script's plan, offline."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from configure_iya_sts import (  # noqa: E402
    MULTIPLE_ACCOUNTS,
    demo_port,
    endpoints_for,
    files_of,
    idp_metadata_url,
    metadata_for,
    on_port,
    parse_args,
    plan_for,
    realm_of,
    ssf_calls,
)


def test_files_plan_signals_and_ports(tmp_path: Path):
    config = tmp_path / "wsfed.json"
    config.write_text(json.dumps({
        "realm": "http://localhost:3000/",
        "replyUrl": "http://localhost:3000/wsfed",
        "privateKey": "generated/rp.key",
        "certificate": "generated/rp.crt",
        "idpMetadata": "generated/idp-metadata.xml",
        "idpCa": "generated/idp-ca.pem",
    }), encoding="utf-8")
    files = files_of(str(config))
    assert files["key"] == str((tmp_path / "generated" / "rp.key").resolve())
    assert files["rp_metadata"] == str((tmp_path / "generated" / "rp-metadata.xml").resolve())
    assert files["idp_ca"] == str((tmp_path / "generated" / "idp-ca.pem").resolve())
    assert files["reply_url"] == "http://localhost:3000/wsfed"
    plan = plan_for(files, "https://localhost:8081", "wsfed-demo-user")
    assert plan[0]["path"].endswith("/admin-api/applications/create")
    assert plan[0]["body"] == {
        "identifier": "http://localhost:3000/",
        "name": "wsfed-caep-nodejs demo",
        "protocols": ["wsfed"],
        "fields": {"wsfedRealm": ["http://localhost:3000/"], "wsfedReplyUrl": ["http://localhost:3000/wsfed"]},
    }
    assert plan[1]["body"] == {"application": "http://localhost:3000/", "attribute": "wsfedReplyUrl", "value": "http://localhost:3000/wsfed"}
    assert any(call["path"] == "https://localhost:8081/wsfed/metadata/http%3A%2F%2Flocalhost%3A3000%2F" for call in plan)
    assert next(call["body"] for call in plan if call["path"].endswith("/admin-api/config/set")) == MULTIPLE_ACCOUNTS
    assert plan[-1]["path"].endswith("/users/create")
    assert not any(call["path"].endswith("/users/create") for call in plan_for(files, "https://localhost:8081", ""))

    with_ssf = tmp_path / "wsfed-ssf.json"
    with_ssf.write_text(json.dumps({**json.loads(config.read_text()), "ssf": {"transmitter": "https://localhost:8081"}}), encoding="utf-8")
    ssf_files = files_of(str(with_ssf))
    assert ssf_files["ssf_transmitter"] == "https://localhost:8081"
    calls = ssf_calls(ssf_files, "https://localhost:8081", "PEM")
    assert [call["path"].replace("https://localhost:8081/admin-api", "") for call in calls] == [
        "/applications/add", "/roles/add-member", "/tls/trust/add", "/applications/add-certificate",
    ]
    assert calls[0]["body"] == {"application": "http://localhost:3000/", "attribute": "oauthAllowedScope", "value": "ssf.manage"}
    assert calls[1]["body"] == {"role": "SSF_MANAGE", "kind": "application", "member": "http://localhost:3000/"}
    assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(ssf_files, "https://localhost:8081", ""))
    assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files_of(str(config)), "https://localhost:8081", ""))

    off = tmp_path / "wsfed-signals-off.json"
    off.write_text(json.dumps({**json.loads(config.read_text()), "signals": False, "ssf": {"transmitter": "https://localhost:8081"}}), encoding="utf-8")
    off_files = files_of(str(off))
    assert off_files["signals"] is False
    assert off_files["ssf_transmitter"] == "https://localhost:8081"
    assert off_files["realm"] == "http://localhost:3000/"
    assert off_files["reply_url"] == "http://localhost:3000/wsfed"
    assert not any(call["path"].endswith("/applications/add-certificate") for call in plan_for(off_files, "https://localhost:8081", ""))
    assert not any(call["path"].endswith("/roles/add-member") for call in plan_for(off_files, "https://localhost:8081", ""))
    on = tmp_path / "wsfed-signals-on.json"
    on.write_text(json.dumps({**json.loads(config.read_text()), "signals": True, "ssf": {"transmitter": "https://localhost:8081"}}), encoding="utf-8")
    assert "signals" not in files_of(str(on))
    assert any(call["path"].endswith("/applications/add-certificate") for call in plan_for(files_of(str(on)), "https://localhost:8081", ""))
    bad = tmp_path / "wsfed-signals-bad.json"
    bad.write_text(json.dumps({**json.loads(config.read_text()), "signals": "no"}), encoding="utf-8")
    with pytest.raises(ValueError, match="signals must be true or false"):
        files_of(str(bad))

    assert realm_of("https://idp.test/realm/acme") == {"origin": "https://idp.test", "base": "https://idp.test/realm/acme"}
    with pytest.raises(ValueError, match="realm"):
        realm_of("https://idp.test/wsfed")
    assert idp_metadata_url("https://idp.test/realm/acme", "urn:x") == "https://idp.test/realm/acme/wsfed/metadata/urn%3Ax"

    parsed = parse_args(["--idp", "https://idp.test/", "--public-url", "http://app.test/", "--no-test-user", "--dry-run"], {})
    assert parsed["idp"] == "https://idp.test"
    assert parsed["public_url"] == "http://app.test"
    assert parsed["public_url_given"] is True
    assert parse_args([], {})["public_url_given"] is False
    assert parse_args([], {"PUBLIC_URL": "http://demo.test"})["public_url_given"] is True
    assert parsed["test_user"] == ""
    assert parsed["dry_run"] is True
    with pytest.raises(SystemExit, match="https"):
        parse_args(["--idp", "http://idp.test"], {})
    with pytest.raises(SystemExit, match="public-url"):
        parse_args(["--public-url", ""], {})
    with pytest.raises(SystemExit, match="Unknown argument"):
        parse_args(["--bogus"], {})

    moved = endpoints_for("http://localhost:3000/", "http://localhost:3000/wsfed", {"public_url_given": False, "port": 3001})
    assert moved == {"realm": "http://localhost:3001/", "reply_url": "http://localhost:3001/wsfed"}
    assert on_port("http://127.0.0.1:3000/wsfed", 3001) == "http://127.0.0.1:3001/wsfed"
    assert on_port("http://[::1]:3000/wsfed", 3001) == "http://[::1]:3001/wsfed"
    assert on_port("not a url", 3001) == "not a url"
    published = endpoints_for("https://app.example/", "https://app.example/wsfed", {"public_url_given": False, "port": 3001})
    assert published == {"realm": "https://app.example/", "reply_url": "https://app.example/wsfed"}
    explicit = endpoints_for("http://localhost:3000/", "http://localhost:3000/wsfed", {"public_url": "http://app.test:9", "public_url_given": True, "port": 3001})
    assert explicit == {"realm": "http://app.test:9/", "reply_url": "http://app.test:9/wsfed"}
    assert demo_port("3000", "3001") == 3001
    assert demo_port("3001", "") == 3001
    assert demo_port("3002", "nope") == 3002
    assert demo_port("", None) is None
    assert demo_port("nope", None) is None
    shifted = dict(files)
    endpoints = endpoints_for(shifted["realm"], shifted["reply_url"], {"public_url_given": False, "port": 3001})
    shifted["realm"] = endpoints["realm"]
    shifted["reply_url"] = endpoints["reply_url"]
    shifted_plan = plan_for(shifted, "https://localhost:8081", "")
    assert shifted_plan[0]["body"]["identifier"] == "http://localhost:3001/"
    assert shifted_plan[0]["body"]["fields"]["wsfedRealm"] == ["http://localhost:3001/"]
    assert shifted_plan[0]["body"]["fields"]["wsfedReplyUrl"] == ["http://localhost:3001/wsfed"]
    assert shifted_plan[1]["body"] == {"application": "http://localhost:3001/", "attribute": "wsfedReplyUrl", "value": "http://localhost:3001/wsfed"}
    assert any(call["path"] == "https://localhost:8081/wsfed/metadata/http%3A%2F%2Flocalhost%3A3001%2F" for call in shifted_plan)

    meta = tmp_path / "wsfed-port.json"
    meta.write_text(json.dumps({
        "realm": "http://localhost:3000/",
        "replyUrl": "http://localhost:3000/wsfed",
        "idpMetadata": "https://idp.example/metadata",
    }), encoding="utf-8")
    xml = metadata_for(str(meta), "http://localhost:3001/", "http://localhost:3001/wsfed")
    assert 'entityID="http://localhost:3001/"' in xml
    assert "<wsa:Address>http://localhost:3001/wsfed</wsa:Address>" in xml
    assert "localhost:3000" not in xml
    assert json.loads(meta.read_text())["realm"] == "http://localhost:3000/"
