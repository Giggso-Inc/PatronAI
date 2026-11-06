import json
import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

os.environ.setdefault("API_KEY", "test-key")

from retina import hub_client
from retina.normaliser import compute_hash, normalise
from routers.ravenhub_retina import (
    LinkPayload,
    get_hub_token_link,
    link_hub_token,
)


PATRON_TOKEN = "123e4567-e89b-12d3-a456-426614174000"


class _FakeStore:
    def __init__(self) -> None:
        self.meta = {}

    def set_hub_token_id(
        self,
        patron_token: str,
        hub_token_id: str,
        hub_token_secret: str = "",
    ) -> bool:
        self.meta[patron_token] = {
            "raven_hub_token_id": hub_token_id,
            "raven_hub_token_secret": hub_token_secret,
        }
        return True

    def get_hub_token_id(self, patron_token: str) -> str:
        return self.meta.get(patron_token, {}).get("raven_hub_token_id", "")

    def get_hub_token_secret(self, patron_token: str) -> str:
        return self.meta.get(patron_token, {}).get("raven_hub_token_secret", "")


def test_retina_hash_is_nfc_stable_for_equivalent_unicode():
    nfc = normalise({"d4": ["Café"]})
    nfd = normalise({"d4": ["Cafe\u0301"]})

    assert nfc == nfd
    assert compute_hash(nfc) == compute_hash(nfd)


@pytest.mark.asyncio
async def test_retina_link_status_does_not_return_hub_token_secret():
    store = _FakeStore()

    linked = await link_hub_token(
        patron_token=PATRON_TOKEN,
        body=LinkPayload(
            raven_hub_token_id="hub-token-id",
            raven_hub_token_secret="hub-token-secret",
        ),
        store=store,
    )
    status = await get_hub_token_link(patron_token=PATRON_TOKEN, store=store)

    assert linked["raven_hub_token_secret_set"] is True
    assert status["linked"] is True
    assert status["raven_hub_token_id"] == "hub-token-id"
    assert status["raven_hub_token_secret_set"] is True
    assert "raven_hub_token_secret" not in status


@pytest.mark.asyncio
async def test_retina_link_requires_hub_token_secret():
    with pytest.raises(HTTPException) as exc:
        await link_hub_token(
            patron_token=PATRON_TOKEN,
            body=LinkPayload(
                raven_hub_token_id="hub-token-id",
                raven_hub_token_secret="",
            ),
            store=_FakeStore(),
        )

    assert exc.value.status_code == 400


def test_hub_client_sends_device_secret_header(monkeypatch):
    captured = {}

    class _Resp:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(req, timeout):
        captured["req"] = req
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(hub_client.urllib.request, "urlopen", fake_urlopen)

    ok = hub_client.post_retina_scan(
        hub_token_id="hub-token-id",
        hub_token_secret="hub-token-secret",
        retina_hash="a" * 64,
        dimensions={"d1": ["mcp"]},
        hub_url="https://hub.example",
    )

    headers = {k.lower(): v for k, v in captured["req"].header_items()}
    body = json.loads(captured["req"].data.decode())

    assert ok is True
    assert captured["timeout"] == hub_client._TIMEOUT_SECS
    assert headers["x-raven-device-secret"] == "hub-token-secret"
    assert body["token_id"] == "hub-token-id"


def test_hub_client_refuses_to_post_without_device_secret(monkeypatch):
    def fail_urlopen(*_args, **_kwargs):
        raise AssertionError("urlopen should not be called without a device secret")

    monkeypatch.setattr(hub_client.urllib.request, "urlopen", fail_urlopen)

    assert hub_client.post_retina_scan(
        hub_token_id="hub-token-id",
        hub_token_secret="",
        retina_hash="a" * 64,
        dimensions={},
        hub_url="https://hub.example",
    ) is False
