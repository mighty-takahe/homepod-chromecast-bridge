"""Comprehensive unit and end-to-end integration tests for PodCast Bridge."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from podcast_bridge.app import create_app
from podcast_bridge.audio_relay import AudioRelayManager, generate_test_chime_wav
from podcast_bridge.cast_auth import CastAuthManager
from podcast_bridge.cast_client import send_test_cast_session
from podcast_bridge.cast_proto import (
    APP_DEFAULT_MEDIA_RECEIVER,
    AuthChallenge,
    CastMessage,
    DeviceAuthMessage,
    HashAlgorithm,
    NS_DEVICEAUTH,
    NS_MEDIA,
    NS_RECEIVER,
    PayloadType,
    SignatureAlgorithm,
    make_binary_message,
    make_json_message,
    pack_cast_message,
)
from podcast_bridge.models import CastAuthMode, PlayerState, TransportMode


def test_cast_proto_roundtrip():
    """Verify binary wire format encoding/decoding of CastMessage and DeviceAuthMessage."""
    challenge = AuthChallenge(
        signature_algorithm=SignatureAlgorithm.RSASSA_PKCS1v15,
        sender_nonce=b"0123456789abcdef",
        hash_algorithm=HashAlgorithm.SHA256,
    )
    auth_msg = DeviceAuthMessage(challenge=challenge)
    raw_auth = auth_msg.SerializeToString()

    cast_msg = make_binary_message("sender-0", "receiver-0", NS_DEVICEAUTH, raw_auth)
    framed = pack_cast_message(cast_msg)
    assert len(framed) == 4 + len(cast_msg.SerializeToString())

    decoded_cast = CastMessage.FromString(framed[4:])
    assert decoded_cast.source_id == "sender-0"
    assert decoded_cast.destination_id == "receiver-0"
    assert decoded_cast.namespace == NS_DEVICEAUTH
    assert decoded_cast.payload_type == PayloadType.BINARY

    decoded_auth = DeviceAuthMessage.FromString(decoded_cast.payload_binary)
    assert decoded_auth.challenge is not None
    assert decoded_auth.challenge.sender_nonce == b"0123456789abcdef"
    assert decoded_auth.challenge.hash_algorithm == HashAlgorithm.SHA256


def test_cast_auth_dynamic_and_precomputed_bundle(tmp_path: Path):
    """Verify 773-window Eureka Gen1 ICA bundle, dynamic CastV2 signing, and sample bundle generation."""
    auth_mgr = CastAuthManager(tmp_path)
    assert auth_mgr.config.mode == CastAuthMode.PRECOMPUTED_BUNDLE
    assert auth_mgr.config.bundle_windows_count == 773

    nonce = b"random_nonce_123"
    ch = DeviceAuthMessage(
        challenge=AuthChallenge(
            signature_algorithm=SignatureAlgorithm.RSASSA_PKCS1v15,
            sender_nonce=nonce,
            hash_algorithm=HashAlgorithm.SHA256,
        )
    )

    # 1. Verify default 773-window Eureka Gen1 ICA hardware-signed bundle
    resp_eureka_bytes = auth_mgr.handle_auth_challenge(ch.SerializeToString())
    parsed_eureka = DeviceAuthMessage.FromString(resp_eureka_bytes)
    assert parsed_eureka.response is not None
    # Precomputed AuthResponse MUST omit sender_nonce (field 5) for stock Android/Chrome
    assert parsed_eureka.response.sender_nonce is None
    ok_eureka, detail_eureka = CastAuthManager.verify_auth_response(
        resp_eureka_bytes,
        peer_cert_der=auth_mgr.get_active_peer_cert_der(),
        expected_nonce=nonce,
    )
    assert ok_eureka is True
    assert "RYW0O FA8FCA6AC5A0" in detail_eureka

    # 2. Switch to dynamic SELF_SIGNED mode
    auth_mgr.config.mode = CastAuthMode.SELF_SIGNED
    resp_bytes = auth_mgr.handle_auth_challenge(ch.SerializeToString())
    ok, detail = CastAuthManager.verify_auth_response(
        resp_bytes,
        peer_cert_der=auth_mgr.get_active_peer_cert_der(),
        expected_nonce=nonce,
    )
    assert ok is True
    assert "dynamic_nonce_bound" in detail

    # 3. Switch to local sample precomputed window bundle
    bundle_info = auth_mgr.generate_sample_precomputed_bundle()
    assert bundle_info["mode"] == CastAuthMode.PRECOMPUTED_BUNDLE
    assert bundle_info["windows_count"] == 1

    resp_bundle_bytes = auth_mgr.handle_auth_challenge(ch.SerializeToString())
    ok2, detail2 = CastAuthManager.verify_auth_response(
        resp_bundle_bytes,
        peer_cert_der=auth_mgr.get_active_peer_cert_der(),
        expected_nonce=nonce,
    )
    assert ok2 is True
    assert "precomputed_peer_cert" in detail2


def test_audio_relay_chime_generator():
    """Verify synthesized 44.1kHz stereo WAV calibration chime is valid RIFF WAVE."""
    wav_data = generate_test_chime_wav(duration_sec=0.5)
    assert wav_data[:4] == b"RIFF"
    assert wav_data[8:12] == b"WAVE"
    assert len(wav_data) > 44100


@pytest.mark.asyncio
async def test_e2e_virtual_chromecast_and_api(tmp_path: Path):
    """Spin up the bridge, query Eureka/DIAL HTTP, run a full TLS CastV2 session, and test controls."""
    app = create_app(data_dir=tmp_path, web_port=18788, mdns_enabled=False)
    manager = app.state.bridge
    manager.settings.base_cast_port = 19009
    manager.settings.base_eureka_port = 19108

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", trust_env=False) as client:
            # 1. Check initial status (2 seeded HomePod Minis + 773-window Eureka Gen1 ICA bundle)
            st_resp = await client.get("/api/status")
            assert st_resp.status_code == 200
            st_data = st_resp.json()
            assert st_data["active_receivers"] >= 2
            assert st_data["auth"]["bundle_windows_count"] == 773
            first_dev = st_data["devices"][0]
            dev_id = first_dev["id"]
            cast_port = first_dev["cast_port"]
            eureka_port = first_dev["eureka_port"]

            # 2. Query the virtual Chromecast's Eureka HTTP server directly over TCP
            async with httpx.AsyncClient(trust_env=False) as lan_client:
                eureka_resp = await lan_client.get(f"http://127.0.0.1:{eureka_port}/setup/eureka_info")
                assert eureka_resp.status_code == 200
                eureka_json = eureka_resp.json()
                assert eureka_json["device_info"]["model_name"] == "Chromecast Audio"
                assert eureka_json["device_info"]["capabilities"]["display_supported"] is False
                assert eureka_json["setup_state"] == 60
                assert eureka_json["tos_accepted"] is True
                assert len(eureka_json["public_key"]) > 40

                # Verify ?params= filtering used by Android Play Services / Chrome
                filtered_resp = await lan_client.get(
                    f"http://127.0.0.1:{eureka_port}/setup/eureka_info?params=version,name,device_info"
                )
                assert filtered_resp.status_code == 200
                filtered_json = filtered_resp.json()
                assert set(filtered_json.keys()) == {"version", "name", "device_info"}

                # Verify mDNS TXT 'cd' matches active TLS peer certificate MD5 digest
                receiver_obj = manager.receivers[dev_id]
                txt_dict = receiver_obj._build_txt_dict()
                assert txt_dict["cd"] == manager.auth_manager.get_active_peer_cert_md5_hex()
                assert len(txt_dict["id"]) == 32 and "-" not in txt_dict["id"]
                assert len(txt_dict["bs"]) == 12

                dial_resp = await lan_client.get(f"http://127.0.0.1:{eureka_port}/ssdp/device-desc.xml")
                assert dial_resp.status_code == 200
                assert "Chromecast Audio" in dial_resp.text
                assert "Application-URL" in dial_resp.headers

            # 3. Trigger a real TLS CastV2 session (CONNECT -> DeviceAuthMessage -> DISCOVERY -> LAUNCH -> LOAD)
            cast_resp = await client.post(
                f"/api/devices/{dev_id}/test-cast",
                json={"title": "E2E HomePod Cast Test"},
            )
            assert cast_resp.status_code == 200
            cast_result = cast_resp.json()
            assert cast_result["ok"] is True
            assert cast_result["auth_verified"] is True
            assert cast_result["player_state"] == "PLAYING"
            assert any("ca=199428" in s for s in cast_result["steps"])

            # Verify the bridged HomePod device state updated to PLAYING
            st_after = (await client.get("/api/status")).json()
            dev_after = next(d for d in st_after["devices"] if d["id"] == dev_id)
            assert dev_after["player_state"] == "PLAYING"
            assert dev_after["media"]["title"] == "E2E HomePod Cast Test"

            # 4. Test volume & pause/play/stop controls
            vol_resp = await client.post(
                f"/api/devices/{dev_id}/control",
                json={"action": "volume", "value": 0.75},
            )
            assert vol_resp.status_code == 200
            assert vol_resp.json()["volume"] == 0.75

            pause_resp = await client.post(
                f"/api/devices/{dev_id}/control",
                json={"action": "pause"},
            )
            assert pause_resp.status_code == 200
            assert pause_resp.json()["player_state"] == "PAUSED"

            # 5. Test audio relay stream endpoint
            relay_resp = await client.get(f"/api/relay/{dev_id}/stream.wav")
            assert relay_resp.status_code == 200
            assert relay_resp.headers["content-type"] == "audio/wav"
            assert relay_resp.content[:4] == b"RIFF"

            # 6. Add a new HomePod Mini via REST API
            add_resp = await client.post(
                "/api/devices",
                json={
                    "name": "Bedroom HomePod Mini",
                    "cast_name": "Bedroom HomePod Mini (Cast)",
                    "ip_address": "192.168.1.199",
                    "airplay_port": 7000,
                    "transport_mode": "simulated",
                },
            )
            assert add_resp.status_code == 200
            new_dev = add_resp.json()
            assert new_dev["name"] == "Bedroom HomePod Mini"

            # Verify the new HomePod Mini's CastV2 TLS receiver immediately accepts connections
            direct_cast = await send_test_cast_session(
                host="127.0.0.1",
                cast_port=new_dev["cast_port"],
                content_url="builtin://test-chime.wav",
                title="Direct Socket Cast Check",
            )
            assert direct_cast["ok"] is True
            assert direct_cast["auth_verified"] is True
