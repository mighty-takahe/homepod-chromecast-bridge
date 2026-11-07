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
    APP_SPOTIFY,
    AuthChallenge,
    CastMessage,
    DeviceAuthMessage,
    HashAlgorithm,
    NS_CONNECTION,
    NS_DEVICEAUTH,
    NS_MEDIA,
    NS_RECEIVER,
    NS_SPOTIFY,
    PayloadType,
    SignatureAlgorithm,
    make_binary_message,
    make_json_message,
    pack_cast_message,
    read_cast_message,
    write_cast_message,
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


@pytest.mark.asyncio
async def test_spotify_custom_cast_session(tmp_path: Path):
    """Verify Spotify custom app (CC32E753) launch, namespace declaration, and secure channel handshake."""
    import ssl
    import os

    app = create_app(data_dir=tmp_path, web_port=18789, mdns_enabled=False)
    manager = app.state.bridge
    manager.settings.base_cast_port = 19209
    manager.settings.base_eureka_port = 19308

    async with app.router.lifespan_context(app):
        first_dev = list(manager.devices.values())[0]
        cast_port = first_dev.cast_port

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", cast_port, ssl=ssl_ctx),
            timeout=5.0,
        )

        try:
            # 1. Virtual connection
            await write_cast_message(
                writer,
                make_json_message("sender-spotify", "receiver-0", NS_CONNECTION, {"type": "CONNECT", "origin": {}}),
            )

            # 2. Device authentication challenge
            nonce = os.urandom(16)
            ch = DeviceAuthMessage(
                challenge=AuthChallenge(
                    signature_algorithm=SignatureAlgorithm.RSASSA_PKCS1v15,
                    sender_nonce=nonce,
                    hash_algorithm=HashAlgorithm.SHA256,
                )
            )
            await write_cast_message(
                writer,
                make_binary_message("sender-spotify", "receiver-0", NS_DEVICEAUTH, ch.SerializeToString()),
            )
            auth_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert auth_reply is not None and auth_reply.namespace == NS_DEVICEAUTH

            # 3. Check App Availability for Spotify (CC32E753)
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    "receiver-0",
                    NS_RECEIVER,
                    {"requestId": 101, "type": "GET_APP_AVAILABILITY", "appId": [APP_SPOTIFY]},
                ),
            )
            avail_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert avail_reply is not None and avail_reply.namespace == NS_RECEIVER
            assert avail_reply.json_payload()["availability"][APP_SPOTIFY] == "APP_AVAILABLE"

            # 4. LAUNCH Spotify app
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    "receiver-0",
                    NS_RECEIVER,
                    {"requestId": 102, "type": "LAUNCH", "appId": APP_SPOTIFY},
                ),
            )
            launch_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert launch_reply is not None and launch_reply.namespace == NS_RECEIVER
            payload = launch_reply.json_payload()
            apps = payload["status"]["applications"]
            assert len(apps) == 1
            spotify_app = apps[0]
            assert spotify_app["appId"] == APP_SPOTIFY
            assert spotify_app["displayName"] == "Spotify"
            transport_id = spotify_app["transportId"]

            # Verify all declared namespaces are strictly valid urn:x-cast: URIs (preventing Android CastSession crash)
            ns_names = [ns_item["name"] for ns_item in spotify_app["namespaces"]]
            assert NS_SPOTIFY in ns_names
            for name in ns_names:
                assert name.startswith("urn:x-cast:"), f"Namespace '{name}' must start with urn:x-cast:"

            # 5. Connect to transportId (receiver immediately replies with MEDIA_STATUS)
            await write_cast_message(
                writer,
                make_json_message("sender-spotify", transport_id, NS_CONNECTION, {"type": "CONNECT", "origin": {}}),
            )
            media_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert media_reply is not None and media_reply.namespace == NS_MEDIA

            # 6. Test Spotify getInfo query with requested deviceID and requestId
            test_client_dev_id = "spotify-client-uuid-999"
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    transport_id,
                    NS_SPOTIFY,
                    {
                        "requestId": 201,
                        "type": "getInfo",
                        "payload": {
                            "remoteName": "Test Remote",
                            "deviceID": test_client_dev_id,
                            "deviceAPI_isGroup": False,
                        },
                    },
                ),
            )
            info_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert info_reply is not None and info_reply.namespace == NS_SPOTIFY
            info_data = info_reply.json_payload()
            assert info_data["type"] == "getInfoResponse"
            assert info_data["requestId"] == 201
            assert info_data["status"] == "OK"
            assert info_data["payload"]["deviceID"] == test_client_dev_id
            assert info_data["payload"]["clientID"] == "76642c7bcc9c466bb99a44ce206edbbe"
            assert info_data["payload"]["tokenType"] == "accesstoken"
            assert info_data["payload"]["deviceAPI_isGroup"] is False

            # 7. Test Spotify addUser handshake
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    transport_id,
                    NS_SPOTIFY,
                    {
                        "requestId": 202,
                        "type": "addUser",
                        "payload": {"blob": "test_access_token_blob", "tokenType": "accesstoken"},
                    },
                ),
            )
            add_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert add_reply is not None and add_reply.namespace == NS_SPOTIFY
            add_data = add_reply.json_payload()
            assert add_data["type"] == "addUserResponse"
            assert add_data["requestId"] == 202
            assert add_data["status"] == "OK"
            assert add_data["payload"]["status"] == "OK"

            # 8. Test Spotify setCredentials query with requestId
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    transport_id,
                    NS_SPOTIFY,
                    {"requestId": 203, "type": "setCredentials", "credentials": "fake_token", "expiresIn": 3600},
                ),
            )
            cred_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert cred_reply is not None and cred_reply.namespace == NS_SPOTIFY
            assert cred_reply.json_payload()["type"] == "setCredentialsResponse"
            assert cred_reply.json_payload()["status"] == "OK"
            assert cred_reply.json_payload()["requestId"] == 203

            # 9. Test Spotify resetUsers query
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    transport_id,
                    NS_SPOTIFY,
                    {"requestId": 204, "type": "resetUsers"},
                ),
            )
            reset_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            assert reset_reply is not None and reset_reply.namespace == NS_SPOTIFY
            assert reset_reply.json_payload()["type"] == "resetUsersResponse"
            assert reset_reply.json_payload()["status"] == "OK"

            # 10. Test 0ms optimistic LOAD
            t_load = asyncio.get_event_loop().time()
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-spotify",
                    transport_id,
                    NS_MEDIA,
                    {
                        "requestId": 103,
                        "type": "LOAD",
                        "media": {
                            "contentId": "spotify:track:12345",
                            "metadata": {"title": "Spotify Test Track", "artist": "Spotify Artist"},
                        },
                    },
                ),
            )
            load_reply = await asyncio.wait_for(read_cast_message(reader), timeout=2.0)
            load_latency = asyncio.get_event_loop().time() - t_load
            assert load_latency < 0.2  # Must respond in sub-second (optimistic 0ms)
            assert load_reply is not None and load_reply.namespace == NS_MEDIA
            media_data = load_reply.json_payload()
            assert media_data["status"][0]["playerState"] == "PLAYING"
            assert media_data["status"][0]["media"]["metadata"]["title"] == "Spotify Test Track"

        finally:
            writer.close()
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_kitchen_retention_and_ha_dual_discovery(tmp_path: Path):
    """Verify Kitchen HomePod Mini is retained when real Living Room is added, and HA entities auto-register."""
    from unittest.mock import AsyncMock
    from podcast_bridge.bridge_manager import BridgeManager
    from podcast_bridge.models import TransportMode

    mgr = BridgeManager(data_dir=tmp_path, web_port=18790, mdns_enabled=False)
    # Mock HA client to return a Kitchen HomePod entity
    mgr.ha_client.discover_media_players = AsyncMock(return_value=[
        {
            "entity_id": "media_player.kitchen_homepod_mini",
            "friendly_name": "Kitchen HomePod Mini",
            "is_homepod": True,
            "device_class": "speaker",
        }
    ])

    await mgr.start(seed_default_if_empty=True)

    # Verify both Living Room and Kitchen are present
    dev_names = [d.name for d in mgr.devices.values()]
    assert any("kitchen" in n.lower() for n in dev_names)
    assert any("living" in n.lower() for n in dev_names)

    # Now simulate finding a physical Living Room HomePod on LAN
    await mgr.register_device(
        name="Living Room HomePod Mini",
        cast_name="Living Room HomePod Mini (Cast)",
        ip_address="192.168.1.55",
        airplay_port=7000,
        model="AudioAccessory5,1",
        transport_mode=TransportMode.PYATV_STREAM,
        start_immediately=False,
    )

    # Run selective purge
    await mgr._purge_seeded_simulated_if_real_present()

    # Living Room seeded demo (192.168.1.142) was purged because real Living Room exists,
    # but Kitchen HomePod Mini MUST STILL EXIST!
    after_devs = [d.name for d in mgr.devices.values()]
    assert any("kitchen" in n.lower() for n in after_devs), "Kitchen HomePod Mini was mistakenly purged!"
    assert any("living" in n.lower() for n in after_devs)

    # Test scan_all: HA media_player.kitchen_homepod_mini auto-links
    mgr.airplay_manager.scan_network = AsyncMock(return_value=[])
    scan_res = await mgr.scan_all()
    assert len(scan_res["ha_entities"]) == 1
    kitchen_dev = next(d for d in mgr.devices.values() if "kitchen" in d.name.lower())
    assert kitchen_dev.ha_entity_id == "media_player.kitchen_homepod_mini"

    await mgr.stop()


@pytest.mark.asyncio
async def test_unified_multi_device_mdns(tmp_path: Path):
    """Verify multi-device RFC 6762 mDNS response packet encoding and shared advertiser behavior."""
    import zeroconf
    from podcast_bridge.bridge_manager import BridgeManager
    from podcast_bridge.cast_receiver import (
        build_multi_mdns_packet,
        build_receiver_goodbye_packet,
    )

    mgr = BridgeManager(data_dir=tmp_path, web_port=18791, mdns_enabled=False)
    await mgr.start(seed_default_if_empty=True)

    # BridgeManager seeded 2 devices (Living Room on 8009 and Kitchen on 8010)
    assert len(mgr.receivers) >= 2
    receivers_list = list(mgr.receivers.values())

    # 1. Build multi-device mDNS packet
    packet = build_multi_mdns_packet(receivers_list, ip_address="192.168.1.50", ttl=120)
    assert len(packet) > 100

    incoming = zeroconf.DNSIncoming(packet)
    assert incoming.valid is True
    assert incoming.num_answers == len(receivers_list)
    assert incoming.num_additionals >= 2 * len(receivers_list)

    all_recs = incoming.answers()
    # Check PTR records for each device
    ptr_records = [a for a in all_recs if a.type == 12]
    assert len(ptr_records) == len(receivers_list)
    ptr_aliases = [p.alias for p in ptr_records]

    for r in receivers_list:
        expected_label = f"Chromecast-Audio-{r.clean_id}._googlecast._tcp.local."
        assert expected_label in ptr_aliases

    # Check SRV records have distinct ports (8009 and 8010)
    srv_records = [a for a in all_recs if a.type == 33]
    srv_ports = {s.port for s in srv_records}
    assert 8009 in srv_ports
    assert 8010 in srv_ports

    # 2. Verify announcement packet places all records in Answer section per RFC 6762 8.3
    ann_pkt = build_multi_mdns_packet(receivers_list, ip_address="192.168.1.50", ttl=120, query_type="announcement")
    ann_inc = zeroconf.DNSIncoming(ann_pkt)
    assert ann_inc.valid is True
    assert ann_inc.num_answers >= 4 * len(receivers_list)
    assert ann_inc.num_additionals == 0

    # 3. Verify host_a query places host A record in Answer section
    host_pkt = build_multi_mdns_packet(receivers_list, ip_address="192.168.1.50", ttl=120, query_type="host_a")
    host_inc = zeroconf.DNSIncoming(host_pkt)
    assert host_inc.valid is True
    assert host_inc.num_answers >= len(receivers_list)

    # 4. Verify goodbye packet has ttl=0
    goodbye_pkt = build_receiver_goodbye_packet(receivers_list[0], ip_address="192.168.1.50")
    gb_incoming = zeroconf.DNSIncoming(goodbye_pkt)
    assert gb_incoming.valid is True
    assert gb_incoming.num_answers == 1
    assert gb_incoming.answers()[0].ttl == 0

    await mgr.stop()


@pytest.mark.asyncio
async def test_state_auto_healing_missing_kitchen(tmp_path: Path):
    """Verify that if bridge_state.json is missing Kitchen or disabled, start() automatically heals state."""
    import json
    from podcast_bridge.bridge_manager import BridgeManager
    from podcast_bridge.models import TransportMode

    state_file = tmp_path / "bridge_state.json"
    # Write a degraded state file containing ONLY Living Room (simulating v0.4.4 purge bug)
    degraded = {
        "settings": {
            "host_ip": "192.168.1.50",
            "mdns_enabled": False,
        },
        "devices": [
            {
                "id": "homepod_living",
                "name": "Living Room HomePod Mini",
                "cast_name": "Living Room HomePod Mini (Cast)",
                "ip_address": "192.168.1.142",
                "cast_port": 8009,
                "eureka_port": 18008,
                "transport_mode": "pyatv_stream",
                "ha_entity_id": "media_player.living_room_homepod_mini",
                "enabled": True,
            }
        ],
    }
    state_file.write_text(json.dumps(degraded, indent=2))

    mgr = BridgeManager(data_dir=tmp_path, web_port=18792, mdns_enabled=False)
    # Start bridge: should auto-heal and restore Kitchen HomePod Mini
    await mgr.start(seed_default_if_empty=True)

    # Both Living Room and Kitchen must be present, enabled, and have distinct ports
    names = [d.name.lower() for d in mgr.devices.values()]
    assert any("living" in n for n in names)
    assert any("kitchen" in n for n in names)
    assert len(mgr.receivers) >= 2

    kitchen_dev = next(d for d in mgr.devices.values() if "kitchen" in d.name.lower())
    living_dev = next(d for d in mgr.devices.values() if "living" in d.name.lower())

    assert kitchen_dev.enabled is True
    assert living_dev.enabled is True
    assert kitchen_dev.cast_port != living_dev.cast_port
    assert kitchen_dev.eureka_port != living_dev.eureka_port

    # Verify state was saved to disk with both devices
    saved = json.loads(state_file.read_text())
    saved_names = [d["name"].lower() for d in saved["devices"]]
    assert any("kitchen" in n for n in saved_names)

    await mgr.stop()


