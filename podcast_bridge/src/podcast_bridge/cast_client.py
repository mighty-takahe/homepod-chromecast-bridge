"""Built-in Google CastV2 TLS Test Sender & Protocol Verifier.

Connects to a VirtualChromecastAudio port over TLS, performs the full CastV2
DeviceAuthMessage cryptographic handshake, launches a Cast receiver app, and
loads a media stream.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import time
from typing import Any, Dict, Optional

from .cast_auth import CastAuthManager
from .cast_proto import (
    APP_DEFAULT_MEDIA_RECEIVER,
    AuthChallenge,
    DeviceAuthMessage,
    HashAlgorithm,
    NS_CONNECTION,
    NS_DEVICEAUTH,
    NS_DISCOVERY,
    NS_HEARTBEAT,
    NS_MEDIA,
    NS_RECEIVER,
    SignatureAlgorithm,
    make_binary_message,
    make_json_message,
    read_cast_message,
    write_cast_message,
)


async def send_test_cast_session(
    host: str,
    cast_port: int,
    content_url: str,
    title: str = "PodCast Bridge Acoustic Check",
    artist: str = "HomePod Mini CastV2 Bridge",
    album: str = "Chromecast Audio Calibration",
    app_id: str = APP_DEFAULT_MEDIA_RECEIVER,
    volume: Optional[float] = None,
) -> Dict[str, Any]:
    """Execute a complete Google CastV2 TLS session against a receiver and return diagnostics."""
    t0 = time.monotonic()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, cast_port, ssl=ssl_ctx),
        timeout=5.0,
    )

    steps = []
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        peer_cert_der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else b""
        steps.append(f"TLS handshake complete ({len(peer_cert_der)} byte peer cert)")

        # 1. Virtual CONNECT to receiver-0
        await write_cast_message(
            writer,
            make_json_message("sender-test", "receiver-0", NS_CONNECTION, {"type": "CONNECT", "origin": {}}),
        )

        # 2. DeviceAuthMessage challenge with 16-byte cryptographic nonce
        nonce = os.urandom(16)
        challenge_msg = DeviceAuthMessage(
            challenge=AuthChallenge(
                signature_algorithm=SignatureAlgorithm.RSASSA_PKCS1v15,
                sender_nonce=nonce,
                hash_algorithm=HashAlgorithm.SHA256,
            )
        )
        await write_cast_message(
            writer,
            make_binary_message("sender-test", "receiver-0", NS_DEVICEAUTH, challenge_msg.SerializeToString()),
        )

        auth_reply = await asyncio.wait_for(read_cast_message(reader), timeout=5.0)
        if not auth_reply or auth_reply.namespace != NS_DEVICEAUTH or not auth_reply.payload_binary:
            raise RuntimeError("Did not receive valid DeviceAuthMessage reply")

        auth_ok, auth_detail = CastAuthManager.verify_auth_response(
            auth_reply.payload_binary,
            peer_cert_der=peer_cert_der,
            expected_nonce=nonce,
        )
        steps.append(f"DeviceAuthMessage: {auth_detail}")

        # 3. Heartbeat PING -> PONG check
        await write_cast_message(
            writer,
            make_json_message("sender-test", "receiver-0", NS_HEARTBEAT, {"type": "PING"}),
        )
        pong = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
        if pong and pong.namespace == NS_HEARTBEAT:
            steps.append("Heartbeat PING -> PONG verified")

        # 3b. Receiver Discovery GET_DEVICE_INFO & Setup eureka_info checks (Android Play Services / Chrome)
        await write_cast_message(
            writer,
            make_json_message("sender-test", "receiver-0", NS_DISCOVERY, {"requestId": 9, "type": "GET_DEVICE_INFO"}),
        )
        disc_reply = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
        if disc_reply and disc_reply.namespace == NS_DISCOVERY:
            disc_payload = disc_reply.json_payload()
            caps = disc_payload.get("deviceCapabilities")
            steps.append(f"Discovery DEVICE_INFO verified (ca={caps}, id={disc_payload.get('deviceId')})")

        # 4. Optional volume set
        if volume is not None:
            await write_cast_message(
                writer,
                make_json_message(
                    "sender-test",
                    "receiver-0",
                    NS_RECEIVER,
                    {"requestId": 10, "type": "SET_VOLUME", "volume": {"level": float(volume)}},
                ),
            )
            await asyncio.wait_for(read_cast_message(reader), timeout=4.0)

        # 5. LAUNCH receiver app
        await write_cast_message(
            writer,
            make_json_message(
                "sender-test",
                "receiver-0",
                NS_RECEIVER,
                {"requestId": 1, "type": "LAUNCH", "appId": app_id},
            ),
        )

        transport_id = "web-0"
        for _ in range(4):
            msg = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            if not msg:
                break
            payload = msg.json_payload()
            if payload.get("type") == "RECEIVER_STATUS":
                apps = payload.get("status", {}).get("applications", [])
                if apps:
                    transport_id = apps[0].get("transportId", "web-0")
                    steps.append(f"Launched app {apps[0].get('displayName')} ({app_id}) -> {transport_id}")
                    break

        # 6. Connect to the launched app's transportId and send LOAD
        await write_cast_message(
            writer,
            make_json_message("sender-test", transport_id, NS_CONNECTION, {"type": "CONNECT", "origin": {}}),
        )
        load_payload = {
            "requestId": 2,
            "type": "LOAD",
            "autoplay": True,
            "currentTime": 0.0,
            "media": {
                "contentId": content_url,
                "contentType": "audio/wav" if content_url.endswith(".wav") else "audio/mpeg",
                "streamType": "BUFFERED",
                "duration": 2.4 if content_url.endswith("test-chime.wav") else 180.0,
                "metadata": {
                    "metadataType": 3,
                    "title": title,
                    "artist": artist,
                    "albumName": album,
                },
            },
        }
        await write_cast_message(
            writer,
            make_json_message("sender-test", transport_id, NS_MEDIA, load_payload),
        )

        media_state = "UNKNOWN"
        for _ in range(6):
            msg = await asyncio.wait_for(read_cast_message(reader), timeout=4.0)
            if not msg:
                break
            payload = msg.json_payload()
            if payload.get("type") == "MEDIA_STATUS":
                st_list = payload.get("status", [])
                if st_list and int(payload.get("requestId", 0)) == 2:
                    media_state = st_list[0].get("playerState", "PLAYING")
                    steps.append(f"MEDIA_STATUS confirmed: {media_state} ('{title}')")
                    break
                elif st_list:
                    media_state = st_list[0].get("playerState", "PLAYING")

        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "ok": True,
            "auth_verified": auth_ok,
            "auth_detail": auth_detail,
            "transport_id": transport_id,
            "player_state": media_state,
            "elapsed_ms": elapsed_ms,
            "steps": steps,
        }
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
