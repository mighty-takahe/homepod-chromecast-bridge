"""Virtual Chromecast Audio Receiver Server (CastV2 over TLS + Eureka HTTP/DIAL + mDNS)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import socket
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

from .cast_auth import CastAuthManager
from .cast_proto import (
    APP_BACKDROP,
    APP_DEFAULT_MEDIA_RECEIVER,
    APP_SPOTIFY,
    APP_YOUTUBE,
    APP_YOUTUBE_MUSIC,
    CHROMECAST_AUDIO_CAPABILITIES,
    CastMessage,
    NS_CONNECTION,
    NS_DEVICEAUTH,
    NS_DISCOVERY,
    NS_HEARTBEAT,
    NS_MEDIA,
    NS_MULTIZONE,
    NS_RECEIVER,
    NS_SETUP,
    NS_YOUTUBE_MDX,
    PayloadType,
    make_binary_message,
    make_json_message,
    read_cast_message,
    write_cast_message,
)
from .models import HomePodDevice, MediaMetadata, PlayerState

logger = logging.getLogger(__name__)

# 1x1 transparent PNG icon for /setup/icon.png
ICON_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

KNOWN_APP_NAMES: Dict[str, str] = {
    APP_DEFAULT_MEDIA_RECEIVER: "Default Media Receiver",
    APP_YOUTUBE_MUSIC: "YouTube Music",
    APP_YOUTUBE: "YouTube",
    APP_SPOTIFY: "Spotify",
    APP_BACKDROP: "Backdrop",
    "B3419EF5": "Plex",
    "2872939A": "Pocket Casts",
    "A9BCCB7C": "Audiobookshelf",
}


class VirtualChromecastAudio:
    """Exposes a single HomePod Mini as a full Google Cast Audio device on the network."""

    def __init__(
        self,
        device: HomePodDevice,
        host_ip: str,
        auth_manager: CastAuthManager,
        on_load_media: Callable[[HomePodDevice, str, MediaMetadata, float], Awaitable[None]],
        on_pause: Callable[[HomePodDevice], Awaitable[None]],
        on_resume: Callable[[HomePodDevice], Awaitable[None]],
        on_stop: Callable[[HomePodDevice], Awaitable[None]],
        on_seek: Callable[[HomePodDevice, float], Awaitable[None]],
        on_volume: Callable[[HomePodDevice, float, Optional[bool]], Awaitable[None]],
        on_event: Optional[Callable[[str, str, str, str, str, str], None]] = None,
        on_state_change: Optional[Callable[[HomePodDevice], None]] = None,
        mdns_enabled: bool = True,
    ) -> None:
        self.device = device
        self.host_ip = host_ip
        self.auth_manager = auth_manager
        self._on_load_media = on_load_media
        self._on_pause = on_pause
        self._on_resume = on_resume
        self._on_stop = on_stop
        self._on_seek = on_seek
        self._on_volume = on_volume
        self._on_event = on_event
        self._on_state_change = on_state_change
        self.mdns_enabled = mdns_enabled

        # Active Cast session state
        self.app_id: str = APP_BACKDROP
        self.app_name: str = "Backdrop"
        self.session_id: str = str(uuid.uuid4())
        self.transport_id: str = "web-0"
        self.media_session_id: int = 1
        self.queue_items: List[Dict[str, Any]] = []
        self.queue_index: int = 0

        self._tls_server: Optional[asyncio.AbstractServer] = None
        self._http_server: Optional[asyncio.AbstractServer] = None
        self._aiozc: Optional[AsyncZeroconf] = None
        self._service_info: Optional[ServiceInfo] = None
        self._clients: Set[asyncio.StreamWriter] = set()

    def _emit(self, direction: str, namespace: str, summary: str, payload_preview: str = "") -> None:
        if self._on_event:
            self._on_event(
                self.device.id,
                self.device.cast_name,
                direction,
                namespace,
                summary,
                payload_preview[:400],
            )

    def _notify_state(self) -> None:
        self.device.connected_senders = len(self._clients)
        if self._on_state_change:
            self._on_state_change(self.device)

    async def start(self) -> None:
        """Start the CastV2 TLS server, Eureka/DIAL HTTP server, and mDNS service."""
        ssl_ctx = self.auth_manager.create_ssl_context()
        self._tls_server = await asyncio.start_server(
            self._handle_tls_client,
            host="0.0.0.0",
            port=self.device.cast_port,
            ssl=ssl_ctx,
        )
        # Update actual bound port if ephemeral port 0 was used
        if self._tls_server.sockets:
            self.device.cast_port = self._tls_server.sockets[0].getsockname()[1]

        self._http_server = await asyncio.start_server(
            self._handle_http_client,
            host="0.0.0.0",
            port=self.device.eureka_port,
        )
        if self._http_server.sockets:
            self.device.eureka_port = self._http_server.sockets[0].getsockname()[1]

        if self.mdns_enabled:
            await self._register_mdns()

        self._emit(
            "system",
            "cast.receiver",
            f"Chromecast Audio '{self.device.cast_name}' listening on TLS :{self.device.cast_port} (Eureka :{self.device.eureka_port})",
        )

    async def stop(self) -> None:
        """Stop mDNS, HTTP server, and CastV2 TLS server."""
        if self._aiozc and self._service_info:
            try:
                await self._aiozc.async_unregister_service(self._service_info)
                await self._aiozc.async_close()
            except Exception as exc:
                logger.debug("mDNS unregister notice: %s", exc)
            self._aiozc = None
            self._service_info = None

        for writer in list(self._clients):
            try:
                writer.close()
            except Exception:
                pass
        self._clients.clear()

        if self._tls_server:
            self._tls_server.close()
            await self._tls_server.wait_closed()
            self._tls_server = None

        if self._http_server:
            self._http_server.close()
            await self._http_server.wait_closed()
            self._http_server = None

    async def _register_mdns(self) -> None:
        """Advertise `_googlecast._tcp.local.` with Chromecast Audio capability flags."""
        try:
            cast_uuid = self.device.cast_uuid or hashlib.md5(self.device.id.encode()).hexdigest()
            self.device.cast_uuid = cast_uuid
            cd_id = hashlib.md5(f"cd:{cast_uuid}".encode()).hexdigest().upper()
            bs_id = cast_uuid[:12].upper()

            properties = {
                "id": cast_uuid,
                "cd": cd_id,
                "rm": "",
                "ve": "05",
                "md": "Chromecast Audio",
                "ic": "/setup/icon.png",
                "fn": self.device.cast_name,
                "ca": str(CHROMECAST_AUDIO_CAPABILITIES),  # 199428 = Full Chromecast Audio capability bitmask
                "st": "0" if self.device.player_state == PlayerState.IDLE else "1",
                "bs": bs_id,
                "nf": "1",
                "rs": "" if self.app_id == APP_BACKDROP else self.app_name,
            }
            svc_name = f"Chromecast-Audio-{cast_uuid}._googlecast._tcp.local."
            ip_bytes = socket.inet_aton(self.host_ip if self.host_ip and self.host_ip != "0.0.0.0" else "127.0.0.1")
            self._service_info = ServiceInfo(
                type_="_googlecast._tcp.local.",
                name=svc_name,
                addresses=[ip_bytes],
                port=self.device.cast_port,
                properties=properties,
                server=f"chromecast-audio-{cast_uuid[:8]}.local.",
            )
            self._aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
            await self._aiozc.async_register_service(self._service_info, allow_name_change=True)
        except Exception as exc:
            logger.warning("mDNS registration skipped/failed for %s: %s", self.device.cast_name, exc)

    def _build_receiver_status(self, request_id: int = 0) -> Dict[str, Any]:
        """Build standard Google Cast RECEIVER_STATUS payload."""
        is_idle = self.app_id == APP_BACKDROP
        namespaces = [
            {"name": NS_MEDIA},
            {"name": NS_DISCOVERY},
            {"name": NS_SETUP},
            {"name": NS_YOUTUBE_MDX},
            {"name": NS_MULTIZONE},
            {"name": "urn:x-cast:com.google.cast.inject"},
        ]
        app_entry = {
            "appId": self.app_id,
            "displayName": self.app_name,
            "isIdleScreen": is_idle,
            "launchedFromCloud": False,
            "namespaces": namespaces,
            "sessionId": self.session_id,
            "statusText": (
                f"Playing: {self.device.media.title}"
                if self.device.player_state == PlayerState.PLAYING
                else self.app_name
            ),
            "transportId": self.transport_id,
            "universalAppId": self.app_id,
        }
        return {
            "requestId": request_id,
            "type": "RECEIVER_STATUS",
            "status": {
                "applications": [app_entry],
                "isActiveInput": True,
                "isStandBy": False,
                "volume": {
                    "controlType": "attenuation",
                    "level": round(self.device.volume, 3),
                    "muted": self.device.muted,
                    "stepInterval": 0.05,
                },
            },
        }

    def _build_media_status(self, request_id: int = 0) -> Dict[str, Any]:
        """Build standard Google Cast MEDIA_STATUS payload."""
        if self.device.player_state == PlayerState.IDLE and not self.device.media.content_url:
            return {
                "requestId": request_id,
                "type": "MEDIA_STATUS",
                "status": [],
            }

        images = [{"url": self.device.media.artwork_url}] if self.device.media.artwork_url else []
        status_entry = {
            "mediaSessionId": self.media_session_id,
            "playbackRate": 1,
            "playerState": self.device.player_state.value,
            "currentTime": round(self.device.media.current_time, 2),
            "supportedMediaCommands": 274447,  # PAUSE | SEEK | STREAM_VOLUME | STREAM_MUTE | QUEUE_NEXT | QUEUE_PREV
            "volume": {
                "level": round(self.device.volume, 3),
                "muted": self.device.muted,
            },
            "media": {
                "contentId": self.device.media.content_url,
                "contentType": self.device.media.content_type or "audio/mpeg",
                "streamType": "BUFFERED",
                "duration": self.device.media.duration or 180.0,
                "metadata": {
                    "metadataType": 3,  # MusicTrackMediaMetadata
                    "title": self.device.media.title,
                    "artist": self.device.media.artist,
                    "subtitle": self.device.media.artist,
                    "albumName": self.device.media.album,
                    "images": images,
                },
            },
        }
        if self.device.player_state == PlayerState.IDLE:
            status_entry["idleReason"] = "FINISHED"
        return {
            "requestId": request_id,
            "type": "MEDIA_STATUS",
            "status": [status_entry],
        }

    async def broadcast_receiver_status(self, request_id: int = 0) -> None:
        payload = self._build_receiver_status(request_id=request_id)
        msg = make_json_message("receiver-0", "*", NS_RECEIVER, payload)
        await self._broadcast(msg)
        self._notify_state()

    async def broadcast_media_status(self, request_id: int = 0) -> None:
        payload = self._build_media_status(request_id=request_id)
        msg = make_json_message(self.transport_id, "*", NS_MEDIA, payload)
        await self._broadcast(msg)
        self._notify_state()

    async def _broadcast(self, msg: CastMessage) -> None:
        for writer in list(self._clients):
            try:
                await write_cast_message(writer, msg)
            except Exception:
                self._clients.discard(writer)

    async def _handle_tls_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        self._clients.add(writer)
        self._notify_state()
        self._emit("cast_in", "tls.connect", f"Sender connected from {peer}")

        try:
            while True:
                msg = await read_cast_message(reader)
                if msg is None:
                    break
                await self._dispatch_cast_message(writer, msg)
        except Exception as exc:
            logger.debug("CastV2 client connection closed (%s): %s", peer, exc)
        finally:
            self._clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass
            self._notify_state()

    async def _dispatch_cast_message(
        self,
        writer: asyncio.StreamWriter,
        msg: CastMessage,
    ) -> None:
        ns = msg.namespace

        # 1. Heartbeat (PING -> PONG)
        if ns == NS_HEARTBEAT:
            data = msg.json_payload()
            if data.get("type") == "PING":
                reply = make_json_message(msg.destination_id, msg.source_id, NS_HEARTBEAT, {"type": "PONG"})
                await write_cast_message(writer, reply)
            return

        # 2. Device Authentication (DeviceAuthMessage challenge -> signed AuthResponse)
        if ns == NS_DEVICEAUTH and msg.payload_type == PayloadType.BINARY and msg.payload_binary is not None:
            self._emit("cast_in", ns, f"DeviceAuthMessage challenge ({len(msg.payload_binary)} bytes)")
            raw_resp = self.auth_manager.handle_auth_challenge(msg.payload_binary)
            reply = make_binary_message("receiver-0", msg.source_id, NS_DEVICEAUTH, raw_resp)
            await write_cast_message(writer, reply)
            self._emit("cast_out", ns, f"Sent signed AuthResponse ({len(raw_resp)} bytes) [mode={self.auth_manager.config.mode.value}]")
            return

        # 3. Virtual Connection lifecycle
        if ns == NS_CONNECTION:
            data = msg.json_payload()
            conn_type = data.get("type", "")
            self._emit("cast_in", ns, f"{conn_type} ({msg.source_id} -> {msg.destination_id})")
            return

        # 4. Receiver Namespace (GET_STATUS, LAUNCH, STOP, SET_VOLUME, GET_APP_AVAILABILITY)
        if ns == NS_RECEIVER:
            data = msg.json_payload()
            msg_type = data.get("type", "")
            req_id = int(data.get("requestId", 0))
            self._emit("cast_in", ns, f"RECEIVER {msg_type} (reqId={req_id})", msg.payload_utf8 or "")

            if msg_type == "GET_STATUS":
                reply = make_json_message(
                    "receiver-0",
                    msg.source_id,
                    NS_RECEIVER,
                    self._build_receiver_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)

            elif msg_type == "GET_APP_AVAILABILITY":
                app_ids = data.get("appId", [])
                availability = {aid: "APP_AVAILABLE" for aid in app_ids}
                reply = make_json_message(
                    "receiver-0",
                    msg.source_id,
                    NS_RECEIVER,
                    {
                        "requestId": req_id,
                        "type": "GET_APP_AVAILABILITY",
                        "availability": availability,
                    },
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", ns, f"APP_AVAILABLE for {app_ids}")

            elif msg_type == "LAUNCH":
                requested_app = data.get("appId", APP_DEFAULT_MEDIA_RECEIVER)
                self.app_id = requested_app
                self.app_name = KNOWN_APP_NAMES.get(requested_app, f"Cast App ({requested_app})")
                self.session_id = str(uuid.uuid4())
                self.transport_id = f"web-{uuid.uuid4().hex[:8]}"
                self.device.media.app_id = self.app_id
                self.device.media.app_name = self.app_name
                status_payload = self._build_receiver_status(request_id=req_id)
                reply = make_json_message("receiver-0", msg.source_id, NS_RECEIVER, status_payload)
                await write_cast_message(writer, reply)
                await self.broadcast_receiver_status(request_id=req_id)
                self._emit("cast_out", ns, f"Launched '{self.app_name}' ({self.app_id}) transport={self.transport_id}")

            elif msg_type == "STOP":
                self.app_id = APP_BACKDROP
                self.app_name = "Backdrop"
                self.device.media.app_id = APP_BACKDROP
                self.device.media.app_name = "Backdrop"
                await self._on_stop(self.device)
                await self.broadcast_receiver_status(request_id=req_id)
                await self.broadcast_media_status(request_id=req_id)

            elif msg_type == "SET_VOLUME":
                vol_obj = data.get("volume", {})
                new_level = vol_obj.get("level", self.device.volume)
                new_muted = vol_obj.get("muted", self.device.muted)
                await self._on_volume(self.device, float(new_level), new_muted)
                await self.broadcast_receiver_status(request_id=req_id)

            return

        # 5. Media Namespace (LOAD, PLAY, PAUSE, STOP, SEEK, QUEUE_*, GET_STATUS)
        if ns == NS_MEDIA:
            data = msg.json_payload()
            msg_type = data.get("type", "")
            req_id = int(data.get("requestId", 0))
            self._emit("cast_in", ns, f"MEDIA {msg_type} (reqId={req_id})", msg.payload_utf8 or "")

            if msg_type == "GET_STATUS":
                reply = make_json_message(
                    msg.destination_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)

            elif msg_type in ("LOAD", "QUEUE_LOAD"):
                if msg_type == "QUEUE_LOAD":
                    items = data.get("items", [])
                    self.queue_items = items
                    self.queue_index = int(data.get("startIndex", 0))
                    media_info = items[self.queue_index].get("media", {}) if items else {}
                else:
                    media_info = data.get("media", {})

                content_url = media_info.get("contentId") or media_info.get("contentUrl") or ""
                content_type = media_info.get("contentType", "audio/mpeg")
                duration = float(media_info.get("duration") or 180.0)
                meta_raw = media_info.get("metadata", {})
                images = meta_raw.get("images", [])
                artwork = images[0].get("url", "") if images else ""
                start_time = float(data.get("currentTime") or 0.0)

                if self.app_id == APP_BACKDROP:
                    self.app_id = APP_DEFAULT_MEDIA_RECEIVER
                    self.app_name = KNOWN_APP_NAMES[APP_DEFAULT_MEDIA_RECEIVER]

                meta = MediaMetadata(
                    title=meta_raw.get("title") or meta_raw.get("songName") or content_url.split("/")[-1] or "Cast Audio Stream",
                    artist=meta_raw.get("artist") or meta_raw.get("subtitle") or "Google Cast Sender",
                    album=meta_raw.get("albumName") or "",
                    artwork_url=artwork,
                    content_url=content_url,
                    content_type=content_type,
                    duration=duration,
                    current_time=start_time,
                    app_id=self.app_id,
                    app_name=self.app_name,
                )
                self.device.media = meta
                self.media_session_id += 1

                await self._on_load_media(self.device, content_url, meta, start_time)
                await self.broadcast_media_status(request_id=req_id)
                await self.broadcast_receiver_status(request_id=0)
                self._emit("cast_out", ns, f"MEDIA_STATUS PLAYING '{meta.title}' -> HomePod '{self.device.name}'")

            elif msg_type == "PAUSE":
                await self._on_pause(self.device)
                await self.broadcast_media_status(request_id=req_id)

            elif msg_type == "PLAY":
                await self._on_resume(self.device)
                await self.broadcast_media_status(request_id=req_id)

            elif msg_type == "STOP":
                await self._on_stop(self.device)
                await self.broadcast_media_status(request_id=req_id)

            elif msg_type == "SEEK":
                pos = float(data.get("currentTime", 0.0))
                await self._on_seek(self.device, pos)
                await self.broadcast_media_status(request_id=req_id)

            elif msg_type == "SET_VOLUME":
                vol_obj = data.get("volume", {})
                new_level = vol_obj.get("level", self.device.volume)
                new_muted = vol_obj.get("muted", self.device.muted)
                await self._on_volume(self.device, float(new_level), new_muted)
                await self.broadcast_media_status(request_id=req_id)

            elif msg_type in ("QUEUE_NEXT", "QUEUE_PREV") and self.queue_items:
                delta = 1 if msg_type == "QUEUE_NEXT" else -1
                self.queue_index = (self.queue_index + delta) % len(self.queue_items)
                item_media = self.queue_items[self.queue_index].get("media", {})
                url = item_media.get("contentId", "")
                meta_raw = item_media.get("metadata", {})
                self.device.media.title = meta_raw.get("title", url)
                self.device.media.content_url = url
                await self._on_load_media(self.device, url, self.device.media, 0.0)
                await self.broadcast_media_status(request_id=req_id)

            return

        # 6. YouTube / YouTube Music MDX Lounge Namespace
        if ns == NS_YOUTUBE_MDX:
            data = msg.json_payload()
            if data.get("type") == "getMdxSessionStatus":
                screen_id = hashlib.sha256(f"yt-screen:{self.device.cast_uuid}".encode()).hexdigest()[:24]
                reply = make_json_message(
                    msg.destination_id,
                    msg.source_id,
                    NS_YOUTUBE_MDX,
                    {
                        "type": "mdxSessionStatus",
                        "data": {"screenId": screen_id},
                    },
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", ns, f"Returned YouTube MDX Lounge screenId={screen_id}")
            return

        # 7. Multizone Namespace
        if ns == NS_MULTIZONE:
            data = msg.json_payload()
            req_id = int(data.get("requestId", 0))
            if data.get("type") == "GET_STATUS":
                reply = make_json_message(
                    msg.destination_id,
                    msg.source_id,
                    NS_MULTIZONE,
                    {
                        "requestId": req_id,
                        "type": "MULTIZONE_STATUS",
                        "status": {"devices": []},
                    },
                )
                await write_cast_message(writer, reply)
            return

        # 8. Receiver Discovery Namespace (queried by Android Play Services / Chrome after DeviceAuth)
        if ns == NS_DISCOVERY:
            data = msg.json_payload()
            req_id = int(data.get("requestId", 0))
            msg_type = data.get("type", "")
            self._emit("cast_in", ns, f"DISCOVERY {msg_type} (reqId={req_id})")
            if msg_type in ("GET_DEVICE_INFO", ""):
                reply = make_json_message(
                    msg.destination_id,
                    msg.source_id,
                    NS_DISCOVERY,
                    {
                        "requestId": req_id,
                        "type": "DEVICE_INFO",
                        "deviceId": self.device.cast_uuid,
                        "deviceModel": "Chromecast Audio",
                        "friendlyName": self.device.cast_name,
                        "deviceCapabilities": CHROMECAST_AUDIO_CAPABILITIES,
                        "deviceIconUrl": "",
                        "controlNotifications": 1,
                        "receiverMetricsId": "",
                    },
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", ns, f"Returned DEVICE_INFO (deviceCapabilities={CHROMECAST_AUDIO_CAPABILITIES})")
            return

        # 9. Cast Setup Namespace
        if ns == NS_SETUP:
            data = msg.json_payload()
            req_id = int(data.get("requestId", 0))
            reply = make_json_message(
                msg.destination_id,
                msg.source_id,
                NS_SETUP,
                {
                    "requestId": req_id,
                    "type": "EUREKA_INFO",
                    "status": "OK",
                    "data": {
                        "name": self.device.cast_name,
                        "ssdp_udn": self.device.cast_uuid,
                        "version": 8,
                    },
                },
            )
            await write_cast_message(writer, reply)
            return

    # --- Eureka / DIAL HTTP Server (Port 8008 / 18008+) ---

    async def _handle_http_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                return
            parts = request_line.decode("utf-8", errors="replace").strip().split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1].split("?")[0] if len(parts) > 1 else "/"

            # Read headers
            content_length = 0
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not line or line in (b"\r\n", b"\n"):
                    break
                hdr = line.decode("utf-8", errors="replace").strip()
                if hdr.lower().startswith("content-length:"):
                    content_length = int(hdr.split(":", 1)[1].strip())

            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(reader.readexactly(content_length), timeout=5.0)

            if path.startswith("/setup/eureka_info"):
                info = {
                    "version": 8,
                    "name": self.device.cast_name,
                    "build_version": "1.56.281627",
                    "cast_build_revision": "1.56.281627",
                    "ssdp_udn": self.device.cast_uuid,
                    "mac_address": self.device.mac_address or "AA:BB:CC:DD:EE:FF",
                    "ip_address": self.host_ip,
                    "connected": True,
                    "ethernet_connected": True,
                    "HasUpdate": False,
                    "device_info": {
                        "model_name": "Chromecast Audio",
                        "manufacturer": "Google Inc.",
                        "product_name": "chirp",
                        "ssdp_udn": self.device.cast_uuid,
                        "capabilities": {
                            "display_supported": False,
                            "wifi_supported": True,
                            "hotspot_supported": False,
                            "ble_supported": False,
                            "multizone_supported": True,
                            "hi_res_audio_supported": True,
                        },
                    },
                }
                await self._send_http(writer, 200, "application/json", json.dumps(info).encode("utf-8"))

            elif path == "/setup/icon.png":
                await self._send_http(writer, 200, "image/png", ICON_PNG_BYTES)

            elif path == "/ssdp/device-desc.xml":
                xml = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <URLBase>http://{self.host_ip}:{self.device.eureka_port}</URLBase>
  <device>
    <deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>
    <friendlyName>{self.device.cast_name}</friendlyName>
    <manufacturer>Google Inc.</manufacturer>
    <modelName>Chromecast Audio</modelName>
    <UDN>uuid:{self.device.cast_uuid}</UDN>
  </device>
</root>"""
                await self._send_http(
                    writer,
                    200,
                    "application/xml",
                    xml.encode("utf-8"),
                    extra_headers={"Application-URL": f"http://{self.host_ip}:{self.device.eureka_port}/apps/"},
                )

            elif path.startswith("/apps/"):
                app_slug = path.split("/apps/", 1)[1].strip("/")
                if method == "POST":
                    self.app_id = APP_YOUTUBE_MUSIC if "Music" in app_slug else APP_YOUTUBE
                    self.app_name = app_slug or "YouTube"
                    self.session_id = str(uuid.uuid4())
                    self._emit("cast_in", "dial.launch", f"DIAL POST /apps/{app_slug}", body.decode("utf-8", errors="replace"))
                    await self._send_http(
                        writer,
                        201,
                        "text/plain",
                        b"",
                        extra_headers={"Location": f"http://{self.host_ip}:{self.device.eureka_port}/apps/{app_slug}/run"},
                    )
                else:
                    state = "running" if self.app_id != APP_BACKDROP else "stopped"
                    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<service xmlns="urn:dial-multiscreen-org:schemas:dial" dialVer="1.7">
  <name>{app_slug}</name>
  <options allowStop="true"/>
  <state>{state}</state>
</service>"""
                    await self._send_http(writer, 200, "application/xml", xml.encode("utf-8"))

            else:
                await self._send_http(writer, 404, "application/json", b'{"error":"not_found"}')
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _send_http(
        writer: asyncio.StreamWriter,
        status_code: int,
        content_type: str,
        body: bytes,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        reason = {200: "OK", 201: "Created", 404: "Not Found"}.get(status_code, "OK")
        lines = [
            f"HTTP/1.1 {status_code} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Access-Control-Allow-Origin: *",
            "Connection: close",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
        header_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
        writer.write(header_bytes + body)
        await writer.drain()
