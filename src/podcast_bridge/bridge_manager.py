"""Central Orchestrator for PodCast Bridge (CastV2 Receivers <-> AirPlay / Home Assistant)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Set

from zeroconf import IPVersion, InterfaceChoice, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

from .airplay_manager import AirPlayManager, make_cast_uuid
from .audio_relay import AudioRelayManager, has_ffmpeg
from .cast_auth import CastAuthManager
from .cast_client import send_test_cast_session
from .cast_receiver import SharedRawMdnsAdvertiser, VirtualChromecastAudio
from .ha_client import HomeAssistantClient
from .models import (
    BridgeSettings,
    HomePodDevice,
    MediaMetadata,
    PlayerState,
    ProtocolEvent,
    TransportMode,
)

logger = logging.getLogger(__name__)


SEEDED_DEMO_IPS = frozenset({"192.168.1.142", "192.168.1.143"})


def detect_local_ip_for_target(target_ip: str = "192.168.1.1") -> str:
    """Detect the local LAN IPv4 address used to route to target_ip."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 7000))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def detect_local_ip() -> str:
    """Detect primary physical LAN IPv4 address (avoiding Docker hassio/docker0 bridge IPs when possible)."""
    env_ip = os.environ.get("BRIDGE_HOST_IP")
    if env_ip:
        return env_ip
    for probe in ("192.168.1.1", "10.0.0.1", "8.8.8.8", "10.255.255.255"):
        ip = detect_local_ip_for_target(probe)
        if ip and not ip.startswith(("127.", "172.17.", "172.30.", "0.")):
            return ip
    return detect_local_ip_for_target("10.255.255.255")


class BridgeManager:
    """Manages HomePod Mini discovery, VirtualChromecastAudio instances, and state persistence."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        web_port: int = 8788,
        mdns_enabled: bool = True,
    ) -> None:
        default_dir = Path(os.environ.get("PODCAST_DATA_DIR", "/data" if os.path.isdir("/data") else "./data"))
        self.data_dir = Path(data_dir or default_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.data_dir / "bridge_state.json"
        self.web_port = web_port

        self.settings = BridgeSettings(
            host_ip=detect_local_ip(),
            mdns_enabled=mdns_enabled,
        )
        self.devices: Dict[str, HomePodDevice] = {}
        self.receivers: Dict[str, VirtualChromecastAudio] = {}
        self.events: Deque[ProtocolEvent] = deque(maxlen=250)
        self._ws_Queues: Set[asyncio.Queue] = set()

        self._load_state()
        if not self.settings.host_ip or self.settings.host_ip.startswith(("127.", "172.17.", "172.30.", "0.")):
            self.settings.host_ip = detect_local_ip()

        self.auth_manager = CastAuthManager(self.data_dir, self.settings.auth)
        self.relay_manager = AudioRelayManager(self.settings.audio)
        self.ha_client = HomeAssistantClient(self.settings.ha, on_event=self._record_event)
        self.airplay_manager = AirPlayManager(self.relay_manager, ha_client=self.ha_client, on_event=self._record_event)

        # Centralized shared mDNS infrastructure (avoids SO_REUSEPORT kernel 4-tuple query collision)
        self._shared_aiozc: Optional[AsyncZeroconf] = None
        self._shared_raw_mdns: Optional[SharedRawMdnsAdvertiser] = None
        self._registered_service_infos: Dict[str, ServiceInfo] = {}

    def _record_event(
        self,
        device_id: str,
        device_name: str,
        direction: str,
        namespace: str,
        summary: str,
        payload_preview: str = "",
    ) -> None:
        ev = ProtocolEvent(
            id=uuid.uuid4().hex[:10],
            timestamp=time.time(),
            device_id=device_id,
            device_name=device_name,
            direction=direction,
            namespace=namespace,
            summary=summary,
            payload_preview=payload_preview,
        )
        self.events.appendleft(ev)
        self._broadcast_ws({"type": "protocol_event", "event": ev.model_dump()})

    def _on_device_state_change(self, device: HomePodDevice) -> None:
        self._broadcast_ws({"type": "device_updated", "device": device.model_dump()})
        if self.settings.mdns_enabled and self._shared_raw_mdns:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._shared_raw_mdns.announce_all())
            except RuntimeError:
                pass

    def _broadcast_ws(self, message: Dict[str, Any]) -> None:
        for q in list(self._ws_Queues):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass

    def subscribe_ws(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._ws_Queues.add(q)
        return q

    def unsubscribe_ws(self, q: asyncio.Queue) -> None:
        self._ws_Queues.discard(q)

    def _load_state(self) -> None:
        if not self.state_file.exists():
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            if "settings" in raw:
                self.settings = BridgeSettings(**raw["settings"])
            for dev_dict in raw.get("devices", []):
                dev = HomePodDevice(**dev_dict)
                dev.player_state = PlayerState.IDLE
                dev.connected_senders = 0
                self.devices[dev.id] = dev
        except Exception as exc:
            logger.warning("Failed to load bridge_state.json: %s", exc)

    def save_state(self) -> None:
        try:
            payload = {
                "settings": self.settings.model_dump(),
                "devices": [d.model_dump() for d in self.devices.values()],
            }
            self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to save bridge_state.json: %s", exc)

    def _allocate_ports(self, existing_device_id: Optional[str] = None) -> tuple[int, int]:
        used_cast = {
            d.cast_port for did, d in self.devices.items() if did != existing_device_id and d.cast_port
        }
        used_eureka = {
            d.eureka_port for did, d in self.devices.items() if did != existing_device_id and d.eureka_port
        }
        c_port = self.settings.base_cast_port
        while c_port in used_cast:
            c_port += 1
        e_port = self.settings.base_eureka_port
        while e_port in used_eureka:
            e_port += 1
        return c_port, e_port

    def _has_real_devices(self) -> bool:
        return any(
            d.transport_mode != TransportMode.SIMULATED or d.ip_address not in SEEDED_DEMO_IPS
            for d in self.devices.values()
        )

    def _sync_host_ip_from_real_devices(self) -> bool:
        """Update self.settings.host_ip to the exact LAN interface IP that routes to discovered HomePods."""
        if os.environ.get("BRIDGE_HOST_IP"):
            return False
        for dev in self.devices.values():
            if dev.transport_mode != TransportMode.SIMULATED and dev.ip_address not in SEEDED_DEMO_IPS:
                candidate = detect_local_ip_for_target(dev.ip_address)
                if candidate and not candidate.startswith(("127.", "0.")):
                    if candidate != self.settings.host_ip:
                        logger.info("Updated bridge host_ip %s -> %s (via HomePod %s)", self.settings.host_ip, candidate, dev.ip_address)
                        self.settings.host_ip = candidate
                        return True
                    return False
        return False

    def _find_device_matching_ha_name(self, ha_name: str) -> Optional[HomePodDevice]:
        ha_norm = "".join(c for c in ha_name.lower() if c.isalnum())
        for dev in self.devices.values():
            dev_norm = "".join(c for c in dev.name.lower() if c.isalnum())
            if ha_norm and dev_norm and (ha_norm in dev_norm or dev_norm in ha_norm):
                return dev
        return None

    async def _purge_seeded_simulated_if_real_present(self) -> bool:
        """Selectively remove seeded demo devices when replaced by real or HA HomePod Minis."""
        real_devs = [
            d for d in self.devices.values()
            if d.transport_mode != TransportMode.SIMULATED
        ]
        if not real_devs:
            return False

        has_real_living = any("living" in d.name.lower() or "living" in (d.ha_entity_id or "").lower() for d in real_devs)
        has_real_kitchen = any("kitchen" in d.name.lower() or "kitchen" in (d.ha_entity_id or "").lower() for d in real_devs)

        seeded_devs = [
            d for d in self.devices.values()
            if d.transport_mode == TransportMode.SIMULATED and d.ip_address in SEEDED_DEMO_IPS
        ]

        changed = False
        for s_dev in seeded_devs:
            s_name = s_dev.name.lower()
            should_purge = False
            if "living" in s_name and has_real_living:
                should_purge = True
            elif "kitchen" in s_name and has_real_kitchen:
                should_purge = True

            if should_purge:
                await self.stop_receiver(s_dev.id)
                self.devices.pop(s_dev.id, None)
                self._broadcast_ws({"type": "device_deleted", "device_id": s_dev.id})
                changed = True

        # Compact ports starting at base_cast_port (8009) if any real device was pushed to 8011+ by seeded demos
        used_ports = [d.cast_port for d in self.devices.values()]
        if self.settings.base_cast_port not in used_ports and self.devices:
            for idx, dev in enumerate(self.devices.values()):
                new_c = self.settings.base_cast_port + idx
                new_e = self.settings.base_eureka_port + idx
                if dev.cast_port != new_c or dev.eureka_port != new_e:
                    await self.stop_receiver(dev.id)
                    dev.cast_port = new_c
                    dev.eureka_port = new_e
                    changed = True

        return changed

    async def _start_shared_mdns(self) -> None:
        """Start shared mDNS advertiser and AsyncZeroconf instances for all bridged speakers."""
        if not self.settings.mdns_enabled or self._shared_raw_mdns is not None:
            return
        adv_ip = self.settings.host_ip if self.settings.host_ip and self.settings.host_ip != "0.0.0.0" else "127.0.0.1"
        try:
            self._shared_raw_mdns = SharedRawMdnsAdvertiser(
                ip_address=adv_ip,
                receivers_provider=lambda: list(self.receivers.values()),
            )
            await self._shared_raw_mdns.start()
        except Exception as exc:
            logger.warning("Shared RawMdnsAdvertiser start notice: %s", exc)

        try:
            if adv_ip not in ("127.0.0.1", "0.0.0.0"):
                self._shared_aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only, interfaces=[adv_ip])
            else:
                self._shared_aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only, interfaces=InterfaceChoice.All)
        except Exception:
            try:
                self._shared_aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
            except Exception as exc:
                logger.warning("Shared AsyncZeroconf start notice: %s", exc)

    async def start(self, seed_default_if_empty: bool = True) -> None:
        """Start the bridge manager, discover HomePods, and launch virtual Chromecast Audio servers."""
        if self.settings.mdns_enabled:
            await self._start_shared_mdns()

        ha_players = await self.ha_client.discover_media_players()

        should_scan = (
            self.settings.mdns_enabled
            and (
                not self.devices
                or len(self.devices) < 2
                or any(d.transport_mode == TransportMode.SIMULATED for d in self.devices.values())
            )
        )
        if should_scan and seed_default_if_empty:
            # Perform a 6s network scan on startup so real HomePod Minis replace any seeded demo devices
            scanned = await self.airplay_manager.scan_network(timeout=6)
            for item in scanned:
                if item.get("is_homepod", True):
                    matched_ha = None
                    dev_norm = "".join(c for c in item["name"].lower() if c.isalnum())
                    for p in ha_players:
                        p_norm = "".join(c for c in p["friendly_name"].lower() if c.isalnum())
                        if p_norm and (p_norm in dev_norm or dev_norm in p_norm):
                            matched_ha = p["entity_id"]
                            break

                    await self.register_device(
                        name=item["name"],
                        ip_address=item["ip_address"],
                        airplay_port=item["airplay_port"],
                        model=item["model"],
                        mac_address=item["mac_address"],
                        transport_mode=TransportMode.PYATV_STREAM,
                        ha_entity_id=matched_ha,
                        start_immediately=False,
                    )

        # Auto-register HomePods discovered in Home Assistant if not found via mDNS
        for p in ha_players:
            if p.get("is_homepod") or "kitchen" in p.get("friendly_name", "").lower() or "kitchen" in p.get("entity_id", "").lower():
                existing = any(d.ha_entity_id == p["entity_id"] for d in self.devices.values())
                if not existing:
                    matched_dev = self._find_device_matching_ha_name(p["friendly_name"])
                    if matched_dev:
                        if not matched_dev.ha_entity_id:
                            matched_dev.ha_entity_id = p["entity_id"]
                    else:
                        await self.register_device(
                            name=p["friendly_name"],
                            ip_address="127.0.0.1",
                            transport_mode=TransportMode.HA_MEDIA_PLAYER,
                            ha_entity_id=p["entity_id"],
                            start_immediately=False,
                        )
                        logger.info("Auto-registered HomePod from Home Assistant: %s (%s)", p["friendly_name"], p["entity_id"])

        for dev in self.devices.values():
            if not dev.ha_entity_id:
                matched = self._match_ha_entity_for_device(dev, ha_players)
                if matched:
                    dev.ha_entity_id = matched

        await self._purge_seeded_simulated_if_real_present()
        self._sync_host_ip_from_real_devices()

        if not self.devices and seed_default_if_empty:
            # Seed two realistic HomePod Mini endpoints so the bridge is immediately usable & testable
            await self.register_device(
                name="Living Room HomePod Mini",
                cast_name="Living Room HomePod Mini (Cast)",
                ip_address="192.168.1.142",
                airplay_port=7000,
                model="AudioAccessory5,1",
                mac_address="D0:81:7A:31:9C:10",
                transport_mode=TransportMode.SIMULATED,
                ha_entity_id="media_player.living_room_homepod_mini",
                start_immediately=False,
            )
            await self.register_device(
                name="Kitchen HomePod Mini",
                cast_name="Kitchen HomePod Mini (Cast)",
                ip_address="192.168.1.143",
                airplay_port=7000,
                model="AudioAccessory5,1",
                mac_address="D0:81:7A:31:9C:22",
                transport_mode=TransportMode.SIMULATED,
                ha_entity_id="media_player.kitchen_homepod_mini",
                start_immediately=False,
            )
        elif seed_default_if_empty:
            has_living = any("living" in d.name.lower() or "living" in (d.ha_entity_id or "").lower() for d in self.devices.values())
            has_kitchen = any("kitchen" in d.name.lower() or "kitchen" in (d.ha_entity_id or "").lower() for d in self.devices.values())
            if not has_living:
                await self.register_device(
                    name="Living Room HomePod Mini",
                    cast_name="Living Room HomePod Mini (Cast)",
                    ip_address="192.168.1.142",
                    airplay_port=7000,
                    model="AudioAccessory5,1",
                    mac_address="D0:81:7A:31:9C:10",
                    transport_mode=TransportMode.SIMULATED,
                    ha_entity_id="media_player.living_room_homepod_mini",
                    start_immediately=False,
                )
            if not has_kitchen:
                await self.register_device(
                    name="Kitchen HomePod Mini",
                    cast_name="Kitchen HomePod Mini (Cast)",
                    ip_address="192.168.1.143",
                    airplay_port=7000,
                    model="AudioAccessory5,1",
                    mac_address="D0:81:7A:31:9C:22",
                    transport_mode=TransportMode.SIMULATED,
                    ha_entity_id="media_player.kitchen_homepod_mini",
                    start_immediately=False,
                )

        # Guarantee all devices are enabled and have non-colliding ports
        used_cast: Set[int] = set()
        used_eureka: Set[int] = set()
        for dev in self.devices.values():
            if not dev.enabled:
                dev.enabled = True
            while dev.cast_port in used_cast:
                dev.cast_port += 1
            used_cast.add(dev.cast_port)
            while dev.eureka_port in used_eureka:
                dev.eureka_port += 1
            used_eureka.add(dev.eureka_port)

        for dev in list(self.devices.values()):
            if dev.enabled:
                await self.start_receiver(dev.id)

        self.save_state()

    async def stop(self) -> None:
        """Stop all virtual Chromecast Audio receivers, shared mDNS advertisers, and AirPlay streams."""
        for dev_id in list(self.receivers.keys()):
            await self.stop_receiver(dev_id)

        if self._shared_raw_mdns:
            await self._shared_raw_mdns.stop()
            self._shared_raw_mdns = None

        if self._shared_aiozc:
            try:
                await self._shared_aiozc.async_close()
            except Exception:
                pass
            self._shared_aiozc = None
            self._registered_service_infos.clear()

        await self.airplay_manager.close_all()

    async def register_device(
        self,
        name: str,
        ip_address: str,
        cast_name: Optional[str] = None,
        airplay_port: int = 7000,
        model: str = "AudioAccessory5,1",
        mac_address: str = "",
        transport_mode: TransportMode = TransportMode.PYATV_STREAM,
        ha_entity_id: Optional[str] = None,
        enabled: bool = True,
        start_immediately: bool = True,
    ) -> HomePodDevice:
        """Register or update a HomePod Mini and allocate its Chromecast Audio receiver."""
        ident = mac_address or f"{ip_address}:{airplay_port}:{name}"
        dev_id = f"homepod_{hashlib.sha1(ident.encode()).hexdigest()[:10]}"
        if dev_id in self.devices:
            dev = self.devices[dev_id]
            dev.name = name
            dev.ip_address = ip_address
            dev.airplay_port = airplay_port
            if cast_name:
                dev.cast_name = cast_name
            if ha_entity_id is not None:
                dev.ha_entity_id = ha_entity_id
            dev.last_seen = time.time()
        else:
            c_port, e_port = self._allocate_ports()
            cast_uuid = make_cast_uuid(dev_id)
            if not mac_address:
                h = cast_uuid[:12].upper()
                mac_address = ":".join(h[i : i + 2] for i in range(0, 12, 2))
            dev = HomePodDevice(
                id=dev_id,
                name=name,
                cast_name=cast_name or f"{name}",
                ip_address=ip_address,
                airplay_port=airplay_port,
                model=model,
                mac_address=mac_address,
                enabled=enabled,
                transport_mode=transport_mode,
                ha_entity_id=ha_entity_id,
                cast_uuid=cast_uuid,
                cast_port=c_port,
                eureka_port=e_port,
            )
            self.devices[dev_id] = dev

        self.save_state()
        if start_immediately and dev.enabled:
            await self.start_receiver(dev.id)
        self._on_device_state_change(dev)
        return dev

    async def update_device(self, device_id: str, updates: Dict[str, Any]) -> HomePodDevice:
        """Update configuration of a bridged HomePod Mini and restart its Cast receiver if needed."""
        dev = self.devices.get(device_id)
        if not dev:
            raise KeyError(f"Unknown device_id: {device_id}")

        restart_needed = False
        for key in ("name", "cast_name", "ip_address", "airplay_port", "model", "ha_entity_id", "airplay_credentials"):
            if key in updates and updates[key] is not None:
                if getattr(dev, key) != updates[key]:
                    setattr(dev, key, updates[key])
                    if key in ("cast_name",):
                        restart_needed = True

        if "transport_mode" in updates and updates["transport_mode"]:
            dev.transport_mode = TransportMode(updates["transport_mode"])

        if "enabled" in updates and updates["enabled"] is not None:
            new_enabled = bool(updates["enabled"])
            if new_enabled != dev.enabled:
                dev.enabled = new_enabled
                restart_needed = True

        self.save_state()
        if restart_needed:
            await self.stop_receiver(device_id)
            if dev.enabled:
                await self.start_receiver(device_id)

        self._on_device_state_change(dev)
        return dev

    async def delete_device(self, device_id: str) -> None:
        await self.stop_receiver(device_id)
        dev = self.devices.pop(device_id, None)
        if dev:
            await self.airplay_manager.stop(dev, emit_event=False)
        self.save_state()
        self._broadcast_ws({"type": "device_deleted", "device_id": device_id})

    async def start_receiver(self, device_id: str) -> None:
        dev = self.devices.get(device_id)
        if not dev or device_id in self.receivers:
            return

        if self.settings.mdns_enabled and self._shared_raw_mdns is None:
            await self._start_shared_mdns()

        receiver = VirtualChromecastAudio(
            device=dev,
            host_ip=self.settings.host_ip,
            auth_manager=self.auth_manager,
            on_load_media=self._handle_cast_load,
            on_pause=self._handle_cast_pause,
            on_resume=self._handle_cast_resume,
            on_stop=self._handle_cast_stop,
            on_seek=self._handle_cast_seek,
            on_volume=self._handle_cast_volume,
            on_event=self._record_event,
            on_state_change=self._on_device_state_change,
            mdns_enabled=False,
            receivers_provider=lambda: list(self.receivers.values()),
        )
        await receiver.start()
        self.receivers[device_id] = receiver

        if self.settings.mdns_enabled:
            if self._shared_aiozc:
                try:
                    s_info = receiver.build_service_info()
                    self._registered_service_infos[device_id] = s_info
                    await self._shared_aiozc.async_register_service(s_info, allow_name_change=True)
                except Exception as exc:
                    logger.warning("Shared Zeroconf registration notice for %s: %s", dev.cast_name, exc)
            if self._shared_raw_mdns:
                await self._shared_raw_mdns.announce_all()

        self._on_device_state_change(dev)

    async def stop_receiver(self, device_id: str) -> None:
        receiver = self.receivers.pop(device_id, None)
        if not receiver:
            return

        if self.settings.mdns_enabled:
            if self._shared_aiozc and device_id in self._registered_service_infos:
                s_info = self._registered_service_infos.pop(device_id)
                try:
                    await self._shared_aiozc.async_unregister_service(s_info)
                except Exception as exc:
                    logger.debug("Shared Zeroconf unregister notice for %s: %s", device_id, exc)
            if self._shared_raw_mdns:
                await self._shared_raw_mdns.announce_goodbye(receiver)

        await receiver.stop()

    async def restart_all_receivers(self) -> None:
        """Restart all enabled Chromecast Audio receivers (e.g. after TLS cert bundle or IP change)."""
        for dev_id in list(self.receivers.keys()):
            await self.stop_receiver(dev_id)
        for dev in list(self.devices.values()):
            if dev.enabled:
                await self.start_receiver(dev.id)

    # --- Callbacks from VirtualChromecastAudio -> AirPlay / Home Assistant ---

    async def _handle_cast_load(
        self,
        device: HomePodDevice,
        content_url: str,
        metadata: MediaMetadata,
        start_time: float,
    ) -> None:
        relay_url = self.relay_manager.get_relay_url(
            self.settings.host_ip,
            self.web_port,
            device.id,
        )
        self.relay_manager.register_source(device.id, content_url)

        if device.transport_mode == TransportMode.HA_MEDIA_PLAYER and device.ha_entity_id:
            device.player_state = PlayerState.PLAYING
            ok = await self.ha_client.play_media(device, relay_url)
            if not ok:
                # Fallback to internal stream tracker so Cast sender stays in sync
                await self.airplay_manager.play_stream(device, content_url, relay_url, start_time=start_time)
        else:
            await self.airplay_manager.play_stream(device, content_url, relay_url, start_time=start_time)
        self._on_device_state_change(device)

    async def _handle_cast_pause(self, device: HomePodDevice) -> None:
        if device.transport_mode == TransportMode.HA_MEDIA_PLAYER and device.ha_entity_id:
            device.player_state = PlayerState.PAUSED
            await self.ha_client.pause(device)
        else:
            await self.airplay_manager.pause(device)
        self._on_device_state_change(device)

    async def _handle_cast_resume(self, device: HomePodDevice) -> None:
        if device.transport_mode == TransportMode.HA_MEDIA_PLAYER and device.ha_entity_id:
            device.player_state = PlayerState.PLAYING
            await self.ha_client.resume(device)
        else:
            await self.airplay_manager.resume(device)
        self._on_device_state_change(device)

    async def _handle_cast_stop(self, device: HomePodDevice) -> None:
        if device.transport_mode == TransportMode.HA_MEDIA_PLAYER and device.ha_entity_id:
            device.player_state = PlayerState.IDLE
            await self.ha_client.stop(device)
        else:
            await self.airplay_manager.stop(device)
        self._on_device_state_change(device)

    async def _handle_cast_seek(self, device: HomePodDevice, position: float) -> None:
        if device.transport_mode == TransportMode.HA_MEDIA_PLAYER and device.ha_entity_id:
            device.media.current_time = position
            await self.ha_client.seek(device, position)
        else:
            await self.airplay_manager.seek(device, position)
        self._on_device_state_change(device)

    async def _handle_cast_volume(
        self,
        device: HomePodDevice,
        level: float,
        muted: Optional[bool] = None,
    ) -> None:
        await self.airplay_manager.set_volume(device, level, muted)
        if device.ha_entity_id and self.ha_client.config.connected:
            await self.ha_client.set_volume(device, level, muted)
        self._on_device_state_change(device)

    def _match_ha_entity_for_device(self, dev: HomePodDevice, ha_players: List[Dict[str, Any]]) -> Optional[str]:
        dev_norm = "".join(c for c in dev.name.lower() if c.isalnum())
        for p in ha_players:
            p_norm = "".join(c for c in p["friendly_name"].lower() if c.isalnum())
            if p_norm and (p_norm in dev_norm or dev_norm in p_norm):
                return p["entity_id"]
        for p in ha_players:
            slug = p["entity_id"].replace("media_player.", "").replace("_", "")
            if slug in dev_norm or dev_norm in slug:
                return p["entity_id"]
        return None

    async def test_cast_to_device(
        self,
        device_id: str,
        custom_url: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Connect a real CastV2 TLS sender to the device's virtual Chromecast port and stream audio."""
        dev = self.devices.get(device_id)
        if not dev:
            raise KeyError(f"Device {device_id} not found")
        if device_id not in self.receivers:
            await self.start_receiver(device_id)

        stream_url = custom_url or self.relay_manager.get_test_chime_url(
            self.settings.host_ip,
            self.web_port,
        )
        track_title = title or f"CastV2 Audio Verification ({dev.name})"
        result = await send_test_cast_session(
            host="127.0.0.1",
            cast_port=dev.cast_port,
            content_url=stream_url,
            title=track_title,
            artist="PodCast Bridge TLS Sender",
            album="HomePod Mini Chromecast Audio Bridge",
        )

        # Wait up to 1.2s to observe physical streaming startup and capture any AirPlay delivery errors
        await asyncio.sleep(1.2)
        result["device_last_error"] = dev.last_error
        result["player_state"] = dev.player_state.value
        result["transport_mode"] = dev.transport_mode.value
        result["ha_entity_id"] = dev.ha_entity_id

        if dev.last_error:
            result["playback_error"] = dev.last_error
            result["troubleshooting"] = [
                "1. Apple Home app -> Home Settings -> Speakers & TV -> set 'Allow Speaker & TV Access' to 'Anyone on the Same Network' (or 'Everyone') with 'Require Password' OFF.",
                f"2. If your HomePod is integrated in Home Assistant, change Audio Delivery Transport to 'Home Assistant ({dev.ha_entity_id or 'media_player'})'.",
                "3. Ensure Home Assistant Add-on has 'host_network: true' enabled.",
            ]
        return result

    async def scan_all(self) -> Dict[str, Any]:
        """Scan LAN via pyatv (AirPlay/RAOP) and query Home Assistant media_player entities."""
        airplay_found = await self.airplay_manager.scan_network(timeout=6)
        ha_players = await self.ha_client.discover_media_players()

        has_explicit_homepod = any(item.get("is_homepod") for item in airplay_found)
        newly_added: List[str] = []
        for item in airplay_found:
            if item.get("is_homepod") or not has_explicit_homepod:
                matched_ha = None
                dev_norm = "".join(c for c in item["name"].lower() if c.isalnum())
                for p in ha_players:
                    p_norm = "".join(c for c in p["friendly_name"].lower() if c.isalnum())
                    if p_norm and (p_norm in dev_norm or dev_norm in p_norm):
                        matched_ha = p["entity_id"]
                        break

                dev = await self.register_device(
                    name=item["name"],
                    ip_address=item["ip_address"],
                    airplay_port=item["airplay_port"],
                    model=item["model"],
                    mac_address=item["mac_address"],
                    transport_mode=TransportMode.PYATV_STREAM,
                    ha_entity_id=matched_ha,
                    start_immediately=False,
                )
                newly_added.append(dev.id)

        # Auto-register HomePods from Home Assistant if not found by mDNS
        for p in ha_players:
            if p.get("is_homepod") or "kitchen" in p.get("friendly_name", "").lower() or "kitchen" in p.get("entity_id", "").lower():
                existing = any(d.ha_entity_id == p["entity_id"] for d in self.devices.values())
                if not existing:
                    matched_dev = self._find_device_matching_ha_name(p["friendly_name"])
                    if matched_dev:
                        if not matched_dev.ha_entity_id:
                            matched_dev.ha_entity_id = p["entity_id"]
                    else:
                        dev = await self.register_device(
                            name=p["friendly_name"],
                            ip_address="127.0.0.1",
                            transport_mode=TransportMode.HA_MEDIA_PLAYER,
                            ha_entity_id=p["entity_id"],
                            start_immediately=False,
                        )
                        newly_added.append(dev.id)
                        logger.info("Auto-registered HomePod from Home Assistant: %s (%s)", dev.name, p["entity_id"])

        # Auto-match existing devices with Home Assistant media_players
        for dev in self.devices.values():
            if not dev.ha_entity_id:
                matched = self._match_ha_entity_for_device(dev, ha_players)
                if matched:
                    dev.ha_entity_id = matched
                    logger.info("Auto-linked HomePod '%s' (%s) to HA entity '%s'", dev.name, dev.ip_address, matched)

        purged = await self._purge_seeded_simulated_if_real_present()
        ip_changed = self._sync_host_ip_from_real_devices()
        if newly_added or purged or ip_changed:
            self.save_state()
            await self.restart_all_receivers()

        return {
            "airplay_discovered": airplay_found,
            "ha_entities": ha_players,
            "auto_registered_ids": newly_added,
            "host_ip": self.settings.host_ip,
        }

    def get_status_summary(self) -> Dict[str, Any]:
        return {
            "version": "0.4.7",
            "host_ip": self.settings.host_ip,
            "web_port": self.web_port,
            "ffmpeg_available": has_ffmpeg(),
            "active_receivers": len(self.receivers),
            "total_devices": len(self.devices),
            "auth": self.auth_manager.config.model_dump(),
            "ha": self.ha_client.config.model_dump(exclude={"token"}),
            "ha_has_token": bool(self.ha_client.config.token),
            "audio": self.relay_manager.config.model_dump(),
            "devices": [d.model_dump() for d in self.devices.values()],
            "events": [e.model_dump() for e in list(self.events)[:60]],
        }
