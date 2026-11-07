"""AirPlay & HomePod Mini Discovery, Pairing, and Audio Streaming Manager via pyatv."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional

import pyatv
from pyatv.const import Protocol

from .audio_relay import AudioRelayManager
from .models import HomePodDevice, PlayerState, TransportMode

logger = logging.getLogger(__name__)


def make_cast_uuid(identifier: str) -> str:
    """Create a deterministic 32-character hex UUID for Google Cast mDNS from a device ID."""
    return hashlib.md5(f"podcast-bridge:{identifier}".encode("utf-8")).hexdigest()


class AirPlayManager:
    """Manages HomePod Mini discovery, pairing, and audio streaming over AirPlay/RAOP."""

    def __init__(
        self,
        relay_manager: AudioRelayManager,
        ha_client: Optional[Any] = None,
        on_event: Optional[Callable[[str, str, str, str, str], None]] = None,
    ) -> None:
        self.relay = relay_manager
        self.ha_client = ha_client
        self._on_event = on_event
        self._active_connections: Dict[str, Any] = {}
        self._pairing_handlers: Dict[str, Any] = {}
        self._playback_tasks: Dict[str, asyncio.Task] = {}

    def _emit(
        self,
        device_id: str,
        device_name: str,
        direction: str,
        namespace: str,
        summary: str,
        payload_preview: str = "",
    ) -> None:
        if self._on_event:
            self._on_event(device_id, device_name, direction, namespace, summary, payload_preview)

    async def scan_network(self, timeout: int = 5, include_all_airplay: bool = True) -> List[Dict[str, Any]]:
        """Scan LAN for HomePod Minis and AirPlay receivers using pyatv."""
        loop = asyncio.get_running_loop()
        discovered: List[Dict[str, Any]] = []
        try:
            atvs = await pyatv.scan(loop, timeout=timeout)
        except Exception as exc:
            logger.warning("pyatv network scan failed: %s", exc)
            return discovered

        for dev in atvs:
            airplay_svc = dev.get_service(Protocol.AirPlay)
            raop_svc = dev.get_service(Protocol.RAOP)
            if not airplay_svc and not raop_svc:
                continue

            model_str = str(getattr(dev.device_info, "raw_model", "") or getattr(dev.device_info, "model", "") or "AirPlay")
            is_homepod = (
                "AudioAccessory" in model_str
                or "HomePod" in model_str
                or "homepod" in dev.name.lower()
            )
            if not include_all_airplay and not is_homepod:
                continue

            identifier = str(dev.identifier or dev.address)
            port = (airplay_svc.port if airplay_svc else (raop_svc.port if raop_svc else 7000)) or 7000
            mac = str(getattr(dev.device_info, "mac", "") or identifier)

            discovered.append({
                "id": f"homepod_{hashlib.sha1(identifier.encode()).hexdigest()[:10]}",
                "name": dev.name,
                "ip_address": str(dev.address),
                "airplay_port": port,
                "model": model_str if model_str != "AirPlay" else ("AudioAccessory5,1" if is_homepod else "AirPlaySpeaker"),
                "mac_address": mac,
                "is_homepod": is_homepod,
                "protocols": [p.name for p in [ s.protocol for s in dev.services ]],
            })

        return discovered

    async def start_pairing(self, device: HomePodDevice) -> Dict[str, Any]:
        """Initiate pyatv AirPlay/RAOP pairing with a HomePod Mini."""
        loop = asyncio.get_running_loop()
        atvs = await pyatv.scan(loop, hosts=[device.ip_address], timeout=4)
        if not atvs:
            raise RuntimeError(f"No AirPlay device responded at {device.ip_address}")

        conf = atvs[0]
        protocol = Protocol.AirPlay if conf.get_service(Protocol.AirPlay) else Protocol.RAOP
        pairing = await pyatv.pair(conf, protocol, loop)
        await pairing.begin()
        self._pairing_handlers[device.id] = (pairing, protocol)
        self._emit(
            device.id,
            device.name,
            "airplay_out",
            "pyatv.pair",
            f"Initiated {protocol.name} pairing with {device.ip_address}",
        )
        return {
            "device_id": device.id,
            "protocol": protocol.name,
            "device_provides_pin": pairing.device_provides_pin,
        }

    async def finish_pairing(self, device: HomePodDevice, pin: str) -> str:
        """Complete pyatv AirPlay pairing using the PIN code and return credentials."""
        entry = self._pairing_handlers.pop(device.id, None)
        if not entry:
            raise RuntimeError("No active pairing session for this device")
        pairing, protocol = entry
        try:
            pairing.pin(int(pin))
            await pairing.finish()
            if not pairing.has_paired:
                raise RuntimeError("Pairing was rejected by the HomePod")
            creds = str(pairing.service.credentials)
            device.airplay_credentials = creds
            device.requires_pairing = False
            self._emit(
                device.id,
                device.name,
                "airplay_out",
                "pyatv.pair",
                f"Completed {protocol.name} pairing successfully",
            )
            return creds
        finally:
            await pairing.close()

    async def _connect_pyatv(
        self,
        device: HomePodDevice,
        protocol_version: Any = None,
    ) -> Any:
        """Connect to a physical HomePod Mini via pyatv with MRP tunnel disabled and unicast mDNS fallback."""
        from ipaddress import IPv4Address
        from pyatv.conf import AppleTV
        from pyatv.core import MutableService
        from pyatv.settings import AirPlayVersion, MrpTunnel
        from pyatv.storage.memory_storage import MemoryStorage

        loop = asyncio.get_running_loop()
        conf: Optional[Any] = None
        try:
            atvs = await pyatv.scan(loop, hosts=[device.ip_address], timeout=3)
            if atvs:
                conf = atvs[0]
        except Exception as exc:
            logger.debug("pyatv scan for %s (%s) notice: %s", device.name, device.ip_address, exc)

        if not conf:
            # Fallback to direct AppleTV config when unicast mDNS is blocked by router
            try:
                ip_obj = IPv4Address(device.ip_address)
            except Exception:
                raise RuntimeError(f"Invalid HomePod IPv4 address: {device.ip_address}")
            conf = AppleTV(ip_obj, device.name)
            props = {
                "am": device.model or "AudioAccessory5,1",
                "model": device.model or "AudioAccessory5,1",
                "ch": "2",
                "ss": "16",
                "sr": "44100",
                "tp": "UDP",
            }
            conf.add_service(MutableService(device.mac_address or "AA:BB:CC:DD:EE:FF", Protocol.RAOP, device.airplay_port, props))
            conf.add_service(MutableService(device.mac_address or "AA:BB:CC:DD:EE:FF", Protocol.AirPlay, device.airplay_port, props))

        if device.airplay_credentials:
            for proto in (Protocol.AirPlay, Protocol.RAOP, Protocol.Companion):
                if conf.get_service(proto):
                    conf.set_credentials(proto, device.airplay_credentials)

        storage = MemoryStorage()
        settings = await storage.get_settings(conf)
        # CRITICAL: Disable MRP tunnel to prevent remote control handshake failures on HomePods
        settings.protocols.airplay.mrp_tunnel = MrpTunnel.Disable
        settings.protocols.raop.protocol_version = protocol_version or AirPlayVersion.Auto

        atv = await pyatv.connect(conf, loop, storage=storage)
        return atv

    async def play_stream(
        self,
        device: HomePodDevice,
        source_url: str,
        relay_url: str,
        start_time: float = 0.0,
    ) -> None:
        """Start streaming audio to the HomePod Mini via the configured AirPlay transport."""
        from pyatv.settings import AirPlayVersion

        await self.stop(device, emit_event=False)
        self.relay.register_source(device.id, source_url)
        device.player_state = PlayerState.PLAYING
        device.media.current_time = start_time
        device.last_error = None

        async def _runner() -> None:
            if device.transport_mode == TransportMode.SIMULATED:
                self._emit(
                    device.id,
                    device.name,
                    "airplay_out",
                    "raop.stream",
                    f"Streaming audio to HomePod Mini ({device.ip_address}:{device.airplay_port}) [44.1kHz 16-bit PCM]",
                    f"source={source_url} relay={relay_url}",
                )
                bytes_streamed = 0
                async for chunk in self.relay.stream_transcoded(device.id, source_url, start_time=start_time):
                    bytes_streamed += len(chunk)
                    if bytes_streamed >= 32768:
                        break
                t0 = time.monotonic() - start_time
                while device.player_state in (PlayerState.PLAYING, PlayerState.PAUSED):
                    if device.player_state == PlayerState.PLAYING:
                        device.media.current_time = round(time.monotonic() - t0, 2)
                        if device.media.duration > 0 and device.media.current_time >= device.media.duration:
                            device.player_state = PlayerState.IDLE
                            device.media.current_time = 0.0
                            break
                    else:
                        t0 = time.monotonic() - device.media.current_time
                    await asyncio.sleep(0.5)
                return

            if device.transport_mode == TransportMode.HA_MEDIA_PLAYER and device.ha_entity_id and self.ha_client:
                self._emit(
                    device.id,
                    device.name,
                    "ha_out",
                    "media_player.play_media",
                    f"Routing Cast audio via Home Assistant to {device.ha_entity_id}",
                    f"url={relay_url}",
                )
                ok = await self.ha_client.play_media(device, relay_url)
                if not ok:
                    device.last_error = f"Home Assistant service call failed for {device.ha_entity_id}"
                return

            # Physical HomePod Mini streaming via pyatv (trying AirPlay 2 then AirPlay 1)
            pyatv_err: Optional[Exception] = None
            for p_ver in (AirPlayVersion.Auto, AirPlayVersion.V1):
                atv = None
                try:
                    self._emit(
                        device.id,
                        device.name,
                        "airplay_out",
                        "pyatv.connect",
                        f"Connecting to HomePod Mini ({device.ip_address}:{device.airplay_port}) [AirPlay {p_ver.value}]",
                        f"url={source_url}",
                    )
                    atv = await self._connect_pyatv(device, protocol_version=p_ver)
                    self._active_connections[device.id] = atv

                    # Ensure volume is unmuted and audible (at least 35% on physical speaker)
                    vol_pct = max(35.0, float((device.volume if not device.muted else 0.5) * 100.0))
                    try:
                        await atv.audio.set_volume(vol_pct)
                    except Exception as v_err:
                        logger.debug("Initial volume set notice: %s", v_err)

                    if device.transport_mode == TransportMode.PYATV_URL:
                        await atv.stream.play_url(relay_url, position=int(start_time))
                    else:
                        # Write audio chunks to temp WAV file and stream over RAOP
                        with tempfile.NamedTemporaryFile(suffix=".wav", delete=True) as tmp:
                            if source_url.endswith("/test-chime.wav") or source_url.startswith("builtin://"):
                                tmp.write(self.relay.get_test_chime_bytes())
                            else:
                                async for chunk in self.relay.stream_transcoded(device.id, source_url, codec="wav", start_time=start_time):
                                    tmp.write(chunk)
                            tmp.flush()
                            try:
                                os.fsync(tmp.fileno())
                            except Exception:
                                pass
                            self._emit(
                                device.id,
                                device.name,
                                "airplay_out",
                                "raop.stream",
                                f"Delivering PCM audio to HomePod Mini via AirPlay ({p_ver.value})",
                            )
                            await atv.stream.stream_file(tmp.name)
                            # Allow HomePod internal AirPlay buffer (1.5-2.0s) to play completely before teardown
                            await asyncio.sleep(1.0)

                    device.player_state = PlayerState.IDLE
                    device.last_error = None
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    pyatv_err = exc
                    logger.warning("pyatv stream (%s) to %s (%s) error: %s", p_ver.value, device.name, device.ip_address, exc)
                finally:
                    if atv:
                        try:
                            atv.close()
                        except Exception:
                            pass
                    self._active_connections.pop(device.id, None)

            # If direct pyatv streaming encountered an error, fall back to Home Assistant media_player if linked
            if device.ha_entity_id and self.ha_client and self.ha_client.config.connected:
                self._emit(
                    device.id,
                    device.name,
                    "ha_out",
                    "media_player.fallback",
                    f"Direct AirPlay hit permission notice; falling back to Home Assistant ({device.ha_entity_id})",
                )
                logger.info("pyatv direct streaming failed (%s); falling back to HA media_player -> %s", pyatv_err, device.ha_entity_id)
                ok = await self.ha_client.play_media(device, relay_url)
                if ok:
                    device.last_error = None
                    return

            # Both direct AirPlay and HA fallback failed
            err_msg = str(pyatv_err or "Unknown AirPlay streaming error")
            device.last_error = err_msg
            self._emit(
                device.id,
                device.name,
                "airplay_out",
                "pyatv.error",
                f"AirPlay error: {err_msg} — Check Apple Home App 'Allow Speaker Access: Anyone on the Same Network'",
            )
            # Advance virtual timeline so Cast sender isn't abruptly severed
            t0 = time.monotonic() - start_time
            while device.player_state in (PlayerState.PLAYING, PlayerState.PAUSED):
                if device.player_state == PlayerState.PLAYING:
                    device.media.current_time = round(time.monotonic() - t0, 2)
                else:
                    t0 = time.monotonic() - device.media.current_time
                await asyncio.sleep(0.5)

        task = asyncio.create_task(_runner())
        self._playback_tasks[device.id] = task

    async def pause(self, device: HomePodDevice) -> None:
        """Pause playback on the HomePod Mini."""
        device.player_state = PlayerState.PAUSED
        self._emit(device.id, device.name, "airplay_out", "airplay.control", "PAUSE -> HomePod Mini")
        atv = self._active_connections.get(device.id)
        if atv:
            try:
                await atv.remote_control.pause()
            except Exception as exc:
                logger.debug("pyatv pause ignored: %s", exc)

    async def resume(self, device: HomePodDevice) -> None:
        """Resume playback on the HomePod Mini."""
        device.player_state = PlayerState.PLAYING
        self._emit(device.id, device.name, "airplay_out", "airplay.control", "PLAY -> HomePod Mini")
        atv = self._active_connections.get(device.id)
        if atv:
            try:
                await atv.remote_control.play()
            except Exception as exc:
                logger.debug("pyatv play ignored: %s", exc)

    async def seek(self, device: HomePodDevice, position: float) -> None:
        """Seek playback position on the HomePod Mini."""
        device.media.current_time = max(0.0, float(position))
        self._emit(
            device.id,
            device.name,
            "airplay_out",
            "airplay.control",
            f"SEEK to {device.media.current_time:.1f}s -> HomePod Mini",
        )
        atv = self._active_connections.get(device.id)
        if atv:
            try:
                await atv.remote_control.set_position(int(position))
            except Exception as exc:
                logger.debug("pyatv seek ignored: %s", exc)

    async def set_volume(self, device: HomePodDevice, level: float, muted: Optional[bool] = None) -> None:
        """Set volume (0.0 to 1.0) on the HomePod Mini via AirPlay audio control."""
        device.volume = round(max(0.0, min(1.0, float(level))), 3)
        if muted is not None:
            device.muted = bool(muted)
        vol_pct = 0.0 if device.muted else round(device.volume * 100.0, 1)
        self._emit(
            device.id,
            device.name,
            "airplay_out",
            "airplay.volume",
            f"SET_VOLUME {vol_pct:.0f}% (muted={device.muted}) -> HomePod Mini",
        )
        atv = self._active_connections.get(device.id)
        if atv:
            try:
                await atv.audio.set_volume(vol_pct)
            except Exception as exc:
                logger.debug("pyatv set_volume ignored: %s", exc)

    async def stop(self, device: HomePodDevice, emit_event: bool = True) -> None:
        """Stop active AirPlay stream for the device."""
        task = self._playback_tasks.pop(device.id, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await self.relay.stop_device_stream(device.id)
        device.player_state = PlayerState.IDLE
        device.media.current_time = 0.0
        if emit_event:
            self._emit(device.id, device.name, "airplay_out", "airplay.control", "STOP -> HomePod Mini")
        atv = self._active_connections.get(device.id)
        if atv:
            try:
                await atv.remote_control.stop()
            except Exception:
                pass

    async def close_all(self) -> None:
        """Cleanly close all playback tasks and pyatv connections."""
        for dev_id in list(self._playback_tasks.keys()):
            task = self._playback_tasks.pop(dev_id, None)
            if task and not task.done():
                task.cancel()
        for dev_id, atv in list(self._active_connections.items()):
            try:
                atv.close()
            except Exception:
                pass
        self._active_connections.clear()
