"""Home Assistant REST API Integration Client.

Works both inside Home Assistant Supervisor (auto-detecting SUPERVISOR_TOKEN)
and standalone via a Long-Lived Access Token.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional

import httpx

from .models import HomeAssistantConfig, HomePodDevice

logger = logging.getLogger(__name__)


class HomeAssistantClient:
    """Interfaces with Home Assistant's REST API for entity discovery and media_player routing."""

    def __init__(
        self,
        config: Optional[HomeAssistantConfig] = None,
        on_event: Optional[Callable[[str, str, str, str, str], None]] = None,
    ) -> None:
        self.config = config or HomeAssistantConfig()
        self._on_event = on_event

        # Auto-detect Home Assistant Supervisor token if available
        supervisor_token = os.environ.get("SUPERVISOR_TOKEN") or os.environ.get("HASSIO_TOKEN")
        if supervisor_token and not self.config.token:
            self.config.token = supervisor_token
            self.config.url = os.environ.get("HA_URL", "http://supervisor/core")

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

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    def _api_base(self) -> str:
        base = self.config.url.rstrip("/")
        if not base.endswith("/api"):
            return f"{base}/api"
        return base

    async def check_connection(self) -> Dict[str, Any]:
        """Verify connectivity to Home Assistant API and discover media_player entities."""
        if not self.config.enabled or not self.config.token:
            self.config.connected = False
            return {"connected": False, "reason": "No Home Assistant token configured"}

        try:
            async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                resp = await client.get(f"{self._api_base()}/", headers=self._headers())
                if resp.status_code == 200:
                    data = resp.json()
                    self.config.connected = True
                    self.config.ha_version = data.get("version", "Connected")
                    entities = await self.discover_media_players()
                    return {
                        "connected": True,
                        "message": data.get("message", "API running."),
                        "entities_count": len(entities),
                    }
                self.config.connected = False
                return {"connected": False, "reason": f"HTTP {resp.status_code}"}
        except Exception as exc:
            self.config.connected = False
            return {"connected": False, "reason": str(exc)}

    async def discover_media_players(self) -> List[Dict[str, Any]]:
        """Query Home Assistant `/api/states` for media_player entities (prioritizing HomePods)."""
        if not self.config.token:
            return []

        players: List[Dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=6.0, trust_env=False) as client:
                resp = await client.get(f"{self._api_base()}/states", headers=self._headers())
                if resp.status_code != 200:
                    return []
                states = resp.json()
                for st in states:
                    entity_id = st.get("entity_id", "")
                    if not entity_id.startswith("media_player."):
                        continue
                    attrs = st.get("attributes", {})
                    friendly_name = attrs.get("friendly_name", entity_id)
                    is_homepod = any(
                        kw in (friendly_name.lower() + " " + entity_id.lower())
                        for kw in ("homepod", "airplay", "apple", "mini")
                    )
                    players.append({
                        "entity_id": entity_id,
                        "friendly_name": friendly_name,
                        "state": st.get("state", "unknown"),
                        "is_homepod": is_homepod,
                        "volume_level": attrs.get("volume_level"),
                        "device_class": attrs.get("device_class", "speaker"),
                    })
        except Exception as exc:
            logger.debug("HA media_player discovery failed: %s", exc)

        players.sort(key=lambda x: (not x["is_homepod"], x["friendly_name"]))
        self.config.discovered_entities = players
        return players

    async def call_service(
        self,
        domain: str,
        service: str,
        service_data: Dict[str, Any],
        device: Optional[HomePodDevice] = None,
    ) -> bool:
        """Call a Home Assistant service (`/api/services/<domain>/<service>`)."""
        if device:
            self._emit(
                device.id,
                device.name,
                "ha_out",
                f"ha.{domain}.{service}",
                f"Home Assistant {domain}.{service} -> {service_data.get('entity_id')}",
                str(service_data),
            )

        if not self.config.token:
            return False

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.post(
                    f"{self._api_base()}/services/{domain}/{service}",
                    headers=self._headers(),
                    json=service_data,
                )
                return resp.status_code in (200, 201)
        except Exception as exc:
            logger.warning("HA service call %s.%s failed: %s", domain, service, exc)
            return False

    async def play_media(self, device: HomePodDevice, media_url: str, content_type: str = "music") -> bool:
        if not device.ha_entity_id:
            return False
        return await self.call_service(
            "media_player",
            "play_media",
            {
                "entity_id": device.ha_entity_id,
                "media_content_id": media_url,
                "media_content_type": content_type,
                "extra": {
                    "title": device.media.title,
                    "thumb": device.media.artwork_url,
                },
            },
            device=device,
        )

    async def pause(self, device: HomePodDevice) -> bool:
        if not device.ha_entity_id:
            return False
        return await self.call_service(
            "media_player",
            "media_pause",
            {"entity_id": device.ha_entity_id},
            device=device,
        )

    async def resume(self, device: HomePodDevice) -> bool:
        if not device.ha_entity_id:
            return False
        return await self.call_service(
            "media_player",
            "media_play",
            {"entity_id": device.ha_entity_id},
            device=device,
        )

    async def stop(self, device: HomePodDevice) -> bool:
        if not device.ha_entity_id:
            return False
        return await self.call_service(
            "media_player",
            "media_stop",
            {"entity_id": device.ha_entity_id},
            device=device,
        )

    async def seek(self, device: HomePodDevice, position: float) -> bool:
        if not device.ha_entity_id:
            return False
        return await self.call_service(
            "media_player",
            "media_seek",
            {"entity_id": device.ha_entity_id, "seek_position": float(position)},
            device=device,
        )

    async def set_volume(self, device: HomePodDevice, level: float, muted: Optional[bool] = None) -> bool:
        if not device.ha_entity_id:
            return False
        ok = await self.call_service(
            "media_player",
            "volume_set",
            {"entity_id": device.ha_entity_id, "volume_level": round(float(level), 3)},
            device=device,
        )
        if muted is not None:
            await self.call_service(
                "media_player",
                "volume_mute",
                {"entity_id": device.ha_entity_id, "is_volume_muted": bool(muted)},
                device=device,
            )
        return ok
