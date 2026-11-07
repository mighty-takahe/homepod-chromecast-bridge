"""Data models for PodCast Bridge."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TransportMode(str, Enum):
    """How audio is delivered to the HomePod Mini."""
    PYATV_STREAM = "pyatv_stream"          # Direct AirPlay/RAOP audio streaming via pyatv + FFmpeg
    PYATV_URL = "pyatv_url"                # Direct AirPlay URL playback via pyatv
    HA_MEDIA_PLAYER = "ha_media_player"    # Forward via Home Assistant media_player.play_media service
    SIMULATED = "simulated"                # Simulated HomePod sink for testing & diagnostics


class CastAuthMode(str, Enum):
    """How the virtual Chromecast Audio authenticates during CastV2 TLS handshake."""
    SELF_SIGNED = "self_signed"            # Generated RSA-2048 Cast cert (works with HA, MA, pychromecast, open senders)
    PRECOMPUTED_BUNDLE = "precomputed_bundle"  # Precomputed time-windowed peer cert + signature bundle (vibecast/shanocast format)
    CUSTOM_KEY = "custom_key"              # Custom donor device cert + private key


class PlayerState(str, Enum):
    """Google Cast Media player states."""
    IDLE = "IDLE"
    BUFFERING = "BUFFERING"
    PLAYING = "PLAYING"
    PAUSED = "PAUSED"


class MediaMetadata(BaseModel):
    """Current track metadata."""
    title: str = "Ready to Cast"
    artist: str = ""
    album: str = ""
    artwork_url: str = ""
    content_url: str = ""
    content_type: str = "audio/mpeg"
    duration: float = 0.0
    current_time: float = 0.0
    app_id: str = ""
    app_name: str = "Backdrop"


class HomePodDevice(BaseModel):
    """Represents a discovered or configured HomePod Mini and its virtual Chromecast Audio bridge."""
    id: str = Field(..., description="Unique identifier (derived from MAC or AirPlay device ID)")
    name: str = Field(..., description="Friendly name of the HomePod Mini")
    cast_name: str = Field(..., description="Friendly name advertised on Google Cast (_googlecast._tcp)")
    ip_address: str = Field(..., description="IPv4 address of the HomePod Mini on LAN")
    airplay_port: int = Field(default=7000, description="AirPlay / RAOP port")
    model: str = Field(default="AudioAccessory5,1", description="Apple model identifier (AudioAccessory5,1 = HomePod mini)")
    mac_address: str = Field(default="", description="Device MAC or identifier")
    enabled: bool = Field(default=True, description="Whether Chromecast Audio receiver is active for this HomePod")
    transport_mode: TransportMode = Field(default=TransportMode.PYATV_STREAM)
    ha_entity_id: Optional[str] = Field(default=None, description="Optional linked Home Assistant media_player entity")
    airplay_credentials: Optional[str] = Field(default=None, description="Stored pyatv AirPlay/RAOP credentials")
    requires_pairing: bool = Field(default=False)

    # Virtual Chromecast Audio network parameters
    cast_uuid: str = Field(default="", description="32-char hex UUID for _googlecast._tcp")
    cast_port: int = Field(default=8009, description="CastV2 TLS port")
    eureka_port: int = Field(default=8008, description="HTTP Eureka / DIAL discovery port")

    # Live state
    player_state: PlayerState = Field(default=PlayerState.IDLE)
    volume: float = Field(default=0.5, ge=0.0, le=1.0)
    muted: bool = Field(default=False)
    media: MediaMetadata = Field(default_factory=MediaMetadata)
    connected_senders: int = Field(default=0)
    last_seen: float = Field(default_factory=time.time)
    last_error: Optional[str] = Field(default=None)


class AuthWindowEntry(BaseModel):
    """A precomputed peer certificate + hardware signature window (vibecast / shanocast compatible)."""
    not_before: int = Field(default=0, description="Unix timestamp start of validity")
    not_after: int = Field(default=4102444800, description="Unix timestamp end of validity")
    peer_cert_pem: str = Field(..., description="PEM-encoded TLS peer certificate")
    peer_key_pem: str = Field(..., description="PEM-encoded TLS peer private key")
    device_cert_pem: str = Field(..., description="PEM-encoded Google Cast device certificate")
    intermediate_certs_pem: List[str] = Field(default_factory=list, description="Intermediate CA certs in PEM")
    signature_hex: str = Field(..., description="Hex-encoded SHA256 signature of the peer cert by the device key")
    signature_sha1_hex: str = Field(default="", description="Optional hex-encoded SHA1 signature for legacy senders")
    hash_algorithm: str = Field(default="SHA256", description="SHA1 or SHA256")


class CastAuthConfig(BaseModel):
    """Configuration for CastV2 device authentication."""
    mode: CastAuthMode = Field(default=CastAuthMode.PRECOMPUTED_BUNDLE)
    bundle_name: Optional[str] = Field(default="eureka_gen1_bundle_2026_2030.json")
    bundle_windows_count: int = Field(default=0)
    bundle_valid_until: Optional[int] = Field(default=None)
    custom_device_cert_pem: Optional[str] = Field(default=None)
    custom_device_key_pem: Optional[str] = Field(default=None)
    custom_intermediate_certs_pem: List[str] = Field(default_factory=list)
    enable_dial_fallback: bool = Field(default=True, description="Enable DIAL / YouTube Lounge endpoints on Eureka port")


class HomeAssistantConfig(BaseModel):
    """Configuration for Home Assistant connection."""
    enabled: bool = Field(default=True)
    url: str = Field(default="http://supervisor/core")
    token: str = Field(default="")
    auto_discover_homepods: bool = Field(default=True)
    connected: bool = Field(default=False)
    ha_version: Optional[str] = Field(default=None)
    discovered_entities: List[Dict[str, Any]] = Field(default_factory=list)


class AudioTranscodeConfig(BaseModel):
    """FFmpeg audio transcoding settings for AirPlay delivery."""
    codec: str = Field(default="wav", description="wav (PCM 16-bit 44.1kHz), mp3, aac, or flac")
    sample_rate: int = Field(default=44100)
    channels: int = Field(default=2)
    bitrate: str = Field(default="320k")
    low_latency: bool = Field(default=True)


class BridgeSettings(BaseModel):
    """Global persistent settings for PodCast Bridge."""
    host_ip: str = Field(default="", description="Auto-detected or manual LAN IPv4 address")
    base_cast_port: int = Field(default=8009, description="Starting TCP port for CastV2 TLS servers")
    base_eureka_port: int = Field(default=18008, description="Starting TCP port for Eureka/DIAL HTTP servers")
    mdns_enabled: bool = Field(default=True, description="Advertise _googlecast._tcp via mDNS")
    auto_scan_interval_sec: int = Field(default=60)
    auth: CastAuthConfig = Field(default_factory=CastAuthConfig)
    ha: HomeAssistantConfig = Field(default_factory=HomeAssistantConfig)
    audio: AudioTranscodeConfig = Field(default_factory=AudioTranscodeConfig)


class ProtocolEvent(BaseModel):
    """Real-time telemetry event for the CastV2 / AirPlay protocol inspector."""
    id: str
    timestamp: float = Field(default_factory=time.time)
    device_id: str
    device_name: str
    direction: str = Field(..., description="'cast_in', 'cast_out', 'airplay_out', 'ha_out', 'system'")
    namespace: str
    summary: str
    payload_preview: str = ""
