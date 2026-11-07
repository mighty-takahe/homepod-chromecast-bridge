# PodCast Bridge — Expose HomePod Minis as Chromecast Audio Devices

**PodCast Bridge** is a Home Assistant Add-on and standalone Docker service that exposes Apple **HomePod Minis** (and other AirPlay / RAOP speakers) as virtual **Google Cast (`Chromecast Audio`)** receivers on your local network.

---

## Architecture

```
Google Cast Sender (Android, Chrome, Home Assistant, Music Assistant, Audiobookshelf, etc.)
   │
   ├─ mDNS Discovery: _googlecast._tcp.local. (md="Chromecast Audio", ca=4)
   ├─ Eureka / DIAL HTTP (:18008+) ──► /setup/eureka_info, /ssdp/device-desc.xml, /apps/*
   └─ CastV2 TLS Server (:8009+) ────► cast_channel.proto
        ├── urn:x-cast:com.google.cast.tp.deviceauth  (DeviceAuthMessage PKI / Bundle Signing)
        ├── urn:x-cast:com.google.cast.tp.heartbeat   (PING / PONG)
        ├── urn:x-cast:com.google.cast.receiver       (GET_STATUS, LAUNCH, SET_VOLUME, STOP)
        ├── urn:x-cast:com.google.cast.media          (LOAD, PLAY, PAUSE, SEEK, QUEUE_*)
        └── urn:x-cast:com.google.youtube.mdx         (YouTube / YouTube Music Lounge screenId)
                │
                ▼
       FFmpeg On-the-Fly Audio Relay (/api/relay/<device_id>/stream.wav|mp3|aac|flac)
                │
                ├──► Direct AirPlay / RAOP Stream via pyatv (HomePod Mini :7000)
                └──► Home Assistant media_player.play_media Service API
```

---

## Features

1. **Per-Speaker Virtual Chromecast Audio Receiver**:
   - Every bridged HomePod Mini gets its own `_googlecast._tcp.local.` mDNS advertisement (`md=Chromecast Audio`, `ca=4` audio-only capability), CastV2 TLS server (`8009+`), and Eureka/DIAL HTTP server (`18008+`).
2. **Dual Discovery & Audio Routing**:
   - **Direct AirPlay (`pyatv` + FFmpeg)**: Scans the local network via mDNS (`_airplay._tcp` / `_raop._tcp`), supports interactive 4-digit PIN pairing, and streams 44.1 kHz 16-bit stereo audio directly to the HomePod Mini.
   - **Home Assistant `media_player` Link**: Auto-detects `SUPERVISOR_TOKEN` when installed as a Home Assistant Add-on (or uses a Long-Lived Access Token) to discover `media_player.*` entities and forward playback, pause, resume, seek, and volume synchronization.
3. **Pluggable CastV2 Device Authentication**:
   - **Self-Signed Cast PKI Mode (Default)**: Generates a persistent Cast Root CA, Eureka Gen1 ICA, Device Auth Certificate, and TLS Peer Certificate, dynamically signing `(sender_nonce || peer_cert_der)`. Works out of the box with Home Assistant's Google Cast integration, Music Assistant, `pychromecast`, custom senders, and DIAL/YouTube Lounge.
   - **Precomputed Certificate Window Bundle Mode**: Compatible with `vibecast` / `shanocast` / `cast-audio-receiver-lab` JSON bundles containing time-windowed TLS peer certificates and hardware signatures required by strict Android/Chrome senders.
4. **Web UI Dashboard & Live Protocol Inspector**:
   - Built-in Home Assistant Ingress & standalone dashboard (`http://<host>:8788`) with live CastV2 protobuf packet inspection, volume & transport controls, AirPlay PIN pairing, and a one-click **Test CastV2 Session** verifier.

---

## HomePod Mini Prerequisite (Apple Home App)

To allow Linux / Home Assistant (`pyatv`) to stream to your HomePod Minis without per-session iCloud token prompts:
1. Open the **Home** app on your iPhone, iPad, or Mac.
2. Tap the **More (`...`)** button &rarr; **Home Settings** &rarr; **Speakers & TV**.
3. Set access to **Everyone** or **Anyone on the Same Network** (and disable *Require Password*).

---

## Installation

### Option 1: Home Assistant Add-on
1. Copy or clone this repository into your Home Assistant `/addons/podcast_bridge` folder (or add the repository URL in **Settings &rarr; Add-ons &rarr; Add-on Store &rarr; Repositories**).
2. Install **PodCast: HomePod to Chromecast Audio Bridge** and click **Start**.
3. Click **Open Web UI** (or enable *Show in sidebar*).

### Option 2: Standalone Docker Compose
```bash
docker compose up -d --build
```
Then open `http://<YOUR_LAN_IP>:8788`. Note that `network_mode: host` is required so mDNS (`5353/udp`) and CastV2 TLS ports (`8009+/tcp`) are reachable on your LAN.

### Option 3: Local Python Virtual Environment
```bash
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"
PYTHONPATH=src .venv/bin/uvicorn podcast_bridge.app:app --host 0.0.0.0 --port 8788
```
