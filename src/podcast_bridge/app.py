"""FastAPI Web Server, Home Assistant Ingress Dashboard, and HTTP Audio Relay."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import io
import os
from pathlib import Path
import tarfile
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .bridge_manager import BridgeManager
from .models import CastAuthMode, TransportMode

STATIC_DIR = Path(__file__).parent / "static"


class CreateDeviceRequest(BaseModel):
    name: str
    ip_address: str
    cast_name: Optional[str] = None
    airplay_port: int = 7000
    model: str = "AudioAccessory5,1"
    mac_address: str = ""
    transport_mode: TransportMode = TransportMode.PYATV_STREAM
    ha_entity_id: Optional[str] = None
    enabled: bool = True


class UpdateDeviceRequest(BaseModel):
    name: Optional[str] = None
    cast_name: Optional[str] = None
    ip_address: Optional[str] = None
    airplay_port: Optional[int] = None
    model: Optional[str] = None
    transport_mode: Optional[TransportMode] = None
    ha_entity_id: Optional[str] = None
    enabled: Optional[bool] = None
    airplay_credentials: Optional[str] = None


class ControlDeviceRequest(BaseModel):
    action: str  # "play", "pause", "stop", "seek", "volume"
    value: Optional[float] = None
    muted: Optional[bool] = None


class TestCastRequest(BaseModel):
    custom_url: Optional[str] = None
    title: Optional[str] = None


class PairingFinishRequest(BaseModel):
    pin: str


class UpdateSettingsRequest(BaseModel):
    host_ip: Optional[str] = None
    auth_mode: Optional[CastAuthMode] = None
    ha_enabled: Optional[bool] = None
    ha_url: Optional[str] = None
    ha_token: Optional[str] = None
    audio_codec: Optional[str] = None
    audio_sample_rate: Optional[int] = None
    audio_bitrate: Optional[str] = None


class GitHubPublishRequest(BaseModel):
    token: str
    repo_name: str = "homepod-chromecast-bridge"
    private: bool = False


def create_app(
    data_dir: Optional[Path] = None,
    web_port: Optional[int] = None,
    mdns_enabled: bool = True,
) -> FastAPI:
    port = web_port or int(os.environ.get("PODCAST_WEB_PORT", "8788"))
    manager = BridgeManager(data_dir=data_dir, web_port=port, mdns_enabled=mdns_enabled)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await manager.start(seed_default_if_empty=True)
        yield
        await manager.stop()

    app = FastAPI(
        title="PodCast Bridge — HomePod Mini to Chromecast Audio",
        version="0.4.7",
        lifespan=lifespan,
    )
    app.state.bridge = manager

    # --- API Routes ---

    @app.get("/api/status")
    async def get_status() -> Dict[str, Any]:
        return manager.get_status_summary()

    @app.post("/api/scan")
    async def scan_network() -> Dict[str, Any]:
        return await manager.scan_all()

    @app.post("/api/devices")
    async def add_device(req: CreateDeviceRequest) -> Dict[str, Any]:
        dev = await manager.register_device(
            name=req.name,
            ip_address=req.ip_address,
            cast_name=req.cast_name,
            airplay_port=req.airplay_port,
            model=req.model,
            mac_address=req.mac_address,
            transport_mode=req.transport_mode,
            ha_entity_id=req.ha_entity_id,
            enabled=req.enabled,
            start_immediately=True,
        )
        return dev.model_dump()

    @app.patch("/api/devices/{device_id}")
    async def update_device(device_id: str, req: UpdateDeviceRequest) -> Dict[str, Any]:
        try:
            dev = await manager.update_device(device_id, req.model_dump(exclude_unset=True))
            return dev.model_dump()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

    @app.delete("/api/devices/{device_id}")
    async def remove_device(device_id: str) -> Dict[str, Any]:
        await manager.delete_device(device_id)
        return {"deleted": device_id}

    @app.post("/api/devices/{device_id}/control")
    async def control_device(device_id: str, req: ControlDeviceRequest) -> Dict[str, Any]:
        dev = manager.devices.get(device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")
        receiver = manager.receivers.get(device_id)

        if req.action == "pause":
            await manager._handle_cast_pause(dev)
        elif req.action == "play":
            await manager._handle_cast_resume(dev)
        elif req.action == "stop":
            await manager._handle_cast_stop(dev)
        elif req.action == "seek" and req.value is not None:
            await manager._handle_cast_seek(dev, float(req.value))
        elif req.action == "volume":
            vol = req.value if req.value is not None else dev.volume
            await manager._handle_cast_volume(dev, float(vol), req.muted)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported action: {req.action}")

        if receiver:
            await receiver.broadcast_media_status()
            await receiver.broadcast_receiver_status()

        return dev.model_dump()

    @app.post("/api/devices/{device_id}/test-cast")
    async def trigger_test_cast(device_id: str, req: Optional[TestCastRequest] = None) -> Dict[str, Any]:
        try:
            custom_url = req.custom_url if req else None
            title = req.title if req else None
            return await manager.test_cast_to_device(device_id, custom_url=custom_url, title=title)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/devices/{device_id}/pair/start")
    async def start_airplay_pairing(device_id: str) -> Dict[str, Any]:
        dev = manager.devices.get(device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")
        try:
            return await manager.airplay_manager.start_pairing(dev)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/devices/{device_id}/pair/finish")
    async def finish_airplay_pairing(device_id: str, req: PairingFinishRequest) -> Dict[str, Any]:
        dev = manager.devices.get(device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")
        try:
            creds = await manager.airplay_manager.finish_pairing(dev, req.pin)
            manager.save_state()
            return {"ok": True, "credentials_saved": bool(creds)}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/settings")
    async def update_settings(req: UpdateSettingsRequest) -> Dict[str, Any]:
        restart_receivers = False
        if req.host_ip and req.host_ip.strip() != manager.settings.host_ip:
            manager.settings.host_ip = req.host_ip.strip()
            restart_receivers = True
        if req.auth_mode and req.auth_mode != manager.auth_manager.config.mode:
            manager.auth_manager.config.mode = req.auth_mode
            manager.settings.auth.mode = req.auth_mode
            restart_receivers = True
        if req.ha_enabled is not None:
            manager.ha_client.config.enabled = req.ha_enabled
            manager.settings.ha.enabled = req.ha_enabled
        if req.ha_url:
            manager.ha_client.config.url = req.ha_url.strip()
            manager.settings.ha.url = req.ha_url.strip()
        if req.ha_token is not None and req.ha_token != "":
            manager.ha_client.config.token = req.ha_token.strip()
            manager.settings.ha.token = req.ha_token.strip()
        if req.audio_codec:
            manager.relay_manager.config.codec = req.audio_codec
            manager.settings.audio.codec = req.audio_codec
        if req.audio_sample_rate:
            manager.relay_manager.config.sample_rate = req.audio_sample_rate
            manager.settings.audio.sample_rate = req.audio_sample_rate
        if req.audio_bitrate:
            manager.relay_manager.config.bitrate = req.audio_bitrate
            manager.settings.audio.bitrate = req.audio_bitrate

        if restart_receivers:
            await manager.restart_all_receivers()
        await manager.ha_client.check_connection()
        manager.save_state()
        return manager.get_status_summary()

    @app.post("/api/auth/bundle")
    async def upload_auth_bundle(request: Request) -> Dict[str, Any]:
        try:
            body = await request.json()
            name = body.get("name", "uploaded_bundle.json")
            res = manager.auth_manager.import_auth_bundle(body, name=name)
            manager.settings.auth = manager.auth_manager.config
            await manager.restart_all_receivers()
            manager.save_state()
            return res
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/auth/bundle/load-eureka")
    async def load_builtin_eureka_bundle() -> Dict[str, Any]:
        try:
            res = manager.auth_manager.load_builtin_eureka_bundle(persist=True)
            manager.settings.auth = manager.auth_manager.config
            await manager.restart_all_receivers()
            manager.save_state()
            return res
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/auth/bundle/download-public")
    async def download_public_bundle() -> Dict[str, Any]:
        try:
            res = await manager.auth_manager.download_public_auth_bundle()
            manager.settings.auth = manager.auth_manager.config
            await manager.restart_all_receivers()
            manager.save_state()
            return res
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/api/auth/bundle/generate-sample")
    async def generate_sample_bundle() -> Dict[str, Any]:
        res = manager.auth_manager.generate_sample_precomputed_bundle()
        manager.settings.auth = manager.auth_manager.config
        await manager.restart_all_receivers()
        manager.save_state()
        return res

    # --- Audio Stream Relay Endpoints ---

    @app.api_route("/api/relay/test-chime.wav", methods=["GET", "HEAD"])
    async def serve_test_chime(request: Request) -> Response:
        wav_bytes = manager.relay_manager.get_test_chime_bytes()
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Length": str(len(wav_bytes)),
            "Content-Type": "audio/wav",
        }
        if request.method == "HEAD":
            return Response(content=b"", headers=headers, media_type="audio/wav")
        return Response(content=wav_bytes, headers=headers, media_type="audio/wav")

    @app.get("/api/relay/{device_id}/stream.{ext}")
    async def serve_device_relay_stream(device_id: str, ext: str) -> StreamingResponse:
        media_types = {
            "wav": "audio/wav",
            "mp3": "audio/mpeg",
            "aac": "audio/aac",
            "flac": "audio/flac",
        }
        mime = media_types.get(ext.lower(), "audio/wav")
        stream_headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Accept-Ranges": "none",
        }
        return StreamingResponse(
            manager.relay_manager.stream_transcoded(device_id, codec=ext.lower()),
            media_type=mime,
            headers=stream_headers,
        )

    @app.get("/api/download/homepod-chromecast-bridge.tar.gz")
    async def download_addon_archive() -> Response:
        """Package the entire Home Assistant Add-on & Docker repository as a downloadable .tar.gz."""
        repo_root = Path(__file__).resolve().parents[2]
        buf = io.BytesIO()
        exclude_dirs = {".venv", ".git", "__pycache__", ".pytest_cache", "data"}
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for item in sorted(repo_root.rglob("*")):
                rel_parts = item.relative_to(repo_root).parts
                if any(part in exclude_dirs or part.endswith(".egg-info") for part in rel_parts):
                    continue
                if item.is_file():
                    tar.add(item, arcname=f"homepod-chromecast-bridge/{item.relative_to(repo_root)}")
        return Response(
            content=buf.getvalue(),
            media_type="application/gzip",
            headers={"Content-Disposition": 'attachment; filename="homepod-chromecast-bridge.tar.gz"'},
        )

    @app.post("/api/github/publish")
    async def publish_to_github(req: GitHubPublishRequest) -> Dict[str, Any]:
        """Create and push the Home Assistant Add-on repository to GitHub using the Git Data REST API."""
        import base64 as _b64
        import subprocess as _sp

        token = req.token.strip()
        if not token:
            raise HTTPException(status_code=400, detail="GitHub Personal Access Token is required")
        repo_name = req.repo_name.strip() or "homepod-chromecast-bridge"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        repo_root = Path(__file__).resolve().parents[2]

        import os as _os
        _os.environ["NO_PROXY"] = "localhost,127.0.0.1"
        _os.environ["no_proxy"] = "localhost,127.0.0.1"

        async with httpx.AsyncClient(base_url="https://api.github.com", headers=headers, timeout=60.0, trust_env=True) as client:
            u_resp = await client.get("/user")
            if u_resp.status_code != 200:
                raise HTTPException(status_code=u_resp.status_code, detail="Invalid or expired GitHub token")
            owner = u_resp.json().get("login")

            await client.post(
                "/user/repos",
                json={
                    "name": repo_name,
                    "description": "Home Assistant Add-on & Docker bridge that exposes Apple HomePod Minis as Google Cast (Chromecast Audio) devices",
                    "private": bool(req.private),
                    "auto_init": True,
                },
            )

            ref_resp = await client.get(f"/repos/{owner}/{repo_name}/git/ref/heads/main")
            parent_sha = ref_resp.json()["object"]["sha"] if ref_resp.status_code == 200 else None

            files = _sp.check_output(["git", "ls-files"], cwd=str(repo_root)).decode().splitlines()
            addon_files = [
                "config.yaml", "Dockerfile", "run.sh", "requirements.txt", "pyproject.toml", "README.md"
            ] + [f for f in files if f.startswith("src/")]

            tree_items = []
            blob_cache: Dict[str, str] = {}
            for rel_path in files:
                raw = (repo_root / rel_path).read_bytes()
                b64 = _b64.b64encode(raw).decode("ascii")
                b_resp = await client.post(f"/repos/{owner}/{repo_name}/git/blobs", json={"content": b64, "encoding": "base64"})
                b_resp.raise_for_status()
                sha = b_resp.json()["sha"]
                blob_cache[rel_path] = sha
                mode = "100755" if rel_path.endswith(".sh") else "100644"
                tree_items.append({"path": rel_path, "mode": mode, "type": "blob", "sha": sha})

            for rel_path in addon_files:
                if rel_path in blob_cache:
                    mode = "100755" if rel_path.endswith(".sh") else "100644"
                    tree_items.append({"path": f"podcast_bridge/{rel_path}", "mode": mode, "type": "blob", "sha": blob_cache[rel_path]})

            t_resp = await client.post(f"/repos/{owner}/{repo_name}/git/trees", json={"tree": tree_items})
            t_resp.raise_for_status()
            tree_sha = t_resp.json()["sha"]

            commit_payload: Dict[str, Any] = {
                "message": "v0.3.0: Fix mDNS cd cert digest, RawMdnsAdvertiser, Eureka :8008/:8443, and NS_SETUP/NS_DISCOVERY wire payloads",
                "tree": tree_sha,
            }
            if parent_sha:
                commit_payload["parents"] = [parent_sha]
            c_resp = await client.post(f"/repos/{owner}/{repo_name}/git/commits", json=commit_payload)
            c_resp.raise_for_status()
            commit_sha = c_resp.json()["sha"]

            if parent_sha:
                await client.patch(f"/repos/{owner}/{repo_name}/git/refs/heads/main", json={"sha": commit_sha, "force": True})
            else:
                await client.post(f"/repos/{owner}/{repo_name}/git/refs", json={"ref": "refs/heads/main", "sha": commit_sha})

        html_url = f"https://github.com/{owner}/{repo_name}"
        return {"ok": True, "owner": owner, "repo": repo_name, "url": html_url, "commit": commit_sha}

    # --- Real-time WebSocket Telemetry ---

    @app.websocket("/api/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        q = manager.subscribe_ws()
        try:
            await ws.send_json({"type": "initial_state", "state": manager.get_status_summary()})
            while True:
                msg = await q.get()
                await ws.send_json(msg)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            manager.unsubscribe_ws(q)

    # --- Static Frontend Routes (Ingress & Direct compatible) ---

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/styles.css")
    async def styles() -> FileResponse:
        return FileResponse(STATIC_DIR / "styles.css", media_type="text/css")

    @app.get("/app.js")
    async def script() -> FileResponse:
        return FileResponse(STATIC_DIR / "app.js", media_type="application/javascript")

    return app


app = create_app()
