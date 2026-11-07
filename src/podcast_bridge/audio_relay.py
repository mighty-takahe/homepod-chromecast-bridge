"""FFmpeg Audio Transcoder, Stream Relay, and Test Audio Generator for AirPlay targets."""

from __future__ import annotations

import asyncio
import io
import logging
import math
import shutil
import struct
import wave
from typing import AsyncIterator, Dict, Optional

from .models import AudioTranscodeConfig

logger = logging.getLogger(__name__)


def has_ffmpeg() -> bool:
    """Return True if ffmpeg binary is available on PATH."""
    return shutil.which("ffmpeg") is not None


def generate_test_chime_wav(duration_sec: float = 4.2, sample_rate: int = 44100) -> bytes:
    """Synthesize a warm stereo C-major9 arpeggiated chime in 16-bit 44.1kHz WAV format with trailing buffer drain."""
    buf = io.BytesIO()
    num_samples = int(duration_sec * sample_rate)
    # Frequencies: C5 (523.25), E5 (659.25), G5 (783.99), B5 (987.77), D6 (1174.66)
    notes = [
        (0.00, 523.25, 0.28),
        (0.18, 659.25, 0.25),
        (0.36, 783.99, 0.22),
        (0.54, 987.77, 0.18),
        (0.72, 1046.50, 0.24),
    ]

    frames = bytearray()
    for i in range(num_samples):
        t = i / sample_rate
        left = 0.0
        right = 0.0
        for idx, (start_t, freq, amp) in enumerate(notes):
            if t >= start_t:
                dt = t - start_t
                # Fast attack, exponential decay
                attack = min(1.0, dt / 0.015)
                decay = math.exp(-dt * 2.4)
                # Fundamental + gentle 2nd harmonic warmth
                sig = (
                    math.sin(2.0 * math.pi * freq * dt)
                    + 0.25 * math.sin(2.0 * math.pi * (freq * 2.0) * dt)
                ) * amp * attack * decay
                # Subtle stereo spread across the arpeggio
                pan = 0.3 + 0.4 * (idx / max(1, len(notes) - 1))
                left += sig * (1.0 - pan * 0.4)
                right += sig * (0.6 + pan * 0.4)

        l_int = max(-32767, min(32767, int(left * 32767)))
        r_int = max(-32767, min(32767, int(right * 32767)))
        frames.extend(struct.pack("<hh", l_int, r_int))

    with wave.open(buf, "wb") as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(bytes(frames))

    return buf.getvalue()


class AudioRelayManager:
    """Manages active media URLs per device and provides FFmpeg on-the-fly transcoding."""

    def __init__(self, config: Optional[AudioTranscodeConfig] = None) -> None:
        self.config = config or AudioTranscodeConfig()
        self._active_sources: Dict[str, str] = {}
        self._active_procs: Dict[str, asyncio.subprocess.Process] = {}
        self._cached_chime_wav: bytes = generate_test_chime_wav()

    def register_source(self, device_id: str, source_url: str) -> None:
        """Associate an upstream media URL with a bridged HomePod device."""
        self._active_sources[device_id] = source_url

    def get_source(self, device_id: str) -> Optional[str]:
        return self._active_sources.get(device_id)

    def get_relay_url(self, host_ip: str, web_port: int, device_id: str) -> str:
        """Return the local HTTP relay URL that AirPlay or Home Assistant can stream from."""
        ext = self.config.codec.lower()
        if ext not in ("wav", "mp3", "aac", "flac"):
            ext = "wav"
        return f"http://{host_ip}:{web_port}/api/relay/{device_id}/stream.{ext}"

    def get_test_chime_url(self, host_ip: str, web_port: int) -> str:
        """Return the local HTTP URL for the built-in test chime."""
        return f"http://{host_ip}:{web_port}/api/relay/test-chime.wav"

    def get_test_chime_bytes(self) -> bytes:
        return self._cached_chime_wav

    async def stop_device_stream(self, device_id: str) -> None:
        """Terminate any active FFmpeg transcode process for the given device."""
        proc = self._active_procs.pop(device_id, None)
        if proc and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    async def stream_transcoded(
        self,
        device_id: str,
        source_url: Optional[str] = None,
        codec: Optional[str] = None,
        start_time: float = 0.0,
    ) -> AsyncIterator[bytes]:
        """Yield transcoded audio chunks using FFmpeg (or fallback WAV chime if source is test chime)."""
        target_url = source_url or self._active_sources.get(device_id)
        if not target_url or target_url.endswith("/test-chime.wav") or target_url.startswith("builtin://"):
            # Stream built-in chime directly
            data = self._cached_chime_wav
            chunk_size = 16384
            for offset in range(0, len(data), chunk_size):
                yield data[offset : offset + chunk_size]
                await asyncio.sleep(0.005)
            return

        if not has_ffmpeg():
            logger.warning("ffmpeg not found; returning test chime bytes as fallback")
            yield self._cached_chime_wav
            return

        await self.stop_device_stream(device_id)

        out_codec = (codec or self.config.codec).lower()
        fmt_args = []
        if out_codec == "mp3":
            fmt_args = ["-c:a", "libmp3lame", "-b:a", self.config.bitrate, "-f", "mp3"]
        elif out_codec == "aac":
            fmt_args = ["-c:a", "aac", "-b:a", self.config.bitrate, "-f", "adts"]
        elif out_codec == "flac":
            fmt_args = ["-c:a", "flac", "-f", "flac"]
        else:
            fmt_args = ["-c:a", "pcm_s16le", "-f", "wav"]

        cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
        if self.config.low_latency:
            cmd.extend(["-fflags", "nobuffer", "-flags", "low_delay"])
        if start_time > 0:
            cmd.extend(["-ss", f"{start_time:.2f}"])
        cmd.extend([
            "-i", target_url,
            "-vn",
            "-ar", str(self.config.sample_rate),
            "-ac", str(self.config.channels),
            *fmt_args,
            "pipe:1",
        ])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._active_procs[device_id] = proc
        try:
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(16384)
                if not chunk:
                    break
                yield chunk
        finally:
            if self._active_procs.get(device_id) is proc:
                self._active_procs.pop(device_id, None)
            if proc.returncode is None:
                try:
                    proc.kill()
                except Exception:
                    pass
