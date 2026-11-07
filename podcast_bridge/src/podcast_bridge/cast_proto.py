"""Wire-accurate Google CastV2 (cast_channel.proto) encoder, decoder, and async framing.

Implements the exact binary specification from Chromium's
`cast/common/channel/proto/cast_channel.proto` without fragile runtime protoc compilation.
"""

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple


# Standard Google CastV2 Namespaces
NS_CONNECTION = "urn:x-cast:com.google.cast.tp.connection"
NS_HEARTBEAT = "urn:x-cast:com.google.cast.tp.heartbeat"
NS_DEVICEAUTH = "urn:x-cast:com.google.cast.tp.deviceauth"
NS_RECEIVER = "urn:x-cast:com.google.cast.receiver"
NS_DISCOVERY = "urn:x-cast:com.google.cast.receiver.discovery"
NS_SETUP = "urn:x-cast:com.google.cast.setup"
NS_PROXIMITY = "urn:x-cast:com.google.cast.proximity"
NS_MEDIA = "urn:x-cast:com.google.cast.media"
NS_YOUTUBE_MDX = "urn:x-cast:com.google.youtube.mdx"
NS_MULTIZONE = "urn:x-cast:com.google.cast.multizone"
NS_SPOTIFY = "urn:x-cast:com.spotify.chromecast.secure.v1"
NS_SPOTIFY_SHORT = "com.spotify.chromecast.secure.v1"

# Chromecast Audio full capability bitmask:
# 4 (AUDIO_OUT) | 256 (HI_RES_AUDIO) | 512 (MULTIZONE) | 2048 | 65536 | 131072 = 199428
CHROMECAST_AUDIO_CAPABILITIES = 199428

# Standard Cast Application IDs
APP_DEFAULT_MEDIA_RECEIVER = "CC1AD845"
APP_YOUTUBE_MUSIC = "2DB7CC49"
APP_YOUTUBE = "233637DE"
APP_BACKDROP = "E8C28D3C"
APP_SPOTIFY = "CC32E753"


class ProtocolVersion(IntEnum):
    CASTV2_1_0 = 0
    CASTV2_1_1 = 1
    CASTV2_1_2 = 2
    CASTV2_1_3 = 3


class PayloadType(IntEnum):
    STRING = 0
    BINARY = 1


class SignatureAlgorithm(IntEnum):
    UNSPECIFIED = 0
    RSASSA_PKCS1v15 = 1
    RSASSA_PSS = 2


class HashAlgorithm(IntEnum):
    SHA1 = 0
    SHA256 = 1


class AuthErrorType(IntEnum):
    INTERNAL_ERROR = 0
    NO_TLS = 1
    SIGNATURE_ALGORITHM_UNAVAILABLE = 2


# --- Low-level Protobuf Wire Format Primitives ---

def _encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as a protobuf varint."""
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _decode_varint(buf: bytes, offset: int) -> Tuple[int, int]:
    """Decode a protobuf varint from buf at offset. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(buf):
        b = buf[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, offset
        shift += 7
        if shift >= 64:
            raise ValueError("Malformed protobuf varint (too many bytes)")
    raise ValueError("Truncated protobuf varint")


def _encode_tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_bytes_field(field_number: int, data: bytes) -> bytes:
    return _encode_tag(field_number, 2) + _encode_varint(len(data)) + data


def _encode_str_field(field_number: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return _encode_bytes_field(field_number, raw)


def _encode_varint_field(field_number: int, value: int) -> bytes:
    return _encode_tag(field_number, 0) + _encode_varint(value)


def _iter_fields(buf: bytes) -> List[Tuple[int, int, Any]]:
    """Parse raw protobuf bytes into a list of (field_number, wire_type, value)."""
    fields: List[Tuple[int, int, Any]] = []
    offset = 0
    length = len(buf)
    while offset < length:
        tag, offset = _decode_varint(buf, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # Varint
            val, offset = _decode_varint(buf, offset)
            fields.append((field_number, wire_type, val))
        elif wire_type == 1:  # 64-bit
            if offset + 8 > length:
                raise ValueError("Truncated 64-bit field")
            fields.append((field_number, wire_type, buf[offset : offset + 8]))
            offset += 8
        elif wire_type == 2:  # Length-delimited
            size, offset = _decode_varint(buf, offset)
            if offset + size > length:
                raise ValueError("Truncated length-delimited field")
            fields.append((field_number, wire_type, buf[offset : offset + size]))
            offset += size
        elif wire_type == 5:  # 32-bit
            if offset + 4 > length:
                raise ValueError("Truncated 32-bit field")
            fields.append((field_number, wire_type, buf[offset : offset + 4]))
            offset += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")
    return fields


# --- CastChannel Protobuf Messages ---

@dataclass
class AuthChallenge:
    signature_algorithm: int = SignatureAlgorithm.RSASSA_PKCS1v15
    sender_nonce: Optional[bytes] = None
    hash_algorithm: int = HashAlgorithm.SHA1

    def SerializeToString(self) -> bytes:
        parts = [_encode_varint_field(1, int(self.signature_algorithm))]
        if self.sender_nonce is not None:
            parts.append(_encode_bytes_field(2, self.sender_nonce))
        parts.append(_encode_varint_field(3, int(self.hash_algorithm)))
        return b"".join(parts)

    @classmethod
    def FromString(cls, data: bytes) -> "AuthChallenge":
        msg = cls()
        for fnum, wtype, val in _iter_fields(data):
            if fnum == 1 and wtype == 0:
                msg.signature_algorithm = int(val)
            elif fnum == 2 and wtype == 2:
                msg.sender_nonce = bytes(val)
            elif fnum == 3 and wtype == 0:
                msg.hash_algorithm = int(val)
        return msg


@dataclass
class AuthResponse:
    signature: bytes = b""
    client_auth_certificate: bytes = b""
    intermediate_certificate: List[bytes] = field(default_factory=list)
    signature_algorithm: int = SignatureAlgorithm.RSASSA_PKCS1v15
    sender_nonce: Optional[bytes] = None
    hash_algorithm: int = HashAlgorithm.SHA1
    crl: Optional[bytes] = None

    def SerializeToString(self) -> bytes:
        parts = [
            _encode_bytes_field(1, self.signature),
            _encode_bytes_field(2, self.client_auth_certificate),
        ]
        for cert in self.intermediate_certificate:
            parts.append(_encode_bytes_field(3, cert))
        parts.append(_encode_varint_field(4, int(self.signature_algorithm)))
        if self.sender_nonce is not None:
            parts.append(_encode_bytes_field(5, self.sender_nonce))
        parts.append(_encode_varint_field(6, int(self.hash_algorithm)))
        if self.crl is not None:
            parts.append(_encode_bytes_field(7, self.crl))
        return b"".join(parts)

    @classmethod
    def FromString(cls, data: bytes) -> "AuthResponse":
        msg = cls()
        for fnum, wtype, val in _iter_fields(data):
            if fnum == 1 and wtype == 2:
                msg.signature = bytes(val)
            elif fnum == 2 and wtype == 2:
                msg.client_auth_certificate = bytes(val)
            elif fnum == 3 and wtype == 2:
                msg.intermediate_certificate.append(bytes(val))
            elif fnum == 4 and wtype == 0:
                msg.signature_algorithm = int(val)
            elif fnum == 5 and wtype == 2:
                msg.sender_nonce = bytes(val)
            elif fnum == 6 and wtype == 0:
                msg.hash_algorithm = int(val)
            elif fnum == 7 and wtype == 2:
                msg.crl = bytes(val)
        return msg


@dataclass
class AuthError:
    error_type: int = AuthErrorType.INTERNAL_ERROR

    def SerializeToString(self) -> bytes:
        return _encode_varint_field(1, int(self.error_type))

    @classmethod
    def FromString(cls, data: bytes) -> "AuthError":
        msg = cls()
        for fnum, wtype, val in _iter_fields(data):
            if fnum == 1 and wtype == 0:
                msg.error_type = int(val)
        return msg


@dataclass
class DeviceAuthMessage:
    challenge: Optional[AuthChallenge] = None
    response: Optional[AuthResponse] = None
    error: Optional[AuthError] = None

    def SerializeToString(self) -> bytes:
        parts = []
        if self.challenge is not None:
            parts.append(_encode_bytes_field(1, self.challenge.SerializeToString()))
        if self.response is not None:
            parts.append(_encode_bytes_field(2, self.response.SerializeToString()))
        if self.error is not None:
            parts.append(_encode_bytes_field(3, self.error.SerializeToString()))
        return b"".join(parts)

    @classmethod
    def FromString(cls, data: bytes) -> "DeviceAuthMessage":
        msg = cls()
        for fnum, wtype, val in _iter_fields(data):
            if fnum == 1 and wtype == 2:
                msg.challenge = AuthChallenge.FromString(val)
            elif fnum == 2 and wtype == 2:
                msg.response = AuthResponse.FromString(val)
            elif fnum == 3 and wtype == 2:
                msg.error = AuthError.FromString(val)
        return msg


@dataclass
class CastMessage:
    protocol_version: int = ProtocolVersion.CASTV2_1_0
    source_id: str = "sender-0"
    destination_id: str = "receiver-0"
    namespace: str = NS_HEARTBEAT
    payload_type: int = PayloadType.STRING
    payload_utf8: Optional[str] = None
    payload_binary: Optional[bytes] = None

    def SerializeToString(self) -> bytes:
        parts = [
            _encode_varint_field(1, int(self.protocol_version)),
            _encode_str_field(2, self.source_id),
            _encode_str_field(3, self.destination_id),
            _encode_str_field(4, self.namespace),
            _encode_varint_field(5, int(self.payload_type)),
        ]
        if self.payload_type == PayloadType.STRING and self.payload_utf8 is not None:
            parts.append(_encode_str_field(6, self.payload_utf8))
        elif self.payload_type == PayloadType.BINARY and self.payload_binary is not None:
            parts.append(_encode_bytes_field(7, self.payload_binary))
        elif self.payload_utf8 is not None:
            parts.append(_encode_str_field(6, self.payload_utf8))
        elif self.payload_binary is not None:
            parts.append(_encode_bytes_field(7, self.payload_binary))
        return b"".join(parts)

    @classmethod
    def FromString(cls, data: bytes) -> "CastMessage":
        msg = cls()
        for fnum, wtype, val in _iter_fields(data):
            if fnum == 1 and wtype == 0:
                msg.protocol_version = int(val)
            elif fnum == 2 and wtype == 2:
                msg.source_id = val.decode("utf-8", errors="replace")
            elif fnum == 3 and wtype == 2:
                msg.destination_id = val.decode("utf-8", errors="replace")
            elif fnum == 4 and wtype == 2:
                msg.namespace = val.decode("utf-8", errors="replace")
            elif fnum == 5 and wtype == 0:
                msg.payload_type = int(val)
            elif fnum == 6 and wtype == 2:
                msg.payload_utf8 = val.decode("utf-8", errors="replace")
            elif fnum == 7 and wtype == 2:
                msg.payload_binary = bytes(val)
        return msg

    def json_payload(self) -> Dict[str, Any]:
        """Parse payload_utf8 as JSON dict if present."""
        if not self.payload_utf8:
            return {}
        try:
            return json.loads(self.payload_utf8)
        except json.JSONDecodeError:
            return {}


# --- Framing Helpers (4-byte Big-Endian Length + Protobuf Payload) ---

def pack_cast_message(msg: CastMessage) -> bytes:
    """Serialize CastMessage with 4-byte big-endian length header."""
    raw = msg.SerializeToString()
    return struct.pack(">I", len(raw)) + raw


def make_json_message(
    source_id: str,
    destination_id: str,
    namespace: str,
    payload: Dict[str, Any],
) -> CastMessage:
    """Create a STRING CastMessage with JSON payload."""
    return CastMessage(
        protocol_version=ProtocolVersion.CASTV2_1_0,
        source_id=source_id,
        destination_id=destination_id,
        namespace=namespace,
        payload_type=PayloadType.STRING,
        payload_utf8=json.dumps(payload),
    )


def make_binary_message(
    source_id: str,
    destination_id: str,
    namespace: str,
    payload: bytes,
) -> CastMessage:
    """Create a BINARY CastMessage."""
    return CastMessage(
        protocol_version=ProtocolVersion.CASTV2_1_0,
        source_id=source_id,
        destination_id=destination_id,
        namespace=namespace,
        payload_type=PayloadType.BINARY,
        payload_binary=payload,
    )


async def read_cast_message(reader: asyncio.StreamReader) -> Optional[CastMessage]:
    """Read a length-prefixed CastMessage from an asyncio StreamReader."""
    try:
        header = await reader.readexactly(4)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > 10 * 1024 * 1024:
        raise ValueError(f"Invalid CastMessage frame length: {length}")
    try:
        body = await reader.readexactly(length)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    return CastMessage.FromString(body)


async def write_cast_message(writer: asyncio.StreamWriter, msg: CastMessage) -> None:
    """Write a length-prefixed CastMessage to an asyncio StreamWriter."""
    writer.write(pack_cast_message(msg))
    await writer.drain()
