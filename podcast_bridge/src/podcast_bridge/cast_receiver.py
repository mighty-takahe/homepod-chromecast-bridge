"""Virtual Chromecast Audio Receiver Server (CastV2 over TLS + Eureka HTTP/HTTPS/DIAL + Dual mDNS)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import socket
import struct
import time
import urllib.parse
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from zeroconf import IPVersion, InterfaceChoice, ServiceInfo
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
    NS_SPOTIFY,
    NS_SPOTIFY_SHORT,
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

MDNS_MULTICAST_ADDR = "224.0.0.251"
MDNS_PORT = 5353
GOOGLECAST_SERVICE = "_googlecast._tcp.local"


def format_canonical_uuid(raw_id: str) -> str:
    """Format a hex string or UUID into canonical lowercase 8-4-4-4-12 UUID."""
    clean = "".join(c for c in raw_id.lower() if c in "0123456789abcdef")
    if len(clean) != 32:
        clean = hashlib.md5(raw_id.encode("utf-8")).hexdigest()
    return f"{clean[0:8]}-{clean[8:12]}-{clean[12:16]}-{clean[16:20]}-{clean[20:32]}"


def clean_device_id(raw_id: str) -> str:
    """Return 32 lowercase hex characters without dashes (used in mDNS TXT 'id')."""
    return format_canonical_uuid(raw_id).replace("-", "")


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for part in name.strip(".").split("."):
        encoded = part.encode("utf-8")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _encode_dns_record(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return _encode_dns_name(name) + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def _encode_txt_rdata(txt: Dict[str, str]) -> bytes:
    out = bytearray()
    for k, v in txt.items():
        entry = f"{k}={v}".encode("utf-8")
        if len(entry) <= 255:
            out.append(len(entry))
            out.extend(entry)
    return bytes(out)


def build_mdns_announcement_packet(
    instance_label: str,
    server_fqdn: str,
    ip_address: str,
    port: int,
    txt: Dict[str, str],
    ttl: int = 120,
) -> bytes:
    """Build a complete RFC 6762 mDNS response packet with PTR in Answer, and SRV/TXT/A in Additional."""
    service_fqdn = f"{GOOGLECAST_SERVICE}."
    instance_fqdn = f"{instance_label}.{GOOGLECAST_SERVICE}."
    host_fqdn = server_fqdn if server_fqdn.endswith(".") else f"{server_fqdn}."

    # PTR is a shared record in Answer section (class 0x0001 IN, no cache-flush bit)
    ptr_rec = _encode_dns_record(service_fqdn, 12, 0x0001, 4500 if ttl > 0 else 0, _encode_dns_name(instance_fqdn))
    # SRV, TXT, and A are unique records in Additional section (class 0x8001 IN with cache-flush)
    srv_rdata = struct.pack(">HHH", 0, 0, port) + _encode_dns_name(host_fqdn)
    srv_rec = _encode_dns_record(instance_fqdn, 33, 0x8001, ttl, srv_rdata)
    txt_rec = _encode_dns_record(instance_fqdn, 16, 0x8001, 4500 if ttl > 0 else 0, _encode_txt_rdata(txt))
    a_rec = _encode_dns_record(host_fqdn, 1, 0x8001, ttl, ipaddress.IPv4Address(ip_address).packed)

    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 3)
    return header + ptr_rec + srv_rec + txt_rec + a_rec


def build_multi_mdns_packet(
    receivers: List[VirtualChromecastAudio],
    ip_address: str,
    ttl: int = 120,
    query_type: str = "ptr",
) -> bytes:
    """Build a complete RFC 6762 mDNS response packet containing all active Cast receivers.

    Supports:
    - query_type='ptr': PTR in Answer section, SRV, TXT, and A in Additional section.
    - query_type='host_a': Host A records in Answer section, PTR, SRV, and TXT in Additional section.
    - query_type='srv': SRV records in Answer section, TXT, A, and PTR in Additional section.
    - query_type='txt': TXT records in Answer section, SRV, A, and PTR in Additional section.
    - query_type='announcement': All records in Answer section per RFC 6762 8.3 for unsolicited announcements.
    """
    if not receivers:
        return struct.pack(">HHHHHH", 0, 0x8400, 0, 0, 0, 0)

    service_fqdn = f"{GOOGLECAST_SERVICE}."
    answers = bytearray()
    additionals = bytearray()
    num_answers = 0
    num_additionals = 0
    seen_hosts: Set[str] = set()

    for r in receivers:
        instance_label = f"Chromecast-Audio-{r.clean_id}"
        instance_fqdn = f"{instance_label}.{GOOGLECAST_SERVICE}."
        host_fqdn = f"{r.hyphenated_uuid}.local."
        txt = r.build_txt_dict() if hasattr(r, "build_txt_dict") else r._build_txt_dict()
        port = r.device.cast_port
        adv_ip = r.host_ip if (r.host_ip and r.host_ip not in ("0.0.0.0", "")) else ip_address

        ptr_rec = _encode_dns_record(
            service_fqdn, 12, 0x0001, 4500 if ttl > 0 else 0, _encode_dns_name(instance_fqdn)
        )
        srv_rdata = struct.pack(">HHH", 0, 0, port) + _encode_dns_name(host_fqdn)
        srv_rec = _encode_dns_record(instance_fqdn, 33, 0x8001, ttl, srv_rdata)
        txt_rec = _encode_dns_record(instance_fqdn, 16, 0x8001, 4500 if ttl > 0 else 0, _encode_txt_rdata(txt))
        a_rec = (
            _encode_dns_record(host_fqdn, 1, 0x8001, ttl, ipaddress.IPv4Address(adv_ip).packed)
            if adv_ip and adv_ip not in ("0.0.0.0", "")
            else b""
        )

        if query_type == "announcement":
            answers.extend(ptr_rec)
            answers.extend(srv_rec)
            answers.extend(txt_rec)
            num_answers += 3
            if a_rec and host_fqdn not in seen_hosts:
                seen_hosts.add(host_fqdn)
                answers.extend(a_rec)
                num_answers += 1
        elif query_type == "host_a":
            if a_rec and host_fqdn not in seen_hosts:
                seen_hosts.add(host_fqdn)
                answers.extend(a_rec)
                num_answers += 1
            additionals.extend(ptr_rec)
            additionals.extend(srv_rec)
            additionals.extend(txt_rec)
            num_additionals += 3
        elif query_type == "srv":
            answers.extend(srv_rec)
            num_answers += 1
            additionals.extend(ptr_rec)
            additionals.extend(txt_rec)
            num_additionals += 2
            if a_rec and host_fqdn not in seen_hosts:
                seen_hosts.add(host_fqdn)
                additionals.extend(a_rec)
                num_additionals += 1
        elif query_type == "txt":
            answers.extend(txt_rec)
            num_answers += 1
            additionals.extend(ptr_rec)
            additionals.extend(srv_rec)
            num_additionals += 2
            if a_rec and host_fqdn not in seen_hosts:
                seen_hosts.add(host_fqdn)
                additionals.extend(a_rec)
                num_additionals += 1
        else:  # default "ptr" query
            answers.extend(ptr_rec)
            num_answers += 1
            additionals.extend(srv_rec)
            additionals.extend(txt_rec)
            num_additionals += 2
            if a_rec and host_fqdn not in seen_hosts:
                seen_hosts.add(host_fqdn)
                additionals.extend(a_rec)
                num_additionals += 1

    # Include canonical bridge host A record
    if ip_address and ip_address not in ("0.0.0.0", ""):
        canon_host = "podcast-bridge.local."
        canon_a = _encode_dns_record(canon_host, 1, 0x8001, ttl, ipaddress.IPv4Address(ip_address).packed)
        if query_type == "announcement":
            answers.extend(canon_a)
            num_answers += 1
        else:
            additionals.extend(canon_a)
            num_additionals += 1

    header = struct.pack(">HHHHHH", 0, 0x8400, 0, num_answers, 0, num_additionals)
    return bytes(header + answers + additionals)


def build_receiver_goodbye_packet(receiver: VirtualChromecastAudio, ip_address: str) -> bytes:
    """Build an RFC 6762 goodbye packet (TTL=0) for a stopping Cast receiver."""
    return build_multi_mdns_packet([receiver], ip_address, ttl=0, query_type="ptr")


class SharedRawMdnsAdvertiser:
    """Direct UDP multicast mDNS responder on 224.0.0.251:5353 and SSDP DIAL on 239.255.255.250:1900.

    Serves unified multi-device RFC 6762 responses and UPnP/SSDP M-SEARCH replies for all bridged
    Chromecast Audio devices, preventing Linux SO_REUSEPORT kernel 4-tuple query starvation across multiple
    speakers and ensuring both Living Room and Kitchen devices are discoverable by Android apps, Spotify, and Chrome.
    """

    def __init__(
        self,
        ip_address: str,
        receivers_provider: Callable[[], List[VirtualChromecastAudio]],
        interval: float = 10.0,
    ) -> None:
        self.ip_address = ip_address
        self.receivers_provider = receivers_provider
        self.interval = interval
        self._sock: Optional[socket.socket] = None
        self._ssdp_sock: Optional[socket.socket] = None
        self._task: Optional[asyncio.Task[None]] = None
        self._announce_task: Optional[asyncio.Task[None]] = None
        self._ssdp_task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        if not self.ip_address or self.ip_address in ("0.0.0.0",):
            return

        # 1. Start mDNS listener on port 5353
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            sock.bind(("", MDNS_PORT))
            if self.ip_address != "127.0.0.1":
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.ip_address))
                except OSError:
                    pass
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            mreq = socket.inet_aton(MDNS_MULTICAST_ADDR) + (
                socket.inet_aton(self.ip_address) if self.ip_address != "127.0.0.1" else socket.inet_aton("0.0.0.0")
            )
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(MDNS_MULTICAST_ADDR) + socket.inet_aton("0.0.0.0"),
                )
            sock.setblocking(False)
            self._sock = sock
            self._task = asyncio.create_task(self._run_loop())
            self._announce_task = asyncio.create_task(self._periodic_announce_loop())
            logger.info("SharedRawMdnsAdvertiser mDNS started on %s:5353", self.ip_address)
        except Exception as exc:
            logger.debug("SharedRawMdnsAdvertiser bind notice (%s): %s", self.ip_address, exc)

        # 2. Start SSDP DIAL listener on port 1900
        try:
            ssdp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            ssdp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    ssdp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            ssdp_sock.bind(("", 1900))
            smreq = socket.inet_aton("239.255.255.250") + (
                socket.inet_aton(self.ip_address) if self.ip_address != "127.0.0.1" else socket.inet_aton("0.0.0.0")
            )
            try:
                ssdp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, smreq)
            except OSError:
                ssdp_sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton("239.255.255.250") + socket.inet_aton("0.0.0.0"),
                )
            ssdp_sock.setblocking(False)
            self._ssdp_sock = ssdp_sock
            self._ssdp_task = asyncio.create_task(self._ssdp_loop())
            logger.info("SharedRawMdnsAdvertiser SSDP started on %s:1900", self.ip_address)
        except Exception as exc:
            logger.debug("SharedRawMdnsAdvertiser SSDP bind notice: %s", exc)

    async def stop(self) -> None:
        for t in (self._task, self._announce_task, self._ssdp_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        self._task = None
        self._announce_task = None
        self._ssdp_task = None

        if self._sock:
            try:
                receivers = [r for r in self.receivers_provider() if getattr(r.device, "enabled", True)]
                if receivers:
                    goodbye = build_multi_mdns_packet(receivers, self.ip_address, ttl=0, query_type="ptr")
                    self._sock.sendto(goodbye, (MDNS_MULTICAST_ADDR, MDNS_PORT))
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        if self._ssdp_sock:
            try:
                self._ssdp_sock.close()
            except Exception:
                pass
            self._ssdp_sock = None

    async def announce_all(self) -> None:
        """Broadcast all active devices to 224.0.0.251:5353."""
        if not self._sock:
            return
        receivers = [r for r in self.receivers_provider() if getattr(r.device, "enabled", True)]
        if not receivers:
            return
        # Broadcast full unsolicited announcement per RFC 6762 8.3
        pkt_ann = build_multi_mdns_packet(receivers, self.ip_address, query_type="announcement")
        pkt_ptr = build_multi_mdns_packet(receivers, self.ip_address, query_type="ptr")
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(self._sock, pkt_ann, (MDNS_MULTICAST_ADDR, MDNS_PORT))
            await loop.sock_sendto(self._sock, pkt_ptr, (MDNS_MULTICAST_ADDR, MDNS_PORT))
        except Exception as exc:
            logger.debug("SharedRawMdnsAdvertiser announce_all notice: %s", exc)

    async def announce_goodbye(self, receiver: VirtualChromecastAudio) -> None:
        """Broadcast a goodbye packet (TTL=0) for a stopping receiver."""
        if not self._sock:
            return
        pkt = build_receiver_goodbye_packet(receiver, self.ip_address)
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(self._sock, pkt, (MDNS_MULTICAST_ADDR, MDNS_PORT))
        except Exception as exc:
            logger.debug("SharedRawMdnsAdvertiser announce_goodbye notice: %s", exc)

    async def _periodic_announce_loop(self) -> None:
        """Periodic gratuitous mDNS announcements to ensure mobile devices pick up all speakers immediately."""
        bursts = 0
        while True:
            try:
                await self.announce_all()
                bursts += 1
                delay = 1.0 if bursts < 3 else (5.0 if bursts < 8 else self.interval)
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Periodic announcement notice: %s", exc)
                await asyncio.sleep(5.0)

    async def _ssdp_loop(self) -> None:
        """SSDP responder for DIAL / Spotify Connect / YouTube M-SEARCH on 239.255.255.250:1900."""
        loop = asyncio.get_running_loop()
        if not self._ssdp_sock:
            return

        while True:
            try:
                data, addr = await loop.sock_recvfrom(self._ssdp_sock, 4096)
                text = data.decode("utf-8", errors="replace")
                if "M-SEARCH" not in text:
                    continue

                is_dial = (
                    "urn:dial-multiscreen-org:service:dial:1" in text
                    or "ssdp:all" in text
                    or "upnp:rootdevice" in text
                )
                if not is_dial:
                    continue

                receivers = [r for r in self.receivers_provider() if getattr(r.device, "enabled", True)]
                for r in receivers:
                    adv_ip = r.host_ip if (r.host_ip and r.host_ip not in ("0.0.0.0", "")) else self.ip_address
                    e_port = r.device.eureka_port
                    u_uuid = r.hyphenated_uuid
                    resp = (
                        "HTTP/1.1 200 OK\r\n"
                        "CACHE-CONTROL: max-age=1800\r\n"
                        "EXT:\r\n"
                        f"LOCATION: http://{adv_ip}:{e_port}/ssdp/device-desc.xml\r\n"
                        "SERVER: Linux/4.19 UPnP/1.0 PodCastBridge/0.4.7\r\n"
                        "ST: urn:dial-multiscreen-org:service:dial:1\r\n"
                        f"USN: uuid:{u_uuid}::urn:dial-multiscreen-org:service:dial:1\r\n"
                        "BOOTID.UPNP.ORG: 1\r\n"
                        "CONFIGID.UPNP.ORG: 1\r\n"
                        "\r\n"
                    ).encode("utf-8")
                    try:
                        await loop.sock_sendto(self._ssdp_sock, resp, addr)
                    except Exception:
                        pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("SSDP loop notice: %s", exc)
                await asyncio.sleep(2.0)

    async def _run_loop(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._sock is not None
        service_wire = _encode_dns_name(GOOGLECAST_SERVICE)[:-1]

        while True:
            try:
                data, addr = await loop.sock_recvfrom(self._sock, 9000)
                if len(data) < 12:
                    continue
                flags = struct.unpack(">H", data[2:4])[0]
                is_query = (flags & 0x8000) == 0
                if not is_query:
                    continue

                receivers = [r for r in self.receivers_provider() if getattr(r.device, "enabled", True)]
                if not receivers:
                    continue

                query_type = "ptr"
                matches = False

                # Parse query using zeroconf.DNSIncoming for exact question matching
                try:
                    incoming = zeroconf.DNSIncoming(data)
                    for q in incoming.questions:
                        qname = q.name.lower().rstrip(".")
                        if qname == GOOGLECAST_SERVICE.lower():
                            matches = True
                            query_type = "ptr"
                            break
                        if any(r.clean_id.lower() in qname for r in receivers):
                            matches = True
                            query_type = "srv" if q.type == 33 else ("txt" if q.type == 16 else "ptr")
                            break
                        if any(r.hyphenated_uuid.lower() in qname for r in receivers) or "podcast-bridge" in qname:
                            matches = True
                            query_type = "host_a"
                            break
                except Exception:
                    pass

                # Wire byte fallback if zeroconf parsing did not match
                if not matches:
                    if service_wire in data or b"_googlecast" in data:
                        matches = True
                        query_type = "ptr"
                    elif any(r.clean_id.encode("ascii") in data for r in receivers):
                        matches = True
                        query_type = "ptr"
                    elif any(r.hyphenated_uuid.encode("ascii") in data for r in receivers):
                        matches = True
                        query_type = "host_a"
                    elif b"podcast-bridge" in data:
                        matches = True
                        query_type = "host_a"
                    else:
                        for r in receivers:
                            inst_wire = _encode_dns_name(f"Chromecast-Audio-{r.clean_id}")[:-1]
                            if inst_wire in data:
                                matches = True
                                query_type = "ptr"
                                break

                if matches:
                    pkt = build_multi_mdns_packet(receivers, self.ip_address, query_type=query_type)
                    # Multicast to 224.0.0.251:5353
                    try:
                        await loop.sock_sendto(self._sock, pkt, (MDNS_MULTICAST_ADDR, MDNS_PORT))
                    except Exception:
                        pass
                    # Direct unicast reply to querier
                    if addr and addr[0] not in ("0.0.0.0", "127.0.0.1"):
                        try:
                            await loop.sock_sendto(self._sock, pkt, addr)
                        except Exception:
                            pass
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("SharedRawMdnsAdvertiser query notice: %s", exc)
                await asyncio.sleep(0.5)


class RawMdnsAdvertiser:
    """Direct UDP multicast mDNS responder on 224.0.0.251:5353 bound to the LAN interface.

    Ensures `_googlecast._tcp.local.` discovery succeeds on Home Assistant OS even when
    Avahi or multiple Docker bridge interfaces (`hassio`, `docker0`) are present.
    """

    def __init__(
        self,
        instance_label: str,
        server_fqdn: str,
        ip_address: str,
        port: int,
        txt_provider: Callable[[], Dict[str, str]],
        interval: float = 20.0,
    ) -> None:
        self.instance_label = instance_label
        self.server_fqdn = server_fqdn
        self.ip_address = ip_address
        self.port = port
        self.txt_provider = txt_provider
        self.interval = interval
        self._sock: Optional[socket.socket] = None
        self._task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        if not self.ip_address or self.ip_address in ("0.0.0.0", "127.0.0.1"):
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            sock.bind(("", MDNS_PORT))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.ip_address))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            mreq = socket.inet_aton(MDNS_MULTICAST_ADDR) + socket.inet_aton(self.ip_address)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(MDNS_MULTICAST_ADDR) + socket.inet_aton("0.0.0.0"),
                )
            sock.setblocking(False)
            self._sock = sock
            self._task = asyncio.create_task(self._run_loop())
        except Exception as exc:
            logger.debug("RawMdnsAdvertiser bind notice (%s): %s", self.ip_address, exc)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._sock:
            try:
                goodbye = build_mdns_announcement_packet(
                    self.instance_label,
                    self.server_fqdn,
                    self.ip_address,
                    self.port,
                    self.txt_provider(),
                    ttl=0,
                )
                self._sock.sendto(goodbye, (MDNS_MULTICAST_ADDR, MDNS_PORT))
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    async def _run_loop(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._sock is not None
        service_wire = _encode_dns_name(GOOGLECAST_SERVICE)[:-1]
        instance_wire = _encode_dns_name(self.instance_label)[:-1]

        # Initial burst (2 announcements 1s apart per RFC 6762)
        for _ in range(2):
            try:
                pkt = build_mdns_announcement_packet(
                    self.instance_label,
                    self.server_fqdn,
                    self.ip_address,
                    self.port,
                    self.txt_provider(),
                )
                await loop.sock_sendto(self._sock, pkt, (MDNS_MULTICAST_ADDR, MDNS_PORT))
            except Exception:
                pass
            await asyncio.sleep(1.0)

        while True:
            try:
                data, addr = await asyncio.wait_for(loop.sock_recvfrom(self._sock, 9000), timeout=self.interval)
                # Only respond to queries (QR bit == 0) that mention _googlecast._tcp.local or our instance
                if len(data) >= 12:
                    flags = struct.unpack(">H", data[2:4])[0]
                    is_query = (flags & 0x8000) == 0
                    if is_query and (service_wire in data or instance_wire in data):
                        pkt = build_mdns_announcement_packet(
                            self.instance_label,
                            self.server_fqdn,
                            self.ip_address,
                            self.port,
                            self.txt_provider(),
                        )
                        await loop.sock_sendto(self._sock, pkt, (MDNS_MULTICAST_ADDR, MDNS_PORT))
                        await loop.sock_sendto(self._sock, pkt, addr)
            except asyncio.TimeoutError:
                try:
                    pkt = build_mdns_announcement_packet(
                        self.instance_label,
                        self.server_fqdn,
                        self.ip_address,
                        self.port,
                        self.txt_provider(),
                    )
                    await loop.sock_sendto(self._sock, pkt, (MDNS_MULTICAST_ADDR, MDNS_PORT))
                except Exception:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(2.0)


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
        receivers_provider: Optional[Callable[[], List[VirtualChromecastAudio]]] = None,
    ) -> None:
        self.device = device
        self.host_ip = host_ip
        self.auth_manager = auth_manager
        self.receivers_provider = receivers_provider
        self._on_load_media = on_load_media
        self._on_pause = on_pause
        self._on_resume = on_resume
        self._on_stop = on_stop
        self._on_seek = on_seek
        self._on_volume = on_volume
        self._on_event = on_event
        self._on_state_change = on_state_change
        self.mdns_enabled = mdns_enabled
        self._started_at = time.monotonic()

        # Normalize device UUIDs (32-hex clean_id for mDNS TXT, 8-4-4-4-12 hyphenated_uuid for CastV2/Eureka)
        raw_uuid = self.device.cast_uuid or hashlib.md5(self.device.id.encode("utf-8")).hexdigest()
        self.clean_id: str = clean_device_id(raw_uuid)
        self.hyphenated_uuid: str = format_canonical_uuid(self.clean_id)
        self.device.cast_uuid = self.clean_id

        # Active Cast session state
        self.app_id: str = APP_BACKDROP
        self.app_name: str = "Backdrop"
        self.session_id: str = str(uuid.uuid4())
        self.transport_id: str = self.session_id
        self.media_session_id: int = 1
        self.queue_items: List[Dict[str, Any]] = []
        self.queue_index: int = 0

        self._tls_server: Optional[asyncio.AbstractServer] = None
        self._http_server: Optional[asyncio.AbstractServer] = None
        self._http_8008_server: Optional[asyncio.AbstractServer] = None
        self._https_8443_server: Optional[asyncio.AbstractServer] = None
        self._aiozc: Optional[AsyncZeroconf] = None
        self._service_info: Optional[ServiceInfo] = None
        self._raw_mdns: Optional[Any] = None
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

    def build_txt_dict(self) -> Dict[str, str]:
        """Build the exact 12-key `_googlecast._tcp.local.` TXT record matching vibecast / Chromecast Audio."""
        cd_id = self.auth_manager.get_active_peer_cert_md5_hex()
        bs_id = hashlib.md5(self.hyphenated_uuid.encode("utf-8")).digest()[:6].hex().upper()
        is_idle = self.app_id == APP_BACKDROP and self.device.player_state == PlayerState.IDLE
        return {
            "ve": "05",
            "md": "Chromecast Audio",
            "fn": self.device.cast_name,
            "id": self.clean_id,
            "cd": cd_id,
            "ca": str(CHROMECAST_AUDIO_CAPABILITIES),
            "bs": bs_id,
            "st": "0" if is_idle else "1",
            "nf": "1",
            "ic": "/setup/icon.png",
            "rs": "" if is_idle else (self.device.media.title or self.app_name),
            "rm": "",
        }

    def _build_txt_dict(self) -> Dict[str, str]:
        return self.build_txt_dict()

    def build_service_info(self) -> ServiceInfo:
        """Build zeroconf ServiceInfo for this virtual Chromecast Audio device."""
        instance_label = f"Chromecast-Audio-{self.clean_id}"
        server_fqdn = f"{self.hyphenated_uuid}.local."
        adv_ip = self.host_ip if self.host_ip and self.host_ip != "0.0.0.0" else "127.0.0.1"
        svc_name = f"{instance_label}._googlecast._tcp.local."
        ip_bytes = socket.inet_aton(adv_ip)
        return ServiceInfo(
            type_="_googlecast._tcp.local.",
            name=svc_name,
            addresses=[ip_bytes],
            port=self.device.cast_port,
            properties=self.build_txt_dict(),
            server=server_fqdn,
        )

    async def start(self) -> None:
        """Start the CastV2 TLS server, Eureka/DIAL HTTP+HTTPS servers, and mDNS service."""
        ssl_ctx = self.auth_manager.create_ssl_context()
        for attempt in range(10):
            try:
                self._tls_server = await asyncio.start_server(
                    self._handle_tls_client,
                    host="0.0.0.0",
                    port=self.device.cast_port,
                    ssl=ssl_ctx,
                )
                break
            except OSError as exc:
                if attempt == 9:
                    raise
                logger.warning(
                    "Port %s already in use for %s TLS server, retrying on %s",
                    self.device.cast_port, self.device.name, self.device.cast_port + 1
                )
                self.device.cast_port += 1

        if self._tls_server and self._tls_server.sockets:
            self.device.cast_port = self._tls_server.sockets[0].getsockname()[1]

        for attempt in range(10):
            try:
                self._http_server = await asyncio.start_server(
                    self._handle_http_client,
                    host="0.0.0.0",
                    port=self.device.eureka_port,
                )
                break
            except OSError as exc:
                if attempt == 9:
                    raise
                logger.warning(
                    "Port %s already in use for %s HTTP server, retrying on %s",
                    self.device.eureka_port, self.device.name, self.device.eureka_port + 1
                )
                self.device.eureka_port += 1

        if self._http_server and self._http_server.sockets:
            self.device.eureka_port = self._http_server.sockets[0].getsockname()[1]

        # If this is the primary receiver (port 8009), also bind standard Eureka HTTP :8008 and HTTPS :8443 if free
        if self.device.cast_port == 8009:
            if self.device.eureka_port != 8008:
                try:
                    self._http_8008_server = await asyncio.start_server(
                        self._handle_http_client,
                        host="0.0.0.0",
                        port=8008,
                    )
                except OSError:
                    self._http_8008_server = None
            try:
                self._https_8443_server = await asyncio.start_server(
                    self._handle_http_client,
                    host="0.0.0.0",
                    port=8443,
                    ssl=ssl_ctx,
                )
            except OSError:
                self._https_8443_server = None

        if self.mdns_enabled:
            await self._register_mdns()

        self._emit(
            "system",
            "cast.receiver",
            (
                f"Chromecast Audio '{self.device.cast_name}' listening on TLS {self.host_ip}:{self.device.cast_port} "
                f"(Eureka :{self.device.eureka_port}, cd={self.auth_manager.get_active_peer_cert_md5_hex()[:8]}…)"
            ),
        )

    async def stop(self) -> None:
        """Stop mDNS, HTTP/HTTPS servers, and CastV2 TLS server."""
        if self._raw_mdns:
            await self._raw_mdns.stop()
            self._raw_mdns = None

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

        for srv_attr in ("_tls_server", "_http_server", "_http_8008_server", "_https_8443_server"):
            srv: Optional[asyncio.AbstractServer] = getattr(self, srv_attr, None)
            if srv is not None:
                srv.close()
                try:
                    await srv.wait_closed()
                except Exception:
                    pass
                setattr(self, srv_attr, None)

    async def _register_mdns(self) -> None:
        """Advertise `_googlecast._tcp.local.` when running standalone without BridgeManager."""
        adv_ip = self.host_ip if self.host_ip and self.host_ip != "0.0.0.0" else "127.0.0.1"

        # 1. Start direct multicast responder on the LAN interface
        self._raw_mdns = SharedRawMdnsAdvertiser(
            ip_address=adv_ip,
            receivers_provider=lambda: [self],
        )
        await self._raw_mdns.start()

        # 2. Register via AsyncZeroconf bound to the LAN interface IP
        try:
            self._service_info = self.build_service_info()
            try:
                if adv_ip not in ("127.0.0.1", "0.0.0.0"):
                    self._aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only, interfaces=[adv_ip])
                else:
                    self._aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only, interfaces=InterfaceChoice.All)
            except Exception:
                self._aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)
            await self._aiozc.async_register_service(self._service_info, allow_name_change=True)
        except Exception as exc:
            logger.warning("Zeroconf mDNS registration notice for %s: %s", self.device.cast_name, exc)
            logger.warning("Zeroconf mDNS registration notice for %s: %s", self.device.cast_name, exc)

    def _build_receiver_status(self, request_id: int = 0) -> Dict[str, Any]:
        """Build standard Google Cast RECEIVER_STATUS payload matching vibecast."""
        is_idle = self.app_id == APP_BACKDROP
        applications: List[Dict[str, Any]] = []
        if not is_idle:
            namespaces = [
                {"name": NS_DISCOVERY},
                {"name": NS_MULTIZONE},
                {"name": NS_SETUP},
                {"name": NS_YOUTUBE_MDX},
                {"name": "urn:x-cast:com.google.cast.inject"},
                {"name": "urn:x-cast:com.google.cast.broadcast"},
                {"name": NS_SPOTIFY},
                {"name": NS_MEDIA},
            ]
            applications.append(
                {
                    "appId": self.app_id,
                    "appType": "WEB",
                    "displayName": self.app_name,
                    "iconUrl": "",
                    "isIdleScreen": False,
                    "launchedFromCloud": False,
                    "namespaces": namespaces,
                    "senderConnected": len(self._clients) > 0,
                    "sessionId": self.session_id,
                    "statusText": (
                        f"Playing: {self.device.media.title}"
                        if self.device.player_state == PlayerState.PLAYING
                        else self.app_name
                    ),
                    "transportId": self.transport_id,
                    "universalAppId": self.app_id,
                }
            )
        return {
            "requestId": request_id,
            "type": "RECEIVER_STATUS",
            "status": {
                "applications": applications,
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
        status_entry: Dict[str, Any] = {
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
                "mediaCategory": "AUDIO",
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

    async def broadcast_receiver_status(
        self,
        request_id: int = 0,
        exclude: Optional[asyncio.StreamWriter] = None,
    ) -> None:
        payload = self._build_receiver_status(request_id=request_id)
        msg = make_json_message("receiver-0", "*", NS_RECEIVER, payload)
        await self._broadcast(msg, exclude=exclude)
        self._notify_state()

    async def broadcast_media_status(
        self,
        request_id: int = 0,
        exclude: Optional[asyncio.StreamWriter] = None,
    ) -> None:
        payload = self._build_media_status(request_id=request_id)
        msg = make_json_message(self.transport_id, "*", NS_MEDIA, payload)
        await self._broadcast(msg, exclude=exclude)
        self._notify_state()

    async def _safe_load_media(self, content_url: str, meta: MediaMetadata, start_time: float) -> None:
        """Stream media to the physical HomePod in the background without blocking Cast socket responses."""
        try:
            await self._on_load_media(self.device, content_url, meta, start_time)
        except Exception as exc:
            logger.warning("Error initiating physical speaker playback on '%s': %s", self.device.name, exc)
            self.device.player_state = PlayerState.IDLE
            await self.broadcast_media_status(request_id=0)

    async def _broadcast(
        self,
        msg: CastMessage,
        exclude: Optional[asyncio.StreamWriter] = None,
    ) -> None:
        for writer in list(self._clients):
            if writer is exclude:
                continue
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
            reply = make_binary_message(msg.destination_id or "receiver-0", msg.source_id, NS_DEVICEAUTH, raw_resp)
            await write_cast_message(writer, reply)
            self._emit(
                "cast_out",
                ns,
                f"Sent signed AuthResponse ({len(raw_resp)} bytes) [mode={self.auth_manager.config.mode.value}]",
            )
            return

        # 3. Virtual Connection lifecycle
        if ns == NS_CONNECTION:
            data = msg.json_payload()
            conn_type = data.get("type", "")
            self._emit("cast_in", ns, f"{conn_type} ({msg.source_id} -> {msg.destination_id})")
            if conn_type == "CONNECT" and msg.destination_id == self.transport_id and self.app_id != APP_BACKDROP:
                # Immediately push current MEDIA_STATUS when sender binds to the active app transport
                media_reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=0),
                )
                await write_cast_message(writer, media_reply)
            return

        # 4. Receiver Namespace (GET_STATUS, LAUNCH, STOP, SET_VOLUME, GET_APP_AVAILABILITY)
        if ns == NS_RECEIVER:
            data = msg.json_payload()
            msg_type = data.get("type", "")
            req_id = int(data.get("requestId") or data.get("request_id") or 0)
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
                # If replacing an already-running app, broadcast empty/stopped status first
                if self.app_id != APP_BACKDROP and self.app_id != requested_app:
                    self.app_id = APP_BACKDROP
                    await self.broadcast_receiver_status(request_id=0)

                self.app_id = requested_app
                self.app_name = KNOWN_APP_NAMES.get(requested_app, f"Cast App ({requested_app})")
                self.session_id = str(uuid.uuid4())
                self.transport_id = self.session_id
                self.device.media.app_id = self.app_id
                self.device.media.app_name = self.app_name
                status_payload = self._build_receiver_status(request_id=req_id)
                reply = make_json_message("receiver-0", msg.source_id, NS_RECEIVER, status_payload)
                await write_cast_message(writer, reply)
                await self.broadcast_receiver_status(request_id=0, exclude=writer)
                self._emit("cast_out", ns, f"Launched '{self.app_name}' ({self.app_id}) transport={self.transport_id}")

            elif msg_type == "STOP":
                self.app_id = APP_BACKDROP
                self.app_name = "Backdrop"
                self.device.media.app_id = APP_BACKDROP
                self.device.media.app_name = "Backdrop"
                self.device.player_state = PlayerState.IDLE
                self.device.media.current_time = 0.0
                reply = make_json_message(
                    "receiver-0",
                    msg.source_id,
                    NS_RECEIVER,
                    self._build_receiver_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_receiver_status(request_id=0, exclude=writer)
                await self.broadcast_media_status(request_id=req_id)
                asyncio.create_task(self._on_stop(self.device))

            elif msg_type == "SET_VOLUME":
                vol_obj = data.get("volume", {})
                new_level = float(vol_obj.get("level", self.device.volume))
                new_muted = vol_obj.get("muted", self.device.muted)
                self.device.volume = round(max(0.0, min(1.0, new_level)), 3)
                if new_muted is not None:
                    self.device.muted = bool(new_muted)
                reply = make_json_message(
                    "receiver-0",
                    msg.source_id,
                    NS_RECEIVER,
                    self._build_receiver_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_receiver_status(request_id=0, exclude=writer)
                asyncio.create_task(self._on_volume(self.device, self.device.volume, self.device.muted))

            return

        # 5. Media Namespace (LOAD, PLAY, PAUSE, STOP, SEEK, QUEUE_*, GET_STATUS)
        if ns == NS_MEDIA:
            data = msg.json_payload()
            msg_type = data.get("type", "")
            req_id = int(data.get("requestId") or data.get("request_id") or 0)
            self._emit("cast_in", ns, f"MEDIA {msg_type} (reqId={req_id})", msg.payload_utf8 or "")

            if msg_type == "GET_STATUS":
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)

            elif msg_type == "QUEUE_GET_ITEM_IDS":
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    {
                        "requestId": req_id,
                        "type": "QUEUE_ITEM_IDS",
                        "mediaSessionId": self.media_session_id,
                        "itemIds": [idx + 1 for idx in range(len(self.queue_items))],
                    },
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
                if msg.destination_id and msg.destination_id != "receiver-0":
                    self.transport_id = msg.destination_id

                meta = MediaMetadata(
                    title=(
                        meta_raw.get("title")
                        or meta_raw.get("songName")
                        or content_url.split("/")[-1]
                        or "Cast Audio Stream"
                    ),
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
                self.device.player_state = PlayerState.PLAYING

                # 0ms Optimistic MEDIA_STATUS: respond immediately so sender UI connects in < 5ms
                reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_media_status(request_id=0, exclude=writer)
                await self.broadcast_receiver_status(request_id=0)
                self._emit("cast_out", ns, f"MEDIA_STATUS PLAYING '{meta.title}' -> HomePod '{self.device.name}' (optimistic 0ms)")

                # Execute physical speaker streaming asynchronously
                asyncio.create_task(self._safe_load_media(content_url, meta, start_time))

            elif msg_type == "PAUSE":
                self.device.player_state = PlayerState.PAUSED
                reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_media_status(request_id=0, exclude=writer)
                asyncio.create_task(self._on_pause(self.device))

            elif msg_type == "PLAY":
                self.device.player_state = PlayerState.PLAYING
                reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_media_status(request_id=0, exclude=writer)
                asyncio.create_task(self._on_resume(self.device))

            elif msg_type == "STOP":
                self.device.player_state = PlayerState.IDLE
                self.device.media.current_time = 0.0
                reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_media_status(request_id=0, exclude=writer)
                asyncio.create_task(self._on_stop(self.device))

            elif msg_type == "SEEK":
                pos = float(data.get("currentTime", 0.0))
                self.device.media.current_time = pos
                reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_media_status(request_id=0, exclude=writer)
                asyncio.create_task(self._on_seek(self.device, pos))

            elif msg_type == "SET_VOLUME":
                vol_obj = data.get("volume", {})
                new_level = float(vol_obj.get("level", self.device.volume))
                new_muted = vol_obj.get("muted", self.device.muted)
                self.device.volume = round(max(0.0, min(1.0, new_level)), 3)
                if new_muted is not None:
                    self.device.muted = bool(new_muted)
                reply = make_json_message(
                    self.transport_id,
                    msg.source_id,
                    NS_MEDIA,
                    self._build_media_status(request_id=req_id),
                )
                await write_cast_message(writer, reply)
                await self.broadcast_media_status(request_id=0, exclude=writer)
                asyncio.create_task(self._on_volume(self.device, self.device.volume, self.device.muted))

            elif msg_type in ("QUEUE_NEXT", "QUEUE_PREV", "QUEUE_UPDATE") and self.queue_items:
                if msg_type == "QUEUE_UPDATE":
                    delta = int(data.get("jump", 1))
                else:
                    delta = 1 if msg_type == "QUEUE_NEXT" else -1
                self.queue_index = (self.queue_index + delta) % len(self.queue_items)
                item_media = self.queue_items[self.queue_index].get("media", {})
                url = item_media.get("contentId", "")
                meta_raw = item_media.get("metadata", {})
                self.device.media.title = meta_raw.get("title", url)
                self.device.media.content_url = url
                self.device.player_state = PlayerState.PLAYING
                await self.broadcast_media_status(request_id=req_id)
                asyncio.create_task(self._safe_load_media(url, self.device.media, 0.0))

            return

        # 5b. Spotify Secure Channel (urn:x-cast:com.spotify.chromecast.secure.v1)
        if ns in (NS_SPOTIFY, NS_SPOTIFY_SHORT) or "spotify.chromecast.secure" in ns:
            data = msg.json_payload()
            msg_type = data.get("type", "")
            req_id = data.get("requestId") if "requestId" in data else data.get("request_id")
            self._emit("cast_in", ns, f"SPOTIFY {msg_type} (source={msg.source_id})", msg.payload_utf8 or "")

            payload_in = data.get("payload") if isinstance(data.get("payload"), dict) else {}
            req_device_id = (
                payload_in.get("deviceID")
                or payload_in.get("device_id")
                or data.get("deviceID")
                or data.get("device_id")
                or self.device.cast_uuid
            )

            if msg_type in ("getInfo", "get_info", "GET_INFO"):
                resp_payload: Dict[str, Any] = {
                    "type": "getInfoResponse",
                    "status": "OK",
                    "payload": {
                        "deviceID": req_device_id,
                        "device_id": req_device_id,
                        "remoteName": self.device.cast_name,
                        "version": "1.0.0",
                        "deviceType": "audio_dongle",
                        "brandDisplayName": "Google",
                        "modelDisplayName": "Chromecast Audio",
                        "clientID": "76642c7bcc9c466bb99a44ce206edbbe",
                        "tokenType": "accesstoken",
                        "deviceAPI_isGroup": False,
                        "aliases": [],
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, f"Returned getInfoResponse deviceID={req_device_id} clientID=76642c7bcc9c466bb99a44ce206edbbe")

            elif msg_type in ("addUser", "add_user", "ADD_USER"):
                resp_payload = {
                    "type": "addUserResponse",
                    "status": "OK",
                    "payload": {
                        "status": "OK",
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, f"Returned addUserResponse status=OK deviceID={req_device_id}")

            elif msg_type in ("setCredentials", "set_credentials", "SET_CREDENTIALS"):
                resp_payload = {
                    "type": "setCredentialsResponse",
                    "status": "OK",
                    "payload": {
                        "status": "OK",
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, "Returned setCredentialsResponse OK")

            elif msg_type in ("resetUsers", "reset_users", "RESET_USERS"):
                resp_payload = {
                    "type": "resetUsersResponse",
                    "status": "OK",
                    "payload": {
                        "status": "OK",
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, "Returned resetUsersResponse OK")

            elif msg_type in ("getUsers", "getUser", "get_users", "GET_USERS"):
                resp_payload = {
                    "type": "getUsersResponse",
                    "status": "OK",
                    "payload": {
                        "status": "OK",
                        "users": [],
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, "Returned getUsersResponse OK")

            elif msg_type in ("getStatus", "get_status", "GET_STATUS", "get_device_info"):
                resp_payload = {
                    "type": "status",
                    "status": "OK",
                    "device": {
                        "name": self.device.cast_name,
                        "device_id": req_device_id,
                        "device_type": "AUDIO_DONGLE",
                        "brand_name": "Google",
                        "model_name": "Chromecast Audio",
                        "capabilities": {"is_speaker": True, "volume_steps": 100},
                    },
                    "payload": {
                        "status": "OK",
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, f"Returned Spotify device status ({self.device.cast_name})")

            elif msg_type in ("set_device", "setDevice", "set_users", "setUsers", "transfer"):
                resp_payload = {
                    "type": "set_device_response",
                    "status": "OK",
                    "device": {
                        "name": self.device.cast_name,
                        "device_id": req_device_id,
                    },
                    "payload": {
                        "status": "OK",
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, f"Acknowledged {msg_type} OK")

            elif msg_type in ("setVolume", "set_volume", "SET_VOLUME"):
                vol = payload_in.get("volume", data.get("volume"))
                if vol is not None:
                    try:
                        val = float(vol)
                        if val > 1.0:
                            val /= 100.0
                        self.device.volume = round(max(0.0, min(1.0, val)), 3)
                        asyncio.create_task(self._on_volume(self.device, self.device.volume, self.device.muted))
                    except Exception:
                        pass
                resp_payload = {
                    "type": "setVolumeResponse",
                    "status": "OK",
                    "payload": {
                        "status": "OK",
                        "volume": self.device.volume,
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, f"Set Spotify volume {self.device.volume}")

            elif msg_type in ("pause", "PAUSE"):
                self.device.player_state = PlayerState.PAUSED
                asyncio.create_task(self._on_pause(self.device))
                resp_payload = {
                    "type": "pauseResponse",
                    "status": "OK",
                    "payload": {"status": "OK", "deviceID": req_device_id},
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, "Spotify pause OK")

            elif msg_type in ("play", "PLAY", "resume", "RESUME"):
                self.device.player_state = PlayerState.PLAYING
                asyncio.create_task(self._on_resume(self.device))
                resp_payload = {
                    "type": "playResponse",
                    "status": "OK",
                    "payload": {"status": "OK", "deviceID": req_device_id},
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, "Spotify play OK")

            else:
                resp_type = f"{msg_type}Response" if not msg_type.endswith("Response") else msg_type
                resp_payload = {
                    "type": resp_type,
                    "status": "OK",
                    "payload": {
                        "status": "OK",
                        "deviceID": req_device_id,
                    },
                }
                if req_id is not None:
                    resp_payload["requestId"] = req_id
                reply = make_json_message(
                    msg.destination_id or self.transport_id,
                    msg.source_id,
                    msg.namespace,
                    resp_payload,
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", msg.namespace, f"Handled custom Spotify msg {msg_type} -> {resp_type}")

            return

        # 6. YouTube / YouTube Music MDX Lounge Namespace
        if ns == NS_YOUTUBE_MDX:
            data = msg.json_payload()
            if data.get("type") == "getMdxSessionStatus":
                screen_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"yt-lounge:{self.hyphenated_uuid}"))
                reply = make_json_message(
                    msg.destination_id,
                    msg.source_id,
                    NS_YOUTUBE_MDX,
                    {
                        "type": "mdxSessionStatus",
                        "data": {
                            "screenId": screen_id,
                            "deviceId": self.hyphenated_uuid,
                        },
                    },
                )
                await write_cast_message(writer, reply)
                self._emit("cast_out", ns, f"Returned YouTube MDX Lounge screenId={screen_id}")
            return

        # 7. Multizone Namespace
        if ns == NS_MULTIZONE:
            data = msg.json_payload()
            req_id = int(data.get("requestId") or data.get("request_id") or 0)
            msg_type = data.get("type", "")
            if msg_type == "GET_CASTING_GROUPS":
                reply = make_json_message(
                    "receiver-0",
                    msg.source_id,
                    NS_MULTIZONE,
                    {
                        "requestId": req_id,
                        "type": "CASTING_GROUPS",
                        "groups": [],
                    },
                )
                await write_cast_message(writer, reply)
            else:
                reply = make_json_message(
                    "receiver-0",
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
            req_id = int(data.get("requestId") or data.get("request_id") or 0)
            msg_type = data.get("type", "")
            self._emit("cast_in", ns, f"DISCOVERY {msg_type} (reqId={req_id})")
            if msg_type in ("GET_DEVICE_INFO", ""):
                reply = make_json_message(
                    "receiver-0",
                    msg.source_id,
                    NS_DISCOVERY,
                    {
                        "type": "DEVICE_INFO",
                        "requestId": req_id,
                        "deviceId": self.hyphenated_uuid,
                        "deviceModel": "Chromecast Audio",
                        "friendlyName": self.device.cast_name,
                        "deviceCapabilities": CHROMECAST_AUDIO_CAPABILITIES,
                        "deviceIconUrl": "",
                        "controlNotifications": 1,
                        "receiverMetricsId": "",
                        "wifiProximityId": "",
                    },
                )
                await write_cast_message(writer, reply)
                self._emit(
                    "cast_out",
                    ns,
                    f"Returned DEVICE_INFO (deviceId={self.hyphenated_uuid}, capabilities={CHROMECAST_AUDIO_CAPABILITIES})",
                )
            return

        # 9. Cast Setup Namespace (uses snake_case on the wire per vibecast setup.rs)
        if ns == NS_SETUP:
            data = msg.json_payload()
            req_id = int(data.get("request_id") or data.get("requestId") or 0)
            self._emit("cast_in", ns, f"SETUP eureka_info (request_id={req_id})")
            reply = make_json_message(
                "receiver-0",
                msg.source_id,
                NS_SETUP,
                {
                    "type": "eureka_info",
                    "request_id": req_id,
                    "response_code": 200,
                    "response_string": "OK",
                    "data": {
                        "device_info": {
                            "ssdp_udn": self.hyphenated_uuid,
                        },
                        "name": self.device.cast_name,
                        "version": 8,
                    },
                },
            )
            await write_cast_message(writer, reply)
            self._emit("cast_out", ns, f"Returned SETUP eureka_info (ssdp_udn={self.hyphenated_uuid})")
            return

    # --- Eureka / DIAL HTTP & HTTPS Server (Port 8008 / 8443 / 18008+) ---

    def _build_eureka_info(self, params_query: Optional[str] = None) -> Dict[str, Any]:
        """Build Chromecast / vibecast-compatible `/setup/eureka_info` JSON payload."""
        uptime = round(time.monotonic() - self._started_at, 2)
        pub_key_b64 = self.auth_manager.get_active_device_public_key_b64()
        token_hash = base64.b64encode(hashlib.sha256(self.hyphenated_uuid.encode("utf-8")).digest()).decode("ascii")
        cloud_dev_id = self.clean_id.upper()
        mac_str = self.device.mac_address or "00:00:00:00:00:00"

        full_info: Dict[str, Any] = {
            "bssid": "",
            "build_version": "446070",
            "cast_build_revision": "3.72.446070",
            "connected": True,
            "ethernet_connected": True,
            "has_update": False,
            "hotspot_bssid": "",
            "ip_address": self.host_ip,
            "locale": "en-US",
            "location": {
                "country_code": "US",
                "latitude": 255.0,
                "longitude": 255.0,
            },
            "mac_address": mac_str,
            "name": self.device.cast_name,
            "opt_in": {
                "crash": False,
                "opencast": False,
                "stats": False,
            },
            "public_key": pub_key_b64,
            "release_track": "",
            "setup_state": 60,
            "setup_stats": {
                "historically_succeeded": True,
                "num_check_connectivity": 0,
                "num_connect_wifi": 0,
                "num_connected_wifi_not_saved": 0,
                "num_initial_eureka_info": 0,
                "num_obtain_ip": 0,
            },
            "ssdp_udn": self.hyphenated_uuid,
            "ssid": "",
            "time_format": 1,
            "tos_accepted": True,
            "uptime": uptime,
            "version": 12,
            "wpa_configured": False,
            "wpa_state": 0,
            "device_info": {
                "capabilities": {
                    "audio_hdr_supported": False,
                    "audio_surround_mode_supported": False,
                    "ble_supported": False,
                    "cast_connect_supported": True,
                    "cloud_groups_supported": False,
                    "cloudcast_supported": True,
                    "display_supported": False,
                    "fdr_supported": False,
                    "hdmi_prefer_50hz_supported": False,
                    "hdmi_prefer_high_fps_supported": False,
                    "hi_res_audio_supported": True,
                    "hotspot_supported": False,
                    "https_setup_supported": True,
                    "keep_hotspot_until_connected_supported": False,
                    "multizone_supported": True,
                    "opencast_supported": False,
                    "reboot_supported": False,
                    "renaming_supported": False,
                    "set_group_audio_delay_supported": False,
                    "set_network_supported": False,
                    "setup_supported": False,
                    "stats_supported": False,
                    "system_sound_effects_supported": False,
                    "wifi_auto_save_supported": False,
                    "wifi_supported": True,
                },
                "cloud_device_id": cloud_dev_id,
                "factory_country_code": "US",
                "hotspot_bssid": "",
                "local_authorization_token_hash": token_hash,
                "mac_address": mac_str,
                "manufacturer": "Google Inc.",
                "model_name": "Chromecast Audio",
                "product_name": "chromecastaudio",
                "public_key": pub_key_b64,
                "ssdp_udn": self.hyphenated_uuid,
                "uptime": uptime,
                "weave_device_id": "",
            },
            "multizone": {
                "audio_output_delay": 0.0,
                "audio_output_delay_hdmi": 0.0,
                "audio_output_delay_oem": 0.0,
                "dynamic_groups": [],
                "groups": [],
                "max_static_groups": 100,
                "multichannel_status": 0,
            },
        }

        if params_query:
            requested_keys = [k.strip() for k in params_query.split(",") if k.strip()]
            if requested_keys:
                return {k: full_info[k] for k in requested_keys if k in full_info}
        return full_info

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
            raw_target = parts[1] if len(parts) > 1 else "/"
            parsed_url = urllib.parse.urlsplit(raw_target)
            path = parsed_url.path or "/"
            query_dict = urllib.parse.parse_qs(parsed_url.query)

            # Read headers
            content_length = 0
            host_header = ""
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not line or line in (b"\r\n", b"\n"):
                    break
                hdr = line.decode("utf-8", errors="replace").strip()
                if hdr.lower().startswith("content-length:"):
                    content_length = int(hdr.split(":", 1)[1].strip())
                elif hdr.lower().startswith("host:"):
                    host_header = hdr.split(":", 1)[1].strip()

            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(reader.readexactly(content_length), timeout=5.0)

            if path.startswith("/setup/eureka_info"):
                params_arg = query_dict.get("params", [None])[0]
                target_receiver = self
                if self.receivers_provider:
                    all_recvs = self.receivers_provider()
                    req_id = query_dict.get("id", [None])[0] or query_dict.get("device_id", [None])[0]
                    if req_id:
                        for r in all_recvs:
                            if req_id.lower() in (r.clean_id.lower(), r.hyphenated_uuid.lower()):
                                target_receiver = r
                                break
                    elif host_header:
                        for r in all_recvs:
                            if r.hyphenated_uuid.lower() in host_header.lower() or r.clean_id.lower() in host_header.lower():
                                target_receiver = r
                                break
                            if "kitchen" in host_header.lower() and "kitchen" in r.device.name.lower():
                                target_receiver = r
                                break
                info = target_receiver._build_eureka_info(params_query=params_arg)
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
    <UDN>uuid:{self.hyphenated_uuid}</UDN>
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
                    if "Spotify" in app_slug:
                        self.app_id = APP_SPOTIFY
                        self.app_name = "Spotify"
                    elif "Music" in app_slug:
                        self.app_id = APP_YOUTUBE_MUSIC
                        self.app_name = "YouTube Music"
                    else:
                        self.app_id = APP_YOUTUBE
                        self.app_name = app_slug or "YouTube"
                    self.session_id = str(uuid.uuid4())
                    self.transport_id = self.session_id
                    self._emit(
                        "cast_in",
                        "dial.launch",
                        f"DIAL POST /apps/{app_slug}",
                        body.decode("utf-8", errors="replace"),
                    )
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
