"""Google CastV2 TLS & Device Authentication Engine.

Supports three authentication strategies:
1. SELF_SIGNED: Auto-generates a persistent Cast Root CA, Intermediate ICA, Device Auth
   Certificate, and TLS Peer Certificate, dynamically signing `(sender_nonce + peer_cert_der)`
   per Chromium's `cast_cert_validator.cc` specification.
2. PRECOMPUTED_BUNDLE: Loads time-windowed precomputed peer certificates and hardware
   signatures (compatible with vibecast / shanocast / cast-audio-receiver-lab JSON bundles).
3. CUSTOM_KEY: Uses a user-supplied donor device certificate and private key.
"""

from __future__ import annotations

import base64
import datetime
import gzip
import hashlib
import json
import logging
import os
import ssl
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from .cast_proto import (
    AuthChallenge,
    AuthError,
    AuthErrorType,
    AuthResponse,
    DeviceAuthMessage,
    HashAlgorithm,
    SignatureAlgorithm,
)
from .models import AuthWindowEntry, CastAuthConfig, CastAuthMode

logger = logging.getLogger(__name__)

BUILTIN_EUREKA_BUNDLE_PATH = Path(__file__).parent / "assets" / "eureka_gen1_bundle.json.gz"
PUBLIC_AUTH_BUNDLE_URL = (
    "https://github.com/Allcrafter1/cast-audio-receiver-bundles/releases/download/"
    "2026.09.20/bundle-through-2030-12-06.json"
)
PUBLIC_AUTH_BUNDLE_SHA256 = "97ac49c254dfdd9ef4a140481ffbff9d62d1bad9aa3909f5e06ea211691af7ef"


class CastAuthManager:
    """Manages TLS certificates and CastV2 DeviceAuthMessage challenge-response signing."""

    def __init__(self, data_dir: Path, config: Optional[CastAuthConfig] = None) -> None:
        self.data_dir = Path(data_dir)
        self.certs_dir = self.data_dir / "certs"
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or CastAuthConfig()
        self.windows: List[AuthWindowEntry] = []

        # Generated / active certificates and keys
        self._root_ca_cert: Optional[x509.Certificate] = None
        self._ica_cert: Optional[x509.Certificate] = None
        self._device_cert: Optional[x509.Certificate] = None
        self._device_key: Optional[rsa.RSAPrivateKey] = None
        self._peer_cert: Optional[x509.Certificate] = None
        self._peer_key: Optional[rsa.RSAPrivateKey] = None

        self._ensure_self_signed_chain()
        self._load_bundle_if_exists()

    def _ensure_self_signed_chain(self) -> None:
        """Generate or load a complete Cast-structured PKI chain (Root -> Eureka ICA -> Device -> TLS Peer)."""
        root_cert_path = self.certs_dir / "cast_root_ca.pem"
        ica_cert_path = self.certs_dir / "eureka_gen1_ica.pem"
        dev_cert_path = self.certs_dir / "device_auth_cert.pem"
        dev_key_path = self.certs_dir / "device_auth_key.pem"
        peer_cert_path = self.certs_dir / "tls_peer_cert.pem"
        peer_key_path = self.certs_dir / "tls_peer_key.pem"

        if (
            root_cert_path.exists()
            and ica_cert_path.exists()
            and dev_cert_path.exists()
            and dev_key_path.exists()
            and peer_cert_path.exists()
            and peer_key_path.exists()
        ):
            try:
                self._root_ca_cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
                self._ica_cert = x509.load_pem_x509_certificate(ica_cert_path.read_bytes())
                self._device_cert = x509.load_pem_x509_certificate(dev_cert_path.read_bytes())
                self._device_key = serialization.load_pem_private_key(dev_key_path.read_bytes(), password=None)
                self._peer_cert = x509.load_pem_x509_certificate(peer_cert_path.read_bytes())
                self._peer_key = serialization.load_pem_private_key(peer_key_path.read_bytes(), password=None)
                return
            except Exception as exc:
                logger.warning("Failed to load existing self-signed Cast PKI chain, regenerating: %s", exc)

        now = datetime.datetime.now(datetime.timezone.utc)
        valid_start = now - datetime.timedelta(days=7)
        valid_end = now + datetime.timedelta(days=3650)

        # 1. Cast Root CA
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Cast Root CA"),
        ])
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_subject)
            .issuer_name(root_subject)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_start)
            .not_valid_after(valid_end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        # 2. Eureka Gen1 Intermediate CA
        ica_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ica_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Eureka Gen1 ICA"),
        ])
        ica_cert = (
            x509.CertificateBuilder()
            .subject_name(ica_subject)
            .issuer_name(root_subject)
            .public_key(ica_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_start)
            .not_valid_after(valid_end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(root_key, hashes.SHA256())
        )

        # 3. Device Auth Certificate (Chromecast Audio identity)
        dev_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dev_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Chromecast Audio"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PodCast Bridge Audio Device"),
        ])
        dev_cert = (
            x509.CertificateBuilder()
            .subject_name(dev_subject)
            .issuer_name(ica_subject)
            .public_key(dev_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_start)
            .not_valid_after(valid_end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ica_key, hashes.SHA256())
        )

        # 4. TLS Peer Certificate (presented during TLS handshake on port 8009)
        peer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        peer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Chromecast Audio Peer"),
        ])
        peer_cert = (
            x509.CertificateBuilder()
            .subject_name(peer_subject)
            .issuer_name(peer_subject)
            .public_key(peer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_start)
            .not_valid_after(valid_end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(peer_key, hashes.SHA256())
        )

        root_cert_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
        ica_cert_path.write_bytes(ica_cert.public_bytes(serialization.Encoding.PEM))
        dev_cert_path.write_bytes(dev_cert.public_bytes(serialization.Encoding.PEM))
        dev_key_path.write_bytes(
            dev_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        peer_cert_path.write_bytes(peer_cert.public_bytes(serialization.Encoding.PEM))
        peer_key_path.write_bytes(
            peer_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        self._root_ca_cert = root_cert
        self._ica_cert = ica_cert
        self._device_cert = dev_cert
        self._device_key = dev_key
        self._peer_cert = peer_cert
        self._peer_key = peer_key

    def _load_bundle_if_exists(self) -> None:
        """Load precomputed auth bundle from disk if present, otherwise load built-in Eureka Gen1 ICA bundle."""
        bundle_path = self.certs_dir / "auth_bundle.json"
        if bundle_path.exists():
            try:
                raw = json.loads(bundle_path.read_text(encoding="utf-8"))
                self._parse_and_activate_bundle(raw, name=raw.get("name", "auth_bundle.json"), persist=False)
                return
            except Exception as exc:
                logger.warning("Failed to parse auth_bundle.json: %s", exc)

        if BUILTIN_EUREKA_BUNDLE_PATH.exists():
            try:
                self.load_builtin_eureka_bundle(persist=False)
            except Exception as exc:
                logger.warning("Failed to load built-in Eureka Gen1 ICA bundle: %s", exc)

    def _parse_and_activate_bundle(
        self,
        bundle_data: Dict[str, Any],
        name: str = "custom_bundle.json",
        persist: bool = True,
    ) -> Dict[str, Any]:
        """Parse either normalized windows or Eureka Gen1 {'cpu', 'ica', 'certs'} format."""
        raw_windows = bundle_data.get("windows") or bundle_data.get("certs") or []
        if not raw_windows and ("peer_cert_pem" in bundle_data or "pu" in bundle_data):
            raw_windows = [bundle_data]

        top_cpu = bundle_data.get("cpu", "")
        top_ica = bundle_data.get("ica", "")
        default_dev_pem = top_cpu or (
            self._device_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            if self._device_cert
            else ""
        )
        default_ica_list = [top_ica] if top_ica else []

        parsed: List[AuthWindowEntry] = []
        for item in raw_windows:
            peer_cert_pem = item.get("peer_cert_pem") or item.get("pu") or ""
            peer_key_pem = item.get("peer_key_pem") or item.get("pr") or ""
            if not peer_cert_pem or not peer_key_pem:
                continue

            not_before = item.get("not_before")
            not_after = item.get("not_after")
            if not_before is None or not_after is None:
                cert_obj = x509.load_pem_x509_certificate(peer_cert_pem.encode("utf-8"))
                not_before = int(cert_obj.not_valid_before_utc.timestamp())
                not_after = int(cert_obj.not_valid_after_utc.timestamp())

            sig_hex = item.get("signature_hex", "")
            if not sig_hex and item.get("sig_sha256"):
                sig_hex = base64.b64decode(item["sig_sha256"]).hex()

            sig_sha1_hex = item.get("signature_sha1_hex", "")
            if not sig_sha1_hex and item.get("sig_sha1"):
                sig_sha1_hex = base64.b64decode(item["sig_sha1"]).hex()

            if not sig_hex and sig_sha1_hex:
                sig_hex = sig_sha1_hex

            entry = AuthWindowEntry(
                not_before=int(not_before),
                not_after=int(not_after),
                peer_cert_pem=peer_cert_pem,
                peer_key_pem=peer_key_pem,
                device_cert_pem=item.get("device_cert_pem") or default_dev_pem,
                intermediate_certs_pem=item.get("intermediate_certs_pem") or default_ica_list,
                signature_hex=sig_hex,
                signature_sha1_hex=sig_sha1_hex,
                hash_algorithm=item.get("hash_algorithm", "SHA256"),
            )
            parsed.append(entry)

        if not parsed:
            raise ValueError("No valid certificate windows found in bundle")

        self.windows = parsed
        if persist:
            bundle_path = self.certs_dir / "auth_bundle.json"
            bundle_path.write_text(
                json.dumps({"name": name, "windows": [w.model_dump() for w in parsed]}, indent=2),
                encoding="utf-8",
            )
        self.config.mode = CastAuthMode.PRECOMPUTED_BUNDLE
        self.config.bundle_name = name
        self.config.bundle_windows_count = len(parsed)
        self.config.bundle_valid_until = max(w.not_after for w in parsed)
        return {
            "mode": self.config.mode,
            "bundle_name": name,
            "windows_count": len(parsed),
            "valid_until": self.config.bundle_valid_until,
        }

    def import_auth_bundle(self, bundle_data: Dict[str, Any], name: str = "custom_bundle.json") -> Dict[str, Any]:
        """Import a precomputed CastV2 authentication bundle (vibecast/shanocast/lab compatible)."""
        return self._parse_and_activate_bundle(bundle_data, name=name, persist=True)

    def load_builtin_eureka_bundle(self, persist: bool = True) -> Dict[str, Any]:
        """Load the built-in 773-window Eureka Gen1 ICA bundle (2026-09-12 through 2030-12-06)."""
        if not BUILTIN_EUREKA_BUNDLE_PATH.exists():
            raise FileNotFoundError(f"Built-in bundle not found at {BUILTIN_EUREKA_BUNDLE_PATH}")
        with gzip.open(BUILTIN_EUREKA_BUNDLE_PATH, "rt", encoding="utf-8") as f:
            raw = json.load(f)
        return self._parse_and_activate_bundle(
            raw,
            name="eureka_gen1_ica_773_windows_2026_2030.json",
            persist=persist,
        )

    async def download_public_auth_bundle(self) -> Dict[str, Any]:
        """Download and verify the public 773-window Eureka Gen1 ICA Cast bundle from GitHub."""
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, trust_env=False) as client:
                resp = await client.get(PUBLIC_AUTH_BUNDLE_URL)
                resp.raise_for_status()
                raw_bytes = resp.content
            sha = hashlib.sha256(raw_bytes).hexdigest()
            if sha != PUBLIC_AUTH_BUNDLE_SHA256:
                raise ValueError(f"SHA256 mismatch: expected {PUBLIC_AUTH_BUNDLE_SHA256}, got {sha}")
            bundle_data = json.loads(raw_bytes.decode("utf-8"))
            return self.import_auth_bundle(bundle_data, name="bundle-through-2030-12-06.json")
        except Exception as exc:
            logger.info("Falling back to built-in Eureka Gen1 ICA bundle (%s)", exc)
            return self.load_builtin_eureka_bundle(persist=True)

    def generate_sample_precomputed_bundle(self) -> Dict[str, Any]:
        """Generate a valid 30-day precomputed window bundle signed by the local Device Auth key for testing."""
        assert self._peer_cert and self._peer_key and self._device_cert and self._device_key and self._ica_cert
        peer_der = self._peer_cert.public_bytes(serialization.Encoding.DER)
        sig256 = self._device_key.sign(peer_der, padding.PKCS1v15(), hashes.SHA256())
        sig1 = self._device_key.sign(peer_der, padding.PKCS1v15(), hashes.SHA1())
        now = int(time.time())
        bundle = {
            "name": "local_precomputed_window_bundle.json",
            "windows": [
                {
                    "not_before": now - 3600,
                    "not_after": now + 86400 * 30,
                    "peer_cert_pem": self._peer_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                    "peer_key_pem": self._peer_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption(),
                    ).decode("utf-8"),
                    "device_cert_pem": self._device_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                    "intermediate_certs_pem": [
                        self._ica_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                        self._root_ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                    ],
                    "signature_hex": sig256.hex(),
                    "signature_sha1_hex": sig1.hex(),
                    "hash_algorithm": "SHA256",
                }
            ],
        }
        return self.import_auth_bundle(bundle, name="local_precomputed_window_bundle.json")

    def _get_active_window(self) -> Optional[AuthWindowEntry]:
        if not self.windows:
            return None
        now = int(time.time())
        for w in self.windows:
            if w.not_before <= now <= w.not_after:
                return w
        return self.windows[0]

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create a server SSLContext presenting the active TLS peer certificate."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if self.config.mode == CastAuthMode.PRECOMPUTED_BUNDLE:
            win = self._get_active_window()
            if win:
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as cf, \
                     tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as kf:
                    cf.write(win.peer_cert_pem)
                    cf.flush()
                    kf.write(win.peer_key_pem)
                    kf.flush()
                    cf_name, kf_name = cf.name, kf.name
                try:
                    ctx.load_cert_chain(certfile=cf_name, keyfile=kf_name)
                    return ctx
                finally:
                    for fname in (cf_name, kf_name):
                        try:
                            os.unlink(fname)
                        except OSError:
                            pass

        peer_cert_path = self.certs_dir / "tls_peer_cert.pem"
        peer_key_path = self.certs_dir / "tls_peer_key.pem"
        ctx.load_cert_chain(certfile=str(peer_cert_path), keyfile=str(peer_key_path))
        return ctx

    def get_active_peer_cert_der(self) -> bytes:
        """Return DER bytes of the active TLS peer certificate."""
        if self.config.mode == CastAuthMode.PRECOMPUTED_BUNDLE:
            win = self._get_active_window()
            if win:
                cert = x509.load_pem_x509_certificate(win.peer_cert_pem.encode("utf-8"))
                return cert.public_bytes(serialization.Encoding.DER)
        assert self._peer_cert is not None
        return self._peer_cert.public_bytes(serialization.Encoding.DER)

    def handle_auth_challenge(self, raw_challenge_bytes: bytes) -> bytes:
        """Process incoming DeviceAuthMessage binary payload and return serialized DeviceAuthMessage response."""
        try:
            auth_msg = DeviceAuthMessage.FromString(raw_challenge_bytes)
            challenge = auth_msg.challenge or AuthChallenge()
        except Exception as exc:
            logger.error("Malformed DeviceAuthMessage challenge: %s", exc)
            err = DeviceAuthMessage(error=AuthError(error_type=AuthErrorType.INTERNAL_ERROR))
            return err.SerializeToString()

        # 1. Precomputed Bundle Mode (Eureka Gen1 ICA / vibecast / shanocast)
        # Note: sender_nonce MUST be omitted (fields [1, 2, 3, 4, 6]) because precomputed
        # hardware signatures are computed over peer_cert_der alone, not (sender_nonce + peer_cert_der).
        if self.config.mode == CastAuthMode.PRECOMPUTED_BUNDLE:
            win = self._get_active_window()
            if win:
                dev_cert = x509.load_pem_x509_certificate(win.device_cert_pem.encode("utf-8"))
                inter_ders = [
                    x509.load_pem_x509_certificate(pem.encode("utf-8")).public_bytes(serialization.Encoding.DER)
                    for pem in win.intermediate_certs_pem
                    if pem.strip()
                ]
                if challenge.hash_algorithm == HashAlgorithm.SHA1 and win.signature_sha1_hex:
                    sig_bytes = bytes.fromhex(win.signature_sha1_hex)
                    hash_alg = HashAlgorithm.SHA1
                else:
                    sig_bytes = bytes.fromhex(win.signature_hex)
                    hash_alg = HashAlgorithm.SHA256 if win.hash_algorithm.upper() == "SHA256" else HashAlgorithm.SHA1

                resp = AuthResponse(
                    signature=sig_bytes,
                    client_auth_certificate=dev_cert.public_bytes(serialization.Encoding.DER),
                    intermediate_certificate=inter_ders,
                    signature_algorithm=challenge.signature_algorithm or SignatureAlgorithm.RSASSA_PKCS1v15,
                    sender_nonce=None,
                    hash_algorithm=hash_alg,
                )
                return DeviceAuthMessage(response=resp).SerializeToString()

        # 2. Dynamic Signing Mode (Self-Signed or Custom Key)
        assert self._device_cert and self._device_key and self._peer_cert and self._ica_cert and self._root_ca_cert
        peer_der = self._peer_cert.public_bytes(serialization.Encoding.DER)
        nonce = challenge.sender_nonce or b""
        to_sign = nonce + peer_der

        use_sha256 = challenge.hash_algorithm == HashAlgorithm.SHA256
        hash_obj = hashes.SHA256() if use_sha256 else hashes.SHA1()
        hash_enum = HashAlgorithm.SHA256 if use_sha256 else HashAlgorithm.SHA1

        if challenge.signature_algorithm == SignatureAlgorithm.RSASSA_PSS:
            sig_pad = padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=padding.PSS.MAX_LENGTH)
            sig_alg = SignatureAlgorithm.RSASSA_PSS
        else:
            sig_pad = padding.PKCS1v15()
            sig_alg = SignatureAlgorithm.RSASSA_PKCS1v15

        signature = self._device_key.sign(to_sign, sig_pad, hash_obj)

        resp = AuthResponse(
            signature=signature,
            client_auth_certificate=self._device_cert.public_bytes(serialization.Encoding.DER),
            intermediate_certificate=[
                self._ica_cert.public_bytes(serialization.Encoding.DER),
                self._root_ca_cert.public_bytes(serialization.Encoding.DER),
            ],
            signature_algorithm=sig_alg,
            sender_nonce=challenge.sender_nonce,
            hash_algorithm=hash_enum,
        )
        return DeviceAuthMessage(response=resp).SerializeToString()

    @staticmethod
    def verify_auth_response(
        raw_response_bytes: bytes,
        peer_cert_der: bytes,
        expected_nonce: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """Verify a DeviceAuthMessage response against the TLS peer certificate and nonce."""
        msg = DeviceAuthMessage.FromString(raw_response_bytes)
        if msg.error is not None:
            return False, f"AuthError returned: {msg.error.error_type}"
        if msg.response is None:
            return False, "Missing AuthResponse in DeviceAuthMessage"

        resp = msg.response
        if not resp.client_auth_certificate or not resp.signature:
            return False, "Empty certificate or signature in AuthResponse"

        dev_cert = x509.load_der_x509_certificate(resp.client_auth_certificate)
        pub_key = dev_cert.public_key()
        hash_obj = hashes.SHA256() if resp.hash_algorithm == HashAlgorithm.SHA256 else hashes.SHA1()

        if resp.signature_algorithm == SignatureAlgorithm.RSASSA_PSS:
            sig_pad = padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=padding.PSS.MAX_LENGTH)
        else:
            sig_pad = padding.PKCS1v15()

        # Try (nonce + peer_cert_der) first, then precomputed (peer_cert_der only)
        candidates = []
        if expected_nonce:
            candidates.append((expected_nonce + peer_cert_der, "dynamic_nonce_bound"))
        candidates.append((peer_cert_der, "precomputed_peer_cert"))

        for payload, mode_label in candidates:
            try:
                pub_key.verify(resp.signature, payload, sig_pad, hash_obj)
                cn = dev_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn_str = cn[0].value if cn else "Unknown"
                return True, f"Verified ({mode_label}) signed by '{cn_str}'"
            except Exception:
                continue

        return False, "Signature verification failed against both dynamic and precomputed payloads"
