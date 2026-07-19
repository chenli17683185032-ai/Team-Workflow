"""Independent Team proxy chains sharing one local Clash forward proxy.

The user's Clash is deliberately treated as an ordinary upstream HTTP/SOCKS
proxy.  Team Workflow never writes a Mihomo configuration, starts another
Mihomo process, or changes a selector.  Each configured owner gets one local
SOCKS5 relay. A relay connects to that owner's fixed or generated second-hop
proxy through the shared Clash before it connects to the requested destination.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import select
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import requests


DEFAULT_LOCAL_CLASH_PROXY = "http://127.0.0.1:7897"
DEFAULT_LISTENER_PORT_BASE = 18_880
DEFAULT_CACHE_TTL = 45.0
CHAIN_PROXY_MODE = "clash_chain"
LEGACY_CHAIN_PROXY_MODE = "lokiproxy_generator"
CHAIN_PROXY_MODES = frozenset({CHAIN_PROXY_MODE, LEGACY_CHAIN_PROXY_MODE})
_GENERATOR_HOST = "gen.lokiproxy.com"
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_HEADER_BYTES = 64 * 1024


class ProxyChainError(RuntimeError):
    code = "proxy_chain_error"


class ProxySourceError(ProxyChainError):
    code = "proxy_source_unavailable"


class ProxySourceNotWhitelistedError(ProxySourceError):
    code = "proxy_source_not_whitelisted"


class ProxySourceDepletedError(ProxySourceError):
    code = "proxy_source_depleted"


class ProxyConfigurationError(ProxyChainError):
    code = "proxy_chain_configuration"


class ProxyRelayError(ProxyChainError):
    code = "proxy_relay_unavailable"


@dataclass(frozen=True)
class _ProxyAddress:
    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""


def _normalize_proxy_scheme(value: str) -> str:
    scheme = str(value or "").casefold()
    aliases = {
        "http": "http",
        "https": "https",
        "socks": "socks5",
        "socks5": "socks5",
        "socks5h": "socks5",
        "s5": "socks5",
        "s5h": "socks5",
    }
    normalized = aliases.get(scheme)
    if normalized is None:
        raise ValueError("proxy URL scheme is unsupported")
    return normalized


def _parse_proxy_address(value: str, *, label: str = "proxy") -> _ProxyAddress:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if any(character.isspace() or ord(character) < 32 for character in text):
        raise ValueError(f"{label} URL contains invalid whitespace")
    try:
        parsed = urllib.parse.urlsplit(text)
        scheme = _normalize_proxy_scheme(parsed.scheme)
        host = str(parsed.hostname or "").strip()
        port = parsed.port
    except (ValueError, UnicodeError):
        raise ValueError(f"{label} URL is invalid") from None
    if not host:
        raise ValueError(f"{label} hostname is required")
    if port is None or not 1 <= int(port) <= 65535:
        raise ValueError(f"{label} port is required")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError(f"{label} URL contains an unsupported path or query")
    try:
        username = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
    except Exception:
        raise ValueError(f"{label} URL credentials are invalid") from None
    if any(ord(character) < 32 for character in username + password):
        raise ValueError(f"{label} URL credentials are invalid")
    return _ProxyAddress(scheme, host, int(port), username, password)


def validate_proxy_url(value: str) -> str:
    """Validate a proxy URL accepted by the local relay and workflow clients."""

    address = _parse_proxy_address(value)
    parsed = urllib.parse.urlsplit(str(value).strip())
    original_scheme = parsed.scheme.casefold()
    scheme = (
        "socks5h"
        if original_scheme in {"socks5h", "s5h"}
        else address.scheme
    )
    return urllib.parse.urlunsplit(parsed._replace(scheme=scheme))


def validate_bootstrap_proxy(value: str) -> str:
    """Validate the single Clash URL shared by every Team proxy chain."""

    return validate_proxy_url(value)


def _safe_proxy_label(value: str) -> str:
    """Return a proxy label without userinfo or secret query material."""

    try:
        address = _parse_proxy_address(value)
    except ValueError:
        return "未配置"
    host = address.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{address.scheme}://{host}:{address.port}"


def validate_generator_url(value: str) -> str:
    """Validate and normalize a LokiProxy generator URL without resolving it."""

    text = str(value or "").strip()
    if not text:
        raise ValueError("LokiProxy generator URL is required")
    if any(character.isspace() or ord(character) < 32 for character in text):
        raise ValueError("LokiProxy generator URL contains invalid whitespace")
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError:
        raise ValueError("LokiProxy generator URL is invalid") from None
    host = str(parsed.hostname or "").casefold()
    if parsed.scheme.casefold() not in {"http", "https"}:
        raise ValueError("LokiProxy generator URL must use HTTP or HTTPS")
    if host != _GENERATOR_HOST and not host.endswith("." + _GENERATOR_HOST):
        raise ValueError("LokiProxy generator host is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("LokiProxy generator URL cannot contain credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("LokiProxy generator port is invalid")
    if parsed.path.rstrip("/") != "/gen":
        raise ValueError("LokiProxy generator URL must target /gen")
    if parsed.fragment:
        raise ValueError("LokiProxy generator URL cannot contain a fragment")
    return urllib.parse.urlunsplit(parsed)


def normalize_chain_proxy_mode(value: Any) -> str:
    mode = str(value or "").strip()
    return CHAIN_PROXY_MODE if mode in CHAIN_PROXY_MODES else mode


def is_chain_proxy_mode(value: Any) -> bool:
    return normalize_chain_proxy_mode(value) == CHAIN_PROXY_MODE


def validate_proxy_source(value: str) -> str:
    """Accept a fixed HTTP/SOCKS endpoint or a legacy Loki generator URL."""

    text = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(text)
        scheme = parsed.scheme.casefold()
    except ValueError:
        raise ValueError("proxy source URL is invalid") from None
    if scheme in {"socks", "socks5", "socks5h", "s5", "s5h"}:
        normalized = validate_proxy_url(text)
        _parse_proxy_address(normalized, label="proxy source")
        return normalized
    if scheme == "http":
        host = str(parsed.hostname or "").casefold()
        if (host == _GENERATOR_HOST or host.endswith("." + _GENERATOR_HOST)) and (
            parsed.path.rstrip("/") == "/gen"
        ):
            return validate_generator_url(text)
        normalized = validate_proxy_url(text)
        _parse_proxy_address(normalized, label="proxy source")
        return normalized
    if scheme == "https":
        return validate_generator_url(text)
    raise ValueError(
        "proxy source must be a complete HTTP/SOCKS URL or supported generator URL"
    )


def validate_lokiproxy_source(value: str) -> str:
    """Compatibility alias for callers using the old provider-specific name."""

    return validate_proxy_source(value)


@dataclass(frozen=True)
class ProxyEndpoint:
    host: str
    port: int
    scheme: str = "socks5"
    username: str = ""
    password: str = ""
    ttl_seconds: float | None = None

    def __post_init__(self) -> None:
        host = str(self.host or "").strip()
        if (
            not host
            or any(character.isspace() or ord(character) < 32 for character in host)
            or any(separator in host for separator in ("/", "@", "://"))
        ):
            raise ValueError("proxy source response host is invalid")
        try:
            port = int(self.port)
        except (TypeError, ValueError) as exc:
            raise ValueError("proxy source response port is invalid") from exc
        if not 1 <= port <= 65535:
            raise ValueError("proxy source response port is invalid")
        scheme = _normalize_proxy_scheme(str(self.scheme or "socks5"))
        if scheme == "https":
            scheme = "http"
        username = str(self.username or "")
        password = str(self.password or "")
        if any(ord(character) < 32 for character in username + password):
            raise ValueError("proxy source response credentials are invalid")
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                return item
    return None


def _candidate_mapping(payload: Any) -> Mapping[str, Any] | None:
    direct = _first_mapping(payload)
    if direct is not None and any(
        key in direct for key in ("ip", "host", "server", "address", "port")
    ):
        return direct
    if not isinstance(direct, Mapping):
        return None
    for key in ("data", "result", "proxy", "proxies", "items"):
        candidate = _first_mapping(direct.get(key))
        if candidate is not None:
            return candidate
        nested = direct.get(key)
        if isinstance(nested, Mapping) and any(
            item_key in nested for item_key in ("ip", "host", "server", "address", "port")
        ):
            return nested
    return None


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _ttl_seconds(payload: Mapping[str, Any], item: Mapping[str, Any]) -> float | None:
    for source in (item, payload):
        for key in ("ttl", "ttlSeconds", "ttl_seconds", "expiresIn", "expireIn"):
            value = _number(source.get(key))
            if value is not None:
                return max(5.0, min(value, 900.0))
        for key in ("expiresAt", "expireAt", "expireTime", "expires"):
            value = _number(source.get(key))
            if value is None:
                continue
            if value > 10_000_000_000:
                value /= 1000.0
            remaining = value - time.time()
            if remaining > 0:
                return max(5.0, min(remaining, 900.0))
    return None


def _endpoint_from_mapping(payload: Mapping[str, Any]) -> ProxyEndpoint:
    item = _candidate_mapping(payload)
    if item is None:
        raise ValueError("proxy source response contains no endpoint")
    nested_auth = item.get("auth") if isinstance(item.get("auth"), Mapping) else {}
    host = item.get("ip") or item.get("host") or item.get("server") or item.get("address")
    port = item.get("port") or item.get("serverPort")
    username = item.get("username") or item.get("user") or nested_auth.get("username")
    password = item.get("password") or item.get("pass") or nested_auth.get("password")
    protocol = (
        item.get("scheme")
        or item.get("protocol")
        or item.get("type")
        or item.get("proxyType")
        or "socks5"
    )
    return ProxyEndpoint(
        host=str(host or "").strip(),
        port=int(port),
        scheme=str(protocol),
        username=str(username or ""),
        password=str(password or ""),
        ttl_seconds=_ttl_seconds(payload, item),
    )


def _endpoint_from_text(value: str) -> ProxyEndpoint:
    text = str(value or "").strip().strip("\"'")
    if not text:
        raise ValueError("proxy source response is empty")
    if "://" in text:
        try:
            parsed = urllib.parse.urlsplit(text)
            scheme = _normalize_proxy_scheme(parsed.scheme)
            host = parsed.hostname or ""
            port = parsed.port
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ValueError
            if port is None:
                raise ValueError
            return ProxyEndpoint(
                host=host,
                port=port,
                scheme=scheme,
                username=urllib.parse.unquote(parsed.username or ""),
                password=urllib.parse.unquote(parsed.password or ""),
            )
        except (ValueError, UnicodeError):
            raise ValueError("proxy source response endpoint is invalid") from None
    if text.startswith("["):
        closing = text.find("]")
        if closing <= 0 or closing + 2 > len(text) or text[closing + 1] != ":":
            raise ValueError("proxy source response endpoint is invalid")
        host, port_text = text[1:closing], text[closing + 2 :]
    else:
        host, separator, port_text = text.rpartition(":")
        if not separator:
            raise ValueError("proxy source response endpoint is invalid")
    try:
        return ProxyEndpoint(host=host, port=int(port_text))
    except (TypeError, ValueError) as exc:
        raise ValueError("proxy source response endpoint is invalid") from exc


def parse_proxy_source_response(payload: Any) -> ProxyEndpoint:
    """Extract one SOCKS5/HTTP endpoint from a legacy generator response."""

    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = bytes(payload).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("proxy source response is not UTF-8") from exc
    if isinstance(payload, str):
        text = payload.strip()
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            return _endpoint_from_text(text)
        if isinstance(decoded, str):
            return _endpoint_from_text(decoded)
        payload = decoded
    if isinstance(payload, Mapping):
        return _endpoint_from_mapping(payload)
    if isinstance(payload, list):
        item = _first_mapping(payload)
        if item is not None:
            return _endpoint_from_mapping(item)
    raise ValueError("proxy source response is not an endpoint object")


def parse_lokiproxy_response(payload: Any) -> ProxyEndpoint:
    """Compatibility alias for the old provider-specific parser name."""

    return parse_proxy_source_response(payload)


class ProxySourceResolver:
    def __init__(
        self,
        *,
        requester: Callable[..., Any] | None = None,
        timeout: tuple[float, float] = (5.0, 20.0),
    ) -> None:
        self.requester = requester
        self.timeout = timeout

    def fetch(self, source_url: str, bootstrap_proxy: str) -> ProxyEndpoint:
        normalized_url = validate_proxy_source(source_url)
        proxy = validate_bootstrap_proxy(bootstrap_proxy)
        parsed_source = urllib.parse.urlsplit(normalized_url)
        fixed_proxy = parsed_source.scheme.casefold() in {
            "socks",
            "socks5",
            "socks5h",
            "s5",
            "s5h",
        } or (
            parsed_source.scheme.casefold() == "http"
            and parsed_source.path in {"", "/"}
            and not parsed_source.query
            and not parsed_source.fragment
        )
        if fixed_proxy:
            source_address = _parse_proxy_address(
                normalized_url, label="proxy source"
            )
            return ProxyEndpoint(
                host=source_address.host,
                port=source_address.port,
                scheme=source_address.scheme,
                username=source_address.username,
                password=source_address.password,
            )
        request_kwargs = {
            "proxies": {"http": proxy, "https": proxy},
            "headers": {"Accept": "application/json, text/plain", "Cache-Control": "no-cache"},
            "timeout": self.timeout,
        }
        try:
            if self.requester is not None:
                response = self.requester("GET", normalized_url, **request_kwargs)
            else:
                session = requests.Session()
                session.trust_env = False
                try:
                    response = session.get(normalized_url, **request_kwargs)
                finally:
                    session.close()
        except (requests.RequestException, OSError, TimeoutError, ValueError) as exc:
            raise ProxySourceError("legacy proxy generator request failed") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        raw: bytes | None = None
        content = getattr(response, "content", None)
        if isinstance(content, (bytes, bytearray)):
            if len(content) > _MAX_RESPONSE_BYTES:
                raise ProxySourceError("legacy proxy generator response is too large")
            raw = bytes(content)
        elif getattr(response, "text", None) is not None:
            raw = str(response.text or "").encode("utf-8")
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise ProxySourceError("legacy proxy generator response is too large")
        if status < 200 or status >= 300:
            error_text = "" if raw is None else raw.decode("utf-8", errors="ignore").casefold()
            if "whitelist" in error_text:
                raise ProxySourceNotWhitelistedError(
                    "proxy generator requires the current Clash exit in its IP whitelist"
                )
            if any(
                marker in error_text
                for marker in (
                    "surplus insufficient",
                    "total surplus 0",
                    "insufficient balance",
                    "quota exhausted",
                )
            ):
                raise ProxySourceDepletedError("proxy source has no remaining quota")
            raise ProxySourceError("legacy proxy generator returned an HTTP error")
        try:
            if raw is not None:
                try:
                    payload: Any = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    payload = raw.decode("utf-8")
            else:
                try:
                    payload = response.json()
                except (TypeError, ValueError, AttributeError):
                    payload = str(getattr(response, "text", "") or "")
            return parse_proxy_source_response(payload)
        except (TypeError, ValueError, UnicodeError, AttributeError) as exc:
            # Legacy generators may return a plain `host:port` line or JSON.
            # Both forms are parsed above without exposing
            # the source URL or response body in the raised error.
            raise ProxySourceError("legacy proxy generator response is incomplete") from exc


LokiProxyFetcher = ProxySourceResolver
LokiProxyEndpoint = ProxyEndpoint


@dataclass(frozen=True)
class OwnerChainConfig:
    owner_id: str
    source_url: str
    bootstrap_proxy: str
    listener_port: int
    effective_proxy: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OwnerChainConfig":
        if not isinstance(value, Mapping):
            raise ValueError("owner proxy chain config is invalid")
        owner_id = str(value.get("owner_id") or value.get("alias_id") or "").strip()
        if not owner_id:
            raise ValueError("owner proxy chain config has no owner")
        mode = normalize_chain_proxy_mode(value.get("mode") or CHAIN_PROXY_MODE)
        if mode != CHAIN_PROXY_MODE:
            raise ValueError("owner proxy chain mode is invalid")
        source_url = validate_proxy_source(str(value.get("source_url") or ""))
        # `bootstrap_name` and `bootstrap_port` are accepted only as a migration
        # bridge for the old Mihomo-config implementation.  A node name is never
        # used as a route; it falls back to the one configured local Clash URL.
        bootstrap = str(
            value.get("bootstrap_proxy")
            or value.get("bootstrap_url")
            or value.get("clash_proxy")
            or ""
        ).strip()
        if not bootstrap:
            legacy = str(value.get("bootstrap_name") or "").strip()
            bootstrap = legacy if "://" in legacy else DEFAULT_LOCAL_CLASH_PROXY
        bootstrap = validate_bootstrap_proxy(bootstrap)
        try:
            listener_port = int(value.get("listener_port"))
        except (TypeError, ValueError) as exc:
            raise ValueError("owner proxy listener port is invalid") from exc
        if not 1 <= listener_port <= 65535:
            raise ValueError("owner proxy listener port is invalid")
        effective_proxy = str(value.get("effective_proxy") or "").strip()
        if not effective_proxy:
            effective_proxy = f"socks5h://127.0.0.1:{listener_port}"
        effective_proxy = validate_proxy_url(effective_proxy)
        parsed_effective = urllib.parse.urlsplit(effective_proxy)
        if (
            parsed_effective.hostname not in {"127.0.0.1", "localhost"}
            or parsed_effective.scheme not in {"socks5", "socks5h"}
            or parsed_effective.port != listener_port
            or parsed_effective.username is not None
            or parsed_effective.password is not None
        ):
            raise ValueError("owner proxy listener must bind to localhost")
        return cls(
            owner_id=owner_id,
            source_url=source_url,
            bootstrap_proxy=bootstrap,
            listener_port=listener_port,
            effective_proxy=effective_proxy,
        )

    @property
    def bootstrap_name(self) -> str:
        """Compatibility alias for callers written for the old chain model."""

        return self.bootstrap_proxy

    @property
    def bootstrap_port(self) -> int:
        """Compatibility view of the shared Clash URL port."""

        return int(urllib.parse.urlsplit(self.bootstrap_proxy).port or 0)

    def as_secret_dict(self) -> dict[str, Any]:
        return {
            "version": 3,
            "mode": CHAIN_PROXY_MODE,
            "owner_id": self.owner_id,
            "source_url": self.source_url,
            "bootstrap_proxy": self.bootstrap_proxy,
            "listener_port": self.listener_port,
            "effective_proxy": self.effective_proxy,
        }


def _short_owner_key(owner_id: str) -> str:
    return hashlib.sha256(str(owner_id).encode("utf-8")).hexdigest()[:12]


def _endpoint_expiry(endpoint: ProxyEndpoint, cache_ttl: float) -> float:
    ttl = endpoint.ttl_seconds if endpoint.ttl_seconds is not None else cache_ttl
    return time.monotonic() + max(5.0, min(float(ttl), cache_ttl))


@dataclass
class _CacheEntry:
    endpoint: ProxyEndpoint
    expires_at: float


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProxyRelayError("proxy connection closed during handshake")
        data.extend(chunk)
    return bytes(data)


def _read_until(sock: socket.socket, marker: bytes, limit: int) -> bytes:
    data = bytearray()
    while marker not in data:
        if len(data) >= limit:
            raise ProxyRelayError("proxy handshake header is too large")
        chunk = sock.recv(min(4096, limit - len(data)))
        if not chunk:
            raise ProxyRelayError("proxy connection closed during handshake")
        data.extend(chunk)
        if len(data) > limit:
            raise ProxyRelayError("proxy handshake header is too large")
    return bytes(data)


def _authority(host: str, port: int) -> str:
    text = str(host)
    if ":" in text and not text.startswith("["):
        text = f"[{text}]"
    return f"{text}:{int(port)}"


def _socks5_address(host: str, port: int) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = str(host).encode("idna")
        if not 1 <= len(encoded) <= 255:
            raise ProxyRelayError("SOCKS5 destination hostname is invalid")
        return b"\x03" + bytes([len(encoded)]) + encoded + int(port).to_bytes(2, "big")
    atyp = b"\x01" if address.version == 4 else b"\x04"
    return atyp + address.packed + int(port).to_bytes(2, "big")


def _discard_socks5_address(sock: socket.socket, atyp: int) -> None:
    if atyp == 1:
        _read_exact(sock, 4)
    elif atyp == 3:
        length = _read_exact(sock, 1)[0]
        _read_exact(sock, length)
    elif atyp == 4:
        _read_exact(sock, 16)
    else:
        raise ProxyRelayError("SOCKS5 proxy returned an invalid address type")
    _read_exact(sock, 2)


def _socks5_negotiate(sock: socket.socket, username: str = "", password: str = "") -> None:
    methods = [2, 0] if username or password else [0]
    sock.sendall(b"\x05" + bytes([len(methods)]) + bytes(methods))
    response = _read_exact(sock, 2)
    if response[0] != 5 or response[1] == 0xFF:
        raise ProxyRelayError("SOCKS5 proxy rejected authentication")
    if response[1] == 2:
        user = username.encode("utf-8")
        secret = password.encode("utf-8")
        if len(user) > 255 or len(secret) > 255:
            raise ProxyRelayError("SOCKS5 proxy credentials are too long")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
        auth = _read_exact(sock, 2)
        if auth[1] != 0:
            raise ProxyRelayError("SOCKS5 proxy authentication failed")
    elif response[1] != 0:
        raise ProxyRelayError("SOCKS5 proxy selected an unsupported method")


def _socks5_connect(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(b"\x05\x01\x00" + _socks5_address(host, port))
    response = _read_exact(sock, 4)
    if response[0] != 5:
        raise ProxyRelayError("SOCKS5 proxy returned an invalid response")
    _discard_socks5_address(sock, response[3])
    if response[1] != 0:
        raise ProxyRelayError("SOCKS5 proxy could not connect to destination")


def _http_connect(
    sock: socket.socket,
    host: str,
    port: int,
    *,
    username: str = "",
    password: str = "",
) -> None:
    headers = [
        f"CONNECT {_authority(host, port)} HTTP/1.1",
        f"Host: {_authority(host, port)}",
        "Proxy-Connection: Keep-Alive",
        "Connection: Keep-Alive",
    ]
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    response = _read_until(sock, b"\r\n\r\n", _MAX_HEADER_BYTES)
    first_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    parts = first_line.split(" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError) as exc:
        raise ProxyRelayError("HTTP proxy returned an invalid response") from exc
    if status < 200 or status >= 300:
        raise ProxyRelayError("HTTP proxy could not connect to destination")


def _connect_to_bootstrap(
    bootstrap: _ProxyAddress,
    endpoint: ProxyEndpoint,
    timeout: float,
) -> socket.socket:
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((bootstrap.host, bootstrap.port), timeout=timeout)
        if bootstrap.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=bootstrap.host)
        if bootstrap.scheme in {"http", "https"}:
            _http_connect(
                sock,
                endpoint.host,
                endpoint.port,
                username=bootstrap.username,
                password=bootstrap.password,
            )
        else:
            _socks5_negotiate(sock, bootstrap.username, bootstrap.password)
            _socks5_connect(sock, endpoint.host, endpoint.port)
        return sock
    except (ProxyRelayError, OSError, ssl.SSLError, TimeoutError) as exc:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if isinstance(exc, ProxyRelayError):
            raise
        raise ProxyRelayError("shared Clash could not reach the second-hop proxy") from exc


def _connect_through_endpoint(
    sock: socket.socket,
    endpoint: ProxyEndpoint,
    target_host: str,
    target_port: int,
) -> None:
    if endpoint.scheme == "http":
        _http_connect(
            sock,
            target_host,
            target_port,
            username=endpoint.username,
            password=endpoint.password,
        )
    else:
        _socks5_negotiate(sock, endpoint.username, endpoint.password)
        _socks5_connect(sock, target_host, target_port)


def _connect_chain(
    bootstrap_proxy: str,
    endpoint: ProxyEndpoint,
    target_host: str,
    target_port: int,
    *,
    timeout: float,
) -> socket.socket:
    bootstrap = _parse_proxy_address(bootstrap_proxy, label="shared Clash proxy")
    sock = _connect_to_bootstrap(bootstrap, endpoint, timeout)
    try:
        _connect_through_endpoint(sock, endpoint, target_host, target_port)
        sock.settimeout(None)
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


def _client_socks5_request(sock: socket.socket) -> tuple[str, int]:
    greeting = _read_exact(sock, 2)
    if greeting[0] != 5:
        raise ProxyRelayError("workflow client did not speak SOCKS5")
    methods = _read_exact(sock, greeting[1])
    if 0 not in methods:
        sock.sendall(b"\x05\xff")
        raise ProxyRelayError("workflow SOCKS5 client requires unsupported auth")
    sock.sendall(b"\x05\x00")
    request = _read_exact(sock, 4)
    if request[0] != 5 or request[1] != 1 or request[2] != 0:
        _send_socks5_failure(sock, 7)
        raise ProxyRelayError("workflow requested an unsupported SOCKS5 command")
    atyp = request[3]
    if atyp == 1:
        host = str(ipaddress.ip_address(_read_exact(sock, 4)))
    elif atyp == 3:
        length = _read_exact(sock, 1)[0]
        host = _read_exact(sock, length).decode("idna")
    elif atyp == 4:
        host = str(ipaddress.ip_address(_read_exact(sock, 16)))
    else:
        _send_socks5_failure(sock, 8)
        raise ProxyRelayError("workflow requested an invalid SOCKS5 address")
    port = int.from_bytes(_read_exact(sock, 2), "big")
    if port <= 0:
        _send_socks5_failure(sock, 8)
        raise ProxyRelayError("workflow requested an invalid destination port")
    return host, port


def _send_socks5_failure(sock: socket.socket, code: int) -> None:
    try:
        sock.sendall(b"\x05" + bytes([int(code) & 0xFF]) + b"\x00\x01" + b"\x00" * 6)
    except OSError:
        pass


def _send_socks5_success(sock: socket.socket) -> None:
    sock.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)


class ChainedProxyRelay:
    """A loopback SOCKS5 listener for one owner-specific proxy chain."""

    def __init__(
        self,
        *,
        owner_id: str,
        bootstrap_proxy: str,
        listener_port: int,
        endpoint_supplier: Callable[[], ProxyEndpoint],
        handshake_timeout: float = 30.0,
    ) -> None:
        self.owner_id = str(owner_id)
        self.bootstrap_proxy = validate_bootstrap_proxy(bootstrap_proxy)
        self.listener_port = int(listener_port)
        if not 1 <= self.listener_port <= 65535:
            raise ValueError("relay listener port is invalid")
        if not callable(endpoint_supplier):
            raise TypeError("endpoint_supplier must be callable")
        self.endpoint_supplier = endpoint_supplier
        self.handshake_timeout = max(2.0, min(float(handshake_timeout), 120.0))
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._active: set[socket.socket] = set()
        self._lock = threading.RLock()
        self._stopping = threading.Event()

    @property
    def effective_proxy(self) -> str:
        return f"socks5h://127.0.0.1:{self.listener_port}"

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread is not None and self._thread.is_alive())

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stopping.clear()
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind(("127.0.0.1", self.listener_port))
                server.listen(64)
                server.settimeout(0.5)
            except OSError as exc:
                server.close()
                raise ProxyConfigurationError("local proxy-chain relay port is unavailable") from exc
            self._server = server
            self._thread = threading.Thread(
                target=self._serve,
                name=f"proxy-chain-relay-{_short_owner_key(self.owner_id)}",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, wait_timeout: float = 5.0) -> bool:
        with self._lock:
            self._stopping.set()
            server = self._server
            thread = self._thread
            active = list(self._active)
            self._server = None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.1, float(wait_timeout)))
        with self._lock:
            stopped = thread is None or not thread.is_alive()
            if stopped:
                self._thread = None
                self._active.clear()
            return stopped

    def _serve(self) -> None:
        while not self._stopping.is_set():
            with self._lock:
                server = self._server
            if server is None:
                return
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                if self._stopping.is_set():
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                self._active.add(client)
            threading.Thread(
                target=self._handle,
                args=(client,),
                name=f"proxy-chain-connection-{_short_owner_key(self.owner_id)}",
                daemon=True,
            ).start()

    def _handle(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(self.handshake_timeout)
            target_host, target_port = _client_socks5_request(client)
            endpoint = self.endpoint_supplier()
            if not isinstance(endpoint, ProxyEndpoint):
                raise ProxyRelayError("second-hop proxy endpoint is invalid")
            upstream = _connect_chain(
                self.bootstrap_proxy,
                endpoint,
                target_host,
                target_port,
                timeout=self.handshake_timeout,
            )
            _send_socks5_success(client)
            client.settimeout(None)
            self._relay(client, upstream)
        except ProxyChainError:
            if upstream is None:
                _send_socks5_failure(client, 1)
        except (OSError, UnicodeError, ValueError, TimeoutError):
            if upstream is None:
                _send_socks5_failure(client, 1)
        finally:
            for connection in (upstream, client):
                if connection is None:
                    continue
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    pass
            with self._lock:
                self._active.discard(client)

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        while not self._stopping.is_set():
            try:
                readable, _, _ = select.select([client, upstream], [], [], 1.0)
            except (OSError, ValueError):
                return
            for source in readable:
                destination = upstream if source is client else client
                try:
                    data = source.recv(64 * 1024)
                except OSError:
                    return
                if not data:
                    return
                try:
                    destination.sendall(data)
                except OSError:
                    return


class ProxyChainManager:
    """Manage two or more owner relays without touching the user's Clash."""

    def __init__(
        self,
        *,
        app_dir: str | Path,
        console_port: int = 8765,
        list_configs: Callable[[], Sequence[Mapping[str, Any]]],
        get_config: Callable[[str], Mapping[str, Any]],
        fetcher: ProxySourceResolver | None = None,
        clash: Any | None = None,
        provider_token: str | None = None,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        bootstrap_proxy: str = DEFAULT_LOCAL_CLASH_PROXY,
    ) -> None:
        del console_port, clash
        self.app_dir = Path(app_dir).expanduser().resolve()
        self.list_configs = list_configs
        self.get_config = get_config
        self.fetcher = fetcher or ProxySourceResolver()
        self.bootstrap_proxy = validate_bootstrap_proxy(bootstrap_proxy)
        self.provider_token = str(provider_token or "")
        self.cache_ttl = max(5.0, min(float(cache_ttl), 900.0))
        self._cache: dict[str, _CacheEntry] = {}
        self._errors: dict[str, str] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._relays: dict[str, ChainedProxyRelay] = {}
        self._relay_configs: dict[str, OwnerChainConfig] = {}
        self._lock = threading.RLock()
        self._apply_lock = threading.Lock()

    def _owner_lock(self, owner_id: str) -> threading.Lock:
        with self._lock:
            return self._locks.setdefault(str(owner_id), threading.Lock())

    def configs(self) -> list[OwnerChainConfig]:
        result: list[OwnerChainConfig] = []
        for raw in self.list_configs():
            try:
                config = OwnerChainConfig.from_mapping(raw)
            except (TypeError, ValueError):
                continue
            result.append(config)
        return result

    def _assert_shared_bootstrap(self, value: str) -> str:
        normalized = validate_bootstrap_proxy(value or self.bootstrap_proxy)
        if normalized != self.bootstrap_proxy:
            raise ProxyConfigurationError(
                "all Team proxy chains must use the same local Clash proxy"
            )
        return normalized

    def prepare(
        self,
        owner_id: str,
        source_url: str,
        bootstrap_proxy: str = "",
    ) -> OwnerChainConfig:
        normalized_owner = str(owner_id or "").strip()
        if not normalized_owner:
            raise ProxyConfigurationError("Team owner is required")
        source = validate_proxy_source(source_url)
        bootstrap = self._assert_shared_bootstrap(bootstrap_proxy)
        existing = {item.owner_id: item for item in self.configs()}
        previous = existing.get(normalized_owner)
        if previous is not None:
            listener_port = previous.listener_port
        else:
            used = {item.listener_port for item in existing.values()}
            with self._lock:
                used.update(relay.listener_port for relay in self._relays.values())
            digest = int(hashlib.sha256(normalized_owner.encode()).hexdigest()[:8], 16)
            listener_port = 0
            for offset in range(0, 1000):
                candidate = DEFAULT_LISTENER_PORT_BASE + ((digest + offset) % 1000)
                if candidate in used or _port_busy(candidate):
                    continue
                listener_port = candidate
                break
            if not listener_port:
                raise ProxyConfigurationError("no free local proxy-chain relay port is available")
        effective = f"socks5h://127.0.0.1:{listener_port}"
        return OwnerChainConfig(
            owner_id=normalized_owner,
            source_url=source,
            bootstrap_proxy=bootstrap,
            listener_port=listener_port,
            effective_proxy=effective,
        )

    def apply(self, *, cleanup: bool = False) -> dict[str, Any]:
        with self._apply_lock:
            desired = {} if cleanup else {item.owner_id: item for item in self.configs()}
            for config in desired.values():
                self._assert_shared_bootstrap(config.bootstrap_proxy)

            with self._lock:
                stale_ids = set(self._relays) - set(desired)
                replacements = [
                    owner_id
                    for owner_id, old_config in self._relay_configs.items()
                    if owner_id in desired and old_config != desired[owner_id]
                ]
                stop_ids = stale_ids | set(replacements)
                old_relays = [
                    self._relays.pop(owner_id)
                    for owner_id in stop_ids
                    if owner_id in self._relays
                ]
                for owner_id in stop_ids:
                    self._relay_configs.pop(owner_id, None)
                    self._cache.pop(owner_id, None)
            for relay in old_relays:
                relay.stop()

            started: list[ChainedProxyRelay] = []
            try:
                for owner_id, config in desired.items():
                    with self._lock:
                        if owner_id in self._relays:
                            continue
                    relay = ChainedProxyRelay(
                        owner_id=owner_id,
                        bootstrap_proxy=config.bootstrap_proxy,
                        listener_port=config.listener_port,
                        endpoint_supplier=lambda owner_id=owner_id: self.refresh(owner_id),
                    )
                    relay.start()
                    with self._lock:
                        self._relays[owner_id] = relay
                        self._relay_configs[owner_id] = config
                    started.append(relay)
            except Exception:
                for relay in started:
                    relay.stop()
                with self._lock:
                    for owner_id, relay in list(self._relays.items()):
                        if relay in started:
                            self._relays.pop(owner_id, None)
                            self._relay_configs.pop(owner_id, None)
                raise
            return {
                "applied": bool(desired or old_relays),
                "chain_count": len(desired),
                "shared_bootstrap": _safe_proxy_label(self.bootstrap_proxy),
            }

    def available_nodes(self) -> list[str]:
        return [self.bootstrap_proxy]

    def refresh(self, owner_id: str, *, force: bool = False) -> ProxyEndpoint:
        normalized_owner = str(owner_id or "").strip()
        try:
            config = OwnerChainConfig.from_mapping(self.get_config(normalized_owner))
        except (KeyError, TypeError, ValueError) as exc:
            raise ProxyConfigurationError("Team proxy chain is not configured") from exc
        self._assert_shared_bootstrap(config.bootstrap_proxy)
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(normalized_owner)
            if not force and cached is not None and cached.expires_at > now:
                return cached.endpoint
        lock = self._owner_lock(normalized_owner)
        with lock:
            now = time.monotonic()
            with self._lock:
                cached = self._cache.get(normalized_owner)
                if not force and cached is not None and cached.expires_at > now:
                    return cached.endpoint
            try:
                endpoint = self.fetcher.fetch(config.source_url, config.bootstrap_proxy)
            except ProxyChainError as exc:
                with self._lock:
                    self._errors[normalized_owner] = exc.code
                raise
            with self._lock:
                self._cache[normalized_owner] = _CacheEntry(
                    endpoint, _endpoint_expiry(endpoint, self.cache_ttl)
                )
                self._errors.pop(normalized_owner, None)
            return endpoint

    def ensure_ready(self, owner_id: str) -> str:
        normalized_owner = str(owner_id or "").strip()
        config = OwnerChainConfig.from_mapping(self.get_config(normalized_owner))
        self.apply()
        self.refresh(normalized_owner, force=True)
        with self._lock:
            relay = self._relays.get(normalized_owner)
        if relay is None or not relay.running:
            raise ProxyRelayError("local proxy-chain relay is not running")
        return config.effective_proxy

    def status(self, owner_id: str) -> dict[str, Any]:
        normalized_owner = str(owner_id or "").strip()
        try:
            config = OwnerChainConfig.from_mapping(self.get_config(normalized_owner))
        except (KeyError, TypeError, ValueError):
            return {"configured": False, "healthy": False, "error": "not_configured"}
        with self._lock:
            cached = self._cache.get(normalized_owner)
            error = self._errors.get(normalized_owner)
            relay = self._relays.get(normalized_owner)
        return {
            "configured": True,
            "healthy": bool(cached is not None and cached.expires_at > time.monotonic()),
            "relay_running": bool(relay is not None and relay.running),
            "error": error,
            "listener": f"127.0.0.1:{config.listener_port}",
            "bootstrap_proxy": _safe_proxy_label(config.bootstrap_proxy),
            "shared_bootstrap": config.bootstrap_proxy == self.bootstrap_proxy,
        }

    def provider_payload(self, owner_id: str) -> bytes:
        """Compatibility diagnostic; no Mihomo provider consumes this payload."""

        endpoint = self.refresh(str(owner_id))
        return json.dumps(
            {
                "proxies": [
                    {
                        "name": f"TeamWorkflow-{_short_owner_key(owner_id)}",
                        "type": endpoint.scheme,
                        "server": endpoint.host,
                        "port": endpoint.port,
                    }
                ]
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def shutdown(self) -> bool:
        with self._lock:
            relays = list(self._relays.values())
            self._relays.clear()
            self._relay_configs.clear()
        stopped = True
        for relay in relays:
            stopped = relay.stop() and stopped
        return stopped


def _port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", int(port)))
        except OSError:
            return True
    return False


__all__ = [
    "CHAIN_PROXY_MODE",
    "CHAIN_PROXY_MODES",
    "ChainedProxyRelay",
    "LEGACY_CHAIN_PROXY_MODE",
    "LokiProxyEndpoint",
    "LokiProxyFetcher",
    "OwnerChainConfig",
    "ProxyEndpoint",
    "ProxyChainError",
    "ProxyChainManager",
    "ProxyConfigurationError",
    "ProxyRelayError",
    "ProxySourceDepletedError",
    "ProxySourceError",
    "ProxySourceNotWhitelistedError",
    "ProxySourceResolver",
    "is_chain_proxy_mode",
    "normalize_chain_proxy_mode",
    "parse_lokiproxy_response",
    "parse_proxy_source_response",
    "validate_bootstrap_proxy",
    "validate_generator_url",
    "validate_lokiproxy_source",
    "validate_proxy_source",
    "validate_proxy_url",
]
