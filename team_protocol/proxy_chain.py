"""Two-hop LokiProxy chains backed by one Mihomo process.

The module deliberately keeps the generator URL out of workflow credentials.  A
workflow receives only a stable loopback listener; the generator response is
resolved just in time and published to a Mihomo proxy-provider.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import socket
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import requests
import yaml


DEFAULT_CLASH_CONFIG = (
    Path.home()
    / "Library"
    / "Application Support"
    / "io.github.clash-verge-rev.clash-verge-rev"
    / "clash-verge.yaml"
)
DEFAULT_CLASH_SOCKET = Path("/tmp/verge/verge-mihomo.sock")
DEFAULT_CLASH_BINARY = Path("/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo")
DEFAULT_BOOTSTRAP_PORT_BASE = 18_780
DEFAULT_OWNER_PORT_BASE = 18_880
DEFAULT_CACHE_TTL = 45.0
_GENERATOR_HOST = "gen.lokiproxy.com"
_CHAIN_PREFIX = "TeamWorkflow::"
_PROVIDER_PREFIX = "teamworkflow_"


class ProxyChainError(RuntimeError):
    code = "proxy_chain_error"


class ProxySourceError(ProxyChainError):
    code = "proxy_source_unavailable"


class ProxyConfigurationError(ProxyChainError):
    code = "proxy_chain_configuration"


def _decode_http_body(headers: bytes, payload: bytes) -> bytes:
    """Decode the bounded HTTP response body returned by the Unix API."""

    fields: dict[str, str] = {}
    for line in headers.split(b"\r\n")[1:]:
        key, separator, value = line.partition(b":")
        if separator:
            fields[key.decode("ascii", errors="ignore").casefold()] = (
                value.decode("ascii", errors="ignore").strip().casefold()
            )
    transfer_encoding = fields.get("transfer-encoding", "")
    if "chunked" not in transfer_encoding:
        content_length = fields.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError as exc:
                raise ProxyConfigurationError("Mihomo REST API response is invalid") from exc
            if length < 0 or length > len(payload):
                raise ProxyConfigurationError("Mihomo REST API response is incomplete")
            return payload[:length]
        return payload

    decoded = bytearray()
    cursor = 0
    while True:
        line_end = payload.find(b"\r\n", cursor)
        if line_end < 0:
            raise ProxyConfigurationError("Mihomo REST API response is incomplete")
        size_text = payload[cursor:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ProxyConfigurationError("Mihomo REST API response is invalid") from exc
        cursor = line_end + 2
        if size < 0 or size > 64 * 1024 * 1024:
            raise ProxyConfigurationError("Mihomo REST API response is invalid")
        if size == 0:
            # Trailers are optional. The terminating CRLF is enough for the
            # responses Mihomo emits, while a trailer block is also accepted.
            if payload[cursor:cursor + 2] == b"\r\n":
                return bytes(decoded)
            trailer_end = payload.find(b"\r\n\r\n", cursor)
            if trailer_end < 0:
                raise ProxyConfigurationError("Mihomo REST API response is incomplete")
            return bytes(decoded)
        end = cursor + size
        if end + 2 > len(payload) or payload[end:end + 2] != b"\r\n":
            raise ProxyConfigurationError("Mihomo REST API response is incomplete")
        decoded.extend(payload[cursor:end])
        cursor = end + 2


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


def validate_bootstrap_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("Clash first-hop node is required")
    if len(text) > 160 or any(ord(character) < 32 for character in text):
        raise ValueError("Clash first-hop node is invalid")
    return text


@dataclass(frozen=True)
class LokiProxyEndpoint:
    host: str
    port: int
    scheme: str = "socks5"
    username: str = ""
    password: str = ""
    ttl_seconds: float | None = None

    def __post_init__(self) -> None:
        host = str(self.host or "").strip()
        if not host or any(character.isspace() for character in host):
            raise ValueError("LokiProxy response host is invalid")
        try:
            port = int(self.port)
        except (TypeError, ValueError) as exc:
            raise ValueError("LokiProxy response port is invalid") from exc
        if not 1 <= port <= 65535:
            raise ValueError("LokiProxy response port is invalid")
        scheme = str(self.scheme or "socks5").casefold().replace("_", "")
        if scheme in {"socks", "socks5h", "socks5"}:
            scheme = "socks5"
        elif scheme in {"http", "https"}:
            scheme = "http"
        else:
            raise ValueError("LokiProxy response protocol is unsupported")
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "username", str(self.username or ""))
        object.__setattr__(self, "password", str(self.password or ""))


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                return item
    return None


def _candidate_mapping(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    direct = _first_mapping(payload)
    if direct is not None and any(
        key in direct for key in ("ip", "host", "server", "port")
    ):
        return direct
    for key in ("data", "result", "proxy", "proxies", "items"):
        candidate = _first_mapping(payload.get(key))
        if candidate is not None:
            return candidate
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


def parse_lokiproxy_response(payload: Any) -> LokiProxyEndpoint:
    """Extract the first endpoint from LokiProxy JSON without accepting a URL."""

    if not isinstance(payload, Mapping):
        raise ValueError("LokiProxy response is not an object")
    item = _candidate_mapping(payload)
    if item is None:
        raise ValueError("LokiProxy response contains no proxy endpoint")
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
    # Accept IP literals and hostnames, but reject values that could smuggle a URL
    # or an authority separator into the generated Mihomo document.
    host_text = str(host or "").strip()
    if "://" in host_text or "/" in host_text or "@" in host_text:
        raise ValueError("LokiProxy response host is invalid")
    try:
        endpoint = LokiProxyEndpoint(
            host=host_text,
            port=int(port),
            scheme=str(protocol),
            username=str(username or ""),
            password=str(password or ""),
            ttl_seconds=_ttl_seconds(payload, item),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    return endpoint


class LokiProxyFetcher:
    def __init__(
        self,
        *,
        requester: Callable[..., Any] | None = None,
        timeout: tuple[float, float] = (5.0, 20.0),
    ) -> None:
        self.requester = requester
        self.timeout = timeout

    def fetch(self, source_url: str, bootstrap_proxy: str) -> LokiProxyEndpoint:
        normalized_url = validate_generator_url(source_url)
        proxy = str(bootstrap_proxy or "").strip()
        if not proxy:
            raise ProxySourceError("Clash first-hop listener is unavailable")
        try:
            if self.requester is not None:
                response = self.requester(
                    "GET",
                    normalized_url,
                    proxies={"http": proxy, "https": proxy},
                    headers={"Accept": "application/json", "Cache-Control": "no-cache"},
                    timeout=self.timeout,
                )
            else:
                session = requests.Session()
                session.trust_env = False
                response = session.get(
                    normalized_url,
                    proxies={"http": proxy, "https": proxy},
                    headers={"Accept": "application/json", "Cache-Control": "no-cache"},
                    timeout=self.timeout,
                )
        except (requests.RequestException, OSError, TimeoutError) as exc:
            raise ProxySourceError("LokiProxy generator request failed") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status < 200 or status >= 300:
            raise ProxySourceError("LokiProxy generator returned an HTTP error")
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise ProxySourceError("LokiProxy generator returned invalid JSON") from exc
        try:
            return parse_lokiproxy_response(payload)
        except ValueError as exc:
            raise ProxySourceError("LokiProxy generator response is incomplete") from exc


@dataclass(frozen=True)
class OwnerChainConfig:
    owner_id: str
    source_url: str
    bootstrap_name: str
    bootstrap_port: int
    listener_port: int
    effective_proxy: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OwnerChainConfig":
        if not isinstance(value, Mapping):
            raise ValueError("owner proxy chain config is invalid")
        owner_id = str(value.get("owner_id") or value.get("alias_id") or "").strip()
        if not owner_id:
            raise ValueError("owner proxy chain config has no owner")
        source_url = validate_generator_url(str(value.get("source_url") or ""))
        bootstrap_name = validate_bootstrap_name(
            str(value.get("bootstrap_name") or value.get("bootstrap") or "")
        )
        try:
            bootstrap_port = int(value.get("bootstrap_port"))
            listener_port = int(value.get("listener_port"))
        except (TypeError, ValueError) as exc:
            raise ValueError("owner proxy chain ports are invalid") from exc
        if not 1 <= bootstrap_port <= 65535 or not 1 <= listener_port <= 65535:
            raise ValueError("owner proxy chain ports are invalid")
        effective_proxy = str(value.get("effective_proxy") or "").strip()
        if not effective_proxy:
            effective_proxy = f"socks5://127.0.0.1:{listener_port}"
        return cls(
            owner_id=owner_id,
            source_url=source_url,
            bootstrap_name=bootstrap_name,
            bootstrap_port=bootstrap_port,
            listener_port=listener_port,
            effective_proxy=effective_proxy,
        )

    def as_secret_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "mode": "lokiproxy_generator",
            "owner_id": self.owner_id,
            "source_url": self.source_url,
            "bootstrap_name": self.bootstrap_name,
            "bootstrap_port": self.bootstrap_port,
            "listener_port": self.listener_port,
            "effective_proxy": self.effective_proxy,
        }


def _short_owner_key(owner_id: str) -> str:
    return hashlib.sha256(str(owner_id).encode("utf-8")).hexdigest()[:12]


def _chain_names(owner_id: str) -> dict[str, str]:
    key = _short_owner_key(owner_id)
    return {
        "bootstrap_listener": f"{_CHAIN_PREFIX}{key} bootstrap",
        "provider": f"{_PROVIDER_PREFIX}{key}",
        "group": f"{_CHAIN_PREFIX}{key} group",
        "owner_listener": f"{_CHAIN_PREFIX}{key} owner",
        "node": f"{_CHAIN_PREFIX}{key} dynamic",
    }


def provider_document(
    owner_id: str,
    endpoint: LokiProxyEndpoint,
    *,
    dialer_proxy: str,
) -> bytes:
    names = _chain_names(owner_id)
    node: dict[str, Any] = {
        "name": names["node"],
        "type": endpoint.scheme,
        "server": endpoint.host,
        "port": endpoint.port,
        "dialer-proxy": validate_bootstrap_name(dialer_proxy),
    }
    if endpoint.username:
        node["username"] = endpoint.username
    if endpoint.password:
        node["password"] = endpoint.password
    return json.dumps(
        {"proxies": [node]},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _generated_name(name: str) -> bool:
    return str(name or "").startswith(_CHAIN_PREFIX)


def build_clash_config(
    base: Mapping[str, Any],
    chains: Sequence[OwnerChainConfig],
    *,
    provider_base_url: str,
    provider_token: str,
) -> dict[str, Any]:
    """Build a full config while preserving user nodes, groups and rules."""

    if not isinstance(base, Mapping):
        raise ProxyConfigurationError("Clash base configuration is invalid")
    result = copy.deepcopy(dict(base))
    result["proxies"] = [
        item
        for item in (result.get("proxies") or [])
        if isinstance(item, Mapping) and not _generated_name(item.get("name"))
    ]
    result["proxy-groups"] = [
        item
        for item in (result.get("proxy-groups") or [])
        if isinstance(item, Mapping) and not _generated_name(item.get("name"))
    ]
    providers = {
        str(name): copy.deepcopy(value)
        for name, value in (result.get("proxy-providers") or {}).items()
        if not str(name).startswith(_PROVIDER_PREFIX)
    }
    listeners = [
        item
        for item in (result.get("listeners") or [])
        if isinstance(item, Mapping) and not _generated_name(item.get("name"))
    ]
    base_url = str(provider_base_url or "").rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise ProxyConfigurationError("proxy provider base URL is invalid")
    token = str(provider_token or "").strip()
    if not token:
        raise ProxyConfigurationError("proxy provider token is empty")

    bootstrap_seen: set[tuple[str, int]] = set()
    for chain in chains:
        names = _chain_names(chain.owner_id)
        bootstrap_key = (chain.bootstrap_name, chain.bootstrap_port)
        if bootstrap_key not in bootstrap_seen:
            listeners.append(
                {
                    "name": names["bootstrap_listener"],
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "port": chain.bootstrap_port,
                    "proxy": chain.bootstrap_name,
                }
            )
            bootstrap_seen.add(bootstrap_key)
        query = urllib.parse.urlencode({"token": token})
        provider_url = (
            f"{base_url}/internal/proxy-chain/"
            f"{urllib.parse.quote(chain.owner_id, safe='')}/provider?{query}"
        )
        providers[names["provider"]] = {
            "type": "http",
            "url": provider_url,
            "path": f"./proxy_providers/{names['provider']}.yaml",
            "interval": 30,
            "proxy": "DIRECT",
            "override": {"dialer-proxy": chain.bootstrap_name},
        }
        result["proxy-groups"].append(
            {"name": names["group"], "type": "select", "use": [names["provider"]]}
        )
        listeners.append(
            {
                "name": names["owner_listener"],
                "type": "mixed",
                "listen": "127.0.0.1",
                "port": chain.listener_port,
                "proxy": names["group"],
            }
        )
    result["proxy-providers"] = providers
    result["listeners"] = listeners
    return result


def dump_clash_config(value: Mapping[str, Any]) -> bytes:
    try:
        return yaml.safe_dump(
            dict(value),
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ).encode("utf-8")
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise ProxyConfigurationError("Clash configuration cannot be serialized") from exc


class MihomoApiClient:
    """Small Unix-socket client for the Mihomo REST API."""

    def __init__(
        self,
        *,
        unix_socket: str | Path | None = None,
        tcp_base_url: str = "",
        secret: str = "",
        timeout: float = 8.0,
    ) -> None:
        self.unix_socket = Path(unix_socket).expanduser() if unix_socket else None
        self.tcp_base_url = str(tcp_base_url or "").rstrip("/")
        self.secret = str(secret or "").strip()
        self.timeout = max(1.0, min(float(timeout), 30.0))

    def _unix_request(self, method: str, path: str, body: bytes) -> tuple[int, bytes]:
        if self.unix_socket is None or not self.unix_socket.exists():
            raise ProxyConfigurationError("Mihomo Unix API socket is unavailable")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(str(self.unix_socket))
            headers = [
                f"{method} {path} HTTP/1.1",
                "Host: localhost",
                "Connection: close",
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
            ]
            if self.secret:
                headers.append(f"Authorization: Bearer {self.secret}")
            sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + body)
            data = bytearray()
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        except OSError as exc:
            raise ProxyConfigurationError("Mihomo REST API request failed") from exc
        finally:
            sock.close()
        header, separator, payload = bytes(data).partition(b"\r\n\r\n")
        if not separator:
            raise ProxyConfigurationError("Mihomo REST API response is invalid")
        first_line = header.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        try:
            status = int(first_line.split(" ", 2)[1])
        except (IndexError, ValueError) as exc:
            raise ProxyConfigurationError("Mihomo REST API response is invalid") from exc
        return status, _decode_http_body(header, payload)

    def put_config(self, payload: bytes) -> None:
        body = json.dumps(
            {"payload": payload.decode("utf-8")},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if self.unix_socket is not None:
            status, _ = self._unix_request("PUT", "/configs?force=true", body)
        else:
            if not self.tcp_base_url:
                raise ProxyConfigurationError("Mihomo REST API endpoint is not configured")
            try:
                response = requests.put(
                    f"{self.tcp_base_url}/configs?force=true",
                    json={"payload": payload.decode("utf-8")},
                    headers=(
                        {"Authorization": f"Bearer {self.secret}"}
                        if self.secret
                        else None
                    ),
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                raise ProxyConfigurationError("Mihomo REST API request failed") from exc
            status = int(response.status_code)
        if status < 200 or status >= 300:
            raise ProxyConfigurationError("Mihomo rejected the Team Workflow configuration")

    def version(self) -> str:
        if self.unix_socket is not None:
            status, body = self._unix_request("GET", "/version", b"")
            if status < 200 or status >= 300:
                raise ProxyConfigurationError("Mihomo version request failed")
            try:
                return str(json.loads(body.decode("utf-8")).get("version") or "unknown")
            except (UnicodeDecodeError, ValueError, AttributeError):
                return "unknown"
        if not self.tcp_base_url:
            raise ProxyConfigurationError("Mihomo REST API endpoint is not configured")
        try:
            response = requests.get(
                f"{self.tcp_base_url}/version",
                headers=(
                    {"Authorization": f"Bearer {self.secret}"} if self.secret else None
                ),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ProxyConfigurationError("Mihomo version request failed") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise ProxyConfigurationError("Mihomo version request failed")
        try:
            return str(response.json().get("version") or "unknown")
        except (TypeError, ValueError, AttributeError):
            return "unknown"


class ClashConfigManager:
    def __init__(
        self,
        *,
        app_dir: str | Path,
        provider_base_url: str,
        provider_token: str,
        source_path: str | Path | None = None,
        api: MihomoApiClient | None = None,
        binary: str | Path | None = None,
    ) -> None:
        self.app_dir = Path(app_dir).expanduser().resolve()
        self.provider_base_url = str(provider_base_url).rstrip("/")
        self.provider_token = str(provider_token or "").strip()
        self.source_path = (
            Path(source_path).expanduser().resolve()
            if source_path is not None
            else Path(
                os.environ.get("TEAM_WORKFLOW_CLASH_CONFIG") or DEFAULT_CLASH_CONFIG
            ).expanduser().resolve()
        )
        socket_path = os.environ.get("TEAM_WORKFLOW_CLASH_SOCKET") or str(
            DEFAULT_CLASH_SOCKET
        )
        self.api = api or MihomoApiClient(
            unix_socket=socket_path,
            tcp_base_url=os.environ.get("TEAM_WORKFLOW_CLASH_API", ""),
            secret=os.environ.get("TEAM_WORKFLOW_CLASH_SECRET", ""),
        )
        self.binary = Path(
            binary
            or os.environ.get("TEAM_WORKFLOW_CLASH_BINARY")
            or DEFAULT_CLASH_BINARY
        ).expanduser()
        self.generated_path = self.app_dir / "clash" / "teamworkflow.yaml"
        self._lock = threading.RLock()

    def _load_base(self) -> dict[str, Any]:
        if not self.source_path.is_file():
            raise ProxyConfigurationError("Clash merged configuration was not found")
        try:
            value = yaml.safe_load(self.source_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ProxyConfigurationError("Clash merged configuration cannot be read") from exc
        if not isinstance(value, Mapping):
            raise ProxyConfigurationError("Clash merged configuration is invalid")
        return dict(value)

    def available_nodes(self) -> set[str]:
        base = self._load_base()
        names: set[str] = set()
        for item in base.get("proxies") or []:
            if isinstance(item, Mapping) and item.get("name"):
                names.add(str(item["name"]))
        for item in base.get("proxy-groups") or []:
            if isinstance(item, Mapping) and item.get("name"):
                names.add(str(item["name"]))
        return names

    def apply(self, chains: Sequence[OwnerChainConfig]) -> dict[str, Any]:
        with self._lock:
            base = self._load_base()
            config = build_clash_config(
                base,
                chains,
                provider_base_url=self.provider_base_url,
                provider_token=self.provider_token,
            )
            payload = dump_clash_config(config)
            self.generated_path.parent.mkdir(parents=True, exist_ok=True)
            self.generated_path.write_bytes(payload)
            os.chmod(self.generated_path, 0o600)
            if self.binary.is_file() and os.access(self.binary, os.X_OK):
                try:
                    completed = subprocess.run(
                        [
                            str(self.binary),
                            "-t",
                            "-d",
                            str(self.source_path.parent),
                            "-f",
                            str(self.generated_path),
                        ],
                        capture_output=True,
                        timeout=20.0,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise ProxyConfigurationError("Mihomo configuration validation failed") from exc
                if completed.returncode != 0:
                    raise ProxyConfigurationError("Mihomo rejected the Team Workflow configuration")
            self.api.put_config(payload)
            try:
                version = self.api.version()
            except ProxyConfigurationError:
                version = "unknown"
            return {
                "applied": True,
                "version": version,
                "chain_count": len(chains),
                "path": str(self.generated_path),
            }


def _load_or_create_provider_token(app_dir: Path) -> str:
    path = app_dir / "proxy-chain.token"
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        value = ""
    if value:
        return value
    value = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="ascii")
    os.chmod(path, 0o600)
    return value


@dataclass
class _CacheEntry:
    endpoint: LokiProxyEndpoint
    expires_at: float


class ProxyChainManager:
    """Coordinate per-owner source refreshes and Mihomo configuration."""

    def __init__(
        self,
        *,
        app_dir: str | Path,
        console_port: int,
        list_configs: Callable[[], Sequence[Mapping[str, Any]]],
        get_config: Callable[[str], Mapping[str, Any]],
        fetcher: LokiProxyFetcher | None = None,
        clash: ClashConfigManager | None = None,
        provider_token: str | None = None,
        cache_ttl: float = DEFAULT_CACHE_TTL,
    ) -> None:
        self.app_dir = Path(app_dir).expanduser().resolve()
        self.console_port = int(console_port)
        self.list_configs = list_configs
        self.get_config = get_config
        self.provider_token = provider_token or _load_or_create_provider_token(self.app_dir)
        self.fetcher = fetcher or LokiProxyFetcher()
        self.clash = clash or ClashConfigManager(
            app_dir=self.app_dir,
            provider_base_url=f"http://127.0.0.1:{self.console_port}",
            provider_token=self.provider_token,
        )
        self.cache_ttl = max(5.0, min(float(cache_ttl), 900.0))
        self._cache: dict[str, _CacheEntry] = {}
        self._errors: dict[str, str] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._lock = threading.RLock()

    def _owner_lock(self, owner_id: str) -> threading.Lock:
        with self._lock:
            return self._locks.setdefault(str(owner_id), threading.Lock())

    def configs(self) -> list[OwnerChainConfig]:
        result: list[OwnerChainConfig] = []
        for raw in self.list_configs():
            try:
                result.append(OwnerChainConfig.from_mapping(raw))
            except (TypeError, ValueError):
                continue
        return result

    def prepare(
        self,
        owner_id: str,
        source_url: str,
        bootstrap_name: str,
    ) -> OwnerChainConfig:
        normalized_owner = str(owner_id or "").strip()
        if not normalized_owner:
            raise ProxyConfigurationError("Team owner is required")
        source = validate_generator_url(source_url)
        bootstrap = validate_bootstrap_name(bootstrap_name)
        existing = {item.owner_id: item for item in self.configs()}
        previous = existing.get(normalized_owner)
        if previous is not None:
            bootstrap_port = previous.bootstrap_port
            listener_port = previous.listener_port
        else:
            used = {
                port
                for item in existing.values()
                for port in (item.bootstrap_port, item.listener_port)
            }
            digest = int(hashlib.sha256(normalized_owner.encode()).hexdigest()[:8], 16)
            bootstrap_port = listener_port = 0
            for offset in range(0, 500):
                candidate_bootstrap = DEFAULT_BOOTSTRAP_PORT_BASE + ((digest + offset * 2) % 500)
                candidate_listener = DEFAULT_OWNER_PORT_BASE + ((digest + offset * 2) % 500)
                if candidate_bootstrap in used or candidate_listener in used:
                    continue
                if _port_busy(candidate_bootstrap) or _port_busy(candidate_listener):
                    continue
                bootstrap_port = candidate_bootstrap
                listener_port = candidate_listener
                break
            if not bootstrap_port:
                raise ProxyConfigurationError("no free local proxy-chain ports are available")
        effective = f"socks5://127.0.0.1:{listener_port}"
        return OwnerChainConfig(
            owner_id=normalized_owner,
            source_url=source,
            bootstrap_name=bootstrap,
            bootstrap_port=bootstrap_port,
            listener_port=listener_port,
            effective_proxy=effective,
        )

    def apply(self, *, cleanup: bool = False) -> dict[str, Any]:
        chains = self.configs()
        if not chains and not cleanup:
            return {"applied": False, "chain_count": 0, "reason": "no_generated_chains"}
        available = self.clash.available_nodes()
        missing = {chain.bootstrap_name for chain in chains} - available
        if missing:
            raise ProxyConfigurationError("one or more Clash first-hop nodes are missing")
        return self.clash.apply(chains)

    def available_nodes(self) -> list[str]:
        return sorted(self.clash.available_nodes(), key=str.casefold)

    def refresh(self, owner_id: str, *, force: bool = False) -> LokiProxyEndpoint:
        normalized_owner = str(owner_id or "").strip()
        config = OwnerChainConfig.from_mapping(self.get_config(normalized_owner))
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
                endpoint = self.fetcher.fetch(
                    config.source_url,
                    f"http://127.0.0.1:{config.bootstrap_port}",
                )
            except ProxyChainError as exc:
                with self._lock:
                    self._errors[normalized_owner] = exc.code
                raise
            ttl = endpoint.ttl_seconds or self.cache_ttl
            ttl = max(5.0, min(ttl, self.cache_ttl))
            with self._lock:
                self._cache[normalized_owner] = _CacheEntry(endpoint, time.monotonic() + ttl)
                self._errors.pop(normalized_owner, None)
            return endpoint

    def provider_payload(self, owner_id: str) -> bytes:
        config = OwnerChainConfig.from_mapping(self.get_config(str(owner_id)))
        endpoint = self.refresh(config.owner_id)
        return provider_document(
            config.owner_id,
            endpoint,
            dialer_proxy=config.bootstrap_name,
        )

    def ensure_ready(self, owner_id: str) -> str:
        config = OwnerChainConfig.from_mapping(self.get_config(str(owner_id)))
        self.apply()
        self.refresh(config.owner_id, force=True)
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
        return {
            "configured": True,
            "healthy": cached is not None and cached.expires_at > time.monotonic(),
            "error": error,
            "listener": f"127.0.0.1:{config.listener_port}",
            "bootstrap": config.bootstrap_name,
        }


def _port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", int(port)))
        except OSError:
            return True
    return False
