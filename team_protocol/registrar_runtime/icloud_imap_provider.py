from __future__ import annotations

import email
import html
import imaplib
import json
import re
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass
from email.message import Message
from email.policy import default
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Callable, Iterable, Mapping

import socks

from .appleemail_provider import MailboxCredentialsInvalidError


PROVIDER_NAME = "icloud_hme_imap"
_RECIPIENT_HEADERS = (
    "To",
    "Delivered-To",
    "X-Original-To",
    "Envelope-To",
    "Resent-To",
    "X-Envelope-To",
)
_OTP_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_CONTEXT_OTP_RE = re.compile(
    r"(?:verification|verify|security|one[- ]time|otp|code)[^0-9]{0,40}(\d{6})",
    re.IGNORECASE,
)


class ImapMailboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class ImapMailboxConfig:
    registration_email: str
    forwarding_email: str
    host: str
    port: int
    username: str
    password: str
    folder: str = "INBOX"
    proxy: str = ""

    @classmethod
    def from_auth_credential(
        cls, auth_credential: str, email_address: str, *, fallback_proxy: str = ""
    ) -> "ImapMailboxConfig":
        try:
            payload = json.loads(str(auth_credential or ""))
        except json.JSONDecodeError as exc:
            raise MailboxCredentialsInvalidError("iCloud IMAP credential is invalid") from exc
        if not isinstance(payload, Mapping) or payload.get("provider") != PROVIDER_NAME:
            raise MailboxCredentialsInvalidError("iCloud IMAP credential is invalid")
        try:
            config = cls(
                registration_email=str(
                    payload.get("registration_email") or email_address or ""
                ).strip().casefold(),
                forwarding_email=str(payload.get("forwarding_email") or "").strip().casefold(),
                host=str(payload.get("imap_host") or "").strip(),
                port=int(payload.get("imap_port") or 993),
                username=str(payload.get("imap_username") or "").strip(),
                password=str(payload.get("imap_password") or ""),
                folder=str(payload.get("imap_folder") or "INBOX").strip(),
                proxy=str(payload.get("mailbox_proxy") or fallback_proxy or "").strip(),
            )
        except (TypeError, ValueError) as exc:
            raise MailboxCredentialsInvalidError("iCloud IMAP credential is invalid") from exc
        try:
            config.validate()
        except ValueError as exc:
            raise MailboxCredentialsInvalidError("iCloud IMAP credential is incomplete") from exc
        return config

    def validate(self) -> None:
        for name, value in (
            ("registration_email", self.registration_email),
            ("forwarding_email", self.forwarding_email),
            ("host", self.host),
            ("username", self.username),
            ("password", self.password),
            ("folder", self.folder),
        ):
            if not value or "\r" in value or "\n" in value:
                raise ValueError(f"{name} is invalid")
        if self.registration_email.count("@") != 1 or self.forwarding_email.count("@") != 1:
            raise ValueError("mailbox email is invalid")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("IMAP port is invalid")
        if any(character.isspace() for character in self.host):
            raise ValueError("IMAP host is invalid")
        if self.proxy:
            _proxy_spec(self.proxy)


ConnectionFactory = Callable[[ImapMailboxConfig, float], Any]


class ImapOtpReader:
    def __init__(
        self,
        config: ImapMailboxConfig,
        *,
        connection_factory: ConnectionFactory | None = None,
        scan_limit: int = 120,
    ) -> None:
        config.validate()
        self.config = config
        self.connection_factory = connection_factory or _create_imap_connection
        self.scan_limit = max(1, min(int(scan_limit), 500))

    def check(self, *, timeout: float = 15.0) -> None:
        connection = self._login(timeout)
        try:
            status, _ = connection.select(self.config.folder, readonly=True)
            if str(status).upper() != "OK":
                raise ImapMailboxError("IMAP folder is unavailable")
        finally:
            _logout(connection)

    def find_code(
        self,
        alias: str,
        *,
        sent_at_ts: float | None,
        excluded_uids: set[str],
        excluded_codes: set[str],
        timeout: float,
    ) -> tuple[str, str] | None:
        connection = self._login(timeout)
        try:
            status, _ = connection.select(self.config.folder, readonly=True)
            if str(status).upper() != "OK":
                raise ImapMailboxError("IMAP folder is unavailable")
            for uid in self._candidate_uids(connection, alias):
                if uid in excluded_uids:
                    continue
                message = self._fetch_message(connection, uid)
                if message is None or not _message_matches_alias(message, alias):
                    continue
                timestamp = _message_timestamp(message)
                if sent_at_ts is not None:
                    if timestamp is None or timestamp < sent_at_ts - 30:
                        continue
                code = _extract_message_code(message)
                if code and code not in excluded_codes:
                    return code, uid
            return None
        finally:
            _logout(connection)

    def _login(self, timeout: float) -> Any:
        try:
            connection = self.connection_factory(
                self.config, max(1.0, min(float(timeout), 30.0))
            )
        except (OSError, TimeoutError, socks.ProxyError) as exc:
            raise ImapMailboxError("IMAP connection failed") from exc
        try:
            status, _ = connection.login(self.config.username, self.config.password)
        except imaplib.IMAP4.error as exc:
            _logout(connection)
            raise MailboxCredentialsInvalidError("iCloud forwarding mailbox rejected login") from exc
        except Exception as exc:
            _logout(connection)
            raise ImapMailboxError("IMAP login failed") from exc
        if str(status).upper() != "OK":
            _logout(connection)
            raise MailboxCredentialsInvalidError("iCloud forwarding mailbox rejected login")
        return connection

    def _candidate_uids(self, connection: Any, alias: str) -> list[str]:
        matched: set[str] = set()
        searched = False
        for header in _RECIPIENT_HEADERS:
            try:
                status, data = connection.uid("search", None, "HEADER", header, alias)
            except Exception:
                continue
            if str(status).upper() != "OK":
                continue
            searched = True
            matched.update(_uids_from_search(data))
        if not matched:
            try:
                status, data = connection.uid("search", None, "ALL")
            except Exception as exc:
                if searched:
                    return []
                raise ImapMailboxError("IMAP search failed") from exc
            if str(status).upper() == "OK":
                matched.update(_uids_from_search(data))
        return sorted(matched, key=_uid_sort_key, reverse=True)[: self.scan_limit]

    @staticmethod
    def _fetch_message(connection: Any, uid: str) -> Message | None:
        for fetch_spec in ("(BODY.PEEK[])", "(RFC822)"):
            try:
                status, data = connection.uid("fetch", uid, fetch_spec)
            except Exception:
                continue
            if str(status).upper() != "OK":
                continue
            raw = _first_message_bytes(data)
            if raw is not None:
                return email.message_from_bytes(raw, policy=default)
        return None


class ICloudImapProvider:
    def __init__(
        self,
        *,
        accounts: Iterable[Any] = (),
        initial_state: Mapping[str, Any] | None = None,
        state_callback: Callable[[dict[str, Any]], None] | None = None,
        reader_factory: Callable[[ImapMailboxConfig], ImapOtpReader] = ImapOtpReader,
        poll_interval: float = 1.0,
        **_: Any,
    ) -> None:
        del accounts
        self._state = _normalize_state(initial_state)
        self._state_callback = state_callback
        self.reader_factory = reader_factory
        self.poll_interval = max(0.05, min(float(poll_interval), 5.0))
        self._lock = threading.RLock()

    def snapshot_state(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._state))

    def wait_for_otp(
        self,
        auth_credential: str,
        email: str,
        *,
        timeout: int = 60,
        stop_event: Any = None,
        sent_at_ts: float | None = None,
        proxy: Any = None,
        proxy_selector: Any = None,
        exclude_codes: set[str] | None = None,
        **_: Any,
    ) -> str:
        selected_proxy = str(proxy or "").strip()
        if proxy_selector is not None:
            try:
                selected_proxy = str(proxy_selector() or selected_proxy).strip()
            except Exception:
                pass
        config = ImapMailboxConfig.from_auth_credential(
            auth_credential, email, fallback_proxy=selected_proxy
        )
        reader = self.reader_factory(config)
        deadline = time.monotonic() + max(1, int(timeout or 60))
        excluded = {str(value) for value in (exclude_codes or set()) if str(value)}
        while time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                return ""
            with self._lock:
                seen = set(self._state["seen_uids"].get(config.registration_email, []))
            remaining = deadline - time.monotonic()
            try:
                result = reader.find_code(
                    config.registration_email,
                    sent_at_ts=sent_at_ts,
                    excluded_uids=seen,
                    excluded_codes=excluded,
                    timeout=min(15.0, max(1.0, remaining)),
                )
            except MailboxCredentialsInvalidError:
                raise
            except ImapMailboxError:
                result = None
            if result is not None:
                code, uid = result
                self._remember_uid(config.registration_email, uid)
                return code
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            delay = min(self.poll_interval, remaining)
            if stop_event is not None:
                stop_event.wait(delay)
            else:
                time.sleep(delay)
        return ""

    def _remember_uid(self, alias: str, uid: str) -> None:
        with self._lock:
            current = list(self._state["seen_uids"].get(alias, []))
            if uid not in current:
                current.append(uid)
            self._state["seen_uids"][alias] = current[-200:]
            snapshot = self.snapshot_state()
        if self._state_callback is not None:
            self._state_callback(snapshot)

    def release_thread_lease(self) -> None:
        return None

    def mark_email_completed(self, **_: Any) -> bool:
        return True


def check_imap_mailbox(config: ImapMailboxConfig, *, timeout: float = 15.0) -> None:
    ImapOtpReader(config).check(timeout=timeout)


def _normalize_state(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {"version": 1, "seen_uids": {}}
    if not isinstance(value, Mapping) or int(value.get("version") or 1) != 1:
        return result
    seen = value.get("seen_uids")
    if not isinstance(seen, Mapping):
        return result
    for alias, uids in seen.items():
        email_address = str(alias or "").strip().casefold()
        if email_address.count("@") != 1 or not isinstance(uids, list):
            continue
        clean = [str(uid) for uid in uids if str(uid).isdigit()]
        result["seen_uids"][email_address] = clean[-200:]
    return result


def _create_imap_connection(config: ImapMailboxConfig, timeout: float) -> Any:
    if config.proxy:
        return _ProxyIMAP4SSL(
            config.host,
            config.port,
            proxy_url=config.proxy,
            timeout=timeout,
        )
    return imaplib.IMAP4_SSL(config.host, config.port, timeout=timeout)


class _ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        proxy_url: str,
        ssl_context: ssl.SSLContext | None = None,
        timeout: float | None = None,
    ) -> None:
        self.proxy_url = proxy_url
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout: float | None):
        proxy_type, host, port, rdns, username, password = _proxy_spec(self.proxy_url)
        raw_socket = socks.socksocket()
        try:
            raw_socket.set_proxy(
                proxy_type,
                addr=host,
                port=port,
                rdns=rdns,
                username=username or None,
                password=password or None,
            )
            raw_socket.settimeout(timeout)
            raw_socket.connect((self.host, self.port))
            return self.ssl_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _proxy_spec(value: str) -> tuple[int, str, int, bool, str, str]:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
        port = parsed.port
    except ValueError as exc:
        raise ValueError("mailbox proxy is invalid") from exc
    scheme = parsed.scheme.casefold()
    proxy_types = {
        "socks5": (socks.SOCKS5, False),
        "socks5h": (socks.SOCKS5, True),
        "http": (socks.HTTP, True),
    }
    if scheme not in proxy_types or not parsed.hostname or port is None:
        raise ValueError("mailbox proxy must be HTTP or SOCKS5 with host and port")
    proxy_type, rdns = proxy_types[scheme]
    return (
        proxy_type,
        str(parsed.hostname),
        int(port),
        rdns,
        urllib.parse.unquote(parsed.username or ""),
        urllib.parse.unquote(parsed.password or ""),
    )


def _message_matches_alias(message: Message, alias: str) -> bool:
    target = str(alias or "").strip().casefold()
    if not target:
        return False
    values: list[str] = []
    for name in _RECIPIENT_HEADERS:
        values.extend(str(value) for value in message.get_all(name, []))
    for _display_name, address in getaddresses(values):
        if str(address or "").strip().casefold() == target:
            return True
    pattern = re.compile(
        rf"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{{|}}~-]){re.escape(target)}"
        r"(?![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])",
        re.IGNORECASE,
    )
    return any(pattern.search(value) for value in values)


def _extract_message_code(message: Message) -> str:
    subject = str(message.get("Subject") or "")
    body = _message_body(message)
    text = f"{subject}\n{body}"
    context_match = _CONTEXT_OTP_RE.search(text)
    if context_match:
        return context_match.group(1)
    fallback = _OTP_RE.search(text)
    return fallback.group(1) if fallback else ""


def _message_body(message: Message) -> str:
    parts: list[str] = []
    candidates = message.walk() if message.is_multipart() else (message,)
    for part in candidates:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            value = part.get_content()
        except (LookupError, UnicodeError):
            raw = part.get_payload(decode=True) or b""
            value = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
        text = str(value or "")
        if part.get_content_type() == "text/html":
            text = html.unescape(re.sub(r"<[^>]+>", " ", text))
        parts.append(text)
    return "\n".join(parts)


def _message_timestamp(message: Message) -> float | None:
    raw = str(message.get("Date") or "").strip()
    if not raw:
        return None
    try:
        value = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if value.tzinfo is None:
        return None
    return value.timestamp()


def _uids_from_search(data: Any) -> set[str]:
    result: set[str] = set()
    if not isinstance(data, (list, tuple)):
        return result
    for item in data:
        if isinstance(item, bytes):
            result.update(part.decode("ascii") for part in item.split() if part.isdigit())
        elif isinstance(item, str):
            result.update(part for part in item.split() if part.isdigit())
    return result


def _uid_sort_key(value: str) -> tuple[int, str]:
    return (int(value), value) if value.isdigit() else (-1, value)


def _first_message_bytes(data: Any) -> bytes | None:
    if not isinstance(data, (list, tuple)):
        return None
    for item in data:
        if isinstance(item, tuple):
            for part in item:
                if isinstance(part, bytes) and b"\n" in part:
                    return part
        elif isinstance(item, bytes) and b"\n" in item:
            return item
    return None


def _logout(connection: Any) -> None:
    try:
        connection.logout()
    except Exception:
        pass
