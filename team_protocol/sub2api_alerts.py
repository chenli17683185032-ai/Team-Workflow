from __future__ import annotations

import email
import imaplib
import json
import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from email.policy import default
from email.utils import getaddresses
from typing import Any, Callable, Mapping

from .database import Database, StateConflictError
from .registrar_runtime.appleemail_provider import MailboxCredentialsInvalidError
from .registrar_runtime.icloud_imap_provider import (
    ImapMailboxConfig,
    ImapMailboxError,
    close_imap_mailbox,
    login_imap_mailbox,
)
from .sub2api import Sub2APIClient, Sub2APIError


ALERT_ENABLED_SETTING = "sub2api_alert_enabled"
ALERT_IMAP_SETTING = "sub2api_alert_imap"
ALERT_SENDER_SETTING = "sub2api_alert_sender"
ALERT_CURSOR_SETTING = "sub2api_alert_cursor"
ALERT_ACTIONS_SETTING = "sub2api_alert_actions"
ACCOUNT_USAGE_THRESHOLD = 90.0
DEFAULT_POLL_INTERVAL_SECONDS = 15.0
DEFAULT_MAX_BACKOFF_SECONDS = 300.0

_MONITOR_SUBJECT_RE = re.compile(
    r"^\[(?:测试|定时|告警|紧急|恢复|正常)\].*云贝.*Sub2API",
    re.IGNORECASE,
)
_UNAUTHORIZED_RE = re.compile(
    r"(?:authentication failed\s*\(401\)|\b(?:http|api returned)\s+401\b)",
    re.IGNORECASE,
)
_LOGGER = logging.getLogger(__name__)


class Sub2APIAlertError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = str(code)
        super().__init__(self.code)


@dataclass(frozen=True)
class MailboxCursor:
    uid_validity: str
    last_uid: int


@dataclass(frozen=True)
class MailboxBatch:
    cursor: MailboxCursor
    should_reconcile: bool
    new_message_count: int


@dataclass(frozen=True)
class CurrentChildTarget:
    workspace_id: str
    workspace_version: int
    workspace_uid: str
    account_id: str
    email: str


@dataclass(frozen=True)
class AccountSignal:
    target: CurrentChildTarget
    remote_account_id: int
    utilization: float | None
    unauthorized: bool


def collect_utilizations(value: Any) -> list[float]:
    found: list[float] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "utilization" and isinstance(child, (int, float)):
                found.append(float(child))
            else:
                found.extend(collect_utilizations(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(collect_utilizations(child))
    return found


def is_unauthorized_error(value: Any) -> bool:
    return bool(_UNAUTHORIZED_RE.search(str(value or "")))


def imap_config_from_secret(value: bytes | str | Mapping[str, Any]) -> ImapMailboxConfig:
    if isinstance(value, bytes):
        raw: Any = value.decode("utf-8")
    else:
        raw = value
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Sub2API alert IMAP config is invalid") from exc
    if not isinstance(raw, Mapping):
        raise ValueError("Sub2API alert IMAP config is invalid")
    allowed = {"host", "port", "username", "password", "folder", "proxy", "recipient"}
    if set(raw) - allowed:
        raise ValueError("Sub2API alert IMAP config contains unsupported fields")
    username = str(raw.get("username") or "").strip().casefold()
    recipient = str(raw.get("recipient") or username).strip().casefold()
    config = ImapMailboxConfig(
        registration_email=recipient,
        forwarding_email=recipient,
        host=str(raw.get("host") or "").strip(),
        port=int(raw.get("port") or 993),
        username=username,
        password=str(raw.get("password") or ""),
        folder=str(raw.get("folder") or "INBOX").strip(),
        proxy=str(raw.get("proxy") or "").strip(),
    )
    config.validate()
    return config


def imap_config_secret(config: ImapMailboxConfig) -> dict[str, Any]:
    config.validate()
    return {
        "host": config.host,
        "port": int(config.port),
        "username": config.username,
        "password": config.password,
        "folder": config.folder,
        "proxy": config.proxy,
        "recipient": config.forwarding_email,
    }


def _remote_email(account: Mapping[str, Any]) -> str:
    extra = account.get("extra") if isinstance(account.get("extra"), Mapping) else {}
    credentials = (
        account.get("credentials")
        if isinstance(account.get("credentials"), Mapping)
        else {}
    )
    return str(
        credentials.get("email")
        or extra.get("email")
        or account.get("name")
        or ""
    ).strip().casefold()


def _remote_workspace(account: Mapping[str, Any]) -> str:
    credentials = (
        account.get("credentials")
        if isinstance(account.get("credentials"), Mapping)
        else {}
    )
    return str(credentials.get("chatgpt_account_id") or "").strip()


def _account_id(account: Mapping[str, Any]) -> int | None:
    try:
        value = int(account.get("id") or 0)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _uids(data: Any) -> list[int]:
    values: list[int] = []
    for item in data or []:
        raw = item if isinstance(item, bytes) else str(item).encode("ascii", errors="ignore")
        for token in raw.split():
            try:
                value = int(token)
            except ValueError:
                continue
            if value > 0:
                values.append(value)
    return sorted(set(values))


def _first_message_bytes(data: Any) -> bytes | None:
    for item in data or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
        if isinstance(item, bytes) and b"\n" in item:
            return item
    return None


def _uid_validity(connection: Any) -> str:
    try:
        _code, data = connection.response("UIDVALIDITY")
    except Exception:
        return ""
    for item in data or []:
        text = item.decode("ascii", errors="ignore") if isinstance(item, bytes) else str(item)
        match = re.search(r"\d+", text)
        if match:
            return match.group(0)
    return ""


def _is_monitor_message(raw_headers: bytes, expected_sender: str) -> bool:
    message = email.message_from_bytes(raw_headers, policy=default)
    senders = {
        str(address or "").strip().casefold()
        for _name, address in getaddresses(message.get_all("From", []))
        if str(address or "").strip()
    }
    subject = str(message.get("Subject") or "").strip()
    return expected_sender.casefold() in senders and bool(
        _MONITOR_SUBJECT_RE.search(subject)
    )


class Sub2APIMonitorMailbox:
    def __init__(
        self,
        config: ImapMailboxConfig,
        expected_sender: str,
        *,
        connection_factory: Callable[[ImapMailboxConfig, float], Any] | None = None,
        scan_limit: int = 200,
    ) -> None:
        config.validate()
        sender = str(expected_sender or "").strip().casefold()
        if sender.count("@") != 1 or any(character.isspace() for character in sender):
            raise ValueError("Sub2API monitor sender is invalid")
        self.config = config
        self.expected_sender = sender
        self.connection_factory = connection_factory
        self.scan_limit = max(1, min(int(scan_limit), 1000))
        self._connection: Any = None
        self._uid_validity = ""

    def close(self) -> None:
        connection, self._connection = self._connection, None
        self._uid_validity = ""
        if connection is not None:
            close_imap_mailbox(connection)

    def _connect(self) -> Any:
        if self._connection is not None:
            return self._connection
        connection = login_imap_mailbox(
            self.config,
            timeout=15.0,
            connection_factory=self.connection_factory,
        )
        try:
            status, _ = connection.select(self.config.folder, readonly=True)
        except Exception as exc:
            close_imap_mailbox(connection)
            raise ImapMailboxError("IMAP folder selection failed") from exc
        if str(status).upper() != "OK":
            close_imap_mailbox(connection)
            raise ImapMailboxError("IMAP folder is unavailable")
        self._connection = connection
        self._uid_validity = _uid_validity(connection)
        return connection

    @staticmethod
    def _search(connection: Any, *criteria: str) -> list[int]:
        try:
            status, data = connection.uid("search", None, *criteria)
        except Exception as exc:
            raise ImapMailboxError("IMAP search failed") from exc
        if str(status).upper() != "OK":
            raise ImapMailboxError("IMAP search failed")
        return _uids(data)

    @staticmethod
    def _fetch_headers(connection: Any, uid: int) -> bytes | None:
        try:
            status, data = connection.uid(
                "fetch",
                str(int(uid)),
                "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])",
            )
        except Exception as exc:
            raise ImapMailboxError("IMAP header fetch failed") from exc
        if str(status).upper() != "OK":
            raise ImapMailboxError("IMAP header fetch failed")
        return _first_message_bytes(data)

    def fetch_after(self, cursor: MailboxCursor | None) -> MailboxBatch:
        connection = self._connect()
        validity = self._uid_validity
        if cursor is None or cursor.uid_validity != validity:
            all_uids = self._search(connection, "ALL")
            return MailboxBatch(
                cursor=MailboxCursor(validity, max(all_uids, default=0)),
                should_reconcile=True,
                new_message_count=0,
            )

        new_uids = [
            uid
            for uid in self._search(
                connection,
                "UID",
                f"{max(1, cursor.last_uid + 1)}:*",
            )
            if uid > cursor.last_uid
        ]
        if not new_uids:
            return MailboxBatch(cursor=cursor, should_reconcile=False, new_message_count=0)

        should_reconcile = len(new_uids) > self.scan_limit
        for uid in new_uids[-self.scan_limit :]:
            raw_headers = self._fetch_headers(connection, uid)
            if raw_headers is not None and _is_monitor_message(
                raw_headers, self.expected_sender
            ):
                should_reconcile = True
        return MailboxBatch(
            cursor=MailboxCursor(validity, max(new_uids)),
            should_reconcile=should_reconcile,
            new_message_count=len(new_uids),
        )


class Sub2APIAlertCoordinator:
    def __init__(
        self,
        database: Database,
        *,
        client_factory: Callable[[], Sub2APIClient],
        handoff_callback: Callable[[str, int], Mapping[str, Any]],
        refresh_callback: Callable[[str], Mapping[str, Any]],
        mailbox_factory: Callable[
            [ImapMailboxConfig, str], Sub2APIMonitorMailbox
        ] = Sub2APIMonitorMailbox,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
    ) -> None:
        self.database = database
        self.client_factory = client_factory
        self.handoff_callback = handoff_callback
        self.refresh_callback = refresh_callback
        self.mailbox_factory = mailbox_factory
        self.poll_interval = max(0.05, float(poll_interval))
        self.max_backoff = max(self.poll_interval, float(max_backoff))
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._mailbox: Sub2APIMonitorMailbox | None = None
        self._status: dict[str, Any] = {
            "enabled": False,
            "running": False,
            "last_poll_at": None,
            "last_reconcile_at": None,
            "last_message_uid": None,
            "last_error": None,
            "last_action": None,
            "targets": [],
        }

    def _configured(self) -> bool:
        raw = str(
            self.database.get_text_setting(ALERT_ENABLED_SETTING, "0") or "0"
        ).strip().casefold()
        return raw in {"1", "true", "yes", "on"}

    def _mailbox_config(self) -> tuple[ImapMailboxConfig, str]:
        sender = str(
            self.database.get_text_setting(ALERT_SENDER_SETTING, "") or ""
        ).strip().casefold()
        secret = self.database.get_secret_setting(ALERT_IMAP_SETTING)
        if secret is None or not sender:
            raise Sub2APIAlertError("alert_configuration_incomplete")
        try:
            config = imap_config_from_secret(secret)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise Sub2APIAlertError("alert_imap_config_invalid") from exc
        return config, sender

    def start(self) -> bool:
        with self._lock:
            enabled = self._configured()
            self._status["enabled"] = enabled
            if not enabled:
                return False
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="sub2api-alert-coordinator",
                daemon=True,
            )
            self._status["running"] = True
            self._thread.start()
            return True

    def request_stop(self) -> None:
        self._stop_event.set()

    def wait_stopped(self, timeout: float = 10.0) -> bool:
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, float(timeout)))
        stopped = thread is None or not thread.is_alive()
        with self._lock:
            if stopped:
                self._status["running"] = False
                self._thread = None
        return stopped

    def shutdown(self, timeout: float = 10.0) -> bool:
        self.request_stop()
        return self.wait_stopped(timeout)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._status))

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(exc, Sub2APIAlertError):
            return exc.code
        if isinstance(exc, MailboxCredentialsInvalidError):
            return "imap_credentials_invalid"
        if isinstance(exc, ImapMailboxError):
            return "imap_unavailable"
        if isinstance(exc, Sub2APIError):
            return "sub2api_unavailable"
        if isinstance(exc, StateConflictError):
            return "action_blocked"
        return "coordinator_error"

    def _set_error(self, code: str | None) -> None:
        with self._lock:
            self._status["last_error"] = code

    def _run(self) -> None:
        backoff = self.poll_interval
        try:
            while not self._stop_event.is_set():
                try:
                    self.poll_once()
                except Exception as exc:
                    code = self._error_code(exc)
                    self._set_error(code)
                    _LOGGER.warning("Sub2API alert coordinator error: %s", code)
                    if self._mailbox is not None:
                        self._mailbox.close()
                        self._mailbox = None
                    if self._stop_event.wait(backoff):
                        break
                    backoff = min(self.max_backoff, max(self.poll_interval, backoff * 2))
                    continue
                backoff = self.poll_interval
                if self._stop_event.wait(self.poll_interval):
                    break
        finally:
            if self._mailbox is not None:
                self._mailbox.close()
                self._mailbox = None
            with self._lock:
                self._status["running"] = False

    @staticmethod
    def _load_cursor(raw: str | None) -> MailboxCursor | None:
        if not raw:
            return None
        try:
            value = json.loads(raw)
            validity = str(value.get("uid_validity") or "")
            last_uid = int(value.get("last_uid") or 0)
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return MailboxCursor(validity, max(0, last_uid))

    def poll_once(self, mailbox: Sub2APIMonitorMailbox | None = None) -> MailboxBatch:
        if not self._configured():
            raise Sub2APIAlertError("alert_coordinator_disabled")
        if mailbox is None:
            if self._mailbox is None:
                config, sender = self._mailbox_config()
                self._mailbox = self.mailbox_factory(config, sender)
            mailbox = self._mailbox
        cursor = self._load_cursor(
            self.database.get_text_setting(ALERT_CURSOR_SETTING, None)
        )
        batch = mailbox.fetch_after(cursor)
        if batch.should_reconcile:
            self.reconcile()
        self.database.set_text_setting(
            ALERT_CURSOR_SETTING,
            json.dumps(
                {
                    "uid_validity": batch.cursor.uid_validity,
                    "last_uid": batch.cursor.last_uid,
                },
                separators=(",", ":"),
            ),
        )
        with self._lock:
            self._status.update(
                {
                    "last_poll_at": self._now(),
                    "last_message_uid": batch.cursor.last_uid,
                    "last_error": None,
                }
            )
        return batch

    def _current_targets(self) -> list[CurrentChildTarget]:
        targets: list[CurrentChildTarget] = []
        for workspace in self.database.list_workspaces():
            if not workspace.get("owner_alias_id"):
                continue
            account = self.database.get_account(str(workspace["current_account_id"]))
            if (
                str(account.get("status") or "") != "bound_current"
                or str(account.get("icloud_role") or "") != "rotating_child"
            ):
                continue
            email_address = str(account.get("email") or "").strip().casefold()
            if email_address.count("@") != 1:
                raise Sub2APIAlertError("current_child_email_invalid")
            targets.append(
                CurrentChildTarget(
                    workspace_id=str(workspace["id"]),
                    workspace_version=int(workspace["version"]),
                    workspace_uid=str(workspace["workspace_uid"]),
                    account_id=str(account["id"]),
                    email=email_address,
                )
            )
        if len(targets) != 2:
            raise Sub2APIAlertError("expected_two_current_children")
        return sorted(targets, key=lambda item: item.workspace_id)

    @staticmethod
    def _measure_target(
        client: Sub2APIClient, target: CurrentChildTarget
    ) -> AccountSignal:
        candidates = client.list_accounts(
            search=target.email,
            platform="openai",
            page_size=100,
        )
        details: list[dict[str, Any]] = []
        for candidate in candidates:
            if _remote_email(candidate) != target.email:
                continue
            remote_id = _account_id(candidate)
            if remote_id is None:
                continue
            detail = client.get_account(remote_id)
            if (
                _remote_email(detail) == target.email
                and _remote_workspace(detail) == target.workspace_uid
            ):
                details.append(detail)
        if len(details) != 1:
            raise Sub2APIAlertError("sub2api_current_child_mapping_ambiguous")
        detail = details[0]
        remote_id = _account_id(detail)
        if remote_id is None:
            raise Sub2APIAlertError("sub2api_current_child_id_invalid")
        unauthorized = is_unauthorized_error(detail.get("error_message"))
        utilization: float | None = None
        if not unauthorized:
            try:
                values = collect_utilizations(client.get_account_usage(remote_id))
            except Sub2APIError:
                detail = client.get_account(remote_id)
                if not is_unauthorized_error(detail.get("error_message")):
                    raise
                unauthorized = True
            else:
                if not values:
                    raise Sub2APIAlertError("sub2api_usage_unavailable")
                utilization = max(values)
        return AccountSignal(
            target=target,
            remote_account_id=remote_id,
            utilization=utilization,
            unauthorized=unauthorized,
        )

    def _load_actions(self) -> dict[str, dict[str, Any]]:
        raw = self.database.get_text_setting(ALERT_ACTIONS_SETTING, "")
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        actions = value.get("actions") if isinstance(value, Mapping) else None
        if not isinstance(actions, Mapping):
            return {}
        return {
            str(key): dict(item)
            for key, item in actions.items()
            if isinstance(item, Mapping)
        }

    def _save_actions(self, actions: Mapping[str, Mapping[str, Any]]) -> None:
        self.database.set_text_setting(
            ALERT_ACTIONS_SETTING,
            json.dumps(
                {"version": 1, "actions": actions},
                separators=(",", ":"),
                sort_keys=True,
            ),
        )

    @staticmethod
    def _action_key(action: str, signal: AccountSignal) -> str:
        return (
            f"{action}:{signal.target.workspace_id}:"
            f"{signal.target.account_id}"
        )

    def _execute_action(
        self,
        action: str,
        signal: AccountSignal,
        actions: dict[str, dict[str, Any]],
    ) -> None:
        key = self._action_key(action, signal)
        existing = actions.get(key)
        if existing and existing.get("state") == "triggered":
            return
        if action == "handoff" and existing and existing.get("state") == "pending":
            workspace = self.database.get_workspace(signal.target.workspace_id)
            run_matches = False
            if workspace.get("last_run_id"):
                run = self.database.get_run(str(workspace["last_run_id"]))
                run_matches = (
                    str(run.get("current_account_id") or "")
                    == signal.target.account_id
                    and str(run.get("state") or "")
                    in {"queued", "running", "stopping", "succeeded"}
                )
            if workspace.get("next_account_id") or run_matches:
                actions[key] = {**existing, "state": "triggered"}
                self._save_actions(actions)
                return

        actions[key] = {"state": "pending", "created_at": self._now()}
        self._save_actions(actions)
        try:
            if action == "refresh":
                self.refresh_callback(signal.target.account_id)
            else:
                self.handoff_callback(
                    signal.target.workspace_id,
                    signal.target.workspace_version,
                )
        except Exception:
            actions.pop(key, None)
            self._save_actions(actions)
            raise
        actions[key] = {
            "state": "triggered",
            "created_at": actions[key]["created_at"],
            "completed_at": self._now(),
        }
        self._save_actions(actions)
        with self._lock:
            self._status["last_action"] = {
                "action": action,
                "workspace_id": signal.target.workspace_id,
                "account_id": signal.target.account_id,
                "completed_at": actions[key]["completed_at"],
            }

    def _apply_signals(self, signals: list[AccountSignal]) -> None:
        actions = self._load_actions()
        current_account_ids = {signal.target.account_id for signal in signals}
        actions = {
            key: value
            for key, value in actions.items()
            if key.rsplit(":", 1)[-1] in current_account_ids
        }
        for signal in signals:
            refresh_key = self._action_key("refresh", signal)
            if not signal.unauthorized and refresh_key in actions:
                actions.pop(refresh_key, None)
                self._save_actions(actions)
        for signal in signals:
            if signal.unauthorized:
                self._execute_action("refresh", signal, actions)
        for signal in signals:
            if (
                not signal.unauthorized
                and signal.utilization is not None
                and signal.utilization >= ACCOUNT_USAGE_THRESHOLD
            ):
                self._execute_action("handoff", signal, actions)
        self._save_actions(actions)

    def measure(self) -> list[AccountSignal]:
        targets = self._current_targets()
        client = self.client_factory()
        try:
            return [self._measure_target(client, target) for target in targets]
        finally:
            client.close()

    def reconcile(self) -> list[AccountSignal]:
        signals = self.measure()
        self._apply_signals(signals)
        with self._lock:
            self._status.update(
                {
                    "last_reconcile_at": self._now(),
                    "targets": [
                        {
                            "workspace_id": signal.target.workspace_id,
                            "account_id": signal.target.account_id,
                            "remote_account_id": signal.remote_account_id,
                            "utilization": signal.utilization,
                            "unauthorized": signal.unauthorized,
                        }
                        for signal in signals
                    ],
                }
            )
        return signals
