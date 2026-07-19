from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import socket
import threading
import time
import webbrowser
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Literal, Mapping

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .database import (
    BindingConflictError,
    ConflictError,
    Database,
    DatabaseConfigurationError,
    DatabaseError,
    NotFoundError,
    RestoreValidationError,
    StaleVersionError,
    StateConflictError,
    ValidationError,
    default_app_dir,
)
from .icloud_hme import (
    HmeClient,
    HmeError,
    HmeSessionError,
    ICloudHmeSession,
    parse_hme_session_import,
)
from .icloud_hme_capture import (
    HmeCaptureBusyError,
    HmeCaptureError,
    HmeCaptureSessionRejectedError,
    ICloudHmeCaptureManager,
)
from .migration import (
    CleanupResult,
    MigrationBackupError,
    MigrationError,
    SourcePayload,
    SourceRecord,
    apply_import,
    cleanup_plaintext,
    create_backup,
    discover_legacy,
    mailbox_inventory_records_from_backup,
    parse_legacy_mailboxes,
    restore_backup,
    validate_legacy,
    verify_backup,
)
from .secret_store import SecretStore, SecretStoreError
from .registrar_runtime.appleemail_provider import MailboxCredentialsInvalidError
from .registrar_runtime.icloud_imap_provider import (
    ImapMailboxConfig,
    ImapMailboxError,
    check_imap_mailbox,
)
from .registrar import validate_proxy_url
from .proxy_chain import (
    ProxyChainError,
    ProxyChainManager,
    ProxyConfigurationError,
    validate_bootstrap_proxy,
    validate_lokiproxy_source,
)
from .sub2api import Sub2APIClient, Sub2APIError
from .task_queue import TaskQueue, redact_value


STATIC_DIR = Path(__file__).resolve().parent / "web_static"
PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_LOCAL_CLASH_PROXY = "http://127.0.0.1:7897"
_SECRET_SETTING_KEYS = frozenset(
    {
        "proxy",
        "management_api_key",
        "sub2api_password",
        "sub2api_api_key",
        "sub2api_totp_secret",
    }
)
_TEXT_SETTING_KEYS = frozenset(
    {
        "output_dir",
        "pat_name",
        "pat_ttl",
        "invite_settle_seconds",
        "management_base_url",
        "management_push",
        "management_replace",
        "management_remote_name",
        "sub2api_base_url",
        "sub2api_email",
        "sub2api_push",
        "sub2api_concurrency",
        "sub2api_priority",
        "sub2api_group_id",
    }
)
_VISIBLE_TEXT_SETTING_KEYS = _TEXT_SETTING_KEYS | {
    "last_backup_path",
    "last_backup_at",
}
_CHILD_LABEL_NUMBER_RE = re.compile(
    r"^(?P<prefix>.*?)(?P<separator>[-_ ]+)(?P<number>[0-9]+)$"
)


def _configured_local_clash_proxy() -> str:
    value = str(
        os.environ.get("TEAM_WORKFLOW_LOCAL_CLASH_PROXY")
        or DEFAULT_LOCAL_CLASH_PROXY
    ).strip()
    try:
        return validate_proxy_url(value)
    except ValueError as exc:
        raise DatabaseConfigurationError(
            "TEAM_WORKFLOW_LOCAL_CLASH_PROXY is invalid"
        ) from exc


def _next_icloud_child_label(
    current_label: str,
    workspace_name: str,
    rotation_count: int,
) -> str:
    """Increment the sequence already carried by the current child label."""

    current = str(current_label or "").strip()
    match = _CHILD_LABEL_NUMBER_RE.fullmatch(current)
    if match is not None:
        return (
            f"{match.group('prefix')}{match.group('separator')}"
            f"{int(match.group('number')) + 1}"
        )

    fallback = str(workspace_name or "").strip() or "Team Workflow"
    return f"{fallback} child {max(0, int(rotation_count)) + 1}"
_SENSITIVE_RESPONSE_KEYS = frozenset(
    {
        "credential_blob",
        "checkpoint_blob",
        "proxy_blob",
        "value_blob",
        "password",
        "mailbox_password",
        "account_password",
        "refresh_token",
        "client_id",
        "credential_purpose",
        "management_api_key",
        "sub2api_password",
        "sub2api_api_key",
        "sub2api_totp_secret",
        "proxy",
        "cookie",
        "session",
        "session_import",
        "imap_password",
        "mailbox_proxy",
        "source_url",
        "provider_token",
        "remote_metadata",
        "anonymousid",
        "recipientmailid",
    }
)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_INSTANCE_LOCK_FILENAME = "console.instance.lock"
_INSTANCE_LOCK_SIZE = 4096


class ConsoleAlreadyRunningError(RuntimeError):
    def __init__(self, url: str = "") -> None:
        self.url = str(url or "").strip()
        super().__init__(
            f"console is already running at {self.url}"
            if self.url
            else "console is already running"
        )


class _ConsoleInstanceLock:
    """Hold one OS-level lock per application data directory."""

    def __init__(self, app_dir: str | Path) -> None:
        self.path = Path(app_dir).expanduser().resolve() / _INSTANCE_LOCK_FILENAME
        self._handle: Any = None

    @staticmethod
    def _lock(handle: Any) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock(handle: Any) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            return
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read_owner_url(self) -> str:
        try:
            with self.path.open("rb") as handle:
                handle.seek(1)
                raw = handle.read(_INSTANCE_LOCK_SIZE - 1).split(b"\x00", 1)[0]
            payload = json.loads(raw.decode("utf-8").strip() or "{}")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return ""
        return str(payload.get("url") or "").strip() if isinstance(payload, dict) else ""

    def acquire(self) -> None:
        if self._handle is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        handle = os.fdopen(descriptor, "r+b")
        try:
            handle.seek(0, os.SEEK_END)
            missing = _INSTANCE_LOCK_SIZE - handle.tell()
            if missing > 0:
                handle.write(b"\x00" * missing)
                handle.flush()
                os.fsync(handle.fileno())
            self._lock(handle)
        except OSError as exc:
            handle.close()
            raise ConsoleAlreadyRunningError(self._read_owner_url()) from exc
        self._handle = handle
        self.set_owner_url("")

    def set_owner_url(self, url: str) -> None:
        if self._handle is None:
            raise RuntimeError("console instance lock is not held")
        payload = json.dumps(
            {"pid": os.getpid(), "url": str(url or "").strip()},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        capacity = _INSTANCE_LOCK_SIZE - 1
        if len(payload) + 1 > capacity:
            raise ValueError("console instance metadata is too large")
        self._handle.seek(1)
        self._handle.write(payload + b"\n")
        self._handle.write(b"\x00" * (capacity - len(payload) - 1))
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            self._unlock(handle)
        finally:
            handle.close()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkspaceCreateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    workspace_uid: str = Field(min_length=1, max_length=500)
    current_account_id: str | None = None
    current_inventory_id: str | None = None
    next_account_id: str | None = None
    next_inventory_id: str | None = None
    owner_alias_id: str | None = None


class WorkspaceUpdateRequest(StrictModel):
    version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=160)
    current_account_id: str | None = None
    current_inventory_id: str | None = None
    next_account_id: str | None = None
    next_inventory_id: str | None = None
    clear_next_account: bool = False
    owner_alias_id: str | None = None
    clear_owner_alias: bool = False


class AccountImportRequest(StrictModel):
    path: str = Field(min_length=1)


class AccountAliasRequest(StrictModel):
    inventory_id: str = Field(min_length=1)


class WorkspaceReplaceAccountRequest(StrictModel):
    version: int = Field(ge=1)
    role: Literal["current", "next"]
    failure_code: Literal["alias_disabled", "mailbox_credentials_invalid"]


class WorkspaceAdvanceRequest(StrictModel):
    version: int = Field(ge=1)


class AccountStatusRequest(StrictModel):
    status: str


class AccountProxyRequest(StrictModel):
    proxy: str = Field(default="", max_length=4096)


class ICloudMailboxCreateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    forwarding_email: str = Field(min_length=3, max_length=320)
    session_import: str = Field(min_length=1, max_length=2_000_000)
    imap_host: str = Field(min_length=1, max_length=320)
    imap_port: int = Field(default=993, ge=1, le=65535)
    imap_username: str = Field(min_length=1, max_length=320)
    imap_password: str = Field(min_length=1, max_length=4096)
    imap_folder: str = Field(default="INBOX", min_length=1, max_length=320)
    proxy: str = Field(default="", max_length=4096)


class ICloudMailboxUpdateRequest(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    forwarding_email: str | None = Field(default=None, min_length=3, max_length=320)
    session_import: str | None = Field(default=None, min_length=1, max_length=2_000_000)
    imap_host: str | None = Field(default=None, min_length=1, max_length=320)
    imap_port: int | None = Field(default=None, ge=1, le=65535)
    imap_username: str | None = Field(default=None, min_length=1, max_length=320)
    imap_password: str | None = Field(default=None, max_length=4096)
    imap_folder: str | None = Field(default=None, min_length=1, max_length=320)
    proxy: str | None = Field(default=None, max_length=4096)
    clear_proxy: bool = False


class ICloudAliasBatchRequest(StrictModel):
    count: int = Field(default=1, ge=1, le=20)
    label_prefix: str = Field(default="Team Workflow", min_length=1, max_length=100)


class ICloudAliasImportItem(StrictModel):
    email: str = Field(min_length=3, max_length=320)
    role: Literal["team_owner", "rotating_child"]
    parent_owner_email: str | None = Field(default=None, min_length=3, max_length=320)
    owner_proxy: str = Field(default="", max_length=4096)
    owner_proxy_mode: Literal["direct", "lokiproxy_generator"] = "direct"
    owner_proxy_source_url: str = Field(default="", max_length=8192)
    owner_proxy_bootstrap: str = Field(default="", max_length=4096)


class ICloudAliasImportRequest(StrictModel):
    items: list[ICloudAliasImportItem] = Field(min_length=1, max_length=100)


class ICloudTeamImportRequest(StrictModel):
    mailbox_id: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=160)
    workspace_uid: str = Field(min_length=1, max_length=500)
    owner_email: str = Field(min_length=3, max_length=320)
    current_child_email: str = Field(min_length=3, max_length=320)
    owner_proxy_mode: Literal["direct", "lokiproxy_generator"] | None = None
    owner_proxy: str = Field(default="", max_length=4096)
    owner_proxy_source_url: str = Field(default="", max_length=8192)
    owner_proxy_bootstrap: str = Field(default="", max_length=4096)


class ICloudOwnerProxyRequest(StrictModel):
    proxy: str = Field(default="", max_length=4096)
    mode: Literal["direct", "lokiproxy_generator"] = "direct"
    source_url: str = Field(default="", max_length=8192)
    bootstrap: str = Field(default="", max_length=4096)


class ICloudWorkspaceHandoffRequest(StrictModel):
    version: int = Field(ge=1)


class ICloudMailboxStatusRequest(StrictModel):
    status: Literal["disabled", "unchecked"]


class ICloudAliasStateRequest(StrictModel):
    state: Literal["active", "inactive"]


class QueueEnqueueRequest(StrictModel):
    workspace_ids: list[str] = Field(min_length=1, max_length=500)


class QueueOrderRequest(StrictModel):
    queue_item_ids: list[str] = Field(max_length=500)


class QueuePauseRequest(StrictModel):
    paused: bool


class SettingsUpdateRequest(StrictModel):
    values: dict[str, str | bool | int | float] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list)


class DialogRequest(StrictModel):
    kind: str
    current: str = ""


class BackupCreateRequest(StrictModel):
    path: str | None = None


class BackupRestoreRequest(StrictModel):
    path: str = Field(min_length=1)


class FieldInputError(ValueError):
    def __init__(self, fields: Mapping[str, str]) -> None:
        self.fields = {str(key): str(value) for key, value in fields.items()}
        super().__init__("invalid request fields")


class ICloudSessionInvalidError(StateConflictError):
    code = "icloud_session_invalid"


@dataclass(frozen=True)
class _BackupModel:
    config: Any
    sources: tuple[SourcePayload, ...]
    migration_id: str

    @property
    def source_records(self) -> tuple[SourceRecord, ...]:
        return tuple(source.record for source in self.sources)


class WebConsoleController:
    """Map local HTTP operations to the persisted workspace domain."""

    def __init__(
        self,
        *,
        database: Database | None = None,
        secret_store: SecretStore | None = None,
        task_queue: TaskQueue | None = None,
        app_dir: str | Path | None = None,
        backup_dir: str | Path | None = None,
        legacy_config_path: str | Path | None = None,
        inventory_expected_count: int | None = None,
        hme_client_factory: Any = HmeClient,
        imap_checker: Any = check_imap_mailbox,
        proxy_chain_manager: Any | None = None,
        hme_capture_manager: Any | None = None,
        enable_proxy_chains: bool = True,
        console_port: int = 8765,
    ) -> None:
        self.app_dir = (
            Path(app_dir).expanduser().resolve()
            if app_dir is not None
            else default_app_dir().expanduser().resolve()
        )
        self.backup_dir = (
            Path(backup_dir).expanduser().resolve()
            if backup_dir is not None
            else self.app_dir / "backups"
        )
        self.secret_store = secret_store or SecretStore()
        self.database = database or Database(
            self.app_dir / "console.db", secret_store=self.secret_store
        )
        self.task_queue = task_queue or TaskQueue(self.database)
        self.legacy_config_path = (
            None
            if legacy_config_path is None
            else Path(legacy_config_path).expanduser().resolve()
        )
        self.inventory_expected_count = (
            None
            if inventory_expected_count is None
            else max(1, int(inventory_expected_count))
        )
        self.request_token = secrets.token_urlsafe(32)
        self.hme_client_factory = hme_client_factory
        self.imap_checker = imap_checker
        self.local_clash_proxy = _configured_local_clash_proxy()
        self.enable_proxy_chains = bool(enable_proxy_chains)
        self.proxy_chains = proxy_chain_manager or ProxyChainManager(
            app_dir=self.app_dir,
            console_port=int(console_port),
            list_configs=self.database.list_icloud_owner_proxy_configs,
            get_config=self.database.get_icloud_owner_proxy_config,
            bootstrap_proxy=self.local_clash_proxy,
        )
        self.hme_capture = hme_capture_manager or ICloudHmeCaptureManager(
            on_session=self._save_captured_hme_session,
            on_status=self._publish_hme_capture_status,
            get_session_template=self._get_hme_session_template,
        )
        self._proxy_chain_startup_error: str | None = None
        self._icloud_operation_lock = threading.Lock()
        self._dialog_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._started = False
        self._migration_status = "initializing"
        self._migration_error: str | None = None
        self._shutdown_probe: Callable[[], bool] = lambda: False

    def _migrate_legacy_proxy_chains(self) -> int:
        """Move old per-node Mihomo configs to the one shared Clash URL."""

        if not self.enable_proxy_chains:
            return 0
        migrated = 0
        for config in self.database.list_icloud_owner_proxy_configs():
            owner_id = str(config.get("owner_id") or "").strip()
            source_url = str(config.get("source_url") or "").strip()
            if not owner_id or not source_url:
                continue
            chain = self.proxy_chains.prepare(
                owner_id,
                source_url,
                self.local_clash_proxy,
            )
            if dict(config) == chain.as_secret_dict():
                continue
            self.database.set_icloud_owner_proxy_config(
                owner_id,
                chain.as_secret_dict(),
            )
            migrated += 1
        return migrated

    def set_shutdown_probe(self, probe: Callable[[], bool]) -> None:
        if not callable(probe):
            raise TypeError("shutdown probe must be callable")
        self._shutdown_probe = probe

    def shutdown_requested(self) -> bool:
        return bool(self._shutdown_probe())

    def startup(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._started:
                return self.health()
            self.database.initialize()
            self._prepare_migration()
            if self._migration_status == "ready":
                self._prepare_inventory_backfill()
            if self._migration_status == "ready":
                self.database.prune_unreferenced_legacy_accounts()
                self._migrate_legacy_proxy_chains()
                if self.enable_proxy_chains:
                    try:
                        self.proxy_chains.apply()
                        self._proxy_chain_startup_error = None
                    except ProxyChainError as exc:
                        self._proxy_chain_startup_error = exc.code
                else:
                    self._proxy_chain_startup_error = None
                self.task_queue.start()
            self._started = True
            return self.health()

    def shutdown(self) -> bool:
        with self._lifecycle_lock:
            shutdown_hme_capture = getattr(self.hme_capture, "shutdown", None)
            hme_capture_stopped = (
                bool(shutdown_hme_capture())
                if callable(shutdown_hme_capture)
                else True
            )
            queue_stopped = self.task_queue.shutdown()
            shutdown_proxy_chains = getattr(self.proxy_chains, "shutdown", None)
            relay_stopped = (
                bool(shutdown_proxy_chains())
                if callable(shutdown_proxy_chains)
                else True
            )
            self._started = False
            return bool(hme_capture_stopped and queue_stopped and relay_stopped)

    def health(self) -> dict[str, Any]:
        return {
            "ready": self._migration_status == "ready",
            "started": self._started,
            "migration": self.migration_status(),
            "proxy_chains": {
                "enabled": self.enable_proxy_chains,
                "ready": self._proxy_chain_startup_error is None,
                "error": self._proxy_chain_startup_error,
            },
        }

    def migration_status(self) -> dict[str, Any]:
        backup_path = self.database.get_meta("migration_backup_path")
        preserved = self.database.get_meta("migration_preserved_paths")
        try:
            preserved_paths = json.loads(preserved) if preserved else []
        except json.JSONDecodeError:
            preserved_paths = []
        return {
            "status": self._migration_status,
            "error": self._migration_error,
            "legacy_source_configured": self.legacy_config_path is not None,
            "backup": {"configured": bool(backup_path), "path": backup_path},
            "preserved_external_paths": preserved_paths,
        }

    def _prepare_migration(self) -> None:
        persisted = self.database.get_meta("migration_status")
        if persisted in {"ready", "complete"}:
            self._migration_status = "ready"
            self._migration_error = None
            return
        if persisted == "cleanup_blocked":
            self._migration_status = "cleanup_blocked"
            self._migration_error = self.database.get_meta("migration_error")
            return
        if self.legacy_config_path is None or not self.legacy_config_path.is_file():
            if self.database.get_meta("migration_id"):
                self._migration_status = "migration_error"
                self._migration_error = "legacy migration is incomplete and its source is unavailable"
                return
            self.database.set_meta("migration_status", "ready")
            self.database.set_meta("migration_completed", "1")
            self._migration_status = "ready"
            self._migration_error = None
            return
        self._run_legacy_migration()

    def _run_legacy_migration(self) -> None:
        try:
            discovery = discover_legacy(self.legacy_config_path)
            model = validate_legacy(discovery)
            apply_import(model, self.database)
            snapshot = self.database.create_snapshot_bytes()
            backup_path = self.app_dir / "backups" / f"migration-{model.migration_id[:16]}.twbackup"
            if backup_path.exists():
                verified = verify_backup(backup_path, self.secret_store)
                if verified.migration_id != model.migration_id:
                    raise MigrationBackupError("existing migration backup does not match")
            else:
                verified = create_backup(
                    model,
                    backup_path,
                    self.secret_store,
                    schema_version=int(self.database.get_meta("schema_version") or 0),
                    instance_id=str(self.database.get_meta("instance_id") or ""),
                    sqlite_snapshot=snapshot,
                )
            self.database.set_meta("migration_backup_path", str(backup_path))
            self.database.set_meta("migration_status", "backup_verified")
            result = cleanup_plaintext(model, verified)
            self._finish_cleanup(result)
        except Exception as exc:
            self._migration_status = "migration_error"
            self._migration_error = str(redact_value(str(exc)))
            self.database.set_meta("migration_status", "migration_error")
            self.database.set_meta("migration_error", self._migration_error)

    def _finish_cleanup(self, result: CleanupResult) -> None:
        preserved = [str(path) for path in result.preserved]
        self.database.set_meta(
            "migration_preserved_paths",
            json.dumps(preserved, ensure_ascii=False, separators=(",", ":")),
        )
        if result.status == "cleanup_blocked":
            codes = ", ".join(sorted({failure.code for failure in result.failures}))
            self._migration_status = "cleanup_blocked"
            self._migration_error = f"legacy plaintext cleanup is blocked: {codes}"
            self.database.set_meta("migration_status", "cleanup_blocked")
            self.database.set_meta("migration_error", self._migration_error)
            return
        self.database.set_meta("migration_status", "complete")
        self.database.set_meta("migration_completed", "1")
        self.database.set_meta("migration_error", "")
        self._migration_status = "ready"
        self._migration_error = None

    def retry_migration_cleanup(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._migration_status == "ready":
                return self.migration_status()
            if self._migration_status == "inventory_migration_error":
                self._migration_status = "ready"
                self._migration_error = None
                self._prepare_inventory_backfill()
                if self._migration_status == "ready":
                    self.database.prune_unreferenced_legacy_accounts()
                    self.task_queue.start()
                    self.task_queue.notify_change()
                return self.migration_status()
            backup_path = self.database.get_meta("migration_backup_path")
            if self._migration_status == "cleanup_blocked" and backup_path:
                verified = verify_backup(backup_path, self.secret_store)
                model = _BackupModel(
                    config=SimpleNamespace(**verified.identity),
                    sources=verified.sources,
                    migration_id=verified.migration_id,
                )
                self._finish_cleanup(cleanup_plaintext(model, verified))
            elif self.legacy_config_path is not None and self.legacy_config_path.is_file():
                self._run_legacy_migration()
            else:
                raise MigrationBackupError("migration recovery source is unavailable")
            if self._migration_status == "ready":
                self._prepare_inventory_backfill()
                if self._migration_status == "ready":
                    self.task_queue.start()
                    self.task_queue.notify_change()
            return self.migration_status()

    def _prepare_inventory_backfill(self) -> None:
        if self.database.get_meta("mailbox_inventory_migration_version") == "1":
            return
        backup_path = self.database.get_meta("migration_backup_path")
        if not backup_path:
            self.database.set_meta("mailbox_inventory_migration_version", "1")
            return
        try:
            verified = verify_backup(backup_path, self.secret_store)
            database_migration_id = str(self.database.get_meta("migration_id") or "")
            database_instance_id = str(self.database.get_meta("instance_id") or "")
            if verified.migration_id != database_migration_id:
                raise MigrationBackupError("inventory source migration identity does not match")
            if verified.instance_id != database_instance_id:
                raise MigrationBackupError("inventory source instance identity does not match")
            records = mailbox_inventory_records_from_backup(verified)
            prechange = self.create_encrypted_backup()
            result = self.database.backfill_mailbox_inventory(
                records,
                migration_id=verified.migration_id,
                expected_count=self.inventory_expected_count,
                legacy_old_email=verified.identity.get("old_email"),
                legacy_new_email=verified.identity.get("new_email"),
            )
            if self.database.get_meta("mailbox_inventory_migration_version") != "1":
                raise StateConflictError("mailbox inventory backfill did not commit its marker")
            self.database.set_meta(
                "mailbox_inventory_prechange_backup_path", str(prechange["path"])
            )
            self.database.set_meta(
                "mailbox_inventory_migration_result",
                json.dumps(_safe_payload(result), ensure_ascii=False, separators=(",", ":")),
            )
        except Exception as exc:
            self._migration_status = "inventory_migration_error"
            self._migration_error = str(redact_value(str(exc)))
            self.database.set_meta("mailbox_inventory_migration_error", self._migration_error)

    def bootstrap(self) -> dict[str, Any]:
        return {
            "request_token": self.request_token,
            "health": self.health(),
            "workspaces": self.list_workspaces(),
            "accounts": self.list_accounts(),
            "queue": self.queue_snapshot(),
            "runs": self.list_runs(limit=100),
            "settings": self.get_settings(),
        }

    def event_reset(self) -> dict[str, Any]:
        return {
            "workspaces": self.list_workspaces(),
            "accounts": self.list_accounts(),
            "queue": self.queue_snapshot(),
            "runs": self.list_runs(limit=100),
            "settings": self.get_settings(),
            "migration": self.migration_status(),
        }

    def list_workspaces(self) -> list[dict[str, Any]]:
        return _safe_payload(self.database.list_workspaces())

    def create_workspace(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        current_account_id, current_inventory_id = _selection(
            payload, "current", required=True
        )
        next_account_id, next_inventory_id = _selection(
            payload, "next", required=False
        )
        workspace = self.database.create_workspace(
            name=str(payload["name"]).strip(),
            workspace_uid=str(payload["workspace_uid"]).strip(),
            current_account_id=current_account_id,
            current_inventory_id=current_inventory_id,
            next_account_id=next_account_id,
            next_inventory_id=next_inventory_id,
            owner_alias_id=_optional_text(payload.get("owner_alias_id")),
        )
        self.task_queue.notify_change()
        return _safe_payload(workspace)

    def update_workspace(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "expected_version": int(payload["version"]),
            "name": _optional_text(payload.get("name")),
        }
        if "current_account_id" in payload or "current_inventory_id" in payload:
            current_account_id, current_inventory_id = _selection(
                payload, "current", required=True
            )
            kwargs["current_account_id"] = current_account_id
            kwargs["current_inventory_id"] = current_inventory_id
        if bool(payload.get("clear_next_account")):
            if payload.get("next_account_id") or payload.get("next_inventory_id"):
                raise FieldInputError(
                    {"clear_next_account": "cannot clear and select next account together"}
                )
            kwargs["next_account_id"] = None
            kwargs["next_inventory_id"] = None
        elif "next_account_id" in payload or "next_inventory_id" in payload:
            next_account_id, next_inventory_id = _selection(
                payload, "next", required=False
            )
            kwargs["next_account_id"] = next_account_id
            kwargs["next_inventory_id"] = next_inventory_id
        if bool(payload.get("clear_owner_alias")):
            if payload.get("owner_alias_id"):
                raise FieldInputError(
                    {"clear_owner_alias": "cannot clear and select a Team owner together"}
                )
            kwargs["owner_alias_id"] = None
        elif "owner_alias_id" in payload:
            kwargs["owner_alias_id"] = _optional_text(payload.get("owner_alias_id"))
        workspace = self.database.update_workspace(str(workspace_id), **kwargs)
        self.task_queue.notify_change()
        return _safe_payload(workspace)

    def enqueue_workspace(self, workspace_id: str) -> dict[str, Any]:
        return _safe_payload(self.task_queue.enqueue([str(workspace_id)])[0])

    def retry_workspace(self, workspace_id: str) -> dict[str, Any]:
        workspace = self.database.get_workspace(str(workspace_id))
        run_id = workspace.get("last_run_id")
        if not run_id:
            raise StateConflictError("workspace has no run to retry")
        return _safe_payload(self.task_queue.retry(str(run_id)))

    def list_accounts(self) -> list[dict[str, Any]]:
        return _safe_payload(self.database.list_accounts())

    def import_accounts(self, path: str | Path) -> dict[str, Any]:
        from .migration import parse_mailbox_inventory_import

        source = Path(path).expanduser().resolve()
        rows, invalid_count = parse_mailbox_inventory_import(source.read_bytes())
        if not rows:
            raise FieldInputError({"path": "TXT contains no valid mailbox records"})
        result = dict(self.database.import_mailbox_inventory(rows))
        result["total"] = int(result.get("total", len(rows))) + int(invalid_count)
        result["invalid"] = int(result.get("invalid", 0)) + int(invalid_count)
        self.task_queue.notify_change()
        return _safe_payload(result)

    def create_account_alias(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        account = self.database.allocate_mailbox_alias(
            str(payload["inventory_id"])
        )
        self.task_queue.notify_change()
        return _safe_payload(account)

    def search_mailbox_inventory(
        self,
        *,
        query: str = "",
        status: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        return _safe_payload(
            self.database.search_mailbox_inventory(
                query=str(query or "").strip(),
                status=status,
                limit=max(1, min(int(limit), 20)),
            )
        )

    def allocate_mailbox_inventory(self, inventory_id: str) -> dict[str, Any]:
        account = self.database.allocate_mailbox_alias(str(inventory_id))
        self.task_queue.notify_change()
        return _safe_payload(account)

    def replace_workspace_account(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        workspace = self.database.replace_workspace_account(
            str(workspace_id),
            role=str(payload["role"]),
            failure_code=str(payload["failure_code"]),
            expected_version=int(payload["version"]),
        )
        self.task_queue.notify_change()
        return _safe_payload(workspace)

    def advance_workspace_accounts(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        result = self.database.advance_workspace_accounts(
            str(workspace_id), expected_version=int(payload["version"])
        )
        self.task_queue.notify_change()
        return _safe_payload(result)

    def update_account_status(self, account_id: str, new_status: str) -> dict[str, Any]:
        account = self.database.transition_account_status(account_id, str(new_status))
        self.task_queue.notify_change()
        return _safe_payload(account)

    def update_account_proxy(self, account_id: str, proxy: str) -> dict[str, Any]:
        value = str(proxy or "").strip()
        account = (
            self.database.set_account_proxy(account_id, value)
            if value
            else self.database.clear_account_proxy(account_id)
        )
        self.task_queue.notify_change()
        return _safe_payload(account)

    def _icloud_secret_from_payload(
        self,
        payload: Mapping[str, Any],
        *,
        existing: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = dict(existing or {})
        current_session = current.get("session")
        imported = payload.get("session_import")
        if imported is not None:
            try:
                session = parse_hme_session_import(str(imported)).as_secret_dict()
            except HmeSessionError as exc:
                raise FieldInputError({"session_import": str(exc)}) from exc
        elif isinstance(current_session, Mapping):
            session = dict(current_session)
        else:
            raise FieldInputError({"session_import": "iCloud HME session is required"})

        current_imap = current.get("imap")
        imap = dict(current_imap) if isinstance(current_imap, Mapping) else {}
        fields = {
            "host": "imap_host",
            "port": "imap_port",
            "username": "imap_username",
            "folder": "imap_folder",
        }
        for target, source in fields.items():
            if source in payload and payload[source] is not None:
                imap[target] = payload[source]
        if "imap_password" in payload and payload["imap_password"]:
            imap["password"] = str(payload["imap_password"])
        if not existing and not str(payload.get("imap_password") or ""):
            raise FieldInputError({"imap_password": "IMAP password is required"})

        if bool(payload.get("clear_proxy")) and str(payload.get("proxy") or "").strip():
            raise FieldInputError({"proxy": "proxy cannot be set and cleared together"})
        proxy = str(current.get("proxy") or "").strip()
        if bool(payload.get("clear_proxy")):
            proxy = ""
        elif "proxy" in payload and str(payload.get("proxy") or "").strip():
            proxy = str(payload["proxy"]).strip()
        return {"session": session, "imap": imap, "proxy": proxy}

    def create_icloud_mailbox(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        secret = self._icloud_secret_from_payload(payload)
        mailbox = self.database.create_icloud_mailbox(
            name=str(payload.get("name") or "").strip(),
            forwarding_email=str(payload.get("forwarding_email") or "").strip(),
            secrets=secret,
        )
        self.task_queue.notify_change()
        return _safe_payload(mailbox)

    def update_icloud_mailbox(
        self, mailbox_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        current_secret = self.database.get_icloud_mailbox_secrets(str(mailbox_id))
        secret_fields = {
            "session_import",
            "imap_host",
            "imap_port",
            "imap_username",
            "imap_password",
            "imap_folder",
            "proxy",
            "clear_proxy",
        }
        secret = (
            self._icloud_secret_from_payload(payload, existing=current_secret)
            if set(payload) & secret_fields
            else None
        )
        mailbox = self.database.update_icloud_mailbox(
            str(mailbox_id),
            name=(str(payload["name"]).strip() if "name" in payload else None),
            forwarding_email=(
                str(payload["forwarding_email"]).strip()
                if "forwarding_email" in payload
                else None
            ),
            secrets=secret,
        )
        self.task_queue.notify_change()
        return _safe_payload(mailbox)

    def list_icloud_mailboxes(self) -> list[dict[str, Any]]:
        return _safe_payload(self.database.list_icloud_mailboxes())

    def _publish_hme_capture_status(self, _: Mapping[str, Any]) -> None:
        self.task_queue.notify_change()

    def _get_hme_session_template(self, mailbox_id: str) -> ICloudHmeSession:
        secret = self.database.get_icloud_mailbox_secrets(str(mailbox_id))
        try:
            return ICloudHmeSession.from_mapping(secret["session"])
        except (KeyError, HmeSessionError, TypeError) as exc:
            raise StateConflictError(
                "iCloud mailbox has no reusable HME session template"
            ) from exc

    def _save_captured_hme_session(
        self, mailbox_id: str, session: ICloudHmeSession
    ) -> dict[str, Any]:
        if not isinstance(session, ICloudHmeSession):
            try:
                session = ICloudHmeSession.from_mapping(session)
            except (HmeSessionError, TypeError) as exc:
                raise StateConflictError(
                    "captured iCloud HME session is invalid"
                ) from exc
        if not self._icloud_operation_lock.acquire(timeout=10.0):
            raise StateConflictError("another iCloud mailbox operation is running")
        try:
            secret = self.database.get_icloud_mailbox_secrets(str(mailbox_id))
            try:
                self.hme_client_factory(
                    session,
                    proxy=str(secret.get("proxy") or "").strip(),
                ).list_aliases()
            except HmeError as exc:
                raise HmeCaptureSessionRejectedError(
                    "自动捕获的 HME Session 未通过 Apple 只读列表验证"
                ) from exc
            updated_secret = dict(secret)
            updated_secret["session"] = session.as_secret_dict()
            mailbox = self.database.update_icloud_mailbox(
                str(mailbox_id),
                secrets=updated_secret,
            )
            self.task_queue.notify_change()
            return _safe_payload(mailbox)
        finally:
            self._icloud_operation_lock.release()

    def start_icloud_hme_capture(self, mailbox_id: str) -> dict[str, Any]:
        mailbox = self.database.get_icloud_mailbox(str(mailbox_id))
        if mailbox["status"] == "disabled":
            raise StateConflictError("iCloud mailbox is disabled")
        return _safe_payload(self.hme_capture.start(str(mailbox_id)))

    def get_icloud_hme_capture_status(self, mailbox_id: str) -> dict[str, Any]:
        self.database.get_icloud_mailbox(str(mailbox_id))
        return _safe_payload(self.hme_capture.status(str(mailbox_id)))

    def cancel_icloud_hme_capture(self, mailbox_id: str) -> dict[str, Any]:
        self.database.get_icloud_mailbox(str(mailbox_id))
        return _safe_payload(self.hme_capture.cancel(str(mailbox_id)))

    def _icloud_alias_with_proxy_status(
        self, alias: Mapping[str, Any]
    ) -> dict[str, Any]:
        result = dict(alias)
        if result.get("role") != "team_owner":
            return result
        config = self.database.get_icloud_owner_proxy_config(str(result["id"]))
        mode = str(config.get("mode") or "direct")
        result["proxy_mode"] = mode
        if mode == "lokiproxy_generator":
            result["proxy_chain"] = self.proxy_chains.status(str(result["id"]))
        return result

    def list_icloud_aliases(self, mailbox_id: str) -> list[dict[str, Any]]:
        self.database.get_icloud_mailbox(str(mailbox_id))
        return _safe_payload(
            [
                self._icloud_alias_with_proxy_status(alias)
                for alias in self.database.list_icloud_aliases(str(mailbox_id))
            ]
        )

    def list_icloud_team_owners(self) -> list[dict[str, Any]]:
        return _safe_payload(
            [
                self._icloud_alias_with_proxy_status(alias)
                for alias in self.database.list_icloud_team_owners()
            ]
        )

    @staticmethod
    def _normalize_remote_icloud_aliases(
        aliases: Any,
    ) -> list[dict[str, Any]]:
        if not isinstance(aliases, list):
            raise StateConflictError("iCloud HME alias list is invalid")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for value in aliases:
            if not isinstance(value, Mapping):
                continue
            email = str(value.get("hme") or value.get("email") or "").strip().casefold()
            anonymous_id = str(value.get("anonymousId") or "").strip()
            if (
                email.count("@") != 1
                or any(character.isspace() for character in email)
                or not anonymous_id
                or email in seen
            ):
                continue
            seen.add(email)
            normalized.append(
                {
                    "email": email,
                    "label": str(value.get("label") or "").strip(),
                    "note": str(value.get("note") or "").strip(),
                    "active": value.get("isActive") is not False,
                    "remote_metadata": dict(value),
                }
            )
        return normalized

    def preview_remote_icloud_aliases(self, mailbox_id: str) -> list[dict[str, Any]]:
        mailbox_id = str(mailbox_id)
        mailbox = self.database.get_icloud_mailbox(mailbox_id)
        if mailbox["status"] == "session_invalid":
            raise ICloudSessionInvalidError("iCloud HME session must be refreshed")
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud mailbox must pass detection before sync")
        if not self._icloud_operation_lock.acquire(blocking=False):
            raise StateConflictError("another iCloud mailbox operation is running")
        try:
            _secret, client = self._icloud_client(mailbox_id)
            try:
                remote = self._normalize_remote_icloud_aliases(client.list_aliases())
            except HmeSessionError as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "session_invalid",
                    failure_code="session_rejected",
                    failure_message="iCloud HME session was rejected",
                )
                raise ICloudSessionInvalidError(
                    "iCloud HME session must be refreshed"
                ) from exc
            except HmeError as exc:
                raise StateConflictError("iCloud HME alias sync failed") from exc
            imported = {
                str(alias["email"]).casefold(): alias
                for alias in self.database.list_icloud_aliases(mailbox_id)
            }
            imported_by_id = {
                str(alias["id"]): alias for alias in imported.values()
            }
            workspaces = self.database.list_workspaces()
            workspace_by_owner = {
                str(workspace["owner_alias_id"]): workspace
                for workspace in workspaces
                if workspace.get("owner_alias_id")
            }
            workspace_by_account = {
                str(account_id): workspace
                for workspace in workspaces
                for account_id in (
                    workspace.get("current_account_id"),
                    workspace.get("next_account_id"),
                )
                if account_id
            }
            imported_workspace_by_email: dict[str, Mapping[str, Any]] = {}
            for email, alias in imported.items():
                workspace = (
                    workspace_by_owner.get(str(alias["id"]))
                    if alias.get("role") == "team_owner"
                    else workspace_by_account.get(
                        str(alias.get("account_id") or "")
                    )
                )
                if workspace is not None:
                    imported_workspace_by_email[email] = workspace
            return _safe_payload(
                [
                    {
                        "email": item["email"],
                        "label": item["label"],
                        "note": item["note"],
                        "active": item["active"],
                        "imported": item["email"] in imported,
                        "imported_id": (
                            imported[item["email"]]["id"]
                            if item["email"] in imported
                            else None
                        ),
                        "imported_role": (
                            imported[item["email"]]["role"]
                            if item["email"] in imported
                            else None
                        ),
                        "parent_owner_alias_id": (
                            imported[item["email"]]["parent_owner_alias_id"]
                            if item["email"] in imported
                            else None
                        ),
                        "parent_owner_email": (
                            imported_by_id[
                                str(imported[item["email"]]["parent_owner_alias_id"])
                            ]["email"]
                            if item["email"] in imported
                            and imported[item["email"]].get("parent_owner_alias_id")
                            and str(
                                imported[item["email"]]["parent_owner_alias_id"]
                            )
                            in imported_by_id
                            else None
                        ),
                        "proxy_configured": (
                            bool(imported[item["email"]].get("proxy_configured"))
                            if item["email"] in imported
                            else False
                        ),
                        "account_status": (
                            imported[item["email"]].get("account_status")
                            if item["email"] in imported
                            else None
                        ),
                        "used_at": (
                            imported[item["email"]].get("used_at")
                            if item["email"] in imported
                            else None
                        ),
                        "workspace_id": (
                            imported_workspace_by_email[item["email"]].get("id")
                            if item["email"] in imported_workspace_by_email
                            else None
                        ),
                        "workspace_name": (
                            imported_workspace_by_email[item["email"]].get("name")
                            if item["email"] in imported_workspace_by_email
                            else None
                        ),
                    }
                    for item in remote
                ]
            )
        finally:
            self._icloud_operation_lock.release()

    @staticmethod
    def _icloud_team_email(payload: Mapping[str, Any], field: str) -> str:
        email = str(payload.get(field) or "").strip().casefold()
        if not _EMAIL_RE.fullmatch(email):
            raise FieldInputError({field: "enter a valid email address"})
        return email

    def _icloud_team_import_result(
        self,
        workspace: Mapping[str, Any],
        *,
        created: bool,
    ) -> dict[str, Any]:
        owner = self.database.get_icloud_alias(str(workspace["owner_alias_id"]))
        current_child = next(
            (
                alias
                for alias in self.database.list_icloud_aliases(str(owner["mailbox_id"]))
                if str(alias.get("account_id") or "")
                == str(workspace["current_account_id"])
            ),
            None,
        )
        if current_child is None:
            raise StateConflictError("Team current child is not linked to its iCloud alias")
        return _safe_payload(
            {
                "created": bool(created),
                "workspace": dict(workspace),
                "owner": owner,
                "current_child": current_child,
            }
        )

    def import_icloud_team(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        mailbox_id = str(payload.get("mailbox_id") or "").strip()
        name = str(payload.get("name") or "").strip()
        workspace_uid = str(payload.get("workspace_uid") or "").strip()
        owner_email = self._icloud_team_email(payload, "owner_email")
        current_child_email = self._icloud_team_email(
            payload, "current_child_email"
        )
        if owner_email == current_child_email:
            raise FieldInputError(
                {"current_child_email": "current child must differ from Team owner"}
            )

        mailbox = self.database.get_icloud_mailbox(mailbox_id)
        local_aliases = self.database.list_icloud_aliases(mailbox_id)
        local_by_email = {
            str(alias["email"]).casefold(): alias for alias in local_aliases
        }
        existing_owner = local_by_email.get(owner_email)
        existing_child = local_by_email.get(current_child_email)
        workspaces = self.database.list_workspaces()

        workspace_with_uid = next(
            (
                workspace
                for workspace in workspaces
                if str(workspace["workspace_uid"]) == workspace_uid
            ),
            None,
        )
        workspace_for_owner = (
            next(
                (
                    workspace
                    for workspace in workspaces
                    if str(workspace.get("owner_alias_id") or "")
                    == str(existing_owner["id"])
                ),
                None,
            )
            if existing_owner is not None
            else None
        )
        existing_workspace = workspace_with_uid or workspace_for_owner
        if existing_workspace is not None:
            if workspace_with_uid is not None and workspace_for_owner is not None:
                if str(workspace_with_uid["id"]) != str(workspace_for_owner["id"]):
                    raise StateConflictError(
                        "Workspace ID and Team owner belong to different Teams"
                    )
            owner = self.database.get_icloud_alias(
                str(existing_workspace["owner_alias_id"])
            )
            current = self.database.get_account(
                str(existing_workspace["current_account_id"])
            )
            if (
                str(existing_workspace["workspace_uid"]) != workspace_uid
                or str(owner["email"]).casefold() != owner_email
                or str(current["email"]).casefold() != current_child_email
            ):
                raise StateConflictError(
                    "Team owner, current child, or Workspace ID is already bound differently"
                )
            return self._icloud_team_import_result(
                existing_workspace,
                created=False,
            )

        if existing_owner is not None and existing_owner.get("role") != "team_owner":
            raise StateConflictError("selected Team owner is already imported as a child")
        if existing_child is not None:
            if existing_child.get("role") != "rotating_child":
                raise StateConflictError("selected current child is already a Team owner")
            parent_id = str(existing_child.get("parent_owner_alias_id") or "")
            if existing_owner is not None and parent_id not in {
                "",
                str(existing_owner["id"]),
            }:
                raise StateConflictError(
                    "selected current child belongs to another Team owner"
                )
            account = self.database.get_account(str(existing_child["account_id"]))
            if account["status"] != "available":
                raise StateConflictError("selected current child is already bound")

        configure_proxy = payload.get("owner_proxy_mode") is not None
        proxy_mode = str(payload.get("owner_proxy_mode") or "")
        direct_proxy = str(payload.get("owner_proxy") or "").strip()
        proxy_source = str(payload.get("owner_proxy_source_url") or "").strip()
        proxy_bootstrap = str(
            payload.get("owner_proxy_bootstrap")
            or (
                self.local_clash_proxy
                if proxy_mode == "lokiproxy_generator"
                else ""
            )
        ).strip()
        if not bool(existing_owner and existing_owner.get("proxy_configured")):
            configure_proxy = True
            if not proxy_mode:
                raise FieldInputError(
                    {"owner_proxy_mode": "configure the Team child proxy"}
                )
        if configure_proxy:
            if proxy_mode == "direct":
                if not direct_proxy:
                    raise FieldInputError(
                        {"owner_proxy": "enter the Team child SOCKS5 proxy"}
                    )
                try:
                    validate_proxy_url(direct_proxy)
                except ValueError as exc:
                    raise FieldInputError({"owner_proxy": str(exc)}) from exc
            elif proxy_mode == "lokiproxy_generator":
                try:
                    proxy_source = validate_lokiproxy_source(proxy_source)
                    proxy_bootstrap = validate_bootstrap_proxy(proxy_bootstrap)
                except ValueError as exc:
                    raise FieldInputError(
                        {"owner_proxy_source_url": str(exc)}
                    ) from exc
                if proxy_bootstrap != self.local_clash_proxy:
                    raise FieldInputError(
                        {
                            "owner_proxy_bootstrap": (
                                "all Team LokiProxy chains must use the shared local Clash proxy"
                            )
                        }
                    )
            else:
                raise FieldInputError(
                    {"owner_proxy_mode": "select a Team child proxy mode"}
                )

        if mailbox["status"] == "session_invalid":
            raise ICloudSessionInvalidError("iCloud HME session must be refreshed")
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud mailbox must pass detection before Team import")
        if not self._icloud_operation_lock.acquire(blocking=False):
            raise StateConflictError("another iCloud mailbox operation is running")
        try:
            _secret, client = self._icloud_client(mailbox_id)
            try:
                remote_items = self._normalize_remote_icloud_aliases(
                    client.list_aliases()
                )
            except HmeSessionError as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "session_invalid",
                    failure_code="session_rejected",
                    failure_message="iCloud HME session was rejected",
                )
                raise ICloudSessionInvalidError(
                    "iCloud HME session must be refreshed"
                ) from exc
            except HmeError as exc:
                raise StateConflictError("iCloud HME Team import failed") from exc
            remote_by_email = {item["email"]: item for item in remote_items}
            selected = {
                "owner_email": remote_by_email.get(owner_email),
                "current_child_email": remote_by_email.get(current_child_email),
            }
            missing_fields = {
                field: "selected Alias no longer exists in iCloud"
                for field, item in selected.items()
                if item is None
            }
            if missing_fields:
                raise FieldInputError(missing_fields)
            inactive_fields = {
                field: "selected Alias is inactive in iCloud"
                for field, item in selected.items()
                if item is not None and not item["active"]
            }
            if inactive_fields:
                raise FieldInputError(inactive_fields)

            imported = self.database.import_icloud_aliases(
                mailbox_id,
                [
                    {
                        "email": owner_email,
                        "role": "team_owner",
                        "remote_metadata": selected["owner_email"]["remote_metadata"],
                        "label": selected["owner_email"]["label"] or owner_email,
                        "owner_proxy": direct_proxy if proxy_mode == "direct" else "",
                    },
                    {
                        "email": current_child_email,
                        "role": "rotating_child",
                        "parent_owner_email": owner_email,
                        "remote_metadata": selected["current_child_email"][
                            "remote_metadata"
                        ],
                        "label": (
                            selected["current_child_email"]["label"]
                            or current_child_email
                        ),
                    },
                ],
            )
        finally:
            self._icloud_operation_lock.release()

        imported_by_email = {
            str(alias["email"]).casefold(): alias for alias in imported
        }
        owner = imported_by_email[owner_email]
        current_child = imported_by_email[current_child_email]
        if configure_proxy:
            self.set_icloud_owner_proxy(
                str(owner["id"]),
                {
                    "mode": proxy_mode,
                    "proxy": direct_proxy,
                    "source_url": proxy_source,
                    "bootstrap": proxy_bootstrap,
                },
            )
        workspace = self.database.create_workspace(
            name=name,
            workspace_uid=workspace_uid,
            current_account_id=str(current_child["account_id"]),
            owner_alias_id=str(owner["id"]),
        )
        self.task_queue.notify_change()
        return self._icloud_team_import_result(workspace, created=True)

    def import_existing_icloud_aliases(
        self, mailbox_id: str, payload: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        mailbox_id = str(mailbox_id)
        selected = payload.get("items")
        if not isinstance(selected, list) or not selected:
            raise FieldInputError({"items": "select at least one iCloud alias"})
        requested: dict[str, Mapping[str, Any]] = {}
        generated_owners: dict[str, dict[str, str]] = {}
        for value in selected:
            if not isinstance(value, Mapping):
                raise FieldInputError({"items": "iCloud alias selection is invalid"})
            email = str(value.get("email") or "").strip().casefold()
            if not email or email in requested:
                raise FieldInputError({"items": "iCloud alias selection has duplicates"})
            normalized = dict(value)
            mode = str(normalized.get("owner_proxy_mode") or "direct")
            role = str(normalized.get("role") or "")
            if role == "team_owner" and mode == "lokiproxy_generator":
                if not self.enable_proxy_chains:
                    raise FieldInputError(
                        {"items": "LokiProxy relay is disabled"}
                    )
                source_url = str(
                    normalized.get("owner_proxy_source_url")
                    or normalized.get("owner_proxy")
                    or ""
                ).strip()
                bootstrap = str(
                    normalized.get("owner_proxy_bootstrap")
                    or self.local_clash_proxy
                ).strip()
                try:
                    source_url = validate_lokiproxy_source(source_url)
                    bootstrap = validate_bootstrap_proxy(bootstrap)
                except ValueError as exc:
                    raise FieldInputError({"items": str(exc)}) from exc
                if bootstrap != self.local_clash_proxy:
                    raise FieldInputError(
                        {"items": "both LokiProxy sources must use the shared local Clash proxy"}
                    )
                generated_owners[email] = {
                    "source_url": source_url,
                    "bootstrap_proxy": bootstrap,
                }
                normalized["owner_proxy"] = ""
            requested[email] = normalized
        mailbox = self.database.get_icloud_mailbox(mailbox_id)
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud mailbox must pass detection before import")
        if not self._icloud_operation_lock.acquire(blocking=False):
            raise StateConflictError("another iCloud mailbox operation is running")
        try:
            _secret, client = self._icloud_client(mailbox_id)
            try:
                remote_items = self._normalize_remote_icloud_aliases(
                    client.list_aliases()
                )
            except HmeSessionError as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "session_invalid",
                    failure_code="session_rejected",
                    failure_message="iCloud HME session was rejected",
                )
                raise StateConflictError("iCloud HME session was rejected") from exc
            except HmeError as exc:
                raise StateConflictError("iCloud HME alias import failed") from exc
            remote_by_email = {item["email"]: item for item in remote_items}
            missing = sorted(set(requested) - set(remote_by_email))
            if missing:
                raise FieldInputError(
                    {"items": "selected iCloud alias no longer exists remotely"}
                )
            inactive = sorted(
                email for email in requested if not remote_by_email[email]["active"]
            )
            if inactive:
                raise FieldInputError(
                    {"items": "inactive iCloud aliases cannot be imported as active Team accounts"}
                )
            imported = self.database.import_icloud_aliases(
                mailbox_id,
                [
                    {
                        **dict(requested[email]),
                        "remote_metadata": remote_by_email[email]["remote_metadata"],
                        "label": remote_by_email[email]["label"] or email,
                    }
                    for email in requested
                ],
            )
            if generated_owners:
                imported_by_email = {
                    str(item["email"]).casefold(): item for item in imported
                }
                configured_owner_ids: list[str] = []
                for email, proxy_source in generated_owners.items():
                    owner = imported_by_email.get(email)
                    if owner is None or owner.get("role") != "team_owner":
                        raise StateConflictError(
                            "imported iCloud Team owner could not be configured"
                        )
                    try:
                        chain = self.proxy_chains.prepare(
                            str(owner["id"]),
                            proxy_source["source_url"],
                            proxy_source["bootstrap_proxy"],
                        )
                    except ValueError as exc:
                        raise FieldInputError({"items": str(exc)}) from exc
                    self.database.set_icloud_owner_proxy_config(
                        str(owner["id"]), chain.as_secret_dict()
                    )
                    configured_owner_ids.append(str(owner["id"]))
                self.proxy_chains.apply()
                for owner_id in configured_owner_ids:
                    self.proxy_chains.refresh(owner_id, force=True)
            self.task_queue.notify_change()
            return _safe_payload(
                [
                    self._icloud_alias_with_proxy_status(
                        self.database.get_icloud_alias(str(item["id"]))
                    )
                    for item in imported
                ]
            )
        finally:
            self._icloud_operation_lock.release()

    def set_icloud_owner_proxy(
        self, alias_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        alias_id = str(alias_id)
        previous = self.database.get_icloud_owner_proxy_config(alias_id)
        mode = str(payload.get("mode") or "direct")
        if mode == "direct":
            if str(payload.get("source_url") or "").strip() or str(
                payload.get("bootstrap") or ""
            ).strip():
                raise FieldInputError(
                    {"mode": "LokiProxy source and first hop require LokiProxy mode"}
                )
            updated = self.database.set_icloud_owner_proxy(
                alias_id, str(payload.get("proxy") or "")
            )
            if previous.get("mode") == "lokiproxy_generator":
                if self.enable_proxy_chains:
                    self.proxy_chains.apply()
        elif mode == "lokiproxy_generator":
            if not self.enable_proxy_chains:
                raise FieldInputError(
                    {"mode": "LokiProxy relay is disabled"}
                )
            source_url = str(
                payload.get("source_url")
                or payload.get("proxy")
                or (
                    previous.get("source_url")
                    if previous.get("mode") == "lokiproxy_generator"
                    else ""
                )
                or ""
            ).strip()
            bootstrap = str(
                payload.get("bootstrap")
                or (
                    previous.get("bootstrap_proxy")
                    if previous.get("mode") == "lokiproxy_generator"
                    else ""
                )
                or self.local_clash_proxy
            ).strip()
            try:
                bootstrap = validate_bootstrap_proxy(bootstrap)
                if bootstrap != self.local_clash_proxy:
                    raise ValueError(
                        "both LokiProxy chains must use the shared local Clash proxy"
                    )
                chain = self.proxy_chains.prepare(alias_id, source_url, bootstrap)
            except ValueError as exc:
                raise FieldInputError({"source_url": str(exc)}) from exc
            updated = self.database.set_icloud_owner_proxy_config(
                alias_id, chain.as_secret_dict()
            )
            self.proxy_chains.apply()
            self.proxy_chains.refresh(alias_id, force=True)
        else:
            raise FieldInputError({"mode": "unsupported iCloud Team owner proxy mode"})
        self.task_queue.notify_change()
        return _safe_payload(self._icloud_alias_with_proxy_status(updated))

    def get_icloud_owner_proxy_status(self, alias_id: str) -> dict[str, Any]:
        alias = self.database.get_icloud_alias(str(alias_id))
        if alias["role"] != "team_owner":
            raise StateConflictError("iCloud alias is not a Team owner")
        config = self.database.get_icloud_owner_proxy_config(str(alias_id))
        mode = str(config.get("mode") or "direct")
        return _safe_payload(
            {
                "configured": bool(alias["proxy_configured"]),
                "mode": mode,
                "chain": (
                    self.proxy_chains.status(str(alias_id))
                    if mode == "lokiproxy_generator"
                    else None
                ),
            }
        )

    def list_proxy_chain_nodes(self) -> dict[str, Any]:
        if not self.enable_proxy_chains:
            return {
                "enabled": False,
                "nodes": [],
                "local_proxy": self.local_clash_proxy,
            }
        # A retry only starts Team Workflow's loopback relays. It never calls a
        # Mihomo API or modifies the user's Clash configuration.
        if self._proxy_chain_startup_error is not None:
            try:
                self.proxy_chains.apply()
                self._proxy_chain_startup_error = None
            except ProxyChainError as exc:
                self._proxy_chain_startup_error = exc.code
                raise
        return {
            "enabled": True,
            "nodes": self.proxy_chains.available_nodes(),
            "local_proxy": self.local_clash_proxy,
            "shared": True,
        }

    def proxy_chain_provider(self, owner_id: str, token: str) -> bytes:
        del owner_id, token
        raise ProxyConfigurationError("legacy Mihomo provider endpoint is disabled")

    def replace_icloud_workspace_child(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._replace_icloud_workspace_child(
            workspace_id,
            payload,
            rescue=False,
        )

    def rescue_icloud_workspace_child(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self._replace_icloud_workspace_child(
            workspace_id,
            payload,
            rescue=True,
        )

    def _replace_icloud_workspace_child(
        self,
        workspace_id: str,
        payload: Mapping[str, Any],
        *,
        rescue: bool,
    ) -> dict[str, Any]:
        workspace_id = str(workspace_id)
        expected_version = int(payload.get("version") or 0)
        workspace = self.database.get_workspace(workspace_id)
        if int(workspace["version"]) != expected_version:
            raise StaleVersionError("workspace version is stale")
        if workspace["owner_alias_id"] is None:
            raise StateConflictError("workspace has no iCloud Team owner")
        if workspace["next_account_id"] is not None:
            last_run = None
            if rescue and workspace.get("last_run_id"):
                last_run = self.database.get_run(str(workspace["last_run_id"]))
                same_rescue = (
                    last_run.get("kind") == "rescue"
                    and last_run.get("workspace_id") == workspace_id
                    and last_run.get("current_account_id")
                    == workspace.get("current_account_id")
                    and last_run.get("next_account_id")
                    == workspace.get("next_account_id")
                )
                if same_rescue and last_run.get("state") == "failed":
                    run = self.task_queue.retry(str(last_run["id"]))
                    return _safe_payload(
                        {
                            "mode": "rescue",
                            "created": False,
                            "resumed": True,
                            "workspace": self.database.get_workspace(workspace_id),
                            "run": run,
                        }
                    )
                if same_rescue and last_run.get("state") in {
                    "queued",
                    "running",
                    "stopping",
                }:
                    return _safe_payload(
                        {
                            "mode": "rescue",
                            "created": False,
                            "resumed": True,
                            "workspace": workspace,
                            "run": last_run,
                        }
                    )
            run = (
                self.task_queue.enqueue_rescue(workspace_id)
                if rescue
                else self.task_queue.enqueue([workspace_id])[0]
            )
            return _safe_payload(
                {
                    "mode": "rescue" if rescue else "handoff",
                    "created": False,
                    "workspace": workspace,
                    "run": run,
                }
            )
        owner = self.database.get_icloud_alias(workspace["owner_alias_id"])
        if owner["role"] != "team_owner" or owner["state"] != "active":
            raise StateConflictError("workspace iCloud Team owner is unavailable")
        if not owner["proxy_configured"]:
            raise StateConflictError("iCloud Team owner S5 is not configured")
        owner_proxy_config = self.database.get_icloud_owner_proxy_config(
            str(owner["id"])
        )
        if owner_proxy_config.get("mode") == "lokiproxy_generator":
            self.proxy_chains.ensure_ready(str(owner["id"]))
        mailbox = self.database.get_icloud_mailbox(owner["mailbox_id"])
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud mailbox must pass detection before handoff")
        if not self._icloud_operation_lock.acquire(blocking=False):
            raise StateConflictError("another iCloud mailbox operation is running")
        remote: Mapping[str, Any] | None = None
        client: Any = None
        try:
            _secret, client = self._icloud_client(owner["mailbox_id"])
            current_label = ""
            for alias in self.database.list_icloud_aliases(owner["mailbox_id"]):
                if str(alias.get("account_id") or "") == str(
                    workspace["current_account_id"]
                ):
                    current_label = str(alias.get("label") or "").strip()
                    break
            label = _next_icloud_child_label(
                current_label,
                str(workspace["name"]),
                int(workspace["rotation_count"]),
            )
            try:
                remote = client.create_alias(
                    label=label,
                    note=f"Team Workflow workspace {workspace_id}",
                )
            except HmeSessionError as exc:
                self.database.set_icloud_mailbox_status(
                    owner["mailbox_id"],
                    "session_invalid",
                    failure_code="session_rejected",
                    failure_message="iCloud HME session was rejected",
                )
                raise StateConflictError("iCloud HME session was rejected") from exc
            except HmeError as exc:
                raise StateConflictError("iCloud child generation failed") from exc
            try:
                if not isinstance(remote, Mapping):
                    raise StateConflictError("iCloud child generation response is invalid")
                email = str(remote.get("hme") or "").strip().casefold()
                if not email:
                    raise StateConflictError("iCloud child generation returned no email")
                prepared = self.database.prepare_icloud_workspace_handoff(
                    workspace_id,
                    expected_version=expected_version,
                    email=email,
                    remote_metadata=remote,
                    label=label,
                )
            except DatabaseError:
                anonymous_id = (
                    str(remote.get("anonymousId") or "").strip()
                    if isinstance(remote, Mapping)
                    else ""
                )
                if anonymous_id and client is not None:
                    try:
                        client.deactivate_alias(anonymous_id)
                    except HmeError:
                        pass
                raise
        finally:
            self._icloud_operation_lock.release()
        try:
            run = (
                self.task_queue.enqueue_rescue(workspace_id)
                if rescue
                else self.task_queue.enqueue([workspace_id])[0]
            )
        finally:
            self.task_queue.notify_change()
        return _safe_payload(
            {
                "mode": "rescue" if rescue else "handoff",
                "created": True,
                **prepared,
                "run": run,
            }
        )

    def _icloud_client(self, mailbox_id: str) -> tuple[dict[str, Any], Any]:
        mailbox = self.database.get_icloud_mailbox(mailbox_id)
        secret = self.database.get_icloud_mailbox_secrets(mailbox_id)
        session_value = secret.get("session")
        if not isinstance(session_value, Mapping):
            raise StateConflictError("iCloud HME session is missing")
        try:
            session = ICloudHmeSession.from_mapping(session_value)
        except HmeSessionError as exc:
            raise StateConflictError("iCloud HME session is invalid") from exc
        client = self.hme_client_factory(
            session,
            proxy=str(secret.get("proxy") or ""),
            timeout=20.0,
        )
        return secret, client

    @staticmethod
    def _imap_config(
        mailbox: Mapping[str, Any], secret: Mapping[str, Any]
    ) -> ImapMailboxConfig:
        imap = secret.get("imap")
        if not isinstance(imap, Mapping):
            raise StateConflictError("iCloud forwarding mailbox is missing")
        config = ImapMailboxConfig(
            registration_email=str(mailbox["forwarding_email"]),
            forwarding_email=str(mailbox["forwarding_email"]),
            host=str(imap.get("host") or ""),
            port=int(imap.get("port") or 993),
            username=str(imap.get("username") or ""),
            password=str(imap.get("password") or ""),
            folder=str(imap.get("folder") or "INBOX"),
            proxy=str(secret.get("proxy") or ""),
        )
        try:
            config.validate()
        except ValueError as exc:
            raise StateConflictError("iCloud forwarding mailbox is invalid") from exc
        return config

    def check_icloud_mailbox(self, mailbox_id: str) -> dict[str, Any]:
        mailbox_id = str(mailbox_id)
        if not self._icloud_operation_lock.acquire(blocking=False):
            raise StateConflictError("another iCloud mailbox operation is running")
        try:
            mailbox = self.database.get_icloud_mailbox(mailbox_id)
            secret, client = self._icloud_client(mailbox_id)
            try:
                settings = client.list_settings()
            except HmeSessionError as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "session_invalid",
                    failure_code="session_rejected",
                    failure_message="iCloud HME session was rejected",
                    checked=True,
                )
                raise StateConflictError("iCloud HME session was rejected") from exc
            except HmeError as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "unchecked",
                    failure_code="hme_unavailable",
                    failure_message="iCloud HME check failed",
                    checked=True,
                )
                raise StateConflictError("iCloud HME check failed") from exc

            selected_forward = str(settings.get("selectedForwardTo") or "").strip().casefold()
            if selected_forward and selected_forward != str(
                mailbox["forwarding_email"]
            ).casefold():
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "unchecked",
                    failure_code="forwarding_mismatch",
                    failure_message="iCloud forwarding address does not match",
                    checked=True,
                )
                raise StateConflictError("iCloud forwarding address does not match")
            try:
                self.imap_checker(self._imap_config(mailbox, secret), timeout=15.0)
            except MailboxCredentialsInvalidError as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "imap_invalid",
                    failure_code="imap_credentials_invalid",
                    failure_message="IMAP credentials were rejected",
                    checked=True,
                )
                raise StateConflictError("IMAP credentials were rejected") from exc
            except (ImapMailboxError, OSError, TimeoutError) as exc:
                self.database.set_icloud_mailbox_status(
                    mailbox_id,
                    "unchecked",
                    failure_code="imap_unavailable",
                    failure_message="IMAP connection check failed",
                    checked=True,
                )
                raise StateConflictError("IMAP connection check failed") from exc

            aliases = settings.get("hmeEmails") or []
            checked = self.database.set_icloud_mailbox_status(
                mailbox_id, "ready", checked=True
            )
            self.task_queue.notify_change()
            return _safe_payload(
                {
                    "mailbox": checked,
                    "remote_alias_count": len(aliases) if isinstance(aliases, list) else 0,
                    "selected_forward_to": selected_forward,
                }
            )
        finally:
            self._icloud_operation_lock.release()

    def generate_icloud_aliases(
        self, mailbox_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        mailbox_id = str(mailbox_id)
        count = int(payload.get("count") or 1)
        if not 1 <= count <= 20:
            raise FieldInputError({"count": "count must be between 1 and 20"})
        prefix = str(payload.get("label_prefix") or "Team Workflow").strip()
        if not prefix or len(prefix) > 100:
            raise FieldInputError({"label_prefix": "label prefix is invalid"})
        mailbox = self.database.get_icloud_mailbox(mailbox_id)
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud mailbox must pass detection before generation")
        if not self._icloud_operation_lock.acquire(blocking=False):
            raise StateConflictError("another iCloud mailbox operation is running")
        created: list[dict[str, Any]] = []
        failure_code: str | None = None
        try:
            _secret, client = self._icloud_client(mailbox_id)
            start = int(mailbox["alias_count"])
            for index in range(count):
                label = f"{prefix} {start + index + 1}"
                try:
                    remote = client.create_alias(
                        label=label,
                        note=f"Team Workflow profile {mailbox_id}",
                    )
                except HmeSessionError:
                    failure_code = "session_rejected"
                    self.database.set_icloud_mailbox_status(
                        mailbox_id,
                        "session_invalid",
                        failure_code=failure_code,
                        failure_message="iCloud HME session was rejected",
                        checked=True,
                    )
                    break
                except HmeError:
                    failure_code = "hme_request_failed"
                    self.database.set_icloud_mailbox_status(
                        mailbox_id,
                        "unchecked",
                        failure_code=failure_code,
                        failure_message="iCloud alias generation failed",
                    )
                    break
                email_address = str(remote.get("hme") or "").strip().casefold()
                if not email_address:
                    failure_code = "invalid_reserve_response"
                    break
                try:
                    stored = self.database.create_icloud_alias(
                        mailbox_id,
                        email=email_address,
                        remote_metadata=remote,
                        label=label,
                    )
                except DatabaseError:
                    anonymous_id = str(remote.get("anonymousId") or "").strip()
                    if anonymous_id:
                        try:
                            client.deactivate_alias(anonymous_id)
                        except HmeError:
                            pass
                    if not created:
                        raise
                    failure_code = "local_persistence_failed"
                    break
                created.append(stored)
            self.task_queue.notify_change()
            if not created and failure_code:
                raise StateConflictError(
                    "iCloud alias generation stopped before an alias was stored"
                )
            return _safe_payload(
                {
                    "requested": count,
                    "created": len(created),
                    "stopped": len(created) != count,
                    "failure_code": failure_code,
                    "items": created,
                    "mailbox": self.database.get_icloud_mailbox(mailbox_id),
                }
            )
        finally:
            self._icloud_operation_lock.release()

    def update_icloud_mailbox_status(
        self, mailbox_id: str, status_value: str
    ) -> dict[str, Any]:
        if status_value not in {"disabled", "unchecked"}:
            raise FieldInputError({"status": "status must be disabled or unchecked"})
        mailbox = self.database.set_icloud_mailbox_status(
            str(mailbox_id), status_value
        )
        self.task_queue.notify_change()
        return _safe_payload(mailbox)

    def update_icloud_alias_state(
        self, alias_id: str, state_value: str
    ) -> dict[str, Any]:
        if state_value not in {"active", "inactive"}:
            raise FieldInputError({"state": "state must be active or inactive"})
        alias = self.database.get_icloud_alias(str(alias_id))
        if alias["role"] == "team_owner":
            raise StateConflictError(
                "iCloud Team owner state is protected; use edit configuration or rescue"
            )
        if alias["state"] == state_value:
            return _safe_payload(alias)
        account = (
            None
            if alias["account_id"] is None
            else self.database.get_account(alias["account_id"])
        )
        if account is not None and account["status"] in {"bound_current", "bound_next"}:
            raise StateConflictError("a bound iCloud alias cannot change remote state")
        mailbox = self.database.get_icloud_mailbox(alias["mailbox_id"])
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud mailbox is not ready")
        _secret, client = self._icloud_client(alias["mailbox_id"])
        remote = self.database.get_icloud_alias_remote(str(alias_id))
        anonymous_id = str(remote.get("anonymousId") or "").strip()
        if not anonymous_id:
            raise StateConflictError("iCloud alias remote identifier is missing")
        try:
            if state_value == "active":
                client.activate_alias(anonymous_id)
            else:
                client.deactivate_alias(anonymous_id)
        except HmeSessionError as exc:
            self.database.set_icloud_mailbox_status(
                alias["mailbox_id"],
                "session_invalid",
                failure_code="session_rejected",
                failure_message="iCloud HME session was rejected",
            )
            raise StateConflictError("iCloud HME session was rejected") from exc
        except HmeError as exc:
            raise StateConflictError("iCloud alias state update failed") from exc
        updated = self.database.set_icloud_alias_state(str(alias_id), state_value)
        if (
            account is not None
            and state_value == "inactive"
            and account["status"] == "available"
        ):
            self.database.transition_account_status(account["id"], "disabled")
        elif (
            account is not None
            and state_value == "active"
            and account["status"] == "disabled"
        ):
            self.database.transition_account_status(account["id"], "available")
        self.task_queue.notify_change()
        return _safe_payload(self.database.get_icloud_alias(str(alias_id)))

    def queue_snapshot(self) -> dict[str, Any]:
        return _safe_payload(self.task_queue.snapshot())

    def enqueue(self, workspace_ids: list[str]) -> list[dict[str, Any]]:
        return _safe_payload(self.task_queue.enqueue(workspace_ids))

    def reorder_queue(self, queue_item_ids: list[str]) -> list[dict[str, Any]]:
        return _safe_payload(self.task_queue.reorder(queue_item_ids))

    def pause_queue(self, paused: bool) -> dict[str, Any]:
        return {"paused": bool(self.task_queue.set_paused(bool(paused)))}

    def list_runs(
        self,
        *,
        workspace_id: str | None = None,
        state: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        return _safe_payload(
            self.database.list_runs(
                workspace_id=workspace_id,
                state=state,
                limit=limit,
            )
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        run = self.database.get_run(run_id)
        run["events"] = self.database.list_run_events(run_id=run_id, limit=2000)
        return _safe_payload(run)

    def stop_run(self, run_id: str) -> dict[str, Any]:
        return {"run_id": str(run_id), "state": self.task_queue.stop(str(run_id))}

    def get_settings(self) -> dict[str, Any]:
        rows = self.database.list_settings()
        values = {
            str(item["key"]): item["value"]
            for item in rows
            if not item["encrypted"] and item["key"] in _VISIBLE_TEXT_SETTING_KEYS
        }
        configured = {
            key: any(
                item["key"] == key and item["encrypted"] and item["configured"]
                for item in rows
            )
            for key in sorted(_SECRET_SETTING_KEYS)
        }
        return {"values": values, "secrets": configured}

    def list_sub2api_groups(self) -> dict[str, Any]:
        base_url = str(
            self.database.get_text_setting(
                "sub2api_base_url", "https://sub2api.example.com"
            )
            or ""
        ).strip()
        email = str(self.database.get_text_setting("sub2api_email", "") or "").strip()
        password_blob = self.database.get_secret_setting("sub2api_password")
        password = "" if password_blob is None else password_blob.decode("utf-8")
        api_key_blob = self.database.get_secret_setting("sub2api_api_key")
        api_key = "" if api_key_blob is None else api_key_blob.decode("utf-8")
        totp_blob = self.database.get_secret_setting("sub2api_totp_secret")
        totp_secret = "" if totp_blob is None else totp_blob.decode("utf-8")
        if not base_url or (not api_key and (not email or not password)):
            raise FieldInputError(
                {
                    "sub2api": (
                        "service URL and either administrator API key or "
                        "administrator email and password are required"
                    )
                }
            )

        client_options = {}
        if api_key:
            client_options["api_key"] = api_key
        if totp_secret:
            client_options["totp_secret"] = totp_secret
        with Sub2APIClient(base_url, email, password, **client_options) as client:
            remote_groups = client.list_groups(include_inactive=True)
        groups = []
        for item in remote_groups:
            try:
                group_id = int(item.get("id") or 0)
            except (TypeError, ValueError):
                continue
            name = str(item.get("name") or "").strip()
            if group_id <= 0 or not name:
                continue
            groups.append(
                {
                    "id": group_id,
                    "name": name,
                    "platform": str(item.get("platform") or "").strip(),
                    "status": str(item.get("status") or "").strip(),
                    "is_exclusive": bool(item.get("is_exclusive", False)),
                }
            )
        groups.sort(
            key=lambda item: (
                item["platform"].casefold(),
                item["name"].casefold(),
                item["id"],
            )
        )
        return {"groups": groups}

    def update_settings(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        values = dict(payload.get("values") or {})
        secret_updates = dict(payload.get("secrets") or {})
        clear_secrets = [str(value) for value in payload.get("clear_secrets") or []]
        invalid_values = sorted(set(values) - _TEXT_SETTING_KEYS)
        invalid_secrets = sorted((set(secret_updates) | set(clear_secrets)) - _SECRET_SETTING_KEYS)
        fields = {}
        if invalid_values:
            fields["values"] = f"unsupported settings: {', '.join(invalid_values)}"
        if invalid_secrets:
            fields["secrets"] = f"unsupported secrets: {', '.join(invalid_secrets)}"
        if set(secret_updates) & set(clear_secrets):
            fields["clear_secrets"] = "a secret cannot be updated and cleared together"
        if fields:
            raise FieldInputError(fields)
        for key, value in values.items():
            self.database.set_text_setting(key, _setting_text(value))
        for key, value in secret_updates.items():
            if value:
                self.database.set_secret_setting(key, value)
        for key in clear_secrets:
            self.database.delete_setting(key)
        self.task_queue.notify_change()
        return self.get_settings()

    def create_encrypted_backup(self, path: str | None = None) -> dict[str, Any]:
        destination = (
            Path(path).expanduser().resolve()
            if path
            else self.backup_dir
            / (
                "console-"
                + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                + ".twbackup"
            )
        )
        model = self._current_backup_model()
        stored_migration_id = self.database.get_meta("migration_id")
        if stored_migration_id is None:
            self.database.set_meta("migration_id", model.migration_id)
        elif stored_migration_id != model.migration_id:
            raise MigrationBackupError("database migration identity does not match backup sources")
        verified = create_backup(
            model,
            destination,
            self.secret_store,
            schema_version=int(self.database.get_meta("schema_version") or 0),
            instance_id=str(self.database.get_meta("instance_id") or ""),
            sqlite_snapshot=self.database.create_snapshot_bytes(),
        )
        self.database.set_text_setting("last_backup_path", str(destination))
        self.database.set_text_setting("last_backup_at", verified.created_at)
        self.task_queue.notify_change()
        return {
            "status": "created",
            "path": str(destination),
            "created_at": verified.created_at,
            "schema_version": verified.schema_version,
        }

    def _current_backup_model(self) -> _BackupModel:
        migration_backup_path = self.database.get_meta("migration_backup_path")
        if migration_backup_path and Path(migration_backup_path).is_file():
            verified = verify_backup(migration_backup_path, self.secret_store)
            return _BackupModel(
                config=SimpleNamespace(**verified.identity),
                sources=verified.sources,
                migration_id=verified.migration_id,
            )
        identity = {
            "workspace_id": "console",
            "old_email": "current@console.invalid",
            "new_email": "next@console.invalid",
        }
        workspaces = self.database.list_workspaces()
        accounts = {item["id"]: item for item in self.database.list_accounts()}
        if workspaces:
            workspace = workspaces[0]
            identity["workspace_id"] = workspace["workspace_uid"]
            current = accounts.get(workspace["current_account_id"])
            next_account = accounts.get(workspace.get("next_account_id"))
            if current:
                identity["old_email"] = current["email"]
            if next_account:
                identity["new_email"] = next_account["email"]
        sources: list[SourcePayload] = []
        source_specs = (
            (
                "workflow_config",
                self.app_dir / ".backup-manifest" / "console.json",
                json.dumps(
                    {"instance_id": self.database.get_meta("instance_id")},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
            ),
            (
                "mail_accounts",
                self.app_dir / ".backup-manifest" / "accounts.txt",
                b"database-owned encrypted account library",
            ),
        )
        for role, path, content in source_specs:
            record = SourceRecord(
                role=role,
                path=path.resolve(),
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                ownership="external",
            )
            sources.append(SourcePayload(record=record, content=content))
        manifest = [source.record.as_manifest() for source in sources]
        migration_id = hashlib.sha256(
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return _BackupModel(
            config=SimpleNamespace(**identity),
            sources=tuple(sources),
            migration_id=migration_id,
        )

    def restore_encrypted_backup(self, path: str | Path) -> dict[str, Any]:
        snapshot = self.task_queue.snapshot()
        if not snapshot.get("paused"):
            raise StateConflictError("queue must be paused before restore")
        if snapshot.get("active_run_id"):
            raise StateConflictError("active run blocks restore")
        self.task_queue.shutdown()
        try:
            result = restore_backup(path, self.secret_store, self.database)
            self.database.initialize()
            persisted = self.database.get_meta("migration_status")
            if persisted in {"imported", "backup_verified"}:
                self.database.set_meta("migration_status", "complete")
                self.database.set_meta("migration_completed", "1")
                self.database.set_meta("migration_backup_path", str(Path(path).resolve()))
                persisted = "complete"
            self._migration_status = (
                "ready" if persisted in {"ready", "complete"} else str(persisted or "ready")
            )
            self._migration_error = None
            if self._migration_status == "ready":
                self._prepare_inventory_backfill()
            if self._migration_status == "ready":
                self.database.prune_unreferenced_legacy_accounts()
        finally:
            if self._migration_status == "ready":
                self.task_queue.start()
                self.task_queue.notify_change()
        return _safe_payload(result)

    def choose_path(self, kind: str, current: str = "") -> dict[str, str]:
        if kind not in {"txt", "directory", "backup"}:
            raise FieldInputError({"kind": "supported values are txt, directory, backup"})
        with self._dialog_lock:
            selected = _choose_path(kind, current)
        return {"path": selected}


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    clean = str(value).strip()
    return clean or None


def _selection(
    payload: Mapping[str, Any], role: str, *, required: bool
) -> tuple[str | None, str | None]:
    account_id = _optional_text(payload.get(f"{role}_account_id"))
    inventory_id = _optional_text(payload.get(f"{role}_inventory_id"))
    selected = int(account_id is not None) + int(inventory_id is not None)
    if selected > 1 or (required and selected != 1):
        message = "select exactly one account or mailbox inventory item"
        raise FieldInputError({role: message})
    return account_id, inventory_id


def _setting_text(value: str | bool | int | float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _safe_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned = {
            str(key): _safe_payload(item)
            for key, item in value.items()
            if str(key).casefold() not in _SENSITIVE_RESPONSE_KEYS
            and not str(key).casefold().endswith("_blob")
        }
        return redact_value(cleaned)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_payload(item) for item in value]
    return redact_value(value)


def _choose_path(kind: str, current: str) -> str:
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    current_path = Path(current).expanduser() if current else None
    initial_dir = ""
    if current_path is not None:
        initial_dir = str(current_path if current_path.is_dir() else current_path.parent)
    try:
        if kind == "directory":
            return str(
                filedialog.askdirectory(
                    parent=root,
                    title="选择目录",
                    initialdir=initial_dir or None,
                )
                or ""
            )
        filetypes = (
            (("加密备份", "*.twbackup"), ("全部文件", "*.*"))
            if kind == "backup"
            else (("文本文件", "*.txt"), ("全部文件", "*.*"))
        )
        return str(
            filedialog.askopenfilename(
                parent=root,
                title="选择文件",
                initialdir=initial_dir or None,
                filetypes=filetypes,
            )
            or ""
        )
    finally:
        root.destroy()


def create_app(
    controller: WebConsoleController | None = None,
    *,
    testing: bool = False,
) -> FastAPI:
    controller = controller or WebConsoleController()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await asyncio.to_thread(controller.startup)
        try:
            yield
        finally:
            await asyncio.to_thread(controller.shutdown)

    app = FastAPI(
        title="Team Workflow Console",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    allowed_hosts = ["127.0.0.1", "localhost"]
    if testing:
        allowed_hosts.append("testserver")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_: Request, exc: RequestValidationError):
        fields: dict[str, str] = {}
        for error in exc.errors():
            location = [str(part) for part in error.get("loc", ()) if part != "body"]
            field = ".".join(location) or "body"
            fields[field] = str(error.get("msg") or "invalid value")
        return JSONResponse(
            {"detail": {"code": "validation_error", "fields": fields}},
            status_code=422,
        )

    @app.middleware("http")
    async def secure_local_requests(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path != "/api/bootstrap":
            token = request.headers.get("X-Workflow-Token") or request.query_params.get("token")
            if not secrets.compare_digest(token or "", controller.request_token):
                return _error_response(403, "invalid_request_token", "invalid request token")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                origin = request.headers.get("Origin", "")
                expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
                if origin != expected:
                    return _error_response(403, "invalid_origin", "invalid origin")
        if (
            path.startswith("/api/")
            and controller._migration_status != "ready"
            and path
            not in {
                "/api/bootstrap",
                "/api/events",
                "/api/migration/status",
                "/api/migration/retry-cleanup",
                "/api/migration/cleanup",
                "/api/migration/cleanup/retry",
                "/api/backups/restore",
                "/api/dialog",
            }
        ):
            return _error_response(
                503,
                "migration_blocked",
                "migration recovery must complete before normal operations",
            )
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "script-src 'self'; style-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/bootstrap")
    async def bootstrap():
        return await _call_controller(controller.bootstrap)

    @app.get("/api/workspaces")
    async def list_workspaces():
        return await _call_controller(controller.list_workspaces)

    @app.post("/api/workspaces", status_code=status.HTTP_201_CREATED)
    async def create_workspace(request: WorkspaceCreateRequest):
        return await _call_controller(controller.create_workspace, request.model_dump())

    @app.patch("/api/workspaces/{workspace_id}")
    async def update_workspace(workspace_id: str, request: WorkspaceUpdateRequest):
        return await _call_controller(
            controller.update_workspace,
            workspace_id,
            request.model_dump(exclude_unset=True),
        )

    @app.post("/api/workspaces/{workspace_id}/enqueue", status_code=202)
    async def enqueue_workspace(workspace_id: str):
        return await _call_controller(controller.enqueue_workspace, workspace_id)

    @app.post("/api/workspaces/{workspace_id}/retry", status_code=202)
    async def retry_workspace(workspace_id: str):
        return await _call_controller(controller.retry_workspace, workspace_id)

    @app.post(
        "/api/workspaces/{workspace_id}/replace-icloud-child",
        status_code=202,
    )
    async def replace_icloud_workspace_child(
        workspace_id: str, request: ICloudWorkspaceHandoffRequest
    ):
        return await _call_controller(
            controller.replace_icloud_workspace_child,
            workspace_id,
            request.model_dump(),
        )

    @app.post(
        "/api/workspaces/{workspace_id}/rescue-icloud-child",
        status_code=202,
    )
    async def rescue_icloud_workspace_child(
        workspace_id: str, request: ICloudWorkspaceHandoffRequest
    ):
        return await _call_controller(
            controller.rescue_icloud_workspace_child,
            workspace_id,
            request.model_dump(),
        )

    @app.get("/api/accounts")
    async def list_accounts():
        return await _call_controller(controller.list_accounts)

    @app.post("/api/accounts/import", status_code=status.HTTP_201_CREATED)
    async def import_accounts(request: AccountImportRequest):
        return await _call_controller(controller.import_accounts, request.path)

    @app.post("/api/accounts/alias", status_code=status.HTTP_201_CREATED)
    async def create_account_alias(request: AccountAliasRequest):
        return await _call_controller(controller.create_account_alias, request.model_dump())

    @app.get("/api/mailbox-inventory")
    async def search_mailbox_inventory(
        query: str = Query("", max_length=320),
        inventory_status: Literal["available", "disabled", "exhausted"] | None = Query(
            None, alias="status"
        ),
        limit: int = Query(20, ge=1, le=20),
    ):
        return await _call_controller(
            controller.search_mailbox_inventory,
            query=query,
            status=inventory_status,
            limit=limit,
        )

    @app.post(
        "/api/mailbox-inventory/{inventory_id}/allocate",
        status_code=status.HTTP_201_CREATED,
    )
    async def allocate_mailbox_inventory(inventory_id: str):
        return await _call_controller(
            controller.allocate_mailbox_inventory, inventory_id
        )

    @app.post("/api/workspaces/{workspace_id}/replace-account")
    async def replace_workspace_account(
        workspace_id: str, request: WorkspaceReplaceAccountRequest
    ):
        return await _call_controller(
            controller.replace_workspace_account,
            workspace_id,
            request.model_dump(),
        )

    @app.post("/api/workspaces/{workspace_id}/advance")
    async def advance_workspace_accounts(
        workspace_id: str, request: WorkspaceAdvanceRequest
    ):
        return await _call_controller(
            controller.advance_workspace_accounts,
            workspace_id,
            request.model_dump(),
        )

    @app.patch("/api/accounts/{account_id}/status")
    async def update_account_status(account_id: str, request: AccountStatusRequest):
        return await _call_controller(
            controller.update_account_status, account_id, request.status
        )

    @app.put("/api/accounts/{account_id}/proxy")
    async def update_account_proxy(account_id: str, request: AccountProxyRequest):
        return await _call_controller(
            controller.update_account_proxy, account_id, request.proxy
        )

    @app.get("/api/icloud-mailboxes")
    async def list_icloud_mailboxes():
        return await _call_controller(controller.list_icloud_mailboxes)

    @app.get("/api/icloud-team-owners")
    async def list_icloud_team_owners():
        return await _call_controller(controller.list_icloud_team_owners)

    @app.get("/api/proxy-chains/nodes")
    async def list_proxy_chain_nodes():
        return await _call_controller(controller.list_proxy_chain_nodes)

    @app.post("/api/icloud-mailboxes", status_code=status.HTTP_201_CREATED)
    async def create_icloud_mailbox(request: ICloudMailboxCreateRequest):
        return await _call_controller(
            controller.create_icloud_mailbox, request.model_dump()
        )

    @app.patch("/api/icloud-mailboxes/{mailbox_id}")
    async def update_icloud_mailbox(
        mailbox_id: str, request: ICloudMailboxUpdateRequest
    ):
        return await _call_controller(
            controller.update_icloud_mailbox,
            mailbox_id,
            request.model_dump(exclude_unset=True),
        )

    @app.post("/api/icloud-mailboxes/{mailbox_id}/check")
    async def check_icloud_mailbox(mailbox_id: str):
        return await _call_controller(controller.check_icloud_mailbox, mailbox_id)

    @app.post(
        "/api/icloud-mailboxes/{mailbox_id}/hme-capture",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_icloud_hme_capture(mailbox_id: str):
        return await _call_controller(
            controller.start_icloud_hme_capture,
            mailbox_id,
        )

    @app.get("/api/icloud-mailboxes/{mailbox_id}/hme-capture")
    async def get_icloud_hme_capture_status(mailbox_id: str):
        return await _call_controller(
            controller.get_icloud_hme_capture_status,
            mailbox_id,
        )

    @app.post("/api/icloud-mailboxes/{mailbox_id}/hme-capture/cancel")
    async def cancel_icloud_hme_capture(mailbox_id: str):
        return await _call_controller(
            controller.cancel_icloud_hme_capture,
            mailbox_id,
        )

    @app.get("/api/icloud-mailboxes/{mailbox_id}/remote-aliases")
    async def preview_remote_icloud_aliases(mailbox_id: str):
        return await _call_controller(
            controller.preview_remote_icloud_aliases, mailbox_id
        )

    @app.post(
        "/api/icloud-mailboxes/{mailbox_id}/aliases/import",
        status_code=status.HTTP_201_CREATED,
    )
    async def import_existing_icloud_aliases(
        mailbox_id: str, request: ICloudAliasImportRequest
    ):
        return await _call_controller(
            controller.import_existing_icloud_aliases,
            mailbox_id,
            request.model_dump(),
        )

    @app.post("/api/icloud-teams/import", status_code=status.HTTP_201_CREATED)
    async def import_icloud_team(request: ICloudTeamImportRequest):
        return await _call_controller(
            controller.import_icloud_team,
            request.model_dump(),
        )

    @app.post(
        "/api/icloud-mailboxes/{mailbox_id}/aliases",
        status_code=status.HTTP_201_CREATED,
    )
    async def generate_icloud_aliases(
        mailbox_id: str, request: ICloudAliasBatchRequest
    ):
        return await _call_controller(
            controller.generate_icloud_aliases,
            mailbox_id,
            request.model_dump(),
        )

    @app.get("/api/icloud-mailboxes/{mailbox_id}/aliases")
    async def list_icloud_aliases(mailbox_id: str):
        return await _call_controller(controller.list_icloud_aliases, mailbox_id)

    @app.patch("/api/icloud-mailboxes/{mailbox_id}/status")
    async def update_icloud_mailbox_status(
        mailbox_id: str, request: ICloudMailboxStatusRequest
    ):
        return await _call_controller(
            controller.update_icloud_mailbox_status,
            mailbox_id,
            request.status,
        )

    @app.patch("/api/icloud-aliases/{alias_id}/state")
    async def update_icloud_alias_state(
        alias_id: str, request: ICloudAliasStateRequest
    ):
        return await _call_controller(
            controller.update_icloud_alias_state,
            alias_id,
            request.state,
        )

    @app.put("/api/icloud-team-owners/{alias_id}/proxy")
    async def set_icloud_owner_proxy(
        alias_id: str, request: ICloudOwnerProxyRequest
    ):
        return await _call_controller(
            controller.set_icloud_owner_proxy,
            alias_id,
            request.model_dump(),
        )

    @app.get("/api/icloud-team-owners/{alias_id}/proxy/status")
    async def get_icloud_owner_proxy_status(alias_id: str):
        return await _call_controller(
            controller.get_icloud_owner_proxy_status,
            alias_id,
        )

    @app.get("/api/queue")
    async def queue_snapshot():
        return await _call_controller(controller.queue_snapshot)

    @app.post("/api/queue", status_code=202)
    async def enqueue(request: QueueEnqueueRequest):
        return await _call_controller(controller.enqueue, request.workspace_ids)

    @app.patch("/api/queue/order")
    async def reorder_queue(request: QueueOrderRequest):
        return await _call_controller(controller.reorder_queue, request.queue_item_ids)

    @app.post("/api/queue/pause")
    async def pause_queue(request: QueuePauseRequest):
        return await _call_controller(controller.pause_queue, request.paused)

    @app.get("/api/runs")
    async def list_runs(
        workspace_id: str | None = None,
        state: str | None = None,
        limit: int = Query(200, ge=1, le=1000),
    ):
        return await _call_controller(
            controller.list_runs,
            workspace_id=workspace_id,
            state=state,
            limit=limit,
        )

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        return await _call_controller(controller.get_run, run_id)

    @app.post("/api/runs/{run_id}/stop")
    async def stop_run(run_id: str):
        return await _call_controller(controller.stop_run, run_id)

    @app.get("/api/settings")
    async def get_settings():
        return await _call_controller(controller.get_settings)

    @app.get("/api/sub2api/groups")
    async def list_sub2api_groups():
        return await _call_controller(controller.list_sub2api_groups)

    @app.put("/api/settings")
    async def update_settings(request: SettingsUpdateRequest):
        return await _call_controller(controller.update_settings, request.model_dump())

    @app.get("/api/migration/status")
    async def migration_status():
        return await _call_controller(controller.migration_status)

    @app.post("/api/migration/retry-cleanup")
    async def retry_migration_cleanup():
        return await _call_controller(controller.retry_migration_cleanup)

    @app.post("/api/migration/cleanup")
    async def cleanup_migration():
        return await _call_controller(controller.retry_migration_cleanup)

    @app.post("/api/migration/cleanup/retry")
    async def retry_cleanup_migration():
        return await _call_controller(controller.retry_migration_cleanup)

    @app.post("/api/backups", status_code=status.HTTP_201_CREATED)
    async def create_encrypted_backup(request: BackupCreateRequest | None = None):
        return await _call_controller(
            controller.create_encrypted_backup,
            None if request is None else request.path,
        )

    @app.post("/api/backups/restore")
    async def restore_encrypted_backup(request: BackupRestoreRequest):
        return await _call_controller(controller.restore_encrypted_backup, request.path)

    @app.post("/api/dialog")
    async def choose_dialog(request: DialogRequest):
        return await _call_controller(controller.choose_path, request.kind, request.current)

    @app.get("/api/events")
    async def events(request: Request):
        return StreamingResponse(
            _event_stream(controller, request), media_type="text/event-stream"
        )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


async def _call_controller(function, *args, **kwargs):
    try:
        return await asyncio.to_thread(function, *args, **kwargs)
    except FieldInputError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "fields": exc.fields},
        ) from exc
    except NotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except (BindingConflictError, StaleVersionError, StateConflictError, ConflictError) as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except HmeCaptureBusyError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except HmeCaptureError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "file_not_found", "message": "selected file was not found"},
        ) from exc
    except (MigrationError, RestoreValidationError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": getattr(exc, "code", "migration_error"), "message": str(exc)},
        ) from exc
    except (SecretStoreError, DatabaseConfigurationError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": getattr(exc, "code", "storage_unavailable"), "message": str(exc)},
        ) from exc
    except Sub2APIError as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": "sub2api_error", "message": str(exc)},
        ) from exc
    except ProxyChainError as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except DatabaseError as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


async def _event_stream(controller: WebConsoleController, request: Request):
    revision = controller.task_queue.revision
    existing = controller.database.list_run_events(after_seq=0, limit=2000)
    current_seq = int(existing[-1]["seq"]) if existing else 0
    yield _sse("reset", controller.event_reset(), current_seq)
    while True:
        if controller.shutdown_requested() or await request.is_disconnected():
            return
        found = await asyncio.to_thread(
            controller.database.list_run_events,
            after_seq=current_seq,
            limit=2000,
        )
        for event in found:
            current_seq = int(event["seq"])
            yield _sse("message", _safe_payload(event), current_seq)
        next_revision = await asyncio.to_thread(
            controller.task_queue.wait_for_change,
            revision,
            1.0,
        )
        if controller.shutdown_requested():
            return
        if next_revision != revision:
            revision = next_revision
            yield _sse("reset", controller.event_reset(), current_seq)
        elif not found:
            yield ": keepalive\n\n"


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"detail": {"code": code, "message": message}},
        status_code=status_code,
    )


def _sse(event_type: str, payload: Mapping[str, Any], event_id: int) -> str:
    data = json.dumps(_safe_payload(payload), ensure_ascii=False, separators=(",", ":"))
    return f"id: {event_id}\nevent: {event_type}\ndata: {data}\n\n"


def _available_port(preferred: int) -> int:
    preferred = int(preferred)
    # Uvicorn allows up to ten seconds for SSE clients to close during a
    # restart; keep the preferred URL stable across that handoff window.
    deadline = time.monotonic() + 12.0
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", preferred))
            except OSError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
                continue
            return preferred
    for port in range(preferred + 1, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no available loopback port found")


def serve_web_console(
    *,
    port: int = 8765,
    open_browser: bool = True,
    app_dir: str | Path | None = None,
    legacy_config_path: str | Path | None = None,
) -> int:
    resolved_app_dir = (
        Path(app_dir).expanduser().resolve()
        if app_dir is not None
        else default_app_dir().expanduser().resolve()
    )
    instance_lock = _ConsoleInstanceLock(resolved_app_dir)
    try:
        instance_lock.acquire()
    except ConsoleAlreadyRunningError as exc:
        location = exc.url or str(resolved_app_dir)
        print(f"Team Workflow Console already running: {location}")
        if open_browser and exc.url:
            webbrowser.open(exc.url)
        return 0

    try:
        selected_port = _available_port(port)
        internal_legacy_path = (
            Path(legacy_config_path).expanduser().resolve()
            if legacy_config_path is not None
            else (Path.cwd() / "workflow.example.json").resolve()
        )
        controller = WebConsoleController(
            app_dir=resolved_app_dir,
            backup_dir=PROJECT_DIR / "backups",
            legacy_config_path=internal_legacy_path,
            inventory_expected_count=7_211,
            console_port=selected_port,
        )
        app = create_app(controller)
        url = f"http://127.0.0.1:{selected_port}"
        instance_lock.set_owner_url(url)
        if open_browser:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        print(f"Team Workflow Console: {url}")
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=selected_port,
                workers=1,
                log_level="warning",
                access_log=False,
                timeout_graceful_shutdown=10.0,
            )
        )
        controller.set_shutdown_probe(lambda: bool(server.should_exit))
        try:
            server.run()
        except KeyboardInterrupt:
            pass
        return 0
    finally:
        instance_lock.release()


def main() -> int:
    return serve_web_console()


if __name__ == "__main__":
    raise SystemExit(main())
