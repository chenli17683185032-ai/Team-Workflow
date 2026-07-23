from __future__ import annotations

import copy
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .database import Database, StateConflictError
from .openbrowser import (
    parse_openbrowser_profile_ids,
    validate_openbrowser_base_url,
    validate_openbrowser_profile_id,
)
from .registrar import (
    MailboxCredentials,
    bind_proxy_sid,
    generate_proxy_sid,
)
from .sub2api import SUB2API_PUSH_CONCURRENCY, SUB2API_PUSH_LOAD_FACTOR
from .workflow import (
    AccountNetworkSpec,
    AccountSpec,
    CurrentAccountRefreshRunner,
    RescueWorkflowRunner,
    WorkflowCancelled,
    WorkflowConfig,
    WorkflowIdentityError,
    WorkflowRunner,
)
from .workflow_display import (
    HANDOFF_STEP_DEFINITIONS,
    RESCUE_STEP_DEFINITIONS,
    STEP_IDS,
    is_routine_log,
    log_level,
)


_AUTHENTICATED_URL_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^\s/@]+)@"
)
_SENSITIVE_QUERY_VALUE_RE = re.compile(
    r"(?P<prefix>(?:[?&]|&amp;)(?:access_token|code|code_challenge|"
    r"code_verifier|id_token|nonce|refresh_token|session_token|state|token)=)"
    r"(?P<value>[^&#\s\"']+)",
    re.IGNORECASE,
)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})
_REFRESH_IDEMPOTENCY_SECONDS = 60.0
_OPERATION_LOG_LIMIT = 300


def redact_text(value: Any, secrets: tuple[str, ...] | list[str] = ()) -> str:
    clean = str(value)
    for secret in sorted({str(item) for item in secrets if str(item)}, key=len, reverse=True):
        clean = clean.replace(secret, "***")
    clean = _AUTHENTICATED_URL_RE.sub(r"\g<scheme>***@", clean)
    return _SENSITIVE_QUERY_VALUE_RE.sub(r"\g<prefix>***", clean)


def redact_value(value: Any, secrets: tuple[str, ...] | list[str] = ()) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        return {
            str(key): redact_value(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return "<bytes>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value, secrets)


class DatabaseCheckpointStore:
    """Persist one encrypted, complete checkpoint document after every mutation."""

    def __init__(self, database: Database, run_id: str) -> None:
        self.database = database
        self.run_id = str(run_id)
        self._lock = threading.RLock()
        loaded = database.get_run_checkpoint(self.run_id)
        self._values: dict[str, Any] = copy.deepcopy(loaded or {})

    def get(self, name: str) -> Any:
        with self._lock:
            return copy.deepcopy(self._values.get(name))

    def set(self, name: str, value: Any) -> None:
        with self._lock:
            candidate = copy.deepcopy(self._values)
            candidate[str(name)] = copy.deepcopy(value)
            self.database.set_run_checkpoint(
                self.run_id,
                candidate,
                current_step=str(name) if str(name) in STEP_IDS else None,
            )
            self._values = candidate

    def mark_step(self, step: str) -> None:
        if step not in STEP_IDS:
            return
        with self._lock:
            self.database.set_run_checkpoint(
                self.run_id,
                copy.deepcopy(self._values),
                current_step=step,
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._values)


class _MemoryCheckpointStore:
    def __init__(self) -> None:
        self._values: dict[str, Any] = {}

    def get(self, name: str) -> Any:
        return copy.deepcopy(self._values.get(str(name)))

    def set(self, name: str, value: Any) -> None:
        self._values[str(name)] = copy.deepcopy(value)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self._values)


class TaskQueue:
    def __init__(
        self,
        database: Database,
        *,
        runner_factory: Callable[..., Any] = WorkflowRunner,
        rescue_runner_factory: Callable[..., Any] = RescueWorkflowRunner,
        refresh_runner_factory: Callable[..., Any] = CurrentAccountRefreshRunner,
        shutdown_timeout: float = 5.0,
    ) -> None:
        self.database = database
        self.runner_factory = runner_factory
        self.rescue_runner_factory = rescue_runner_factory
        self.refresh_runner_factory = refresh_runner_factory
        self.shutdown_timeout = max(0.0, float(shutdown_timeout))
        self._condition = threading.Condition(threading.RLock())
        self._revision = 0
        self._thread: threading.Thread | None = None
        self._started = False
        self._closing = False
        self._active_run_id: str | None = None
        self._active_stop_event: threading.Event | None = None
        self._run_operation: dict[str, Any] | None = None
        self._active_refresh_account_id: str | None = None
        self._active_refresh_stop_event: threading.Event | None = None
        self._recent_refresh_results: dict[str, tuple[float, dict[str, Any]]] = {}
        self._refresh_operation: dict[str, Any] | None = None
        self._last_worker_error: str | None = None

    @property
    def revision(self) -> int:
        with self._condition:
            return self._revision

    @property
    def active_run_id(self) -> str | None:
        with self._condition:
            return self._active_run_id

    def _bump_locked(self) -> int:
        self._revision += 1
        self._condition.notify_all()
        return self._revision

    @staticmethod
    def _append_operation_log_locked(
        operation: dict[str, Any],
        *,
        step: str | None,
        level: str,
        message: str,
        routine: bool = False,
        created_at: str | None = None,
        seq: int | None = None,
    ) -> None:
        entry = {
            "step": step,
            "level": str(level or "info"),
            "message": str(message),
            "routine": bool(routine),
            "created_at": created_at
            or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if seq is not None:
            entry["seq"] = int(seq)
        logs = operation.setdefault("logs", [])
        logs.append(entry)
        if len(logs) > _OPERATION_LOG_LIMIT:
            del logs[:-_OPERATION_LOG_LIMIT]

    def _record_run_operation_event_locked(
        self, run_id: str, event: Mapping[str, Any]
    ) -> None:
        operation = self._run_operation
        if operation is None or operation.get("run_id") != str(run_id):
            return
        self._append_operation_log_locked(
            operation,
            step=str(event.get("step") or "") or None,
            level=str(event.get("level") or "info"),
            message=str(event.get("message") or ""),
            routine=bool(event.get("routine")),
            created_at=str(event.get("created_at") or "") or None,
            seq=(
                int(event["seq"])
                if event.get("seq") is not None
                else None
            ),
        )

    def notify_change(self) -> int:
        with self._condition:
            return self._bump_locked()

    def wait_for_change(self, after_revision: int, timeout: float | None = None) -> int:
        target = max(0, int(after_revision))
        with self._condition:
            self._condition.wait_for(
                lambda: self._revision > target or self._closing,
                timeout=timeout,
            )
            return self._revision

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            return {
                "paused": self.database.is_queue_paused(),
                "active_run_id": self._active_run_id,
                "run_operation": copy.deepcopy(self._run_operation),
                "active_refresh_account_id": self._active_refresh_account_id,
                "credential_refresh": copy.deepcopy(self._refresh_operation),
                "items": self.database.list_queue(),
                "revision": self._revision,
                "started": self._started,
                "closing": self._closing,
                "last_worker_error": self._last_worker_error,
            }

    def start(self) -> tuple[str, ...]:
        with self._condition:
            if self._started:
                return ()
            recovered = tuple(self.database.recover_interrupted_runs())
            for run_id in recovered:
                self._append_event_locked(
                    run_id,
                    step=None,
                    level="warning",
                    message="interrupted run recovered and requeued",
                )
            self._closing = False
            self._started = True
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="workflow-task-queue",
                daemon=True,
            )
            self._bump_locked()
            self._thread.start()
            return recovered

    def enqueue(self, workspace_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        with self._condition:
            if self._active_refresh_account_id is not None:
                raise StateConflictError("current child credential refresh is active")
            runs = self.database.enqueue_workspaces(workspace_ids)
            for run in runs:
                self._append_event_locked(
                    run["id"], step=None, level="info", message="run queued"
                )
            self._bump_locked()
            return runs

    def enqueue_rescue(self, workspace_id: str) -> dict[str, Any]:
        with self._condition:
            if self._active_refresh_account_id is not None:
                raise StateConflictError("current child credential refresh is active")
            run = self.database.enqueue_rescue_workspace(str(workspace_id))
            self._append_event_locked(
                run["id"],
                step=None,
                level="warning",
                message="emergency rescue queued",
            )
            self._bump_locked()
            return run

    def set_paused(self, paused: bool) -> bool:
        with self._condition:
            result = self.database.set_queue_paused(bool(paused))
            self._bump_locked()
            return result

    def pause(self) -> bool:
        return self.set_paused(True)

    def resume(self) -> bool:
        return self.set_paused(False)

    def reorder(self, queue_item_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        with self._condition:
            queue = self.database.reorder_queue(queue_item_ids)
            self._bump_locked()
            return queue

    def stop(self, run_id: str) -> str:
        run_id = str(run_id)
        with self._condition:
            state = self.database.request_stop(run_id)
            if state == "stopping" and self._active_run_id == run_id:
                if self._active_stop_event is not None:
                    self._active_stop_event.set()
                self._append_event_locked(
                    run_id,
                    step=None,
                    level="warning",
                    message="stop requested",
                )
            elif state == "cancelled":
                self._append_event_locked(
                    run_id,
                    step=None,
                    level="warning",
                    message="queued run cancelled",
                )
            self._bump_locked()
            return state

    def retry(self, run_id: str) -> dict[str, Any]:
        run_id = str(run_id)
        with self._condition:
            run = self.database.retry_run(run_id)
            self._append_event_locked(
                run_id,
                step=None,
                level="info",
                message="failed run queued for retry",
            )
            self._bump_locked()
            return run

    def retry_registered_account(
        self, run_id: str, account_id: str
    ) -> dict[str, Any]:
        run_id = str(run_id)
        with self._condition:
            run = self.database.retry_run(
                run_id,
                registered_account_id=str(account_id),
            )
            self._append_event_locked(
                run_id,
                step="new_login",
                level="info",
                message=(
                    "Sub2API imported account verified; failed run queued for "
                    "existing-account login"
                ),
            )
            self._bump_locked()
            return run

    def refresh_current_account(self, account_id: str) -> dict[str, Any]:
        account_id = str(account_id)
        stop_event = threading.Event()
        secrets: tuple[str, ...] = ()
        with self._condition:
            if self._closing:
                raise StateConflictError("task queue is shutting down")
            if self._active_run_id is not None:
                raise StateConflictError("active workflow blocks credential refresh")
            if self._active_refresh_account_id is not None:
                raise StateConflictError("another current child refresh is active")
            recent = self._recent_refresh_results.get(account_id)
            if (
                recent is not None
                and time.monotonic() - recent[0] < _REFRESH_IDEMPOTENCY_SECONDS
            ):
                self._refresh_operation = {
                    "account_id": account_id,
                    "state": "succeeded",
                    "current_step": None,
                    "reused": True,
                    "stages": {
                        "old_login": "done",
                        "pat": "done",
                        "sub2api_export": "done",
                    },
                    "result": dict(recent[1]),
                    "logs": [],
                }
                self._append_operation_log_locked(
                    self._refresh_operation,
                    step=None,
                    level="info",
                    message="recent credential refresh result reused",
                )
                self._bump_locked()
                return {**recent[1], "reused": True}
            self._active_refresh_account_id = account_id
            self._active_refresh_stop_event = stop_event
            self._refresh_operation = {
                "account_id": account_id,
                "state": "running",
                "current_step": None,
                "reused": False,
                "stages": {
                    "old_login": "pending",
                    "pat": "pending",
                    "sub2api_export": "pending",
                },
                "result": None,
                "error": "",
                "logs": [],
            }
            self._append_operation_log_locked(
                self._refresh_operation,
                step=None,
                level="info",
                message="credential refresh started",
            )
            self._bump_locked()
        try:
            (
                config,
                mailbox,
                proxy,
                network,
                secrets,
            ) = self._build_current_refresh_inputs(account_id)
            active_step: list[str | None] = [None]

            def on_log(message: str) -> None:
                clean = redact_text(message, secrets)
                with self._condition:
                    operation = self._refresh_operation
                    if operation is None or operation.get("account_id") != account_id:
                        return
                    self._append_operation_log_locked(
                        operation,
                        step=active_step[0],
                        level=log_level(clean),
                        message=clean,
                        routine=is_routine_log(clean),
                    )
                    self._bump_locked()

            def on_event(event: Mapping[str, Any]) -> None:
                if event.get("type") != "step":
                    return
                step = str(event.get("step") or "")
                state = str(event.get("state") or "")
                if step not in {"old_login", "pat", "sub2api_export"}:
                    return
                stage_state = {
                    "active": "running",
                    "done": "done",
                    "skipped": "skipped",
                    "error": "failed",
                    "cancelled": "cancelled",
                }.get(state)
                if stage_state is None:
                    return
                if state == "active":
                    active_step[0] = step
                with self._condition:
                    operation = self._refresh_operation
                    if operation is None or operation.get("account_id") != account_id:
                        return
                    operation["stages"][step] = stage_state
                    operation["current_step"] = step if state == "active" else None
                    self._append_operation_log_locked(
                        operation,
                        step=step,
                        level=(
                            "error"
                            if state == "error"
                            else "warning"
                            if state == "cancelled"
                            else "info"
                        ),
                        message=f"stage {state}",
                    )
                    self._bump_locked()
                if state != "active" and active_step[0] == step:
                    active_step[0] = None

            runner = self.refresh_runner_factory(
                config,
                checkpoint_store=_MemoryCheckpointStore(),
                old_mailbox=mailbox,
                new_mailbox=mailbox,
                expanded_proxy=proxy,
                old_network=network,
                new_network=network,
                verbose=False,
                stop_event=stop_event,
                logger=on_log,
                event_callback=on_event,
            )
            result = runner.run()
            if not isinstance(result, Mapping):
                raise RuntimeError("credential refresh result is not an object")
            safe_result = dict(redact_value(result, secrets))
            with self._condition:
                self._recent_refresh_results[account_id] = (
                    time.monotonic(),
                    dict(safe_result),
                )
                if self._refresh_operation is not None:
                    self._append_operation_log_locked(
                        self._refresh_operation,
                        step=None,
                        level="info",
                        message="credential refresh succeeded",
                    )
                    self._refresh_operation.update(
                        {
                            "state": "succeeded",
                            "current_step": None,
                            "result": dict(safe_result),
                            "error": "",
                        }
                    )
                self._bump_locked()
            return safe_result
        except StateConflictError as exc:
            with self._condition:
                if self._refresh_operation is not None:
                    current_step = self._refresh_operation.get("current_step")
                    if current_step:
                        self._refresh_operation["stages"][current_step] = "failed"
                    safe_error = redact_text(exc, secrets)
                    self._append_operation_log_locked(
                        self._refresh_operation,
                        step=str(current_step or "") or None,
                        level="error",
                        message=f"credential refresh failed: {safe_error}",
                    )
                    self._refresh_operation.update(
                        {
                            "state": "failed",
                            "current_step": None,
                            "error": safe_error,
                        }
                    )
                    self._bump_locked()
            raise
        except Exception as exc:
            safe_error = redact_text(exc, secrets)
            with self._condition:
                if self._refresh_operation is not None:
                    current_step = self._refresh_operation.get("current_step")
                    if current_step:
                        self._refresh_operation["stages"][current_step] = "failed"
                    self._append_operation_log_locked(
                        self._refresh_operation,
                        step=str(current_step or "") or None,
                        level="error",
                        message=f"credential refresh failed: {safe_error}",
                    )
                    self._refresh_operation.update(
                        {
                            "state": "failed",
                            "current_step": None,
                            "error": safe_error,
                        }
                    )
                    self._bump_locked()
            raise StateConflictError(
                f"current child credential refresh failed: {safe_error}"
            ) from exc
        finally:
            secrets = ()
            with self._condition:
                self._active_refresh_account_id = None
                self._active_refresh_stop_event = None
                self._bump_locked()

    def shutdown(self, timeout: float | None = None) -> bool:
        wait_timeout = self.shutdown_timeout if timeout is None else max(0.0, float(timeout))
        with self._condition:
            thread = self._thread
            if thread is None:
                self._closing = True
                self._started = False
                self._bump_locked()
                return True
            self._closing = True
            if self._active_run_id is not None:
                try:
                    self.database.request_stop(self._active_run_id)
                except StateConflictError:
                    pass
                if self._active_stop_event is not None:
                    self._active_stop_event.set()
            if self._active_refresh_stop_event is not None:
                self._active_refresh_stop_event.set()
            self._bump_locked()
        thread.join(wait_timeout)
        stopped = not thread.is_alive()
        with self._condition:
            if stopped:
                self._thread = None
                self._started = False
            self._bump_locked()
        return stopped

    def _worker_loop(self) -> None:
        try:
            while True:
                with self._condition:
                    item = None
                    while item is None:
                        if self._closing:
                            return
                        if self._active_refresh_account_id is not None:
                            self._condition.wait()
                            continue
                        try:
                            paused = self.database.is_queue_paused()
                            item = None if paused else self.database.claim_next_queue_item()
                        except Exception as exc:
                            self._last_worker_error = redact_text(exc)
                            self._condition.wait(timeout=0.25)
                            continue
                        if item is None:
                            self._condition.wait()
                    run_id = str(item["run_id"])
                    stop_event = threading.Event()
                    self._active_run_id = run_id
                    self._active_stop_event = stop_event
                    self._last_worker_error = None
                    self._bump_locked()
                self._execute_claimed(run_id, stop_event)
                with self._condition:
                    self._active_run_id = None
                    self._active_stop_event = None
                    self._bump_locked()
        finally:
            with self._condition:
                self._active_run_id = None
                self._active_stop_event = None
                self._started = False
                self._condition.notify_all()

    def _execute_claimed(self, run_id: str, stop_event: threading.Event) -> None:
        secrets: tuple[str, ...] = ()
        try:
            checkpoint = DatabaseCheckpointStore(self.database, run_id)
            run_kind = str(self.database.get_run(run_id).get("kind") or "handoff")
            step_definitions = (
                RESCUE_STEP_DEFINITIONS
                if run_kind == "rescue"
                else HANDOFF_STEP_DEFINITIONS
            )
            checkpoint_snapshot = checkpoint.snapshot()
            with self._condition:
                self._run_operation = {
                    "run_id": run_id,
                    "kind": run_kind,
                    "state": "running",
                    "current_step": None,
                    "stages": {
                        step: "done" if step in checkpoint_snapshot else "pending"
                        for step, _label in step_definitions
                    },
                    "error": "",
                    "manual_login_state": None,
                    "logs": [],
                }
                self._bump_locked()
            (
                config,
                old_mailbox,
                new_mailbox,
                proxy,
                old_network,
                new_network,
                secrets,
            ) = self._build_run_inputs(run_id, rescue=run_kind == "rescue")
            current_step: list[str | None] = [None]

            def on_log(message: str) -> None:
                clean = redact_text(message, secrets)
                self._append_event(
                    run_id,
                    step=current_step[0],
                    level=log_level(clean),
                    message=clean,
                    routine=is_routine_log(clean),
                )

            def on_event(event: Mapping[str, Any]) -> None:
                event_type = str(event.get("type") or "")
                if event_type == "manual_login":
                    manual_state = str(event.get("state") or "")
                    if manual_state not in {
                        "profile_started",
                        "waiting_for_user",
                        "wrong_account",
                        "waiting_for_team",
                        "verified",
                        "profile_stopped",
                    }:
                        return
                    with self._condition:
                        operation = self._run_operation
                        if operation is not None and operation.get("run_id") == run_id:
                            operation["manual_login_state"] = manual_state
                            self._bump_locked()
                    return
                if event_type != "step":
                    return
                step = str(event.get("step") or "")
                state = str(event.get("state") or "")
                if step not in STEP_IDS or state not in {
                    "active",
                    "done",
                    "skipped",
                    "error",
                    "cancelled",
                }:
                    return
                if state == "active":
                    current_step[0] = step
                    checkpoint.mark_step(step)
                elif current_step[0] == step:
                    current_step[0] = None
                level = "error" if state == "error" else "warning" if state == "cancelled" else "info"
                self._append_event(
                    run_id,
                    step=step,
                    level=level,
                    message=f"stage {state}",
                )
                with self._condition:
                    operation = self._run_operation
                    if operation is not None and operation.get("run_id") == run_id:
                        operation["stages"][step] = {
                            "active": "running",
                            "done": "done",
                            "skipped": "skipped",
                            "error": "failed",
                            "cancelled": "cancelled",
                        }[state]
                        operation["current_step"] = (
                            step if state == "active" else None
                        )
                        self._bump_locked()

            self._append_event(run_id, step=None, level="info", message="run started")
            runner_factory = (
                self.rescue_runner_factory
                if run_kind == "rescue"
                else self.runner_factory
            )
            runner = runner_factory(
                config,
                checkpoint_store=checkpoint,
                old_mailbox=old_mailbox,
                new_mailbox=new_mailbox,
                expanded_proxy=proxy,
                old_network=old_network,
                new_network=new_network,
                verbose=False,
                stop_event=stop_event,
                logger=on_log,
                event_callback=on_event,
            )
            result = runner.run()
            if stop_event.is_set() or self.database.get_run(run_id)["state"] == "stopping":
                self.database.mark_run_cancelled(run_id)
                self._append_event(
                    run_id, step=current_step[0], level="warning", message="run cancelled"
                )
            else:
                safe_result = redact_value(result, secrets)
                self.database.complete_run_and_rotate(
                    run_id,
                    safe_result if isinstance(safe_result, Mapping) else None,
                )
                self._append_event(run_id, step=None, level="info", message="run succeeded")
        except WorkflowIdentityError as exc:
            try:
                current_state = self.database.get_run(run_id)["state"]
                if current_state == "stopping" or stop_event.is_set():
                    self.database.mark_run_cancelled(run_id)
                    self._append_event(
                        run_id, step=None, level="warning", message="run cancelled"
                    )
                else:
                    safe_error = redact_text(exc, secrets)
                    if exc.role == "owner":
                        self.database.fail_run(run_id, safe_error)
                    else:
                        self.database.fail_run_and_replace_account(
                            run_id,
                            role=exc.role,
                            failure_code=exc.code,
                            redacted_error=safe_error,
                        )
                    self._append_event(
                        run_id,
                        step=None,
                        level="error",
                        message=f"run failed: {safe_error}",
                    )
            except Exception as terminal_exc:
                try:
                    current_state = self.database.get_run(run_id)["state"]
                    if current_state in {"running", "stopping"}:
                        safe_error = redact_text(exc, secrets)
                        self.database.fail_run(run_id, safe_error)
                        self._append_event(
                            run_id,
                            step=None,
                            level="error",
                            message=f"run failed: {safe_error}",
                        )
                except Exception:
                    pass
                with self._condition:
                    self._last_worker_error = redact_text(terminal_exc, secrets)
        except WorkflowCancelled:
            self.database.mark_run_cancelled(run_id)
            self._append_event(run_id, step=None, level="warning", message="run cancelled")
        except Exception as exc:
            try:
                current_state = self.database.get_run(run_id)["state"]
                if current_state == "stopping" or stop_event.is_set():
                    self.database.mark_run_cancelled(run_id)
                    self._append_event(
                        run_id, step=None, level="warning", message="run cancelled"
                    )
                else:
                    safe_error = redact_text(exc, secrets)
                    self.database.fail_run(run_id, safe_error)
                    self._append_event(
                        run_id,
                        step=None,
                        level="error",
                        message=f"run failed: {safe_error}",
                    )
            except Exception as terminal_exc:
                with self._condition:
                    self._last_worker_error = redact_text(terminal_exc, secrets)
        finally:
            try:
                final_run = self.database.get_run(run_id)
            except Exception:
                final_run = None
            if final_run is not None:
                with self._condition:
                    operation = self._run_operation
                    if operation is not None and operation.get("run_id") == run_id:
                        final_state = str(final_run.get("state") or "failed")
                        current = operation.get("current_step")
                        if current and final_state in {"failed", "cancelled"}:
                            operation["stages"][current] = (
                                "cancelled" if final_state == "cancelled" else "failed"
                            )
                        operation.update(
                            {
                                "state": final_state,
                                "current_step": None,
                                "error": str(final_run.get("redacted_error") or ""),
                            }
                        )
                        self._bump_locked()
            secrets = ()

    def _build_current_refresh_inputs(
        self, account_id: str
    ) -> tuple[
        WorkflowConfig,
        MailboxCredentials,
        str,
        AccountNetworkSpec,
        tuple[str, ...],
    ]:
        account = self.database.get_account(str(account_id))
        if (
            account.get("source") != "icloud_hme"
            or account.get("icloud_role") != "rotating_child"
            or account.get("status") != "bound_current"
        ):
            raise StateConflictError(
                "only the active iCloud child can refresh its credentials"
            )
        workspace = next(
            (
                item
                for item in self.database.list_workspaces()
                if item.get("current_account_id") == account["id"]
            ),
            None,
        )
        if workspace is None or workspace.get("status") in {"queued", "running"}:
            raise StateConflictError(
                "active child is not bound to an idle workspace"
            )
        if str(account.get("icloud_owner_alias_id") or "") != str(
            workspace.get("owner_alias_id") or ""
        ):
            raise StateConflictError("active child no longer matches its Team owner")

        credentials = self.database.get_resolved_account_credentials(account["id"])
        mailbox = self._mailbox(account, credentials)
        account_proxy = self.database.get_account_proxy(account["id"])
        proxy_template = self._secret_setting("proxy")
        source_proxy = (
            str(account_proxy)
            if account_proxy is not None
            else str(proxy_template or "").strip()
        )
        identity = self.database.ensure_account_network_identity(
            account["id"], proxy_sid=generate_proxy_sid()
        )
        try:
            proxy = bind_proxy_sid(
                source_proxy,
                str(identity["proxy_sid"]),
                required=account_proxy is None and bool(source_proxy),
            )
        except ValueError as exc:
            raise StateConflictError("active child proxy configuration is invalid") from exc
        network = AccountNetworkSpec(
            proxy=proxy,
            proxy_sid=str(identity["proxy_sid"]),
            proxy_geo=(
                dict(identity["proxy_geo"])
                if isinstance(identity.get("proxy_geo"), Mapping)
                else None
            ),
            fingerprint_profile=(
                dict(identity["fingerprint_profile"])
                if isinstance(identity.get("fingerprint_profile"), Mapping)
                else None
            ),
            browserforge_fingerprint=(
                dict(identity["browserforge_fingerprint"])
                if isinstance(identity.get("browserforge_fingerprint"), Mapping)
                else None
            ),
            toolchain=(
                dict(identity["toolchain"])
                if isinstance(identity.get("toolchain"), Mapping)
                else None
            ),
            persist_callback=lambda updates: self.database.merge_account_network_identity(
                str(account["id"]), updates
            ),
        )
        config = WorkflowConfig(
            old_account=AccountSpec(
                str(account["email"]),
                str(credentials.get("account_password") or ""),
            ),
            new_account=AccountSpec(
                str(account["email"]),
                str(credentials.get("account_password") or ""),
            ),
            workspace_id=str(workspace["workspace_uid"]),
            proxy=proxy,
            pat_name=self._text_setting("pat_name", str(account["email"])),
            pat_ttl=self._int_setting("pat_ttl", 5_184_000, minimum=60),
            output_dir=Path(
                self._text_setting("output_dir", "output")
            ).expanduser().resolve(),
            management_base_url="",
            management_key="",
            push=False,
            replace=False,
            remote_name="",
            invite_settle_seconds=0.0,
            sub2api_concurrency=self._int_setting(
                "sub2api_concurrency", SUB2API_PUSH_CONCURRENCY, minimum=0
            ),
            sub2api_priority=self._int_setting(
                "sub2api_priority", 1, minimum=0
            ),
            sub2api_load_factor=self._int_setting(
                "sub2api_load_factor", SUB2API_PUSH_LOAD_FACTOR, minimum=1
            ),
            sub2api_all_groups=self._bool_setting(
                "sub2api_all_groups", True
            ),
            sub2api_group_id=self._optional_int_setting(
                "sub2api_group_id", minimum=1
            ),
            new_account_registered=True,
            old_session_token=str(
                credentials.get("browser_session_token") or ""
            ),
            persist_old_session=lambda token: self.database.set_account_browser_session(
                str(account["id"]), token
            ),
            clear_old_session=lambda: self.database.clear_account_browser_session(
                str(account["id"])
            ),
            persist_new_session=lambda token: self.database.set_account_browser_session(
                str(account["id"]), token
            ),
        )
        known_secrets = tuple(
            sorted(
                {
                    str(value)
                    for value in (
                        *credentials.values(),
                        source_proxy,
                        proxy,
                        identity.get("proxy_sid"),
                    )
                    if value and isinstance(value, (str, int, float))
                },
                key=len,
                reverse=True,
            )
        )
        return config, mailbox, proxy, network, known_secrets

    def _build_run_inputs(
        self, run_id: str, *, rescue: bool = False
    ) -> tuple[
        WorkflowConfig,
        MailboxCredentials,
        MailboxCredentials,
        str,
        AccountNetworkSpec,
        AccountNetworkSpec,
        tuple[str, ...],
    ]:
        run = self.database.get_run(run_id)
        if (str(run.get("kind") or "handoff") == "rescue") != bool(rescue):
            raise StateConflictError("run kind no longer matches its executor")
        workspace = self.database.get_workspace(run["workspace_id"])
        if (
            workspace["current_account_id"] != run["current_account_id"]
            or workspace["next_account_id"] != run["next_account_id"]
            or workspace["workspace_uid"] != run["workspace_uid_snapshot"]
        ):
            raise StateConflictError("workspace no longer matches the run snapshot")

        old_account = self.database.get_account(run["current_account_id"])
        new_account = self.database.get_account(run["next_account_id"])
        if (
            old_account["email"].casefold() != run["current_email_snapshot"].casefold()
            or new_account["email"].casefold() != run["next_email_snapshot"].casefold()
        ):
            raise StateConflictError("account identity no longer matches the run snapshot")

        owner_alias_id = str(workspace["owner_alias_id"] or "").strip()
        if rescue and not owner_alias_id:
            raise StateConflictError("rescue run has no iCloud Team owner")
        if owner_alias_id:
            for account in (old_account, new_account):
                if (
                    account.get("icloud_role") != "rotating_child"
                    or str(account.get("icloud_owner_alias_id") or "") != owner_alias_id
                ):
                    raise StateConflictError(
                        "iCloud Team workflow requires two child accounts"
                    )

        new_credentials = self.database.get_resolved_account_credentials(new_account["id"])
        new_mailbox = self._mailbox(new_account, new_credentials)
        if rescue:
            owner_alias = self.database.get_icloud_alias(owner_alias_id)
            old_mailbox, old_credentials = self._icloud_owner_mailbox(owner_alias)
            old_execution_id = owner_alias_id
            old_execution_email = str(owner_alias["email"])
            old_password = ""
        else:
            old_credentials = self.database.get_resolved_account_credentials(
                old_account["id"]
            )
            old_mailbox = self._mailbox(old_account, old_credentials)
            old_execution_id = str(old_account["id"])
            old_execution_email = str(run["current_email_snapshot"])
            old_password = str(old_credentials.get("account_password") or "")

        proxy_template = self._secret_setting("proxy")
        had_run_proxy = bool(run["proxy_configured"])
        proxy = self.database.get_run_proxy(run_id) if run["proxy_configured"] else None
        if proxy is None:
            proxy = str(proxy_template or "").strip()
            self.database.set_run_proxy(run_id, proxy)

        checkpoint = self.database.get_run_checkpoint(run_id) or {}
        proxy_snapshot = self.database.get_run_account_proxy_snapshot(run_id)
        if proxy_snapshot is None:
            if had_run_proxy:
                current_override = None
                next_override = None
            else:
                current_override = (
                    self.database.get_icloud_owner_proxy(owner_alias_id)
                    if rescue
                    else self.database.get_account_proxy(old_account["id"])
                )
                next_override = self.database.get_account_proxy(new_account["id"])

            def proxy_entry(account_proxy: str | None) -> dict[str, str]:
                if account_proxy is not None:
                    return {"proxy": account_proxy, "source": "account"}
                if proxy:
                    return {"proxy": proxy, "source": "global"}
                return {"proxy": "", "source": "direct"}

            proxy_snapshot = {
                "version": 1,
                "current": proxy_entry(current_override),
                "next": proxy_entry(next_override),
            }
            self.database.set_run_account_proxy_snapshot(run_id, proxy_snapshot)

        old_identity = (
            self.database.ensure_icloud_owner_network_identity(
                owner_alias_id,
                proxy_sid=generate_proxy_sid(),
            )
            if rescue
            else self.database.ensure_account_network_identity(
                old_account["id"],
                proxy_sid=generate_proxy_sid(),
            )
        )
        new_identity = self.database.ensure_account_network_identity(
            new_account["id"],
            proxy_sid=generate_proxy_sid(),
        )
        try:
            openbrowser_profile_id = validate_openbrowser_profile_id(
                new_identity.get("openbrowser_profile_id")
            )
            openbrowser_profile_ids = parse_openbrowser_profile_ids(
                self._text_setting("openbrowser_profile_ids", "")
            )
            openbrowser_base_url = validate_openbrowser_base_url(
                self._text_setting(
                    "openbrowser_base_url", "http://127.0.0.1:50325"
                )
            )
        except ValueError as exc:
            raise StateConflictError("OpenBrowser run configuration is invalid") from exc
        if openbrowser_profile_id not in openbrowser_profile_ids:
            raise StateConflictError(
                "bound OpenBrowser profile is outside the configured pool"
            )
        openbrowser_api_key = self._secret_setting("openbrowser_api_key")
        if not openbrowser_api_key:
            raise StateConflictError("OpenBrowser API key is not configured")
        openbrowser_manual_timeout_seconds = self._int_setting(
            "openbrowser_manual_timeout_seconds", 1800, minimum=60
        )
        if openbrowser_manual_timeout_seconds > 86_400:
            raise StateConflictError("OpenBrowser manual login timeout is invalid")
        if old_identity["proxy_sid"] == new_identity["proxy_sid"]:
            raise StateConflictError("old and new accounts share the same proxy SID")
        legacy_profile = checkpoint.get("_fingerprint_profile")
        legacy_geo = checkpoint.get("_proxy_geo")
        legacy_browserforge = checkpoint.get("_browserforge_fingerprint")
        legacy_toolchain = checkpoint.get("_browser_toolchain")

        def uses_legacy_identity(role: str, identity: Mapping[str, Any]) -> bool:
            if isinstance(identity.get("fingerprint_profile"), Mapping):
                return False
            role_steps = (
                {"old_login", "old_workspace", "invite", "old_leave"}
                if role == "old"
                else {"new_login", "new_workspace", "pat"}
            )
            return (
                any(step in checkpoint for step in role_steps)
                and isinstance(legacy_profile, Mapping)
                and isinstance(legacy_geo, Mapping)
            )

        old_legacy = False if rescue else uses_legacy_identity("old", old_identity)
        new_legacy = uses_legacy_identity("new", new_identity)
        legacy_openai_steps = {
            "old_login",
            "old_workspace",
            "new_login",
            "new_workspace",
            "invite",
            "old_leave",
            "pat",
        }

        def account_proxy(
            role: str, identity: Mapping[str, Any], *, legacy_recovery: bool
        ) -> str:
            entry = proxy_snapshot[role]
            source_proxy = str(entry["proxy"])
            try:
                bound = bind_proxy_sid(
                    source_proxy,
                    str(identity["proxy_sid"]),
                    required=entry["source"] == "global" and bool(source_proxy),
                )
            except ValueError:
                if not any(step in checkpoint for step in legacy_openai_steps):
                    raise
                return proxy
            return proxy if legacy_recovery else bound

        old_proxy = account_proxy("current", old_identity, legacy_recovery=old_legacy)
        new_proxy = account_proxy("next", new_identity, legacy_recovery=new_legacy)

        def account_network(
            account_proxy: str,
            identity: Mapping[str, Any],
            *,
            legacy_recovery: bool,
            persist_callback: Callable[[Mapping[str, Any]], Any],
        ) -> AccountNetworkSpec:
            source = dict(identity)
            if legacy_recovery:
                source.update(
                    {
                        "proxy_geo": dict(legacy_geo),
                        "fingerprint_profile": dict(legacy_profile),
                    }
                )
                if isinstance(legacy_browserforge, Mapping):
                    source["browserforge_fingerprint"] = dict(legacy_browserforge)
                if isinstance(legacy_toolchain, Mapping):
                    source["toolchain"] = dict(legacy_toolchain)
            return AccountNetworkSpec(
                proxy=account_proxy,
                proxy_sid=str(source["proxy_sid"]),
                proxy_geo=(
                    dict(source["proxy_geo"])
                    if isinstance(source.get("proxy_geo"), Mapping)
                    else None
                ),
                fingerprint_profile=(
                    dict(source["fingerprint_profile"])
                    if isinstance(source.get("fingerprint_profile"), Mapping)
                    else None
                ),
                browserforge_fingerprint=(
                    dict(source["browserforge_fingerprint"])
                    if isinstance(source.get("browserforge_fingerprint"), Mapping)
                    else None
                ),
                toolchain=(
                    dict(source["toolchain"])
                    if isinstance(source.get("toolchain"), Mapping)
                    else None
                ),
                persist_callback=(
                    None
                    if legacy_recovery
                    else persist_callback
                ),
                legacy_recovery=legacy_recovery,
            )

        if rescue:
            old_persist_callback = (
                lambda updates: self.database.merge_icloud_owner_network_identity(
                    old_execution_id,
                    updates,
                )
            )
        else:
            old_persist_callback = (
                lambda updates: self.database.merge_account_network_identity(
                    old_execution_id,
                    updates,
                )
            )
        old_network = account_network(
            old_proxy,
            old_identity,
            legacy_recovery=old_legacy,
            persist_callback=old_persist_callback,
        )
        new_network = account_network(
            new_proxy,
            new_identity,
            legacy_recovery=new_legacy,
            persist_callback=lambda updates: self.database.merge_account_network_identity(
                new_account["id"],
                updates,
            ),
        )

        management_key = self._secret_setting("management_api_key")
        sub2api_password = self._secret_setting("sub2api_password")
        sub2api_api_key = self._secret_setting("sub2api_api_key")
        sub2api_totp_secret = self._secret_setting("sub2api_totp_secret")
        output_dir = Path(self._text_setting("output_dir", "output")).expanduser().resolve()
        config = WorkflowConfig(
            old_account=AccountSpec(
                old_execution_email,
                old_password,
            ),
            new_account=AccountSpec(
                run["next_email_snapshot"],
                str(new_credentials.get("account_password") or ""),
            ),
            workspace_id=run["workspace_uid_snapshot"],
            proxy=proxy,
            pat_name=self._text_setting("pat_name", run["next_email_snapshot"]),
            pat_ttl=self._int_setting("pat_ttl", 5_184_000, minimum=60),
            output_dir=output_dir,
            management_base_url=self._text_setting(
                "management_base_url", "https://management.example.com"
            ),
            management_key=management_key,
            push=self._bool_setting("management_push", False),
            replace=self._bool_setting("management_replace", False),
            remote_name=self._text_setting("management_remote_name", ""),
            invite_settle_seconds=self._float_setting(
                "invite_settle_seconds", 2.0, minimum=0.0
            ),
            sub2api_base_url=self._text_setting(
                "sub2api_base_url", "https://sub2api.example.com"
            ),
            sub2api_email=self._text_setting("sub2api_email", ""),
            sub2api_password=sub2api_password,
            sub2api_api_key=sub2api_api_key,
            sub2api_totp_secret=sub2api_totp_secret,
            sub2api_push=self._bool_setting("sub2api_push", False),
            sub2api_concurrency=self._int_setting(
                "sub2api_concurrency", SUB2API_PUSH_CONCURRENCY, minimum=0
            ),
            sub2api_priority=self._int_setting("sub2api_priority", 1, minimum=0),
            sub2api_load_factor=self._int_setting(
                "sub2api_load_factor", SUB2API_PUSH_LOAD_FACTOR, minimum=1
            ),
            sub2api_all_groups=self._bool_setting(
                "sub2api_all_groups", True
            ),
            sub2api_group_id=self._optional_int_setting(
                "sub2api_group_id", minimum=1
            ),
            new_account_registered=bool(
                new_credentials.get("registered_account")
            ),
            old_session_token=(
                ""
                if rescue
                else str(old_credentials.get("browser_session_token") or "")
            ),
            persist_old_session=(
                None
                if rescue
                else lambda token: self.database.set_account_browser_session(
                    str(old_account["id"]), token
                )
            ),
            clear_old_session=(
                None
                if rescue
                else lambda: self.database.clear_account_browser_session(
                    str(old_account["id"])
                )
            ),
            persist_new_session=lambda token: self.database.set_account_browser_session(
                str(new_account["id"]), token
            ),
            openbrowser_base_url=openbrowser_base_url,
            openbrowser_api_key=openbrowser_api_key,
            openbrowser_profile_id=openbrowser_profile_id,
            openbrowser_manual_timeout_seconds=openbrowser_manual_timeout_seconds,
        )
        known_secrets = tuple(
            sorted(
                {
                    str(value)
                    for value in (
                        *old_credentials.values(),
                        *new_credentials.values(),
                        proxy_template,
                        proxy,
                        proxy_snapshot["current"]["proxy"],
                        proxy_snapshot["next"]["proxy"],
                        old_proxy,
                        new_proxy,
                        old_identity.get("proxy_sid"),
                        new_identity.get("proxy_sid"),
                        management_key,
                        sub2api_password,
                        sub2api_api_key,
                        sub2api_totp_secret,
                        openbrowser_api_key,
                    )
                    if value
                },
                key=len,
                reverse=True,
            )
        )
        return (
            config,
            old_mailbox,
            new_mailbox,
            proxy,
            old_network,
            new_network,
            known_secrets,
        )

    def _icloud_owner_mailbox(
        self,
        owner_alias: Mapping[str, Any],
    ) -> tuple[MailboxCredentials, dict[str, Any]]:
        if owner_alias.get("role") != "team_owner":
            raise StateConflictError("rescue identity is not an iCloud Team owner")
        mailbox_id = str(owner_alias.get("mailbox_id") or "").strip()
        if not mailbox_id:
            raise StateConflictError("iCloud Team owner mailbox is missing")
        mailbox = self.database.get_icloud_mailbox(mailbox_id)
        if mailbox["status"] != "ready":
            raise StateConflictError("iCloud Team owner mailbox is not ready")
        secret = self.database.get_icloud_mailbox_secrets(mailbox_id)
        imap = secret.get("imap")
        if not isinstance(imap, Mapping):
            raise StateConflictError("iCloud Team owner IMAP configuration is missing")
        credentials = {
            "provider": "icloud_hme_imap",
            "forwarding_email": str(mailbox["forwarding_email"]),
            "imap_host": str(imap.get("host") or ""),
            "imap_port": int(imap.get("port") or 993),
            "imap_username": str(imap.get("username") or ""),
            "imap_password": str(imap.get("password") or ""),
            "imap_folder": str(imap.get("folder") or "INBOX"),
            "mailbox_proxy": str(secret.get("proxy") or ""),
            "account_password": "",
        }
        account = {
            "email": str(owner_alias["email"]),
            "primary_email": str(mailbox["forwarding_email"]),
        }
        return self._mailbox(account, credentials), credentials

    @staticmethod
    def _mailbox(
        account: Mapping[str, Any], credentials: Mapping[str, Any]
    ) -> MailboxCredentials:
        provider = str(credentials.get("provider") or "appleemail_hotmail").strip()
        if provider == "icloud_hme_imap":
            required = {
                "forwarding_email": str(credentials.get("forwarding_email") or "").strip(),
                "imap_host": str(credentials.get("imap_host") or "").strip(),
                "imap_username": str(credentials.get("imap_username") or "").strip(),
                "imap_password": str(credentials.get("imap_password") or ""),
            }
            if any(not value for value in required.values()):
                raise StateConflictError("iCloud forwarding mailbox credentials are incomplete")
            return MailboxCredentials(
                primary_email=str(account["primary_email"]),
                registration_email=str(account["email"]),
                client_id="",
                refresh_token="",
                provider=provider,
                forwarding_email=required["forwarding_email"],
                imap_host=required["imap_host"],
                imap_port=int(credentials.get("imap_port") or 993),
                imap_username=required["imap_username"],
                imap_password=required["imap_password"],
                imap_folder=str(credentials.get("imap_folder") or "INBOX"),
                mailbox_proxy=str(credentials.get("mailbox_proxy") or ""),
            )
        client_id = str(credentials.get("client_id") or "").strip()
        refresh_token = str(credentials.get("refresh_token") or "").strip()
        if not client_id or not refresh_token:
            raise StateConflictError("account mailbox credentials are incomplete")
        return MailboxCredentials(
            primary_email=str(account["primary_email"]),
            registration_email=str(account["email"]),
            client_id=client_id,
            refresh_token=refresh_token,
            password=str(credentials.get("mailbox_password") or ""),
        )

    def _text_setting(self, key: str, default: str) -> str:
        value = self.database.get_text_setting(key, default)
        return default if value is None else str(value)

    def _secret_setting(self, key: str) -> str:
        value = self.database.get_secret_setting(key)
        return "" if value is None else value.decode("utf-8")

    def _bool_setting(self, key: str, default: bool) -> bool:
        value = self._text_setting(key, "1" if default else "0").strip().casefold()
        if value in _TRUE_VALUES:
            return True
        if value in _FALSE_VALUES:
            return False
        raise StateConflictError(f"setting {key} is not a boolean")

    def _int_setting(self, key: str, default: int, *, minimum: int) -> int:
        try:
            value = int(self._text_setting(key, str(default)))
        except ValueError as exc:
            raise StateConflictError(f"setting {key} is not an integer") from exc
        return max(minimum, value)

    def _optional_int_setting(self, key: str, *, minimum: int) -> int | None:
        raw = self._text_setting(key, "").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError as exc:
            raise StateConflictError(f"setting {key} is not an integer") from exc
        if value < minimum:
            raise StateConflictError(f"setting {key} must be at least {minimum}")
        return value

    def _float_setting(self, key: str, default: float, *, minimum: float) -> float:
        try:
            value = float(self._text_setting(key, str(default)))
        except ValueError as exc:
            raise StateConflictError(f"setting {key} is not a number") from exc
        return max(minimum, value)

    def _append_event(
        self,
        run_id: str,
        *,
        step: str | None,
        level: str,
        message: str,
        routine: bool = False,
    ) -> dict[str, Any]:
        event = self.database.append_run_event(
            run_id,
            step=step,
            level=level,
            message=message,
            routine=routine,
        )
        with self._condition:
            self._record_run_operation_event_locked(run_id, event)
            self._bump_locked()
        return event

    def _append_event_locked(
        self,
        run_id: str,
        *,
        step: str | None,
        level: str,
        message: str,
        routine: bool = False,
    ) -> dict[str, Any]:
        event = self.database.append_run_event(
            run_id,
            step=step,
            level=level,
            message=message,
            routine=routine,
        )
        self._record_run_operation_event_locked(run_id, event)
        self._bump_locked()
        return event
