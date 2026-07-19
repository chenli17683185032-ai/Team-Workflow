from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .chatgpt import AuthContext, ChatGPTApiError, ChatGPTClient
from .cpa import build_cpa, build_cpa_filename
from .management import ManagementClient
from .registrar import (
    MailboxCredentials,
    RegistrarAdapter,
    RegistrarIdentityError,
    RegistrarProxyLease,
    proxy_region_code,
)
from .sub2api import (
    Sub2APIClient,
    build_sub2api_export,
    build_sub2api_filename,
)


_FINGERPRINT_STATE_STEP = "_fingerprint_profile"
_BROWSERFORGE_STATE_STEP = "_browserforge_fingerprint"
_BROWSER_TOOLCHAIN_STATE_STEP = "_browser_toolchain"
_PROXY_GEO_STATE_STEP = "_proxy_geo"
_REGISTRAR_PROVIDER_STATE_STEP = "_registrar_provider_state"
_TEAM_MEMBER_LIMIT = 2
_MEMBER_FEEDBACK_TIMEOUT_SECONDS = 15.0
_MEMBER_FEEDBACK_POLL_SECONDS = 0.5
_RESCUE_MAX_MEMBER_REMOVALS = 100
_FINGERPRINT_BOUND_STEPS = (
    "old_login",
    "old_workspace",
    "invite",
    "old_leave",
    "new_login",
    "new_workspace",
    "member_verify",
    "pat",
)
_MAX_CLOCK_SKEW_SECONDS = 60.0


@dataclass(frozen=True)
class AccountSpec:
    email: str
    password: str = ""


@dataclass(frozen=True)
class AccountNetworkSpec:
    proxy: str
    proxy_sid: str
    proxy_geo: Mapping[str, Any] | None = None
    fingerprint_profile: Mapping[str, Any] | None = None
    browserforge_fingerprint: Mapping[str, Any] | None = None
    toolchain: Mapping[str, Any] | None = None
    persist_callback: Callable[[Mapping[str, Any]], Any] | None = None
    legacy_recovery: bool = False


@dataclass
class _AccountNetworkRuntime:
    proxy: str | None
    description: str
    proxy_geo: dict[str, Any] | None
    fingerprint_profile: Any
    fingerprint_restored: bool
    browserforge_fingerprint: Any = None


@dataclass(frozen=True)
class WorkflowConfig:
    old_account: AccountSpec
    new_account: AccountSpec
    workspace_id: str
    proxy: str
    pat_name: str
    pat_ttl: int
    output_dir: Path
    management_base_url: str
    management_key: str
    push: bool
    replace: bool
    remote_name: str
    invite_settle_seconds: float
    sub2api_base_url: str = "https://sub2api.example.com"
    sub2api_email: str = ""
    sub2api_password: str = ""
    sub2api_api_key: str = ""
    sub2api_totp_secret: str = ""
    sub2api_push: bool = False
    sub2api_concurrency: int = 10
    sub2api_priority: int = 1
    sub2api_group_id: int | None = None


class CheckpointStore(Protocol):
    def get(self, name: str) -> Any: ...

    def set(self, name: str, value: Any) -> None: ...


class WorkflowCancelled(RuntimeError):
    pass


class WorkflowIdentityError(RuntimeError):
    ALLOWED_CODES = frozenset({"alias_disabled", "mailbox_credentials_invalid"})
    ALLOWED_ROLES = frozenset({"current", "next", "owner"})

    def __init__(self, code: str, role: str) -> None:
        normalized_code = str(code or "").strip()
        normalized_role = str(role or "").strip()
        if normalized_code not in self.ALLOWED_CODES:
            raise ValueError("unsupported workflow identity error code")
        if normalized_role not in self.ALLOWED_ROLES:
            raise ValueError("unsupported workflow identity role")
        self.code = normalized_code
        self.role = normalized_role
        super().__init__(f"{normalized_code}:{normalized_role}")


class _WorkspaceSwitchError(RuntimeError):
    pass


def _email_from_item(item: Mapping[str, Any]) -> str:
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    return str(
        item.get("email")
        or item.get("email_address")
        or item.get("user_email")
        or user.get("email")
        or ""
    ).strip().casefold()


def _user_id_from_item(item: Mapping[str, Any]) -> str:
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    return str(item.get("id") or item.get("user_id") or user.get("id") or "").strip()


def _items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("items", "users", "members", "account_invites", "invites"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _counted_items(payload: Mapping[str, Any]) -> tuple[list[dict[str, Any]], int]:
    items = _items(payload)
    raw_total = payload.get("total")
    if isinstance(raw_total, bool):
        return items, len(items)
    try:
        reported_total = int(raw_total)
    except (TypeError, ValueError):
        reported_total = len(items)
    return items, max(len(items), max(0, reported_total))


def _identity_present(
    items: list[dict[str, Any]], *, user_id: str, email: str
) -> bool:
    normalized_id = str(user_id or "").strip()
    normalized_email = str(email or "").strip().casefold()
    for item in items:
        item_id = _user_id_from_item(item)
        if normalized_id and item_id == normalized_id:
            return True
        if normalized_email and _email_from_item(item) == normalized_email:
            return True
    return False


def _active_invites(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    terminal_states = frozenset(
        {"accepted", "cancelled", "canceled", "deleted", "expired", "revoked"}
    )
    return [
        item
        for item in _items(payload)
        if str(item.get("status") or item.get("state") or "").strip().casefold()
        not in terminal_states
    ]


class WorkflowRunner:
    def __init__(
        self,
        config: WorkflowConfig,
        *,
        checkpoint_store: CheckpointStore,
        old_mailbox: MailboxCredentials,
        new_mailbox: MailboxCredentials,
        expanded_proxy: str | None = None,
        old_network: AccountNetworkSpec | None = None,
        new_network: AccountNetworkSpec | None = None,
        registrar: Any = None,
        chatgpt: Any = None,
        management: Any = None,
        sub2api: Any = None,
        verbose: bool = True,
        stop_event: threading.Event | None = None,
        logger: Callable[[str], None] | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.config = config
        self.state = checkpoint_store
        if not callable(getattr(self.state, "get", None)) or not callable(
            getattr(self.state, "set", None)
        ):
            raise TypeError("checkpoint_store must provide get(name) and set(name, value)")
        self._mailboxes = {
            "old_login": old_mailbox,
            "new_login": new_mailbox,
        }
        self.registrar = registrar or RegistrarAdapter(config.output_dir / ".registrar")
        if (old_network is None) != (new_network is None):
            raise ValueError("old_network and new_network must be supplied together")
        self._account_network_mode = old_network is not None
        self._proxy_leases: list[RegistrarProxyLease] = []
        self._networks: dict[str, _AccountNetworkRuntime] = {}
        self._chatgpt_clients: dict[str, Any] = {}
        self._owned_chatgpt_clients: list[Any] = []
        try:
            if self._account_network_mode:
                assert old_network is not None and new_network is not None
                account_specs = {"old": old_network, "new": new_network}
                account_leases: dict[str, RegistrarProxyLease] = {}
                for role, network in (("old", old_network), ("new", new_network)):
                    lease = RegistrarProxyLease(
                        explicit_proxy=network.proxy,
                        preexpanded=True,
                    )
                    lease.__enter__()
                    self._proxy_leases.append(lease)
                    account_leases[role] = lease
                geo_resolver = getattr(self.registrar, "resolve_proxy_geo", None)
                current_geos: dict[str, Any] = {}
                if callable(geo_resolver):
                    with ThreadPoolExecutor(
                        max_workers=2,
                        thread_name_prefix="account-proxy-geo",
                    ) as executor:
                        futures = {
                            role: executor.submit(geo_resolver, lease.proxy)
                            for role, lease in account_leases.items()
                        }
                        current_geos = {
                            role: future.result()
                            for role, future in futures.items()
                        }
                for role in ("old", "new"):
                    self._networks[role] = self._resolve_account_network(
                        role,
                        account_specs[role],
                        account_leases[role],
                        current_geo=current_geos.get(role),
                    )
            else:
                lease = RegistrarProxyLease(
                    explicit_proxy=config.proxy if expanded_proxy is None else expanded_proxy,
                    preexpanded=expanded_proxy is not None,
                )
                lease.__enter__()
                self._proxy_leases.append(lease)
                legacy = self._resolve_legacy_network(lease)
                self._networks = {"old": legacy, "new": legacy}

            if chatgpt is not None:
                self._chatgpt_clients = {"old": chatgpt, "new": chatgpt}
            elif self._account_network_mode:
                for role in ("old", "new"):
                    runtime = self._networks[role]
                    kwargs: dict[str, Any] = {"proxy": runtime.proxy}
                    if runtime.fingerprint_profile is not None:
                        kwargs["session_profile"] = runtime.fingerprint_profile
                    client = ChatGPTClient(**kwargs)
                    self._chatgpt_clients[role] = client
                    self._owned_chatgpt_clients.append(client)
            else:
                runtime = self._networks["old"]
                kwargs = {"proxy": runtime.proxy}
                if runtime.fingerprint_profile is not None:
                    kwargs["session_profile"] = runtime.fingerprint_profile
                client = ChatGPTClient(**kwargs)
                self._chatgpt_clients = {"old": client, "new": client}
                self._owned_chatgpt_clients.append(client)
        except Exception:
            for client in self._owned_chatgpt_clients:
                try:
                    client.close()
                except Exception:
                    pass
            for lease in self._proxy_leases:
                lease.close()
            raise
        self._proxy_lease = self._proxy_leases[0]
        self.effective_proxy = self._networks["old"].proxy
        self.fingerprint_profile = self._networks["old"].fingerprint_profile
        self.fingerprint_restored = self._networks["old"].fingerprint_restored
        self.proxy_geo = self._networks["old"].proxy_geo
        self.chatgpt = self._chatgpt_clients["old"]
        self.management = management
        self.sub2api = sub2api
        self.verbose = verbose
        self.stop_event = stop_event
        self.logger = logger
        self.event_callback = event_callback
        self._owns_chatgpt = bool(self._owned_chatgpt_clients)

    def close(self) -> None:
        seen: set[int] = set()
        for client in self._owned_chatgpt_clients:
            marker = id(client)
            if marker in seen:
                continue
            seen.add(marker)
            try:
                client.close()
            except Exception:
                pass
        for lease in self._proxy_leases:
            try:
                lease.close()
            except Exception:
                pass

    def _resolve_browserforge_assets(
        self,
        profile: Any,
        *,
        stored_fingerprint: Mapping[str, Any] | None,
        stored_toolchain: Mapping[str, Any] | None,
        has_openai_checkpoint: bool,
        legacy_recovery: bool = False,
    ) -> tuple[Any, dict[str, Any] | None, dict[str, Any] | None]:
        resolver = getattr(self.registrar, "resolve_browserforge_fingerprint", None)
        serializer = getattr(self.registrar, "serialize_browserforge_fingerprint", None)
        toolchain_resolver = getattr(self.registrar, "browser_toolchain_metadata", None)
        if not callable(resolver):
            return None, None, None
        if not callable(serializer) or not callable(toolchain_resolver):
            raise RuntimeError("registrar BrowserForge integration is incomplete")
        if stored_fingerprint is None and has_openai_checkpoint and not legacy_recovery:
            raise RuntimeError(
                "checkpoint contains OpenAI steps but no BrowserForge fingerprint"
            )
        if stored_fingerprint is None and legacy_recovery:
            return None, None, None
        current_toolchain = dict(toolchain_resolver(profile))
        if stored_toolchain is not None and dict(stored_toolchain) != current_toolchain:
            raise RuntimeError("account browser toolchain no longer matches the locked identity")
        fingerprint = resolver(profile, stored_fingerprint)
        serialized = serializer(fingerprint)
        if stored_fingerprint is not None and dict(stored_fingerprint) != serialized:
            raise RuntimeError("stored BrowserForge fingerprint changed during restoration")
        return fingerprint, serialized, current_toolchain

    @staticmethod
    def _account_bound_steps(role: str) -> tuple[str, ...]:
        if role == "old":
            return (
                "old_login",
                "old_workspace",
                "invite",
                "old_leave",
                "owner_login",
                "owner_workspace",
                "rescue_clear",
                "rescue_invite",
            )
        return (
            "new_login",
            "new_workspace_login",
            "new_workspace",
            "member_verify",
            "rescue_verify",
            "pat",
        )

    def _resolve_account_network(
        self,
        role: str,
        spec: AccountNetworkSpec,
        lease: RegistrarProxyLease,
        *,
        current_geo: Mapping[str, Any] | None = None,
    ) -> _AccountNetworkRuntime:
        profile_resolver = getattr(self.registrar, "resolve_session_profile", None)
        profile_serializer = getattr(self.registrar, "serialize_session_profile", None)
        if not callable(profile_resolver) or not callable(profile_serializer):
            raise RuntimeError("registrar fingerprint integration is incomplete")
        stored_profile = spec.fingerprint_profile
        stored_geo = spec.proxy_geo
        stored_browserforge = spec.browserforge_fingerprint
        stored_toolchain = spec.toolchain
        for name, value in (
            ("fingerprint profile", stored_profile),
            ("proxy geo", stored_geo),
            ("BrowserForge fingerprint", stored_browserforge),
            ("browser toolchain", stored_toolchain),
        ):
            if value is not None and not isinstance(value, Mapping):
                raise RuntimeError(f"stored account {name} is not a JSON object")
        has_openai_checkpoint = any(
            self.state.get(step) is not None
            for step in self._account_bound_steps(role)
        )
        if stored_profile is None and has_openai_checkpoint:
            raise RuntimeError(
                f"checkpoint contains {role} OpenAI steps but no account fingerprint"
            )
        if stored_profile is not None and stored_geo is None:
            raise RuntimeError("stored account fingerprint has no proxy geo identity")

        geo_resolver = getattr(self.registrar, "resolve_proxy_geo", None)
        if not callable(geo_resolver):
            raise RuntimeError("registrar proxy geo integration is incomplete")
        resolved_geo = current_geo if current_geo is not None else geo_resolver(lease.proxy)
        if not isinstance(resolved_geo, Mapping):
            raise RuntimeError("proxy geo resolver did not return an object")
        current_geo = dict(resolved_geo)
        if not current_geo.get("resolved"):
            raise RuntimeError("proxy geolocation could not be resolved in strict identity mode")
        if current_geo.get("timezone_exact") is False:
            raise RuntimeError("proxy geolocation did not provide an exact timezone")
        if str(current_geo.get("source") or "").strip() == "ipwho.is":
            if current_geo.get("clock_checked") is not True:
                raise RuntimeError("proxy geolocation could not verify the local UTC clock")
            try:
                clock_skew_seconds = float(current_geo["clock_skew_seconds"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "proxy geolocation returned an invalid UTC clock measurement"
                ) from exc
            if abs(clock_skew_seconds) > _MAX_CLOCK_SKEW_SECONDS:
                raise RuntimeError(
                    "local UTC clock differs from the proxy time source by more than "
                    f"{int(_MAX_CLOCK_SKEW_SECONDS)} seconds"
                )
        geo = dict(stored_geo) if isinstance(stored_geo, Mapping) else current_geo
        configured_region = proxy_region_code(lease.proxy or "")
        resolved_country = str(current_geo.get("country_code") or "").strip().upper()
        if configured_region and configured_region != resolved_country:
            raise RuntimeError(
                f"proxy region {configured_region} does not match resolved country {resolved_country or '<empty>'}"
            )

        restored = isinstance(stored_profile, Mapping)
        profile = profile_resolver(stored_profile, geo_hint=geo)
        serialized_profile = profile_serializer(profile)
        if stored_profile is not None and dict(stored_profile) != serialized_profile:
            raise RuntimeError("stored account fingerprint changed during restoration")
        browserforge, serialized_browserforge, toolchain = (
            self._resolve_browserforge_assets(
                profile,
                stored_fingerprint=stored_browserforge,
                stored_toolchain=stored_toolchain,
                has_openai_checkpoint=has_openai_checkpoint,
                legacy_recovery=spec.legacy_recovery,
            )
        )
        updates: dict[str, Any] = {
            "proxy_geo": geo,
            "fingerprint_profile": serialized_profile,
        }
        if serialized_browserforge is not None:
            updates["browserforge_fingerprint"] = serialized_browserforge
        if toolchain is not None:
            updates["toolchain"] = toolchain
        if spec.persist_callback is not None:
            spec.persist_callback(updates)
        return _AccountNetworkRuntime(
            proxy=lease.proxy,
            description=lease.description,
            proxy_geo=geo,
            fingerprint_profile=profile,
            fingerprint_restored=restored,
            browserforge_fingerprint=browserforge,
        )

    def _resolve_legacy_network(
        self,
        lease: RegistrarProxyLease,
    ) -> _AccountNetworkRuntime:
        profile_resolver = getattr(self.registrar, "resolve_session_profile", None)
        profile_serializer = getattr(self.registrar, "serialize_session_profile", None)
        if not callable(profile_resolver) or not callable(profile_serializer):
            return _AccountNetworkRuntime(
                proxy=lease.proxy,
                description=lease.description,
                proxy_geo=None,
                fingerprint_profile=None,
                fingerprint_restored=False,
            )
        stored_profile = self.state.get(_FINGERPRINT_STATE_STEP)
        if stored_profile is not None and not isinstance(stored_profile, Mapping):
            raise RuntimeError("stored fingerprint profile is not a JSON object")
        has_openai_checkpoint = any(
            self.state.get(step) is not None for step in _FINGERPRINT_BOUND_STEPS
        )
        if stored_profile is None and has_openai_checkpoint:
            raise RuntimeError("checkpoint contains OpenAI steps but no fingerprint profile")
        stored_geo = self.state.get(_PROXY_GEO_STATE_STEP)
        if stored_geo is not None and not isinstance(stored_geo, Mapping):
            raise RuntimeError("stored proxy geo hint is not a JSON object")
        if stored_profile is None and stored_geo is None:
            geo_resolver = getattr(self.registrar, "resolve_proxy_geo", None)
            if callable(geo_resolver):
                resolved_geo = geo_resolver(lease.proxy)
                if not isinstance(resolved_geo, Mapping):
                    raise RuntimeError("proxy geo resolver did not return an object")
                stored_geo = dict(resolved_geo)
                self.state.set(_PROXY_GEO_STATE_STEP, stored_geo)
        geo = dict(stored_geo) if isinstance(stored_geo, Mapping) else None
        restored = isinstance(stored_profile, Mapping)
        profile = profile_resolver(stored_profile, geo_hint=geo)
        serialized_profile = profile_serializer(profile)
        if stored_profile != serialized_profile:
            self.state.set(_FINGERPRINT_STATE_STEP, serialized_profile)

        stored_browserforge = self.state.get(_BROWSERFORGE_STATE_STEP)
        if stored_browserforge is not None and not isinstance(stored_browserforge, Mapping):
            raise RuntimeError("stored BrowserForge fingerprint is not a JSON object")
        stored_toolchain = self.state.get(_BROWSER_TOOLCHAIN_STATE_STEP)
        if stored_toolchain is not None and not isinstance(stored_toolchain, Mapping):
            raise RuntimeError("stored browser toolchain is not a JSON object")
        browserforge, serialized_browserforge, toolchain = (
            self._resolve_browserforge_assets(
                profile,
                stored_fingerprint=stored_browserforge,
                stored_toolchain=stored_toolchain,
                has_openai_checkpoint=has_openai_checkpoint,
            )
        )
        if serialized_browserforge is not None and stored_browserforge != serialized_browserforge:
            self.state.set(_BROWSERFORGE_STATE_STEP, serialized_browserforge)
        if toolchain is not None and stored_toolchain != toolchain:
            self.state.set(_BROWSER_TOOLCHAIN_STATE_STEP, toolchain)
        return _AccountNetworkRuntime(
            proxy=lease.proxy,
            description=lease.description,
            proxy_geo=geo,
            fingerprint_profile=profile,
            fingerprint_restored=restored,
            browserforge_fingerprint=browserforge,
        )

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(message)
        if self.verbose:
            print(message)

    def _emit_event(self, event: dict[str, Any]) -> None:
        if self.event_callback is None:
            return
        try:
            self.event_callback(event)
        except Exception:
            pass

    def _run_stage(self, step: str, operation: Callable[[], Any]) -> Any:
        self._emit_event({"type": "step", "step": step, "state": "active"})
        try:
            result = operation()
        except WorkflowCancelled:
            self._emit_event({"type": "step", "step": step, "state": "cancelled"})
            raise
        except Exception:
            self._emit_event({"type": "step", "step": step, "state": "error"})
            raise
        self._emit_event(
            {
                "type": "step",
                "step": step,
                "state": "skipped" if result is None else "done",
            }
        )
        return result

    def _check_cancel(self) -> None:
        if self.stop_event is not None and self.stop_event.is_set():
            raise WorkflowCancelled("workflow cancelled")

    def _registrar_event(self, event: dict[str, Any]) -> None:
        level = str(event.get("level") or "info").upper()
        step = str(event.get("step") or "").strip()
        message = str(event.get("message") or "").strip()
        step_text = f"[{step}] " if step else ""
        self._log(f"[{level}] {step_text}{message}")

    @staticmethod
    def _validate_login_session(
        spec: AccountSpec, session: Mapping[str, Any]
    ) -> None:
        context = AuthContext.from_mapping(session)
        if not context.session_token:
            raise RuntimeError("login result has no session_token")
        if context.email and context.email.casefold() != spec.email.casefold():
            raise RuntimeError(
                f"login returned {context.email}, expected {spec.email}"
            )

    def _login(
        self,
        spec: AccountSpec,
        step: str,
        *,
        select_workspace: bool = True,
    ) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get(step)
        if isinstance(cached, dict):
            self._validate_login_session(spec, cached)
            self._log(f"[resume] {step}")
            return cached
        role = "old" if step in {"old_login", "owner_login"} else "new"
        mailbox = self._mailboxes.get(f"{role}_login")
        network = self._networks[role]
        action = "register" if step == "new_login" else "login"
        self._log(f"[{action}] {spec.email}")
        login_kwargs: dict[str, Any] = {
            "email": spec.email,
            "account_password": spec.password,
            "mailbox": mailbox,
            "proxy": network.proxy,
            "workspace_id": self.config.workspace_id if select_workspace else None,
            "verbose": self.verbose and self.logger is None,
            "stop_event": self.stop_event,
            "event_callback": self._registrar_event if self.logger is not None else None,
        }
        if network.fingerprint_profile is not None:
            login_kwargs["session_profile"] = network.fingerprint_profile
        provider_state = self.state.get(_REGISTRAR_PROVIDER_STATE_STEP)
        if provider_state is not None and not isinstance(provider_state, Mapping):
            raise RuntimeError("stored registrar provider state is not a JSON object")
        login_kwargs["provider_initial_state"] = dict(provider_state or {})
        login_kwargs["provider_state_callback"] = self._checkpoint_provider_state
        try:
            operation = (
                getattr(self.registrar, "register", None)
                if step == "new_login"
                and mailbox is not None
                and mailbox.provider == "icloud_hme_imap"
                else None
            )
            if not callable(operation):
                operation = self.registrar.login
            session = operation(**login_kwargs)
        except RegistrarIdentityError as exc:
            self._check_cancel()
            role = (
                "owner"
                if step == "owner_login"
                else "current"
                if step == "old_login"
                else "next"
            )
            raise WorkflowIdentityError(exc.code, role) from exc
        except Exception:
            self._check_cancel()
            raise
        self._check_cancel()
        if not isinstance(session, Mapping):
            raise RuntimeError("login result is not an object")
        self._validate_login_session(spec, session)
        self.state.set(step, session)
        return session

    def _checkpoint_provider_state(self, provider_state: dict[str, Any]) -> None:
        if not isinstance(provider_state, dict):
            raise TypeError("registrar provider state callback must provide an object")
        self.state.set(_REGISTRAR_PROVIDER_STATE_STEP, provider_state)

    def _switch_workspace(self, source: Mapping[str, Any], step: str) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get(step)
        if isinstance(cached, dict):
            self._log(f"[resume] {step}")
            return cached
        context = AuthContext.from_mapping(source)
        if not context.session_token:
            raise RuntimeError("login result has no session_token")
        self._log(f"[workspace] {self.config.workspace_id}")
        role = "old" if step in {"old_workspace", "owner_workspace"} else "new"
        session = self._chatgpt_clients[role].refresh_session(
            context.session_token,
            account_id=self.config.workspace_id,
        )
        self._check_cancel()
        switched = AuthContext.from_mapping(session)
        if switched.account_id != self.config.workspace_id:
            raise _WorkspaceSwitchError(
                f"workspace switch returned {switched.account_id or '<empty>'}, expected {self.config.workspace_id}"
            )
        self.state.set(step, session)
        return session

    def _ensure_invited(self, old_session: Mapping[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("invite")
        leave_checkpoint = self.state.get("old_leave")
        if isinstance(cached, dict) and isinstance(leave_checkpoint, dict):
            self._log("[resume] invite handoff already entered leave stage")
            return cached
        context = AuthContext.from_mapping(old_session)
        target = self.config.new_account.email.casefold()
        client = self._chatgpt_clients["old"]
        members = client.get_members(context.access_token, self.config.workspace_id)
        member_items, active_member_count = _counted_items(members)
        if active_member_count != len(member_items):
            raise RuntimeError("Team member list is incomplete")
        if active_member_count > _TEAM_MEMBER_LIMIT:
            raise RuntimeError(
                f"Team active member limit exceeded ({active_member_count}/{_TEAM_MEMBER_LIMIT})"
            )
        invites = client.get_invites(context.access_token, self.config.workspace_id)
        active_invites = _active_invites(invites)
        if any(_email_from_item(item) != target for item in active_invites):
            raise RuntimeError("Team has unrelated pending invites")
        if isinstance(cached, dict):
            self._log(
                f"[resume] invite active_members={active_member_count}/{_TEAM_MEMBER_LIMIT}"
            )
            return cached
        if any(_email_from_item(item) == target for item in member_items):
            result = {"action": "already-member", "email": self.config.new_account.email}
        else:
            if any(_email_from_item(item) == target for item in active_invites):
                result = {"action": "already-invited", "email": self.config.new_account.email}
            else:
                response = client.invite(
                    context.access_token,
                    self.config.workspace_id,
                    self.config.new_account.email,
                )
                result = {"action": "invited", "email": self.config.new_account.email, "response": response}
        result["active_members_before"] = active_member_count
        result["member_limit"] = _TEAM_MEMBER_LIMIT
        self.state.set("invite", result)
        self._log(f"[invite] {result['action']} {self.config.new_account.email}")
        if self.config.invite_settle_seconds:
            if self.stop_event is not None:
                if self.stop_event.wait(self.config.invite_settle_seconds):
                    raise WorkflowCancelled("workflow cancelled")
            else:
                threading.Event().wait(self.config.invite_settle_seconds)
        return result

    def _wait_for_old_departure(
        self,
        old_session: Mapping[str, Any],
        *,
        deletion_started: bool,
    ) -> dict[str, Any]:
        context = AuthContext.from_mapping(old_session)
        client = self._chatgpt_clients["old"]
        new_login = self.state.get("new_login")
        new_context = (
            AuthContext.from_mapping(new_login)
            if isinstance(new_login, Mapping)
            else None
        )
        deadline = time.monotonic() + _MEMBER_FEEDBACK_TIMEOUT_SECONDS
        while True:
            self._check_cancel()
            try:
                members = client.get_members(
                    context.access_token,
                    self.config.workspace_id,
                )
            except ChatGPTApiError as exc:
                if deletion_started and exc.status_code in {401, 403}:
                    result = {
                        "verified": True,
                        "active_members": None,
                        "member_limit": _TEAM_MEMBER_LIMIT,
                        "old_child_absent": True,
                        "measurement": "access-revoked",
                    }
                    self._log("[leave-verify] old child access revoked")
                    return result
                raise

            member_items, active_member_count = _counted_items(members)
            if active_member_count != len(member_items):
                raise RuntimeError("Team member list is incomplete after old child leave")
            if active_member_count > _TEAM_MEMBER_LIMIT:
                raise RuntimeError(
                    f"Team active member limit exceeded before new child login "
                    f"({active_member_count}/{_TEAM_MEMBER_LIMIT})"
                )
            old_child_present = _identity_present(
                member_items,
                user_id=context.user_id,
                email=self.config.old_account.email,
            )
            new_child_present = _identity_present(
                member_items,
                user_id=new_context.user_id if new_context is not None else "",
                email=self.config.new_account.email,
            )
            has_join_capacity = active_member_count < _TEAM_MEMBER_LIMIT
            if not old_child_present and (has_join_capacity or new_child_present):
                result = {
                    "verified": True,
                    "active_members": active_member_count,
                    "member_limit": _TEAM_MEMBER_LIMIT,
                    "old_child_absent": True,
                    "new_child_present": new_child_present,
                    "measurement": "member-list",
                }
                self._log(
                    f"[leave-verify] active_members={active_member_count}/{_TEAM_MEMBER_LIMIT}"
                )
                return result

            if time.monotonic() >= deadline:
                if old_child_present:
                    raise RuntimeError(
                        "Team departure verification failed before new child login: "
                        "old child is still active"
                    )
                raise RuntimeError(
                    "Team departure verification failed before new child login: "
                    "no free member slot"
                )

            wait_seconds = min(
                _MEMBER_FEEDBACK_POLL_SECONDS,
                max(0.0, deadline - time.monotonic()),
            )
            if self.stop_event is not None:
                if self.stop_event.wait(wait_seconds):
                    raise WorkflowCancelled("workflow cancelled")
            else:
                threading.Event().wait(wait_seconds)

    def _leave_old_account(self, old_session: Mapping[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("old_leave")
        context = AuthContext.from_mapping(old_session)
        if not context.user_id:
            raise RuntimeError("old account session has no user id")
        client = self._chatgpt_clients["old"]
        if isinstance(cached, dict) and cached.get("action") != "started":
            departure_guard = self._wait_for_old_departure(
                old_session,
                deletion_started=True,
            )
            result = dict(cached)
            result["departure_guard"] = departure_guard
            self.state.set("old_leave", result)
            self._log("[resume] old_leave verified")
            return result

        deletion_started = isinstance(cached, dict)
        try:
            members = client.get_members(context.access_token, self.config.workspace_id)
        except ChatGPTApiError as exc:
            if not deletion_started or exc.status_code not in {401, 403}:
                raise
            result = {
                "action": "already-left",
                "user_id": context.user_id,
                "departure_guard": {
                    "verified": True,
                    "active_members": None,
                    "member_limit": _TEAM_MEMBER_LIMIT,
                    "old_child_absent": True,
                    "measurement": "access-revoked",
                },
            }
        else:
            member_items, active_member_count = _counted_items(members)
            if active_member_count != len(member_items):
                raise RuntimeError("Team member list is incomplete before old child leave")
            old_child_present = _identity_present(
                member_items,
                user_id=context.user_id,
                email=self.config.old_account.email,
            )
            response = None
            action = "already-left"
            if old_child_present:
                self.state.set(
                    "old_leave",
                    {"action": "started", "user_id": context.user_id},
                )
                deletion_started = True
                response = client.leave(
                    context.access_token,
                    self.config.workspace_id,
                    context.user_id,
                )
                action = "left"
            departure_guard = self._wait_for_old_departure(
                old_session,
                deletion_started=deletion_started,
            )
            result = {
                "action": action,
                "user_id": context.user_id,
                "departure_guard": departure_guard,
            }
            if response is not None:
                result["response"] = response
        self.state.set("old_leave", result)
        self._log(f"[leave] {result['action']} {context.user_id}")
        return result

    def _verify_team_membership(
        self,
        new_session: Mapping[str, Any],
        old_session: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._check_cancel()
        new_context = AuthContext.from_mapping(new_session)
        old_context = AuthContext.from_mapping(old_session)
        members = self._chatgpt_clients["new"].get_members(
            new_context.access_token,
            self.config.workspace_id,
        )
        member_items, active_member_count = _counted_items(members)
        if active_member_count != len(member_items):
            raise RuntimeError("Team member list is incomplete after handoff")
        if active_member_count > _TEAM_MEMBER_LIMIT:
            raise RuntimeError(
                f"Team active member limit exceeded after handoff "
                f"({active_member_count}/{_TEAM_MEMBER_LIMIT})"
            )
        if _identity_present(
            member_items,
            user_id=old_context.user_id,
            email=self.config.old_account.email,
        ):
            raise RuntimeError("Team membership verification failed: old child is still active")
        if not _identity_present(
            member_items,
            user_id=new_context.user_id,
            email=self.config.new_account.email,
        ):
            raise RuntimeError("Team membership verification failed: new child is missing")
        result = {
            "verified": True,
            "active_members": active_member_count,
            "member_limit": _TEAM_MEMBER_LIMIT,
            "old_child_absent": True,
            "new_child_present": True,
        }
        self.state.set("member_verify", result)
        self._log(
            f"[member-verify] active_members={active_member_count}/{_TEAM_MEMBER_LIMIT}"
        )
        return result

    def _create_pat(self, new_session: Mapping[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("pat")
        if isinstance(cached, dict) and cached.get("access_token"):
            self._log("[resume] pat")
            return cached
        context = AuthContext.from_mapping(new_session)
        self._log(f"[pat] {self.config.pat_name}")
        result = self._chatgpt_clients["new"].create_personal_access_token(
            context.access_token,
            self.config.workspace_id,
            name=self.config.pat_name,
            ttl=self.config.pat_ttl,
        )
        if not result.get("access_token"):
            raise RuntimeError("PAT response has no access_token")
        self.state.set("pat", result)
        return result

    @staticmethod
    def _write_private_json(path: Path, payload: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                descriptor = -1
                handle.write(json.dumps(dict(payload), ensure_ascii=False, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            os.chmod(path, 0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

    def _write_cpa(self, new_session: Mapping[str, Any], pat: Mapping[str, Any]) -> Path:
        self._check_cancel()
        cached = self.state.get("cpa")
        if isinstance(cached, dict):
            cached_path = Path(str(cached.get("path") or ""))
            if cached_path.exists():
                self._log("[resume] cpa")
                return cached_path
        payload = build_cpa(new_session, personal_access_token=str(pat.get("access_token") or ""))
        filename = build_cpa_filename(str(payload.get("email") or self.config.new_account.email))
        path = self.config.output_dir / filename
        self._write_private_json(path, payload)
        self.state.set("cpa", {"path": str(path.resolve()), "filename": filename})
        self._log(f"[cpa] {path.resolve()}")
        return path

    @staticmethod
    def _has_forbidden_sub2api_material(value: Any) -> bool:
        if isinstance(value, Mapping):
            for key, item in value.items():
                normalized = str(key).replace("_", "").casefold()
                if normalized in {
                    "authorization",
                    "cookie",
                    "cookies",
                    "headers",
                    "sessiontoken",
                }:
                    return True
                if WorkflowRunner._has_forbidden_sub2api_material(item):
                    return True
        elif isinstance(value, list):
            return any(
                WorkflowRunner._has_forbidden_sub2api_material(item)
                for item in value
            )
        return False

    @staticmethod
    def _sub2api_account_from_file(path: Path) -> dict[str, Any]:
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise RuntimeError("Sub2API export is not a JSON object")
        if WorkflowRunner._has_forbidden_sub2api_material(document):
            raise RuntimeError("Sub2API export contains forbidden session material")
        if set(document) != {"exported_at", "proxies", "accounts"}:
            raise RuntimeError("Sub2API export has an invalid top-level structure")
        if document.get("proxies") != []:
            raise RuntimeError("Sub2API export contains unexpected proxies")
        accounts = document.get("accounts")
        if not isinstance(accounts, list) or len(accounts) != 1:
            raise RuntimeError("Sub2API export must contain exactly one account")
        account = accounts[0]
        if not isinstance(account, dict):
            raise RuntimeError("Sub2API export account is invalid")
        return account

    @staticmethod
    def _sub2api_accounts_match(
        cached: Mapping[str, Any], expected: Mapping[str, Any]
    ) -> bool:
        for key in (
            "name",
            "platform",
            "type",
            "concurrency",
            "priority",
            "group_ids",
        ):
            if cached.get(key) != expected.get(key):
                return False
        cached_credentials = cached.get("credentials")
        expected_credentials = expected.get("credentials")
        cached_extra = cached.get("extra")
        expected_extra = expected.get("extra")
        if not all(
            isinstance(value, Mapping)
            for value in (
                cached_credentials,
                expected_credentials,
                cached_extra,
                expected_extra,
            )
        ):
            return False
        for key in (
            "access_token",
            "auth_mode",
            "openai_auth_mode",
            "token_type",
            "chatgpt_account_id",
            "chatgpt_user_id",
            "email",
            "expires_at",
            "plan_type",
        ):
            if cached_credentials.get(key) != expected_credentials.get(key):
                return False
        for key in (
            "email",
            "email_key",
            "name",
            "auth_provider",
            "import_source",
            "source",
        ):
            if cached_extra.get(key) != expected_extra.get(key):
                return False
        return True

    def _write_sub2api_export(
        self,
        new_session: Mapping[str, Any],
        pat: Mapping[str, Any],
    ) -> Path:
        self._check_cancel()
        token = str(pat.get("access_token") or "").strip()
        expected = build_sub2api_export(
            new_session,
            personal_access_token=token,
            concurrency=self.config.sub2api_concurrency,
            priority=self.config.sub2api_priority,
            group_id=self.config.sub2api_group_id,
            personal_access_token_expires_at=pat.get("expires_at"),
        )
        expected_account = expected["accounts"][0]
        cached = self.state.get("sub2api_export")
        cached_path: Path | None = None
        if isinstance(cached, dict):
            raw_cached_path = str(cached.get("path") or "").strip()
            cached_path = Path(raw_cached_path) if raw_cached_path else None
            if cached_path is not None and cached_path.exists():
                try:
                    cached_account = self._sub2api_account_from_file(cached_path)
                except (OSError, ValueError, RuntimeError):
                    pass
                else:
                    if self._sub2api_accounts_match(
                        cached_account, expected_account
                    ):
                        os.chmod(cached_path, 0o600)
                        self._log("[resume] sub2api_export")
                        return cached_path
        if cached_path is None:
            filename = build_sub2api_filename(
                str(expected_account.get("name") or self.config.new_account.email)
            )
            path = self.config.output_dir / filename
        else:
            path = cached_path
            filename = str(cached.get("filename") or path.name)
        self._write_private_json(path, expected)
        self.state.set(
            "sub2api_export", {"path": str(path.resolve()), "filename": filename}
        )
        self._log(f"[sub2api-export] {path.resolve()}")
        return path

    def _push(self, cpa_path: Path) -> dict[str, Any] | None:
        self._check_cancel()
        if not self.config.push:
            return None
        cached = self.state.get("push")
        if isinstance(cached, dict) and cached.get("verified"):
            self._log("[resume] push")
            return cached
        if not self.config.management_key:
            raise RuntimeError("management.api_key or CPA_MANAGEMENT_KEY is required when push=true")
        client = self.management or ManagementClient(
            self.config.management_base_url,
            self.config.management_key,
        )
        result = client.push_file(
            cpa_path,
            remote_name=self.config.remote_name or None,
            replace=self.config.replace,
        )
        payload = {
            "action": result.action,
            "filename": result.filename,
            "verified": result.verified,
            "message": result.message,
        }
        self.state.set("push", payload)
        self._log(f"[push] {result.action} verified={result.verified}")
        return payload

    def _push_sub2api(
        self,
        export_path: Path,
    ) -> dict[str, Any] | None:
        self._check_cancel()
        if not self.config.sub2api_push:
            return None
        cached = self.state.get("push_sub2api")
        if isinstance(cached, dict) and cached.get("verified"):
            self._log("[resume] push_sub2api")
            return cached
        verified_session_auth = bool(
            self.config.sub2api_email
            and self.config.sub2api_password
            and self.config.sub2api_totp_secret
        )
        if not verified_session_auth:
            raise RuntimeError(
                "Sub2API push requires administrator email, password, and TOTP secret"
            )
        account = self._sub2api_account_from_file(export_path)
        owns_client = self.sub2api is None
        client_options = {}
        if self.config.sub2api_api_key:
            client_options["api_key"] = self.config.sub2api_api_key
        if self.config.sub2api_totp_secret:
            client_options["totp_secret"] = self.config.sub2api_totp_secret
        client = self.sub2api or Sub2APIClient(
            self.config.sub2api_base_url,
            self.config.sub2api_email,
            self.config.sub2api_password,
            **client_options,
        )
        try:
            result = client.push_account(account)
        finally:
            if owns_client:
                client.close()
        payload = {
            "action": result.action,
            "account_name": result.account_name,
            "verified": result.verified,
            "message": result.message,
        }
        self.state.set("push_sub2api", payload)
        self._log(f"[sub2api] {result.action} verified={result.verified}")
        return payload

    def _log_network_context(self) -> None:
        roles = ("old", "new") if self._account_network_mode else ("old",)
        for role in roles:
            network = self._networks[role]
            label = f"[{role}] " if self._account_network_mode else ""
            self._log(f"[proxy] {label}{network.description}")
            if network.proxy_geo is not None:
                geo_status = "已匹配" if network.proxy_geo.get("resolved") else "已回退"
                self._log(
                    f"[geo] {label}{geo_status} country="
                    f"{network.proxy_geo.get('country_code') or '<unknown>'} "
                    f"locale={network.proxy_geo.get('locale') or '<unknown>'} "
                    f"timezone={network.proxy_geo.get('timezone_id') or '<unknown>'} "
                    f"source={network.proxy_geo.get('source') or '<unknown>'}"
                )
            profile = network.fingerprint_profile
            if profile is not None:
                profile_action = "已恢复" if network.fingerprint_restored else "已生成"
                self._log(
                    f"[fingerprint] {label}{profile_action}并锁定 "
                    f"{getattr(profile, 'profile_id', '<unknown>')} "
                    f"impersonate={getattr(profile, 'impersonate', '<unknown>')} "
                    f"os={getattr(profile, 'os', '<unknown>')} "
                    f"locale={getattr(profile, 'locale', '<unknown>')} "
                    f"timezone={getattr(profile, 'timezone_id', '<unknown>')}"
                )

    def run(self) -> dict[str, Any]:
        try:
            self._log_network_context()
            self._check_cancel()
            def old_login_stage() -> dict[str, Any]:
                login = self._login(self.config.old_account, "old_login")
                return self._switch_workspace(login, "old_workspace")

            old_workspace = self._run_stage("old_login", old_login_stage)
            invite = self._run_stage("invite", lambda: self._ensure_invited(old_workspace))
            old_leave = self._run_stage(
                "old_leave", lambda: self._leave_old_account(old_workspace)
            )
            new_login = self._run_stage(
                "new_login",
                lambda: self._login(
                    self.config.new_account,
                    "new_login",
                    select_workspace=False,
                ),
            )

            def member_verify_stage() -> tuple[dict[str, Any], dict[str, Any]]:
                try:
                    new_workspace = self._switch_workspace(new_login, "new_workspace")
                except _WorkspaceSwitchError:
                    self._log("[reauth] new account workspace selection")
                    workspace_login = self._login(
                        self.config.new_account,
                        "new_workspace_login",
                    )
                    new_workspace = self._switch_workspace(
                        workspace_login,
                        "new_workspace",
                    )
                member_verify = self._verify_team_membership(
                    new_workspace,
                    old_workspace,
                )
                return new_workspace, member_verify

            new_workspace, member_verify = self._run_stage(
                "member_verify", member_verify_stage
            )
            pat = self._run_stage("pat", lambda: self._create_pat(new_workspace))
            cpa_path = self._run_stage(
                "cpa", lambda: self._write_cpa(new_workspace, pat)
            )
            sub2api_path = self._run_stage(
                "sub2api_export",
                lambda: self._write_sub2api_export(new_workspace, pat),
            )
            push = self._run_stage("push", lambda: self._push(cpa_path))
            sub2api = self._run_stage(
                "push_sub2api", lambda: self._push_sub2api(sub2api_path)
            )
            self._check_cancel()
            summary = {
                "old_email": self.config.old_account.email,
                "new_email": self.config.new_account.email,
                "workspace_id": self.config.workspace_id,
                "invite": invite.get("action"),
                "old_leave": old_leave.get("action"),
                "member_guard": member_verify,
                "cpa_path": str(cpa_path.resolve()),
                "sub2api_path": str(sub2api_path.resolve()),
                "push": push,
                "sub2api": sub2api,
            }
            self.state.set("complete", summary)
            return summary
        finally:
            self.close()


class RescueWorkflowRunner(WorkflowRunner):
    """Recover a Team through its owner without using the broken child."""

    @staticmethod
    def _matching_owner_items(
        items: list[dict[str, Any]],
        context: AuthContext,
        owner_email: str,
    ) -> list[dict[str, Any]]:
        return [
            item
            for item in items
            if _identity_present(
                [item],
                user_id=context.user_id,
                email=owner_email,
            )
        ]

    def _owner_member_snapshot(
        self,
        owner_session: Mapping[str, Any],
        *,
        phase: str,
    ) -> tuple[AuthContext, list[dict[str, Any]], dict[str, Any]]:
        context = AuthContext.from_mapping(owner_session)
        if not context.access_token:
            raise RuntimeError("Team owner session has no access token")
        payload = self._chatgpt_clients["old"].get_members(
            context.access_token,
            self.config.workspace_id,
        )
        items, active_count = _counted_items(payload)
        if active_count != len(items):
            raise RuntimeError(f"Team member list is incomplete {phase}")
        owners = self._matching_owner_items(
            items,
            context,
            self.config.old_account.email,
        )
        if len(owners) != 1:
            raise RuntimeError(f"Team owner identity is not unique {phase}")
        return context, items, {
            "active_members": active_count,
            "owner_present": True,
        }

    def _wait_until_member_absent(
        self,
        owner_session: Mapping[str, Any],
        user_id: str,
    ) -> None:
        deadline = time.monotonic() + _MEMBER_FEEDBACK_TIMEOUT_SECONDS
        while True:
            self._check_cancel()
            _context, items, _snapshot = self._owner_member_snapshot(
                owner_session,
                phase="after rescue member removal",
            )
            if all(_user_id_from_item(item) != user_id for item in items):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Team rescue member removal was not confirmed by remote feedback"
                )
            wait_seconds = min(
                _MEMBER_FEEDBACK_POLL_SECONDS,
                max(0.0, deadline - time.monotonic()),
            )
            if self.stop_event is not None:
                if self.stop_event.wait(wait_seconds):
                    raise WorkflowCancelled("workflow cancelled")
            else:
                threading.Event().wait(wait_seconds)

    def _clear_team_to_owner(
        self,
        owner_session: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("rescue_clear")
        handoff_started = any(
            self.state.get(step) is not None
            for step in ("rescue_invite", "new_login", "rescue_verify", "pat")
        )
        if isinstance(cached, dict) and handoff_started:
            self._log("[resume] rescue clear is locked after invitation")
            return cached

        progress = self.state.get("rescue_clear_progress")
        removed_count = (
            int(progress.get("removed_count") or 0)
            if isinstance(progress, Mapping)
            else 0
        )
        client = self._chatgpt_clients["old"]
        while True:
            context, items, snapshot = self._owner_member_snapshot(
                owner_session,
                phase="during rescue clear",
            )
            owner_items = self._matching_owner_items(
                items,
                context,
                self.config.old_account.email,
            )
            owner_marker = id(owner_items[0])
            others = [item for item in items if id(item) != owner_marker]
            if not others:
                active_invites = _active_invites(
                    client.get_invites(context.access_token, self.config.workspace_id)
                )
                target_email = self.config.new_account.email.casefold()
                if any(_email_from_item(item) != target_email for item in active_invites):
                    raise RuntimeError(
                        "Team rescue found unrelated pending invites before new child login"
                    )
                if snapshot["active_members"] != 1:
                    raise RuntimeError(
                        "Team rescue requires exactly one active owner before invitation"
                    )
                result = {
                    "verified": True,
                    "active_members": 1,
                    "owner_present": True,
                    "removed_members": removed_count,
                    "member_limit": _TEAM_MEMBER_LIMIT,
                }
                self.state.set("rescue_clear", result)
                self._log(
                    f"[rescue-clear] active_members=1/{_TEAM_MEMBER_LIMIT} "
                    f"removed={removed_count}"
                )
                return result

            if removed_count >= _RESCUE_MAX_MEMBER_REMOVALS:
                raise RuntimeError("Team rescue member removal limit was exceeded")
            target_ids = [_user_id_from_item(item) for item in others]
            if any(not value for value in target_ids) or len(set(target_ids)) != len(target_ids):
                raise RuntimeError("Team rescue member identity is incomplete")
            target_id = target_ids[0]
            self.state.set(
                "rescue_clear_progress",
                {
                    "phase": "removing",
                    "removed_count": removed_count,
                    "target_user_id": target_id,
                },
            )
            client.remove_member(
                context.access_token,
                self.config.workspace_id,
                target_id,
            )
            self._wait_until_member_absent(owner_session, target_id)
            removed_count += 1
            self.state.set(
                "rescue_clear_progress",
                {"phase": "confirmed", "removed_count": removed_count},
            )

    def _ensure_rescue_invited(
        self,
        owner_session: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("rescue_invite")
        context, members, snapshot = self._owner_member_snapshot(
            owner_session,
            phase="before rescue invitation",
        )
        target = self.config.new_account.email.casefold()
        target_present = _identity_present(members, user_id="", email=target)
        expected_count = 2 if target_present else 1
        if snapshot["active_members"] != expected_count:
            raise RuntimeError(
                "Team rescue member count changed before new child login"
            )
        active_invites = _active_invites(
            self._chatgpt_clients["old"].get_invites(
                context.access_token,
                self.config.workspace_id,
            )
        )
        if any(_email_from_item(item) != target for item in active_invites):
            raise RuntimeError("Team rescue found unrelated pending invites")
        if target_present:
            action = "already-member"
            response = None
        elif any(_email_from_item(item) == target for item in active_invites):
            action = "already-invited"
            response = None
        elif isinstance(cached, dict):
            raise RuntimeError("Team rescue invitation checkpoint has no remote feedback")
        else:
            response = self._chatgpt_clients["old"].invite(
                context.access_token,
                self.config.workspace_id,
                self.config.new_account.email,
            )
            action = "invited"
        result = {
            "action": action,
            "active_members_before": snapshot["active_members"],
            "member_limit": _TEAM_MEMBER_LIMIT,
        }
        if response is not None:
            result["response"] = response
        self.state.set("rescue_invite", result)
        self._log(f"[rescue-invite] {action} {self.config.new_account.email}")
        if self.config.invite_settle_seconds:
            if self.stop_event is not None:
                if self.stop_event.wait(self.config.invite_settle_seconds):
                    raise WorkflowCancelled("workflow cancelled")
            else:
                threading.Event().wait(self.config.invite_settle_seconds)
        return result

    def _verify_rescue_membership(
        self,
        new_session: Mapping[str, Any],
        owner_session: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._check_cancel()
        new_context = AuthContext.from_mapping(new_session)
        owner_context = AuthContext.from_mapping(owner_session)
        client = self._chatgpt_clients["new"]
        payload = client.get_members(new_context.access_token, self.config.workspace_id)
        members, active_count = _counted_items(payload)
        if active_count != len(members):
            raise RuntimeError("Team member list is incomplete after rescue")
        owner_present = _identity_present(
            members,
            user_id=owner_context.user_id,
            email=self.config.old_account.email,
        )
        new_present = _identity_present(
            members,
            user_id=new_context.user_id,
            email=self.config.new_account.email,
        )
        if active_count != _TEAM_MEMBER_LIMIT or not owner_present or not new_present:
            raise RuntimeError(
                "Team rescue verification requires exactly the owner and new child"
            )
        active_invites = _active_invites(
            client.get_invites(new_context.access_token, self.config.workspace_id)
        )
        target = self.config.new_account.email.casefold()
        if any(_email_from_item(item) != target for item in active_invites):
            raise RuntimeError("Team rescue verification found unrelated pending invites")
        result = {
            "verified": True,
            "active_members": active_count,
            "member_limit": _TEAM_MEMBER_LIMIT,
            "owner_present": True,
            "new_child_present": True,
            "other_members_absent": True,
        }
        self.state.set("rescue_verify", result)
        self._log(
            f"[rescue-verify] active_members={active_count}/{_TEAM_MEMBER_LIMIT}"
        )
        return result

    def run(self) -> dict[str, Any]:
        try:
            self._log_network_context()
            self._check_cancel()

            def owner_login_stage() -> dict[str, Any]:
                login = self._login(self.config.old_account, "owner_login")
                return self._switch_workspace(login, "owner_workspace")

            owner_workspace = self._run_stage("owner_login", owner_login_stage)
            clear = self._run_stage(
                "rescue_clear",
                lambda: self._clear_team_to_owner(owner_workspace),
            )
            invite = self._run_stage(
                "rescue_invite",
                lambda: self._ensure_rescue_invited(owner_workspace),
            )
            new_login = self._run_stage(
                "new_login",
                lambda: self._login(
                    self.config.new_account,
                    "new_login",
                    select_workspace=False,
                ),
            )

            def verify_stage() -> tuple[dict[str, Any], dict[str, Any]]:
                try:
                    new_workspace = self._switch_workspace(new_login, "new_workspace")
                except _WorkspaceSwitchError:
                    self._log("[reauth] new account workspace selection")
                    workspace_login = self._login(
                        self.config.new_account,
                        "new_workspace_login",
                    )
                    new_workspace = self._switch_workspace(
                        workspace_login,
                        "new_workspace",
                    )
                guard = self._verify_rescue_membership(
                    new_workspace,
                    owner_workspace,
                )
                return new_workspace, guard

            new_workspace, member_guard = self._run_stage(
                "rescue_verify",
                verify_stage,
            )
            pat = self._run_stage("pat", lambda: self._create_pat(new_workspace))
            cpa_path = self._run_stage(
                "cpa", lambda: self._write_cpa(new_workspace, pat)
            )
            sub2api_path = self._run_stage(
                "sub2api_export",
                lambda: self._write_sub2api_export(new_workspace, pat),
            )
            push = self._run_stage("push", lambda: self._push(cpa_path))
            sub2api = self._run_stage(
                "push_sub2api", lambda: self._push_sub2api(sub2api_path)
            )
            self._check_cancel()
            summary = {
                "mode": "rescue",
                "owner_email": self.config.old_account.email,
                "new_email": self.config.new_account.email,
                "workspace_id": self.config.workspace_id,
                "clear": clear,
                "invite": invite.get("action"),
                "member_guard": member_guard,
                "cpa_path": str(cpa_path.resolve()),
                "sub2api_path": str(sub2api_path.resolve()),
                "push": push,
                "sub2api": sub2api,
            }
            self.state.set("complete", summary)
            return summary
        finally:
            self.close()
