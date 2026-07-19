from __future__ import annotations

import socket
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .chatgpt import AuthContext, ChatGPTClient
from .database import StateConflictError
from .proxy_chain import ChainedProxyRelay, ProxySourceResolver, is_chain_proxy_mode
from .registrar import MailboxCredentials, RegistrarAdapter, validate_proxy_url


class WorkspaceLookupError(StateConflictError):
    code = "workspace_lookup_failed"


def _candidate_ids(*payloads: Mapping[str, Any]) -> list[str]:
    candidates: list[str] = []

    def append(value: Any) -> None:
        identifier = str(value or "").strip()
        if identifier and "@" not in identifier and identifier not in candidates:
            candidates.append(identifier)

    def record(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        for key in (
            "id",
            "account_id",
            "accountId",
            "workspace_id",
            "workspaceId",
            "chatgpt_account_id",
        ):
            append(value.get(key))
        nested = value.get("account")
        if isinstance(nested, Mapping):
            record(nested)

    def container(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        context = AuthContext.from_mapping(value)
        append(context.account_id)
        for key in ("account", "workspace"):
            record(value.get(key))
        for key in ("accounts", "workspaces"):
            collection = value.get(key)
            if isinstance(collection, list):
                for item in collection[:50]:
                    record(item)
            elif isinstance(collection, Mapping):
                for identifier, item in list(collection.items())[:50]:
                    record(item)
                    append(identifier)
        for key in ("data", "session"):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                container(nested)
        user = value.get("user")
        if isinstance(user, Mapping):
            for key in ("accounts", "workspaces"):
                collection = user.get(key)
                if isinstance(collection, list):
                    for item in collection[:50]:
                        record(item)
                elif isinstance(collection, Mapping):
                    for identifier, item in list(collection.items())[:50]:
                        record(item)
                        append(identifier)

    for payload in payloads:
        container(payload)
    return candidates[:50]


def _member_snapshot(payload: Mapping[str, Any]) -> tuple[set[str], int, bool]:
    items: list[Mapping[str, Any]] = []
    for key in ("items", "users", "members"):
        value = payload.get(key)
        if isinstance(value, list):
            items = [item for item in value if isinstance(item, Mapping)]
            break
    raw_total = payload.get("total")
    try:
        reported_total = int(raw_total) if not isinstance(raw_total, bool) else len(items)
    except (TypeError, ValueError):
        reported_total = len(items)
    total = max(len(items), max(0, reported_total))
    emails: set[str] = set()
    for item in items:
        user = item.get("user") if isinstance(item.get("user"), Mapping) else {}
        email = str(
            item.get("email")
            or item.get("email_address")
            or item.get("user_email")
            or user.get("email")
            or ""
        ).strip().casefold()
        if email:
            emails.add(email)
    return emails, total, total == len(items)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class WorkspaceLookupService:
    def __init__(
        self,
        *,
        registrar_factory: Any = RegistrarAdapter,
        chatgpt_client_factory: Any = ChatGPTClient,
        relay_factory: Any = ChainedProxyRelay,
        proxy_fetcher: Any | None = None,
    ) -> None:
        self.registrar_factory = registrar_factory
        self.chatgpt_client_factory = chatgpt_client_factory
        self.relay_factory = relay_factory
        self.proxy_fetcher = proxy_fetcher or ProxySourceResolver()

    @contextmanager
    def _network(
        self,
        *,
        mode: str,
        proxy: str,
        source_url: str,
        bootstrap_proxy: str,
    ) -> Iterator[str]:
        if mode == "direct":
            try:
                normalized_proxy = validate_proxy_url(proxy)
            except ValueError as exc:
                raise WorkspaceLookupError("子号代理配置无效") from exc
            yield normalized_proxy
            return
        if not is_chain_proxy_mode(mode):
            raise WorkspaceLookupError("子号代理模式无效")

        try:
            endpoint = self.proxy_fetcher.fetch(source_url, bootstrap_proxy)
            relay = self.relay_factory(
                owner_id="workspace-lookup",
                bootstrap_proxy=bootstrap_proxy,
                listener_port=_free_loopback_port(),
                endpoint_supplier=lambda: endpoint,
            )
            relay.start()
        except Exception as exc:
            raise WorkspaceLookupError("子号 Clash 两跳链路不可用") from exc
        try:
            yield relay.effective_proxy
        finally:
            relay.stop()

    @staticmethod
    def _mailbox(
        mailbox: Mapping[str, Any],
        secret: Mapping[str, Any],
        child_email: str,
    ) -> MailboxCredentials:
        imap = secret.get("imap")
        if not isinstance(imap, Mapping):
            raise WorkspaceLookupError("iCloud IMAP 配置不完整")
        forwarding_email = str(mailbox.get("forwarding_email") or "").strip()
        required = {
            "forwarding_email": forwarding_email,
            "imap_host": str(imap.get("host") or "").strip(),
            "imap_username": str(imap.get("username") or "").strip(),
            "imap_password": str(imap.get("password") or ""),
        }
        if any(not value for value in required.values()):
            raise WorkspaceLookupError("iCloud IMAP 配置不完整")
        return MailboxCredentials(
            primary_email=forwarding_email,
            registration_email=child_email,
            client_id="",
            refresh_token="",
            provider="icloud_hme_imap",
            forwarding_email=forwarding_email,
            imap_host=required["imap_host"],
            imap_port=int(imap.get("port") or 993),
            imap_username=required["imap_username"],
            imap_password=required["imap_password"],
            imap_folder=str(imap.get("folder") or "INBOX"),
            mailbox_proxy=str(secret.get("proxy") or ""),
        )

    def lookup(
        self,
        *,
        mailbox: Mapping[str, Any],
        mailbox_secret: Mapping[str, Any],
        owner_email: str,
        child_email: str,
        proxy_mode: str,
        proxy: str = "",
        source_url: str = "",
        bootstrap_proxy: str = "",
    ) -> dict[str, Any]:
        owner = str(owner_email or "").strip().casefold()
        child = str(child_email or "").strip().casefold()
        if not owner or not child or owner == child:
            raise WorkspaceLookupError("母号与当前子号身份无效")

        with self._network(
            mode=str(proxy_mode or "").strip(),
            proxy=str(proxy or "").strip(),
            source_url=str(source_url or "").strip(),
            bootstrap_proxy=str(bootstrap_proxy or "").strip(),
        ) as effective_proxy:
            with tempfile.TemporaryDirectory(prefix="team-workflow-workspace-lookup-") as directory:
                registrar = self.registrar_factory(Path(directory))
                try:
                    geo_hint = registrar.resolve_proxy_geo(effective_proxy)
                    if not isinstance(geo_hint, Mapping) or not geo_hint.get("resolved"):
                        raise WorkspaceLookupError("无法验证子号代理出口")
                    profile = registrar.resolve_session_profile(geo_hint=geo_hint)
                    login = registrar.login(
                        email=child,
                        account_password="",
                        mailbox=self._mailbox(mailbox, mailbox_secret, child),
                        proxy=effective_proxy,
                        workspace_id=None,
                        session_profile=profile,
                        verbose=False,
                    )
                except WorkspaceLookupError:
                    raise
                except Exception as exc:
                    raise WorkspaceLookupError("当前子号登录失败") from exc

                login_context = AuthContext.from_mapping(login)
                if not login_context.session_token:
                    raise WorkspaceLookupError("当前子号登录结果无有效 Session")
                if login_context.email and login_context.email.casefold() != child:
                    raise WorkspaceLookupError("当前子号登录身份不一致")

                client = self.chatgpt_client_factory(
                    proxy=effective_proxy,
                    session_profile=profile,
                )
                try:
                    try:
                        base_session = client.refresh_session(login_context.session_token)
                    except Exception as exc:
                        raise WorkspaceLookupError("当前子号 Session 刷新失败") from exc
                    base_context = AuthContext.from_mapping(base_session)
                    if base_context.email and base_context.email.casefold() != child:
                        raise WorkspaceLookupError("当前子号 Session 身份不一致")
                    candidates = _candidate_ids(login, base_session)
                    if not candidates:
                        raise WorkspaceLookupError("当前子号没有可识别的 Team")

                    matches: list[str] = []
                    checked = 0
                    unsafe_match = False
                    for candidate in candidates:
                        try:
                            session = (
                                base_session
                                if base_context.account_id == candidate
                                and base_context.access_token
                                else client.refresh_session(
                                    login_context.session_token,
                                    account_id=candidate,
                                )
                            )
                            context = AuthContext.from_mapping(session)
                            if context.account_id != candidate or not context.access_token:
                                continue
                            members = client.get_members(context.access_token, candidate)
                            emails, total, complete = _member_snapshot(members)
                        except Exception:
                            continue
                        checked += 1
                        if owner not in emails or child not in emails:
                            continue
                        if not complete or total != 2:
                            unsafe_match = True
                            continue
                        matches.append(candidate)

                    if unsafe_match:
                        raise WorkspaceLookupError("匹配 Team 不是母号与当前子号恰好两人")
                    if not checked:
                        raise WorkspaceLookupError("无法读取当前子号的 Team 成员")
                    if len(matches) != 1:
                        raise WorkspaceLookupError(
                            "未找到唯一且恰好两人的母号与当前子号 Team"
                        )
                    return {
                        "workspace_uid": matches[0],
                        "member_count": 2,
                        "verified": True,
                    }
                finally:
                    close = getattr(client, "close", None)
                    if callable(close):
                        close()
