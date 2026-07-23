from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

_LOGIN_PATCH_LOCK = threading.RLock()
_PROXY_SID_RE = re.compile(r"(?i)(-sid-)([^-]+)")
_PROXY_REGION_RE = re.compile(r"(?i)(?:^|-)region-([A-Za-z]{2})(?:-|$)")
_PROXY_SID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


class _CallbackEventQueue:
    def __init__(self, callback: Callable[[dict[str, Any]], None]):
        self._callback = callback

    def put_nowait(self, event: dict[str, Any]) -> None:
        try:
            self._callback(event)
        except Exception:
            pass


@dataclass(frozen=True)
class MailboxCredentials:
    primary_email: str
    registration_email: str
    client_id: str
    refresh_token: str
    password: str = ""
    provider: str = "appleemail_hotmail"
    forwarding_email: str = ""
    imap_host: str = ""
    imap_port: int = 993
    imap_username: str = ""
    imap_password: str = ""
    imap_folder: str = "INBOX"
    mailbox_proxy: str = ""

    def as_auth_credential(self) -> str:
        if self.provider == "icloud_hme_imap":
            payload = {
                "provider": self.provider,
                "primary_email": self.primary_email,
                "registration_email": self.registration_email,
                "forwarding_email": self.forwarding_email or self.primary_email,
                "imap_host": self.imap_host,
                "imap_port": int(self.imap_port),
                "imap_username": self.imap_username,
                "imap_password": self.imap_password,
                "imap_folder": self.imap_folder,
                "mailbox_proxy": self.mailbox_proxy,
            }
        else:
            payload = {
                "provider": "appleemail_hotmail",
                "primary_email": self.primary_email,
                "registration_email": self.registration_email,
                "client_id": self.client_id,
                "refresh_token": self.refresh_token,
                "password": self.password,
            }
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )


def _normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lower = text.lower()
    scheme_aliases = {
        "sk5://": "socks5://",
        "sk5h://": "socks5h://",
        "s5://": "socks5://",
        "s5h://": "socks5h://",
        "socks://": "socks5://",
        "ss://": "socks5://",
        "ss5://": "socks5://",
        "ss5h://": "socks5h://",
    }
    for prefix, replacement in scheme_aliases.items():
        if lower.startswith(prefix):
            return replacement + text[len(prefix) :]
    return text if "://" in text else f"{default_scheme}://{text}"


def validate_proxy_url(value: str) -> str:
    proxy = _normalize_proxy_url(value)
    if not proxy:
        raise ValueError("proxy is required")
    if any(character.isspace() or ord(character) < 32 for character in proxy):
        raise ValueError("proxy URL contains invalid whitespace")
    try:
        parsed = urllib.parse.urlsplit(proxy)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("proxy URL is invalid") from None
    if parsed.scheme.casefold() not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError("proxy URL scheme is unsupported")
    if not hostname:
        raise ValueError("proxy hostname is required")
    if port is None:
        raise ValueError("proxy port is required")
    return urllib.parse.urlunsplit(parsed)


def _render_proxy_template(value: str, index: int) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    random_hex = secrets.token_hex(4)
    random_long = secrets.token_hex(8)
    return (
        text.replace("{worker}", str(index))
        .replace("{index}", str(index))
        .replace("{rand}", random_hex)
        .replace("{rand8}", random_hex)
        .replace("{rand16}", random_long)
    )


def generate_proxy_sid(length: int = 8) -> str:
    size = int(length)
    if not 8 <= size <= 32:
        raise ValueError("proxy SID length must be between 8 and 32")
    return "".join(secrets.choice(_PROXY_SID_ALPHABET) for _ in range(size))


def _validated_proxy_sid(value: str) -> str:
    sid = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{8,32}", sid):
        raise ValueError("proxy SID must be 8-32 ASCII letters or digits")
    return sid


def bind_proxy_sid(value: str, sid: str, *, required: bool = False) -> str:
    proxy = _normalize_proxy_url(value)
    if not proxy:
        return ""
    stable_sid = _validated_proxy_sid(sid)
    parsed = urllib.parse.urlsplit(proxy)
    userinfo, separator, hostinfo = parsed.netloc.rpartition("@")
    if not separator:
        if required:
            raise ValueError("account-level proxy SID requires proxy userinfo")
        return proxy
    username_raw, password_separator, password_raw = userinfo.partition(":")
    username = urllib.parse.unquote(username_raw)
    replacements = 0

    placeholder_count = username.count("{sid}")
    if placeholder_count:
        if placeholder_count != 1:
            raise ValueError("proxy username must contain exactly one {sid} placeholder")
        username = username.replace("{sid}", stable_sid)
        replacements += 1

    sid_matches = list(_PROXY_SID_RE.finditer(username))
    if sid_matches:
        if len(sid_matches) != 1:
            raise ValueError("proxy username must contain exactly one -sid- value")
        username = _PROXY_SID_RE.sub(
            lambda match: f"{match.group(1)}{stable_sid}",
            username,
            count=1,
        )
        replacements += 1

    stable_short = stable_sid[:8]
    stable_long = hashlib.sha256(stable_sid.encode("ascii")).hexdigest()[:16]
    template_replacements = {
        "{worker}": "1",
        "{index}": "1",
        "{rand}": stable_short,
        "{rand8}": stable_short,
        "{rand16}": stable_long,
    }
    for placeholder, replacement in template_replacements.items():
        if placeholder in username:
            username = username.replace(placeholder, replacement)
            replacements += 1

    rewritten_parts: dict[str, str] = {}
    for part_name in ("path", "query", "fragment"):
        part_value = str(getattr(parsed, part_name) or "")
        for placeholder, replacement in template_replacements.items():
            if placeholder in part_value:
                part_value = part_value.replace(placeholder, replacement)
                replacements += 1
        rewritten_parts[part_name] = part_value

    if required and replacements == 0:
        raise ValueError(
            "proxy username must contain {sid}, -sid-<value>, or a stable rand placeholder"
        )
    encoded_username = urllib.parse.quote(
        username,
        safe="!$&'()*+,;=-._~",
    )
    encoded_userinfo = encoded_username
    if password_separator:
        encoded_userinfo += f":{password_raw}"
    rebound = parsed._replace(
        netloc=f"{encoded_userinfo}@{hostinfo}",
        **rewritten_parts,
    )
    return urllib.parse.urlunsplit(rebound)


def proxy_region_code(value: str) -> str:
    proxy = _normalize_proxy_url(value)
    if not proxy:
        return ""
    parsed = urllib.parse.urlsplit(proxy)
    username = urllib.parse.unquote(parsed.username or "")
    match = _PROXY_REGION_RE.search(username)
    return "" if match is None else match.group(1).upper()


def _mask_proxy_for_log(value: str) -> str:
    text = _normalize_proxy_url(value)
    if not text:
        return "直连"
    return re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://)[^@/\s]+@",
        r"\1******@",
        text,
    )


class RegistrarProxyLease:
    def __init__(
        self,
        *,
        explicit_proxy: str = "",
        index: int = 1,
        preexpanded: bool = False,
    ):
        self.explicit_proxy = str(explicit_proxy or "").strip()
        self.index = int(index)
        self.preexpanded = bool(preexpanded)
        self.proxy: str | None = None
        self.source = "direct"
        self.description = "未配置代理，当前直连"
        self._entered = False

    def __enter__(self) -> "RegistrarProxyLease":
        if self._entered:
            return self
        self._entered = True
        self.proxy = None
        self.source = "direct"
        self.description = "未配置代理，当前直连"

        if self.explicit_proxy:
            rendered = (
                self.explicit_proxy
                if self.preexpanded
                else _render_proxy_template(self.explicit_proxy, self.index)
            )
            self.proxy = _normalize_proxy_url(rendered)
            self.source = "workflow"
            self.description = f"使用工作流代理：{_mask_proxy_for_log(self.proxy)}"
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self._entered = False

    def close(self) -> None:
        self.__exit__(None, None, None)


def primary_email_for_alias(email: str) -> str:
    normalized = str(email or "").strip().lower()
    if "@" not in normalized:
        return ""
    local, domain = normalized.rsplit("@", 1)
    return f"{local.split('+', 1)[0]}@{domain}"


class RegistrarIdentityError(RuntimeError):
    ALLOWED_CODES = frozenset(
        {"alias_disabled", "account_deactivated", "mailbox_credentials_invalid"}
    )

    def __init__(self, code: str) -> None:
        normalized = str(code or "").strip()
        if normalized not in self.ALLOWED_CODES:
            raise ValueError("unsupported registrar identity error code")
        self.code = normalized
        super().__init__(normalized)


class RegistrarAdapter:
    def __init__(self, state_dir: str | Path | None = None):
        from .proxy_geo import resolve_proxy_geo
        from .registrar_runtime import (
            appleemail_provider,
            fingerprint_profiles,
            icloud_imap_provider,
            register,
            sentinel_browser,
        )

        self.state_dir = Path(state_dir or Path.cwd() / "output" / ".registrar").resolve()
        self._login = register.login_existing_account_for_token
        self._register_module = register
        self._event_emitter = register.EventEmitter
        self._provider_class = appleemail_provider.AppleEmailHotmailProvider
        self._icloud_provider_class = icloud_imap_provider.ICloudImapProvider
        self._mailbox_identity_error_class = (
            appleemail_provider.MailboxCredentialsInvalidError
        )
        self._create_session_profile = fingerprint_profiles.create_session_profile
        self._session_profile_class = fingerprint_profiles.SessionProfile
        self._resolve_proxy_geo = resolve_proxy_geo
        self._browserforge_fingerprint_for_profile = (
            sentinel_browser._browserforge_fingerprint_for_profile
        )
        self._restore_browserforge_fingerprint = (
            sentinel_browser.restore_browserforge_fingerprint
        )
        self._serialize_browserforge_fingerprint = (
            sentinel_browser.serialize_browserforge_fingerprint
        )
        self._browser_toolchain_metadata = sentinel_browser.browser_toolchain_metadata

    def resolve_proxy_geo(self, proxy: str | None) -> dict[str, Any]:
        hint = self._resolve_proxy_geo(proxy)
        if not isinstance(hint, Mapping):
            raise RuntimeError("proxy geo resolver did not return an object")
        return dict(hint)

    def resolve_session_profile(
        self,
        serialized: Mapping[str, Any] | None = None,
        *,
        geo_hint: Mapping[str, Any] | None = None,
    ) -> Any:
        if serialized is None:
            return self._create_session_profile(
                scope="auto_desktop",
                geo_hint=geo_hint,
            )
        if not isinstance(serialized, Mapping):
            raise ValueError("stored fingerprint profile must be a JSON object")
        try:
            return self._session_profile_class(**dict(serialized)).validate()
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "stored fingerprint profile is incompatible; disable resume to start a new workflow"
            ) from exc

    @staticmethod
    def serialize_session_profile(profile: Any) -> dict[str, Any]:
        serializer = getattr(profile, "to_legacy_dict", None)
        if not callable(serializer):
            raise ValueError("fingerprint profile cannot be serialized")
        payload = serializer()
        if not isinstance(payload, dict):
            raise ValueError("fingerprint profile serializer did not return an object")
        json.dumps(payload, ensure_ascii=False)
        return payload

    def resolve_browserforge_fingerprint(
        self,
        profile: Any,
        serialized: Mapping[str, Any] | None = None,
    ) -> Any:
        if serialized is not None:
            if not isinstance(serialized, Mapping):
                raise ValueError("stored BrowserForge fingerprint must be an object")
            return self._restore_browserforge_fingerprint(profile, dict(serialized))
        return self._browserforge_fingerprint_for_profile(
            profile,
            fingerprint_scope=str(getattr(profile, "scope", "auto_desktop")),
        )

    def serialize_browserforge_fingerprint(self, fingerprint: Any) -> dict[str, Any]:
        payload = self._serialize_browserforge_fingerprint(fingerprint)
        json.dumps(payload, ensure_ascii=False)
        return payload

    def browser_toolchain_metadata(self, profile: Any) -> dict[str, Any]:
        return dict(self._browser_toolchain_metadata(profile))

    def login(
        self,
        *,
        email: str,
        account_password: str,
        mailbox: MailboxCredentials,
        proxy: str | None = None,
        workspace_id: str | None = None,
        session_profile: Any = None,
        provider_initial_state: Mapping[str, Any] | None = None,
        provider_state_callback: Callable[[dict[str, Any]], None] | None = None,
        verbose: bool = True,
        stop_event: threading.Event | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if provider_initial_state is not None and not isinstance(
            provider_initial_state, Mapping
        ):
            raise TypeError("provider_initial_state must be a mapping")
        provider_name = str(mailbox.provider or "appleemail_hotmail").strip().casefold()
        if provider_name == "appleemail_hotmail":
            provider_class = self._provider_class
        elif provider_name == "icloud_hme_imap":
            provider_class = self._icloud_provider_class
        else:
            raise ValueError("unsupported mailbox provider")
        provider = provider_class(
            accounts=[],
            **(
                {"api_base": "https://www.appleemail.top"}
                if provider_name == "appleemail_hotmail"
                else {}
            ),
            initial_state=dict(provider_initial_state or {}),
            state_callback=provider_state_callback,
        )
        explicit_password = bool(str(account_password or "").strip())
        internal_password = str(account_password or mailbox.password or "otp-only").strip()
        original_extractor = self._register_module._try_extract_chatgpt_session_token
        emitter_queue = _CallbackEventQueue(event_callback) if event_callback is not None else None
        emitter = self._event_emitter(q=emitter_queue, cli_mode=verbose)

        def _session_from_closure(session_get: Any) -> Any:
            try:
                values = [cell.cell_contents for cell in (session_get.__closure__ or ())]
                closure = dict(zip(session_get.__code__.co_freevars, values))
            except Exception:
                return None
            return closure.get("session")

        def _is_workspace_selection_step(value: str) -> bool:
            parsed = urllib.parse.urlsplit(str(value or "").strip())
            if parsed.netloc and parsed.netloc.lower() != "auth.openai.com":
                return False
            path = parsed.path.rstrip("/").lower()
            return path == "/workspace" or path.startswith("/workspace/")

        def _extract_with_workspace(*, continue_url: str, session_get: Any, **kwargs: Any):
            selected_url = str(continue_url or "").strip()
            target_workspace = str(workspace_id or "").strip()
            if target_workspace and _is_workspace_selection_step(selected_url):
                session = _session_from_closure(session_get)
                if session is None:
                    raise RuntimeError("could not access registrar OAuth session for workspace selection")
                did = ""
                try:
                    did = str(session.cookies.get("oai-did") or "").strip()
                except Exception:
                    did = ""
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": "https://auth.openai.com",
                    "Referer": selected_url or "https://auth.openai.com/workspace",
                }
                if did:
                    headers["oai-device-id"] = did
                request_kwargs: dict[str, Any] = {
                    "json": {"workspace_id": target_workspace},
                    "headers": headers,
                    "timeout": 30,
                    "allow_redirects": False,
                    "verify": False,
                    "http_version": "v2",
                }
                if proxy:
                    request_kwargs["proxies"] = {"http": proxy, "https": proxy}
                response = session.post(
                    "https://auth.openai.com/api/accounts/workspace/select",
                    **request_kwargs,
                )
                if int(getattr(response, "status_code", 0) or 0) not in (200, 301, 302, 303, 307, 308):
                    raise RuntimeError(
                        f"workspace/select failed: HTTP {response.status_code} {str(response.text or '')[:240]}"
                    )
                location = str(getattr(response, "headers", {}).get("Location") or "").strip()
                if location:
                    selected_url = urllib.parse.urljoin("https://auth.openai.com/", location)
                elif int(response.status_code) == 200:
                    try:
                        payload = response.json()
                    except Exception:
                        payload = {}
                    extracted = self._register_module._extract_post_create_url(
                        payload,
                        "https://chatgpt.com",
                    )
                    if extracted:
                        selected_url = extracted
            return original_extractor(
                continue_url=selected_url,
                session_get=session_get,
                **kwargs,
            )

        with _LOGIN_PATCH_LOCK:
            self._register_module._try_extract_chatgpt_session_token = _extract_with_workspace
            try:
                try:
                    result = self._login(
                        email=email,
                        account_password=internal_password,
                        proxy=proxy,
                        mail_provider=provider,
                        mail_provider_name=provider_name,
                        mail_auth_credential=mailbox.as_auth_credential(),
                        session_profile=session_profile,
                        emitter=emitter,
                        stop_event=stop_event,
                    )
                except self._mailbox_identity_error_class as exc:
                    raise RegistrarIdentityError(
                        "mailbox_credentials_invalid"
                    ) from exc
            finally:
                self._register_module._try_extract_chatgpt_session_token = original_extractor
        if not isinstance(result, dict) or not result.get("ok"):
            identity_error_code = (
                str(result.get("identity_error_code") or "").strip()
                if isinstance(result, dict)
                else ""
            )
            if identity_error_code in RegistrarIdentityError.ALLOWED_CODES:
                raise RegistrarIdentityError(identity_error_code)
            if isinstance(result, dict) and result.get("fatal_deactivated") is True:
                raise RegistrarIdentityError("account_deactivated")
            error = result.get("error") if isinstance(result, dict) else result
            raise RuntimeError(str(error or "registrar login failed"))
        token_data = result.get("token_data")
        if not isinstance(token_data, dict):
            raise RuntimeError("registrar login did not return token_data")
        if not explicit_password:
            token_data.pop("account_password", None)
            token_data.pop("password", None)
        return token_data

    def register(
        self,
        *,
        email: str,
        account_password: str,
        mailbox: MailboxCredentials,
        proxy: str | None = None,
        workspace_id: str | None = None,
        session_profile: Any = None,
        provider_initial_state: Mapping[str, Any] | None = None,
        provider_state_callback: Callable[[dict[str, Any]], None] | None = None,
        verbose: bool = True,
        stop_event: threading.Event | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        del email, account_password, workspace_id
        if provider_initial_state is not None and not isinstance(
            provider_initial_state, Mapping
        ):
            raise TypeError("provider_initial_state must be a mapping")
        provider_name = str(mailbox.provider or "appleemail_hotmail").strip().casefold()
        if provider_name != "icloud_hme_imap":
            raise ValueError("registration is only supported for iCloud HME accounts")
        provider_class = self._icloud_provider_class
        provider = provider_class(
            accounts=[mailbox],
            initial_state=dict(provider_initial_state or {}),
            state_callback=provider_state_callback,
        )
        emitter_queue = (
            _CallbackEventQueue(event_callback) if event_callback is not None else None
        )
        emitter = self._event_emitter(q=emitter_queue, cli_mode=verbose)
        token_json = self._register_module.run(
            proxy,
            emitter=emitter,
            stop_event=stop_event,
            mail_provider=provider,
            mail_provider_name=provider_name,
            session_profile=session_profile,
        )
        if not token_json:
            raise RuntimeError("registrar registration failed")
        try:
            token_data = json.loads(str(token_json))
        except json.JSONDecodeError as exc:
            raise RuntimeError("registrar registration result is invalid") from exc
        if not isinstance(token_data, dict):
            raise RuntimeError("registrar registration result is invalid")
        token_data.pop("account_password", None)
        token_data.pop("password", None)
        return token_data

    def login_in_browser_context(
        self,
        *,
        context: Any,
        page: Any,
        email: str,
        account_password: str,
        mailbox: MailboxCredentials,
        timeout_seconds: float,
        provider_initial_state: Mapping[str, Any] | None = None,
        provider_state_callback: Callable[[dict[str, Any]], None] | None = None,
        state_callback: Callable[[str], None] | None = None,
        verbose: bool = True,
        stop_event: threading.Event | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if context is None or page is None:
            raise ValueError("browser context and page are required")
        if provider_initial_state is not None and not isinstance(
            provider_initial_state, Mapping
        ):
            raise TypeError("provider_initial_state must be a mapping")
        provider_name = str(mailbox.provider or "").strip().casefold()
        if provider_name != "icloud_hme_imap":
            raise ValueError("OpenBrowser automatic login requires an iCloud HME mailbox")
        provider = self._icloud_provider_class(
            accounts=[mailbox],
            initial_state=dict(provider_initial_state or {}),
            state_callback=provider_state_callback,
        )
        emitter_queue = (
            _CallbackEventQueue(event_callback) if event_callback is not None else None
        )
        emitter = self._event_emitter(q=emitter_queue, cli_mode=verbose)
        FlowClass = self._register_module._load_browser_register_flow_class()
        flow = FlowClass(
            config={
                "entry_intent": "login",
                "timeout_seconds": max(1, int(float(timeout_seconds))),
                "flow_timeout_seconds": max(1.0, float(timeout_seconds)),
            },
            context=context,
            page=page,
            emitter=emitter,
            state_callback=state_callback,
        )
        try:
            result = flow.run_registration_and_oauth_sync(
                email=str(email or "").strip(),
                account_password=str(account_password or ""),
                mail_provider=provider,
                mail_auth_credential=mailbox.as_auth_credential(),
                random_profile=self._register_module._generate_random_profile(),
                stop_event=stop_event,
            )
        except self._mailbox_identity_error_class as exc:
            raise RegistrarIdentityError("mailbox_credentials_invalid") from exc
        token_data = (
            result.get("session_token_data") if isinstance(result, Mapping) else None
        )
        if not isinstance(token_data, Mapping):
            raise RuntimeError("OpenBrowser automatic login did not return session data")
        session = dict(token_data)
        expected_email = str(email or "").strip().casefold()
        session_email = str(session.get("email") or "").strip().casefold()
        if not session_email or session_email != expected_email:
            raise RuntimeError("OpenBrowser automatic login returned a different account")
        session.pop("account_password", None)
        session.pop("password", None)
        return session
