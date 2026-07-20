from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlencode, urlparse

from .cpa import (
    OPENAI_AUTH_CLAIM,
    build_cpa,
    decode_jwt_payload,
    sanitize_file_token,
)


class Sub2APIError(RuntimeError):
    pass


SUB2API_PUSH_CONCURRENCY = 9999
SUB2API_PUSH_LOAD_FACTOR = 9999


@dataclass(frozen=True)
class Sub2APIPushResult:
    action: str
    account_name: str
    verified: bool
    message: str
    account_id: int | None = None
    group_count: int = 0
    concurrency: int | None = None
    load_factor: int | None = None


def _clean_token(value: str) -> str:
    token = str(value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _totp_code(secret: str, *, at: float | None = None) -> str:
    raw_secret = str(secret or "").strip()
    if raw_secret.lower().startswith("otpauth://"):
        values = parse_qs(urlparse(raw_secret).query).get("secret") or []
        raw_secret = str(values[0] if values else "")
    normalized = "".join(raw_secret.split()).replace("-", "").upper().rstrip("=")
    if not normalized:
        raise ValueError("TOTP secret is required")
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    try:
        key = base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("TOTP secret is not valid base32") from exc
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _without_empty(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in values.items()
        if value is not None and (not isinstance(value, str) or value.strip())
    }


def _as_utc_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, bool) or value is None:
        return None
    elif isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp <= 0:
            return None
        if timestamp > 100_000_000_000:
            timestamp /= 1000
        try:
            return datetime.fromtimestamp(timestamp, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            numeric = float(text)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
        else:
            return _as_utc_datetime(numeric)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _jwt_expiry(token: str) -> datetime | None:
    payload = decode_jwt_payload(_clean_token(token))
    return _as_utc_datetime(payload.get("exp"))


def _session_expiry(session: Mapping[str, Any]) -> datetime | None:
    nested_tokens = (
        session.get("tokens") if isinstance(session.get("tokens"), dict) else {}
    )
    session_access_token = str(
        session.get("accessToken")
        or session.get("access_token")
        or nested_tokens.get("accessToken")
        or nested_tokens.get("access_token")
        or ""
    )
    return _jwt_expiry(session_access_token) or _as_utc_datetime(
        session.get("expired")
        or session.get("expiresAt")
        or session.get("expires_at")
        or session.get("expires")
    )


def _email_key(email: str) -> str:
    return re.sub(r"^_+|_+$", "", re.sub(r"[^a-z0-9]+", "_", email.casefold()))


def _normalized_group_ids(
    group_ids: Sequence[int] | None,
    *,
    group_id: int | None = None,
) -> tuple[int, ...]:
    values: set[int] = set()
    raw_values: list[Any] = list(group_ids or ())
    if group_id is not None:
        raw_values.append(group_id)
    for raw_value in raw_values:
        if isinstance(raw_value, bool):
            raise ValueError("Sub2API group IDs must be positive integers")
        try:
            value = int(raw_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Sub2API group IDs must be positive integers") from exc
        if value <= 0:
            raise ValueError("Sub2API group IDs must be positive integers")
        values.add(value)
    return tuple(sorted(values))


def build_sub2api_account(
    session: Mapping[str, Any],
    *,
    personal_access_token: str,
    concurrency: int = 10,
    priority: int = 1,
    load_factor: int | None = None,
    group_id: int | None = None,
    group_ids: Sequence[int] | None = None,
    personal_access_token_expires_at: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    token = _clean_token(personal_access_token)
    if not token:
        raise ValueError("personal access token is required for Sub2API")
    if concurrency < 0 or priority < 0:
        raise ValueError("Sub2API concurrency and priority must be non-negative")
    if load_factor is not None and not 1 <= int(load_factor) <= 10_000:
        raise ValueError("Sub2API load factor must be between 1 and 10000")
    normalized_group_ids = _normalized_group_ids(group_ids, group_id=group_id)

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cpa = build_cpa(session, personal_access_token=token, now=now)
    nested_tokens = (
        session.get("tokens") if isinstance(session.get("tokens"), dict) else {}
    )
    session_access_token = str(
        session.get("accessToken")
        or session.get("access_token")
        or nested_tokens.get("access_token")
        or ""
    )
    access_payload = decode_jwt_payload(session_access_token)
    auth_claim = access_payload.get(OPENAI_AUTH_CLAIM)
    auth_claim = auth_claim if isinstance(auth_claim, dict) else {}
    email = str(cpa.get("email") or "").strip()
    account_id = str(cpa.get("account_id") or "").strip()
    user_id = str(
        auth_claim.get("chatgpt_user_id")
        or auth_claim.get("user_id")
        or ((session.get("user") or {}).get("id") if isinstance(session.get("user"), dict) else "")
        or ""
    ).strip()
    plan_type = str(cpa.get("plan_type") or "").strip()
    name = email or str(cpa.get("name") or "ChatGPT Account").strip()
    exported_at = _iso_utc(now)
    expires_at = (
        _as_utc_datetime(personal_access_token_expires_at)
        or _jwt_expiry(token)
        or _session_expiry(session)
    )
    expires_in = (
        max(0, int((expires_at - now).total_seconds()))
        if expires_at is not None
        else None
    )

    credentials = _without_empty(
        {
            "access_token": token,
            "auth_mode": "personalAccessToken",
            "openai_auth_mode": "personal_access_token",
            "token_type": "Bearer",
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": user_id,
            "email": email,
            "expires_at": _iso_utc(expires_at) if expires_at is not None else None,
            "expires_in": expires_in,
            "plan_type": plan_type,
        }
    )
    extra = _without_empty(
        {
            "email": email,
            "email_key": _email_key(email),
            "name": name,
            "auth_provider": "codex_personal_access_token",
            "import_source": "codex_personal_access_token",
            "source": "chatgpt_web_session",
            "last_refresh": exported_at,
        }
    )
    account = {
        "name": name,
        "platform": "openai",
        "type": "oauth",
        "concurrency": int(concurrency),
        "priority": int(priority),
        "credentials": credentials,
        "extra": extra,
    }
    if load_factor is not None:
        account["load_factor"] = int(load_factor)
    if normalized_group_ids:
        account["group_ids"] = list(normalized_group_ids)
    return account


def build_sub2api_export(
    session: Mapping[str, Any],
    *,
    personal_access_token: str,
    concurrency: int = 10,
    priority: int = 1,
    load_factor: int | None = None,
    group_id: int | None = None,
    group_ids: Sequence[int] | None = None,
    personal_access_token_expires_at: Any = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    exported_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    account = build_sub2api_account(
        session,
        personal_access_token=personal_access_token,
        concurrency=concurrency,
        priority=priority,
        load_factor=load_factor,
        group_id=group_id,
        group_ids=group_ids,
        personal_access_token_expires_at=personal_access_token_expires_at,
        now=exported_at,
    )
    return {
        "exported_at": _iso_utc(exported_at),
        "proxies": [],
        "accounts": [account],
    }


def build_sub2api_filename(
    email: str, *, local_time: datetime | None = None
) -> str:
    local_time = local_time or datetime.now().astimezone()
    timestamp = local_time.strftime("%Y-%m-%d_%H-%M-%S")
    return f"{sanitize_file_token(email)}.sub2api.{timestamp}.json"


class Sub2APIClient:
    def __init__(
        self,
        base_url: str,
        email: str = "",
        password: str = "",
        *,
        api_key: str = "",
        totp_secret: str = "",
        timeout: float = 30.0,
        impersonate: str = "chrome145",
        session: Any = None,
    ):
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.email = str(email or "").strip()
        self.password = str(password or "")
        self.api_key = str(api_key or "").strip()
        self.totp_secret = str(totp_secret or "").strip()
        self.timeout = timeout
        self.impersonate = impersonate
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("Sub2API base URL must start with http:// or https://")
        if not self.api_key and (not self.email or not self.password):
            raise ValueError(
                "Sub2API administrator API key or email and password are required"
            )
        if session is None:
            try:
                from curl_cffi import requests as curl_requests
            except ImportError as exc:
                raise RuntimeError("curl_cffi is required for Sub2API requests") from exc
            session = curl_requests.Session()
        self._session = session
        self._access_token = ""

    @property
    def _use_session_auth(self) -> bool:
        has_totp_session = bool(self.email and self.password and self.totp_secret)
        return has_totp_session or not self.api_key

    @property
    def api_base_url(self) -> str:
        return f"{self.base_url}/api/v1"

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "Sub2APIClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()

    @staticmethod
    def _unwrap(payload: Any) -> Any:
        if not isinstance(payload, dict):
            raise Sub2APIError("Sub2API response is not a JSON object")
        if "code" not in payload:
            return payload
        try:
            code = int(payload.get("code") or 0)
        except (TypeError, ValueError):
            code = -1
        if code != 0:
            raise Sub2APIError(str(payload.get("message") or f"Sub2API error code {code}"))
        return payload.get("data")

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: Mapping[str, Any] | None = None,
        authenticated: bool = True,
    ) -> Any:
        if authenticated and self._use_session_auth and not self._access_token:
            self.login()
        headers = {"Accept": "application/json"}
        if path == "/admin" or path.startswith("/admin/"):
            headers["X-Admin-UI-Request"] = "1"
        if path == "/user" or path.startswith("/user/"):
            headers["X-User-UI-Request"] = "1"
        if authenticated:
            if self._use_session_auth:
                headers["Authorization"] = f"Bearer {self._access_token}"
            else:
                headers["x-api-key"] = self.api_key
        response = self._session.request(
            method,
            f"{self.api_base_url}{path}",
            json=dict(json_data) if json_data is not None else None,
            headers=headers,
            impersonate=self.impersonate,
            timeout=self.timeout,
            verify=False,
        )
        try:
            payload = response.json()
        except Exception as exc:
            raise Sub2APIError(
                f"Sub2API HTTP {response.status_code} returned non-JSON content"
            ) from exc
        if not 200 <= response.status_code < 300:
            detail = payload.get("message") if isinstance(payload, dict) else None
            code = payload.get("code") if isinstance(payload, dict) else None
            code_label = f" [{code}]" if code else ""
            raise Sub2APIError(
                f"Sub2API HTTP {response.status_code} on {method.upper()} {path}"
                f"{code_label}: {detail or response.reason}"
            )
        return self._unwrap(payload)

    def login(self) -> None:
        data = self._request(
            "POST",
            "/auth/login",
            json_data={"email": self.email, "password": self.password},
            authenticated=False,
        )
        if isinstance(data, dict) and data.get("requires_2fa") is True:
            if not self.totp_secret:
                raise Sub2APIError(
                    "Sub2API login requires TOTP; configure the administrator TOTP secret"
                )
            temp_token = str(data.get("temp_token") or "").strip()
            if not temp_token:
                raise Sub2APIError("Sub2API 2FA login did not return a temporary token")
            try:
                totp_code = _totp_code(self.totp_secret)
            except ValueError as exc:
                raise Sub2APIError("Sub2API TOTP secret is invalid") from exc
            data = self._request(
                "POST",
                "/auth/login/2fa",
                json_data={"temp_token": temp_token, "totp_code": totp_code},
                authenticated=False,
            )
        token = str((data or {}).get("access_token") if isinstance(data, dict) else "").strip()
        if not token:
            raise Sub2APIError("Sub2API login did not return an access token")
        self._access_token = token

    def export_accounts(
        self, *, account_ids: Sequence[int] | None = None
    ) -> list[dict[str, Any]]:
        query = {"include_proxies": "false"}
        if account_ids:
            query["ids"] = ",".join(str(int(value)) for value in account_ids)
        data = self._request("GET", f"/admin/accounts/data?{urlencode(query)}")
        accounts = data.get("accounts") if isinstance(data, dict) else None
        return [dict(item) for item in (accounts or []) if isinstance(item, dict)]

    def list_accounts(
        self,
        *,
        search: str = "",
        platform: str = "openai",
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        query = urlencode(
            {
                "page": 1,
                "page_size": max(1, min(int(page_size), 1000)),
                "platform": str(platform or "").strip(),
                "search": str(search or "").strip(),
            }
        )
        data = self._request("GET", f"/admin/accounts?{query}")
        items = data.get("items") if isinstance(data, Mapping) else None
        if not isinstance(items, list):
            raise Sub2APIError("Sub2API accounts response is not a paginated list")
        return [dict(item) for item in items if isinstance(item, Mapping)]

    def get_account(self, account_id: int) -> dict[str, Any]:
        data = self._request("GET", f"/admin/accounts/{int(account_id)}")
        if not isinstance(data, Mapping):
            raise Sub2APIError("Sub2API account response is not an object")
        return dict(data)

    def verify_step_up(self) -> None:
        if not self._use_session_auth or not self.totp_secret:
            raise Sub2APIError(
                "Sub2API protected operations require a TOTP-verified administrator session"
            )
        try:
            code = _totp_code(self.totp_secret)
        except ValueError as exc:
            raise Sub2APIError("Sub2API TOTP secret is invalid") from exc
        self._request(
            "POST",
            "/user/totp/step-up",
            json_data={"code": code},
        )

    def list_groups(
        self,
        *,
        platform: str = "",
        include_inactive: bool = False,
    ) -> list[dict[str, Any]]:
        query = urlencode(
            {
                key: value
                for key, value in {
                    "platform": str(platform or "").strip(),
                    "include_inactive": "true" if include_inactive else "",
                }.items()
                if value
            }
        )
        path = "/admin/groups/all" + (f"?{query}" if query else "")
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise Sub2APIError("Sub2API groups response is not a list")
        return [dict(item) for item in data if isinstance(item, Mapping)]

    def selectable_openai_group_ids(self) -> tuple[int, ...]:
        values: set[int] = set()
        for group in self.list_groups(platform="openai"):
            platform = str(group.get("platform") or "openai").strip().casefold()
            status = str(group.get("status") or "active").strip().casefold()
            if platform != "openai" or status != "active":
                continue
            try:
                group_id = int(group.get("id") or 0)
            except (TypeError, ValueError):
                continue
            if group_id > 0:
                values.add(group_id)
        if not values:
            raise Sub2APIError("Sub2API has no selectable active OpenAI groups")
        return tuple(sorted(values))

    @staticmethod
    def _credentials(account: Mapping[str, Any]) -> Mapping[str, Any]:
        value = account.get("credentials")
        return value if isinstance(value, Mapping) else {}

    @classmethod
    def _same_identity(cls, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        left_credentials = cls._credentials(left)
        right_credentials = cls._credentials(right)
        left_account = str(left_credentials.get("chatgpt_account_id") or "").strip()
        right_account = str(right_credentials.get("chatgpt_account_id") or "").strip()
        left_email = str(left_credentials.get("email") or "").strip().casefold()
        right_email = str(right_credentials.get("email") or "").strip().casefold()
        if left_account and right_account and left_email and right_email:
            return left_account == right_account and left_email == right_email
        if left_account and right_account:
            return left_account == right_account
        return bool(left_email and right_email and left_email == right_email)

    @classmethod
    def _same_token(cls, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        left_token = _clean_token(str(cls._credentials(left).get("access_token") or ""))
        right_token = _clean_token(str(cls._credentials(right).get("access_token") or ""))
        return bool(left_token and right_token and left_token == right_token)

    @staticmethod
    def _group_ids(account: Mapping[str, Any]) -> tuple[int, ...]:
        values: set[int] = set()
        raw_group_ids = account.get("group_ids")
        if isinstance(raw_group_ids, (list, tuple, set)):
            for value in raw_group_ids:
                try:
                    group_id = int(value)
                except (TypeError, ValueError):
                    continue
                if group_id > 0:
                    values.add(group_id)
        for key, id_key in (("account_groups", "group_id"), ("groups", "id")):
            raw_groups = account.get(key)
            if not isinstance(raw_groups, (list, tuple)):
                continue
            for item in raw_groups:
                if not isinstance(item, Mapping):
                    continue
                try:
                    group_id = int(item.get(id_key) or 0)
                except (TypeError, ValueError):
                    continue
                if group_id > 0:
                    values.add(group_id)
        return tuple(sorted(values))

    @classmethod
    def _groups_match(cls, remote: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
        expected_group_ids = set(cls._group_ids(expected))
        return not expected_group_ids or expected_group_ids.issubset(cls._group_ids(remote))

    @staticmethod
    def _account_id(account: Mapping[str, Any]) -> int | None:
        try:
            value = int(account.get("id") or 0)
        except (TypeError, ValueError):
            return None
        return value if value > 0 else None

    @classmethod
    def _settings_match(
        cls, remote: Mapping[str, Any], expected: Mapping[str, Any]
    ) -> bool:
        try:
            concurrency_matches = int(remote.get("concurrency") or 0) == int(
                expected.get("concurrency") or 0
            )
            load_factor_matches = int(remote.get("load_factor") or 0) == int(
                expected.get("load_factor") or 0
            )
        except (TypeError, ValueError):
            return False
        return (
            concurrency_matches
            and load_factor_matches
            and cls._group_ids(remote) == cls._group_ids(expected)
        )

    @classmethod
    def _settings_payload(cls, account: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "concurrency": int(account.get("concurrency") or 0),
            "load_factor": int(account.get("load_factor") or 0),
            "group_ids": list(cls._group_ids(account)),
            "confirm_mixed_channel_risk": True,
        }

    @classmethod
    def _account_search(cls, account: Mapping[str, Any]) -> str:
        credentials = cls._credentials(account)
        extra = account.get("extra") if isinstance(account.get("extra"), Mapping) else {}
        return str(
            credentials.get("email")
            or extra.get("email")
            or account.get("name")
            or ""
        ).strip()

    def _matching_account_detail(
        self,
        exported_account: Mapping[str, Any],
        expected: Mapping[str, Any],
    ) -> dict[str, Any]:
        search = self._account_search(exported_account) or self._account_search(expected)
        candidates = self.list_accounts(search=search)
        matches = [
            item
            for item in candidates
            if self._same_identity(item, expected)
            and str(item.get("name") or "") == str(exported_account.get("name") or "")
        ]
        if len(matches) != 1 or self._account_id(matches[0]) is None:
            raise Sub2APIError(
                "Sub2API existing account could not be mapped to one account ID"
            )
        return matches[0]

    @classmethod
    def _create_payload(cls, account: Mapping[str, Any]) -> dict[str, Any]:
        credentials = dict(cls._credentials(account))
        token = _clean_token(str(credentials.pop("access_token", "") or ""))
        if not token:
            raise Sub2APIError("Sub2API account has no personal access token")
        group_ids = list(cls._group_ids(account))
        payload = {
            "access_token": token,
            "name": str(account.get("name") or "").strip(),
            "concurrency": int(account.get("concurrency") or 0),
            "priority": int(account.get("priority") or 0),
            "auto_pause_on_expired": bool(account.get("auto_pause_on_expired", True)),
            "credential_extras": credentials,
            "extra": dict(account.get("extra") or {}) if isinstance(account.get("extra"), Mapping) else {},
            "skip_default_group_bind": bool(group_ids),
        }
        if group_ids:
            payload["group_ids"] = group_ids
            payload["confirm_mixed_channel_risk"] = True
        if account.get("load_factor") is not None:
            payload["load_factor"] = int(account["load_factor"])
        for key in ("expires_at", "rate_multiplier"):
            if account.get(key) is not None:
                payload[key] = account[key]
        return payload

    def push_production_account(
        self,
        account: Mapping[str, Any],
        *,
        dry_run: bool = False,
    ) -> Sub2APIPushResult:
        desired = dict(account)
        desired["concurrency"] = SUB2API_PUSH_CONCURRENCY
        desired["load_factor"] = SUB2API_PUSH_LOAD_FACTOR
        desired["group_ids"] = list(self.selectable_openai_group_ids())
        account_name = str(desired.get("name") or "ChatGPT Account")

        if self.totp_secret:
            self.verify_step_up()
        remote_accounts = self.export_accounts()
        token_matches = [
            remote for remote in remote_accounts if self._same_token(remote, desired)
        ]
        if len(token_matches) > 1:
            raise Sub2APIError(
                f"Sub2API token matches multiple accounts: {account_name}"
            )
        if token_matches:
            detail = self._matching_account_detail(token_matches[0], desired)
            account_id = self._account_id(detail)
            if account_id is None:
                raise Sub2APIError("Sub2API existing account has no valid account ID")
            if self._settings_match(detail, desired):
                return Sub2APIPushResult(
                    action="skipped",
                    account_name=account_name,
                    verified=True,
                    message="Sub2API account and scheduling settings already match",
                    account_id=account_id,
                    group_count=len(self._group_ids(desired)),
                    concurrency=SUB2API_PUSH_CONCURRENCY,
                    load_factor=SUB2API_PUSH_LOAD_FACTOR,
                )
            if dry_run:
                return Sub2APIPushResult(
                    action="would-update",
                    account_name=account_name,
                    verified=False,
                    message="dry run: Sub2API scheduling settings would be updated",
                    account_id=account_id,
                    group_count=len(self._group_ids(desired)),
                    concurrency=SUB2API_PUSH_CONCURRENCY,
                    load_factor=SUB2API_PUSH_LOAD_FACTOR,
                )
            self._request(
                "PUT",
                f"/admin/accounts/{account_id}",
                json_data=self._settings_payload(desired),
            )
            verified = self.get_account(account_id)
            if not self._same_identity(verified, desired) or not self._settings_match(
                verified, desired
            ):
                raise Sub2APIError(
                    f"Sub2API post-update verification failed: {account_name}"
                )
            return Sub2APIPushResult(
                action="updated",
                account_name=account_name,
                verified=True,
                message="Sub2API account scheduling settings updated and verified",
                account_id=account_id,
                group_count=len(self._group_ids(desired)),
                concurrency=SUB2API_PUSH_CONCURRENCY,
                load_factor=SUB2API_PUSH_LOAD_FACTOR,
            )

        if any(self._same_identity(remote, desired) for remote in remote_accounts):
            raise Sub2APIError(
                f"Sub2API account identity already exists with a different token: {account_name}"
            )
        if dry_run:
            return Sub2APIPushResult(
                action="would-create",
                account_name=account_name,
                verified=False,
                message="dry run: Sub2API account would be created",
                group_count=len(self._group_ids(desired)),
                concurrency=SUB2API_PUSH_CONCURRENCY,
                load_factor=SUB2API_PUSH_LOAD_FACTOR,
            )

        created = self._request(
            "POST",
            "/admin/openai/create-from-codex-pat",
            json_data=self._create_payload(desired),
        )
        account_id = self._account_id(created if isinstance(created, Mapping) else {})
        if account_id is None:
            raise Sub2APIError(f"Sub2API create did not return an account ID: {account_name}")
        verified = self.get_account(account_id)
        if not self._same_identity(verified, desired) or not self._settings_match(
            verified, desired
        ):
            raise Sub2APIError(f"Sub2API post-create verification failed: {account_name}")
        return Sub2APIPushResult(
            action="created",
            account_name=account_name,
            verified=True,
            message="Sub2API account created and verified",
            account_id=account_id,
            group_count=len(self._group_ids(desired)),
            concurrency=SUB2API_PUSH_CONCURRENCY,
            load_factor=SUB2API_PUSH_LOAD_FACTOR,
        )

    def push_account(
        self,
        account: Mapping[str, Any],
        *,
        dry_run: bool = False,
    ) -> Sub2APIPushResult:
        account = dict(account)
        account_name = str(account.get("name") or "ChatGPT Account")
        if self.totp_secret:
            self.verify_step_up()
        remote_accounts = self.export_accounts()
        matching_remote = next(
            (remote for remote in remote_accounts if self._same_token(remote, account)),
            None,
        )
        if matching_remote is not None:
            if not self._groups_match(matching_remote, account):
                raise Sub2APIError(
                    f"Sub2API account exists outside the configured group: {account_name}"
                )
            return Sub2APIPushResult(
                action="skipped",
                account_name=account_name,
                verified=True,
                message="Sub2API account already has the same token",
            )
        if any(self._same_identity(remote, account) for remote in remote_accounts):
            raise Sub2APIError(
                f"Sub2API account identity already exists with a different token: {account_name}"
            )
        if dry_run:
            return Sub2APIPushResult(
                action="would-create",
                account_name=account_name,
                verified=False,
                message="dry run: Sub2API account would be created",
            )

        self._request(
            "POST",
            "/admin/openai/create-from-codex-pat",
            json_data=self._create_payload(account),
        )
        matching_remote = next(
            (
                remote
                for remote in self.export_accounts()
                if self._same_token(remote, account)
            ),
            None,
        )
        if matching_remote is None:
            raise Sub2APIError(f"Sub2API post-create verification failed: {account_name}")
        if not self._groups_match(matching_remote, account):
            raise Sub2APIError(
                f"Sub2API post-create group verification failed: {account_name}"
            )
        return Sub2APIPushResult(
            action="created",
            account_name=account_name,
            verified=True,
            message="Sub2API account created and verified",
        )
