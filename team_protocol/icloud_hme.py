from __future__ import annotations

import json
import re
import shlex
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import requests


CORE_SESSION_COOKIE_NAMES = frozenset(
    {
        "X-APPLE-DS-WEB-SESSION-TOKEN",
        "X-APPLE-WEBAUTH-USER",
        "X-APPLE-WEBAUTH-TOKEN",
    }
)
_HME_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62})-maildomainws\.icloud\.com(?:\.cn)?$",
    re.IGNORECASE,
)
_HME_PATHS = frozenset(
    {
        "/v2/hme/list",
        "/v1/hme/generate",
        "/v1/hme/reserve",
        "/v1/hme/activate",
        "/v1/hme/deactivate",
        "/v1/hme/delete",
    }
)
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)


class HmeError(RuntimeError):
    pass


class HmeSessionError(HmeError):
    pass


@dataclass(frozen=True)
class ICloudHmeSession:
    host: str
    dsid: str
    client_id: str
    client_build_number: str
    client_mastering_number: str
    cookie: str
    lang_code: str = "en-us"
    origin: str = "https://www.icloud.com"
    referer: str = "https://www.icloud.com/"
    user_agent: str = _DEFAULT_USER_AGENT

    def as_secret_dict(self) -> dict[str, str]:
        return {
            "host": self.host,
            "dsid": self.dsid,
            "client_id": self.client_id,
            "client_build_number": self.client_build_number,
            "client_mastering_number": self.client_mastering_number,
            "cookie": self.cookie,
            "lang_code": self.lang_code,
            "origin": self.origin,
            "referer": self.referer,
            "user_agent": self.user_agent,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ICloudHmeSession":
        try:
            session = cls(
                host=str(value["host"]).strip().lower(),
                dsid=str(value["dsid"]).strip(),
                client_id=str(value["client_id"]).strip(),
                client_build_number=str(value["client_build_number"]).strip(),
                client_mastering_number=str(value["client_mastering_number"]).strip(),
                cookie=str(value["cookie"]).strip(),
                lang_code=str(value.get("lang_code") or "en-us").strip(),
                origin=str(value.get("origin") or "https://www.icloud.com").strip(),
                referer=str(value.get("referer") or "https://www.icloud.com/").strip(),
                user_agent=str(value.get("user_agent") or _DEFAULT_USER_AGENT).strip(),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HmeSessionError("iCloud HME session is incomplete") from exc
        _validate_session(session)
        return session


def parse_hme_session_import(text: str) -> ICloudHmeSession:
    source = str(text or "").strip()
    if not source:
        raise HmeSessionError("paste an iCloud HME cURL command or HAR document")
    try:
        document = json.loads(source)
    except json.JSONDecodeError:
        return _parse_curl(source)
    if not isinstance(document, Mapping) or not isinstance(document.get("log"), Mapping):
        raise HmeSessionError("session import must be a cURL command or HAR document")
    return _parse_har(document)


def parse_hme_request(
    url: str,
    headers: Mapping[str, Any],
    *,
    cookies: Any = None,
) -> ICloudHmeSession:
    """Build a validated HME session from one captured browser request."""

    if _validated_hme_url(str(url or "")).path != "/v2/hme/list":
        raise HmeSessionError("captured iCloud HME request is not the list endpoint")
    normalized_headers = {
        str(name).strip().casefold(): str(value).strip()
        for name, value in dict(headers or {}).items()
        if str(name).strip() and str(value).strip()
    }
    cookie = normalized_headers.get("cookie", "")
    if not cookie:
        pairs: list[str] = []
        if isinstance(cookies, Mapping) and not {
            "name",
            "value",
        }.issubset(cookies):
            iterable: Any = [
                {"name": name, "value": value}
                for name, value in cookies.items()
            ]
        elif isinstance(cookies, Mapping):
            iterable = [cookies]
        else:
            iterable = cookies or ()
        for item in iterable:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name") or "").strip()
            value = str(item.get("value") or "").strip()
            if name:
                pairs.append(f"{name}={value}")
        cookie = "; ".join(pairs)
    normalized_headers["cookie"] = cookie
    return _session_from_request(str(url or ""), cookie, normalized_headers)


def _parse_curl(text: str) -> ICloudHmeSession:
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise HmeSessionError("cURL command has invalid quoting") from exc
    if not tokens or tokens[0].rsplit("/", 1)[-1].casefold() not in {"curl", "curl.exe"}:
        raise HmeSessionError("session import is not a cURL command")

    url = ""
    headers: dict[str, str] = {}
    cookie = ""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-H", "--header"} and index + 1 < len(tokens):
            index += 1
            _record_header(headers, tokens[index])
        elif token.startswith("--header="):
            _record_header(headers, token.split("=", 1)[1])
        elif token in {"-b", "--cookie"} and index + 1 < len(tokens):
            index += 1
            cookie = tokens[index]
        elif token.startswith("--cookie="):
            cookie = token.split("=", 1)[1]
        elif token == "--url" and index + 1 < len(tokens):
            index += 1
            url = tokens[index]
        elif token.startswith("https://") and not url:
            url = token
        index += 1
    cookie = cookie or headers.get("cookie", "")
    return _session_from_request(url, cookie, headers)


def _parse_har(document: Mapping[str, Any]) -> ICloudHmeSession:
    entries = document.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise HmeSessionError("HAR log.entries must be a list")
    fallback: Mapping[str, Any] | None = None
    selected: Mapping[str, Any] | None = None
    for entry in entries:
        request = entry.get("request") if isinstance(entry, Mapping) else None
        if not isinstance(request, Mapping):
            continue
        try:
            parsed = _validated_hme_url(str(request.get("url") or ""))
        except HmeSessionError:
            continue
        fallback = fallback or request
        if parsed.path == "/v2/hme/list":
            selected = request
            break
    selected = selected or fallback
    if selected is None:
        raise HmeSessionError("HAR contains no iCloud HME request")

    headers: dict[str, str] = {}
    for item in selected.get("headers", []):
        if isinstance(item, Mapping):
            name = str(item.get("name") or "").strip().casefold()
            value = str(item.get("value") or "").strip()
            if name and value:
                headers[name] = value
    cookie = headers.get("cookie", "")
    if not cookie:
        pairs = []
        for item in selected.get("cookies", []):
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("name") or "").strip()
            value = str(item.get("value") or "").strip()
            if name:
                pairs.append(f"{name}={value}")
        cookie = "; ".join(pairs)
    return _session_from_request(str(selected.get("url") or ""), cookie, headers)


def _record_header(headers: dict[str, str], raw: str) -> None:
    name, separator, value = str(raw or "").partition(":")
    if separator and name.strip() and value.strip():
        headers[name.strip().casefold()] = value.strip()


def _session_from_request(
    url: str, cookie: str, headers: Mapping[str, str]
) -> ICloudHmeSession:
    parsed = _validated_hme_url(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def query_value(name: str) -> str:
        values = query.get(name)
        value = str(values[0]).strip() if values else ""
        if not value:
            raise HmeSessionError(f"iCloud HME request is missing {name}")
        return value

    origin = str(headers.get("origin") or _default_origin(parsed.hostname or "")).strip()
    referer = str(headers.get("referer") or f"{origin}/").strip()
    user_agent = str(headers.get("user-agent") or _DEFAULT_USER_AGENT).strip()
    session = ICloudHmeSession(
        host=str(parsed.hostname or "").lower(),
        dsid=query_value("dsid"),
        client_id=query_value("clientId"),
        client_build_number=query_value("clientBuildNumber"),
        client_mastering_number=query_value("clientMasteringNumber"),
        cookie=str(cookie or "").strip(),
        origin=origin,
        referer=referer,
        user_agent=user_agent,
    )
    _validate_session(session)
    return session


def _validated_hme_url(value: str) -> urllib.parse.ParseResult:
    try:
        parsed = urllib.parse.urlparse(str(value or "").strip())
        port = parsed.port
    except ValueError as exc:
        raise HmeSessionError("iCloud HME request URL is invalid") from exc
    host = str(parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or not _HME_HOST_RE.fullmatch(host)
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        raise HmeSessionError("iCloud HME request host is not allowed")
    if parsed.path not in _HME_PATHS:
        raise HmeSessionError("iCloud HME request path is not allowed")
    return parsed


def _default_origin(host: str) -> str:
    return "https://www.icloud.com.cn" if host.endswith(".icloud.com.cn") else "https://www.icloud.com"


def _validate_session(session: ICloudHmeSession) -> None:
    if not _HME_HOST_RE.fullmatch(session.host):
        raise HmeSessionError("iCloud HME session host is not allowed")
    for name, value in (
        ("dsid", session.dsid),
        ("client_id", session.client_id),
        ("client_build_number", session.client_build_number),
        ("client_mastering_number", session.client_mastering_number),
        ("cookie", session.cookie),
        ("user_agent", session.user_agent),
    ):
        if not value or "\r" in value or "\n" in value:
            raise HmeSessionError(f"iCloud HME session {name} is invalid")
    cookie_names = {
        part.partition("=")[0].strip()
        for part in session.cookie.split(";")
        if part.partition("=")[0].strip()
    }
    missing = sorted(CORE_SESSION_COOKIE_NAMES - cookie_names)
    if missing:
        raise HmeSessionError("iCloud HME session Cookie is incomplete")
    expected_origin = _default_origin(session.host)
    if session.origin.rstrip("/") != expected_origin:
        raise HmeSessionError("iCloud HME session Origin is invalid")
    if not session.referer.startswith(f"{expected_origin}/"):
        raise HmeSessionError("iCloud HME session Referer is invalid")


Requester = Callable[..., Any]


class HmeClient:
    def __init__(
        self,
        session: ICloudHmeSession,
        *,
        proxy: str = "",
        timeout: float = 20.0,
        requester: Requester = requests.request,
    ) -> None:
        _validate_session(session)
        self.session = session
        self.proxy = str(proxy or "").strip()
        self.timeout = max(1.0, min(float(timeout), 60.0))
        self.requester = requester

    def list_settings(self) -> dict[str, Any]:
        response = self._request("GET", "/v2/hme/list")
        result = response.get("result")
        if not isinstance(result, dict):
            raise HmeError("iCloud HME list response is invalid")
        return result

    def list_aliases(self) -> list[dict[str, Any]]:
        aliases = self.list_settings().get("hmeEmails") or []
        if not isinstance(aliases, list):
            raise HmeError("iCloud HME alias list is invalid")
        return [dict(item) for item in aliases if isinstance(item, Mapping)]

    def generate_alias(self) -> str:
        response = self._request(
            "POST", "/v1/hme/generate", {"langCode": self.session.lang_code}
        )
        value = (response.get("result") or {}).get("hme")
        email = str(value or "").strip().casefold()
        if email.count("@") != 1:
            raise HmeError("iCloud HME generate response is invalid")
        return email

    def reserve_alias(self, email: str, *, label: str, note: str = "") -> dict[str, Any]:
        response = self._request(
            "POST",
            "/v1/hme/reserve",
            {"hme": str(email).strip(), "label": str(label).strip(), "note": str(note).strip()},
        )
        alias = (response.get("result") or {}).get("hme")
        if not isinstance(alias, Mapping):
            raise HmeError("iCloud HME reserve response is invalid")
        return dict(alias)

    def create_alias(self, *, label: str, note: str = "") -> dict[str, Any]:
        candidate = self.generate_alias()
        return self.reserve_alias(candidate, label=label, note=note)

    def activate_alias(self, anonymous_id: str) -> None:
        self._request("POST", "/v1/hme/activate", {"anonymousId": str(anonymous_id).strip()})

    def deactivate_alias(self, anonymous_id: str) -> None:
        self._request("POST", "/v1/hme/deactivate", {"anonymousId": str(anonymous_id).strip()})

    def _request(
        self, method: str, path: str, payload: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        params = urllib.parse.urlencode(
            {
                "clientBuildNumber": self.session.client_build_number,
                "clientMasteringNumber": self.session.client_mastering_number,
                "clientId": self.session.client_id,
                "dsid": self.session.dsid,
            }
        )
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        try:
            requester = self.requester
            if requester is requests.request:
                # An empty HME proxy means an intentional direct connection;
                # do not silently inherit the process-wide Clash environment.
                session = requests.Session()
                session.trust_env = False
                requester = session.request
            response = requester(
                method,
                f"https://{self.session.host}{path}?{params}",
                headers={
                    "Accept": "*/*",
                    "Content-Type": "text/plain",
                    "Cookie": self.session.cookie,
                    "Origin": self.session.origin,
                    "Referer": self.session.referer,
                    "User-Agent": self.session.user_agent,
                },
                data=(
                    json.dumps(dict(payload), ensure_ascii=True, separators=(",", ":"))
                    if payload is not None
                    else None
                ),
                proxies=proxies,
                timeout=self.timeout,
            )
        except (requests.RequestException, OSError, TimeoutError) as exc:
            raise HmeError("iCloud HME request failed") from exc
        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code in {401, 403, 421}:
            raise HmeSessionError("iCloud HME session is expired or rejected")
        if status_code < 200 or status_code >= 300:
            raise HmeError(f"iCloud HME request returned HTTP {status_code or 'unknown'}")
        try:
            body = response.json()
        except (TypeError, ValueError) as exc:
            raise HmeError("iCloud HME response is not JSON") from exc
        if not isinstance(body, dict):
            raise HmeError("iCloud HME response is invalid")
        if body.get("success") is not True:
            code = _safe_error_code(body)
            suffix = f" ({code})" if code else ""
            raise HmeError(f"iCloud HME rejected the request{suffix}")
        return body


def _safe_error_code(payload: Mapping[str, Any]) -> str:
    candidates: list[Any] = [payload.get("errorCode"), payload.get("code")]
    error = payload.get("error")
    if isinstance(error, Mapping):
        candidates.extend((error.get("errorCode"), error.get("code")))
    for value in candidates:
        text = str(value or "").strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", text):
            return text
    return ""
