from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlparse


DEFAULT_OPENBROWSER_BASE_URL = "http://127.0.0.1:50325"
DEFAULT_OPENBROWSER_LOGIN_URL = "https://chatgpt.com/"
_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_CHATGPT_HOSTS = frozenset({"chatgpt.com", "www.chatgpt.com"})
_AUTH_HOSTS = frozenset({"auth.openai.com"})
_SESSION_COOKIE_NAMES = (
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
)


class OpenBrowserError(RuntimeError):
    pass


@dataclass(frozen=True)
class OpenBrowserProfile:
    profile_id: str
    name: str
    running: bool
    debug_port: int | None = None


def _session_cookie_token(cookies: Any) -> str:
    values = {
        str(cookie.get("name") or "").strip(): str(cookie.get("value") or "").strip()
        for cookie in (cookies if isinstance(cookies, list) else [])
        if isinstance(cookie, Mapping)
    }
    for base_name in _SESSION_COOKIE_NAMES:
        direct = values.get(base_name, "")
        if direct:
            return direct
        chunks = sorted(
            (
                (int(name[len(base_name) + 1 :]), value)
                for name, value in values.items()
                if name.startswith(f"{base_name}.")
                and name[len(base_name) + 1 :].isdigit()
                and value
            ),
            key=lambda item: item[0],
        )
        if chunks:
            return "".join(value for _index, value in chunks)
    return ""


def read_chatgpt_session(context: Any) -> dict[str, Any] | None:
    pages = list(getattr(context, "pages", []) or [])
    for page in reversed(pages):
        parsed = urlparse(str(getattr(page, "url", "") or ""))
        if str(parsed.hostname or "").casefold() not in _CHATGPT_HOSTS:
            continue
        try:
            result = page.evaluate(
                """async () => {
                    const response = await fetch('/api/auth/session', {
                        credentials: 'include',
                    });
                    let data = null;
                    try { data = await response.json(); } catch (_) {}
                    return {status: response.status, data};
                }"""
            )
        except Exception:
            continue
        if not isinstance(result, Mapping) or int(result.get("status") or 0) != 200:
            continue
        payload = result.get("data") if isinstance(result.get("data"), Mapping) else {}
        access_token = str(payload.get("accessToken") or "").strip()
        user = payload.get("user") if isinstance(payload.get("user"), Mapping) else {}
        email = str(user.get("email") or "").strip()
        try:
            cookies = context.cookies(["https://chatgpt.com"])
        except TypeError:
            cookies = context.cookies()
        except Exception:
            cookies = []
        session_token = str(payload.get("sessionToken") or "").strip() or _session_cookie_token(
            cookies
        )
        if access_token and session_token and email:
            return {
                "access_token": access_token,
                "refresh_token": "",
                "session_token": session_token,
                "email": email,
                "token_source": "openbrowser_manual",
                "type": "codex",
            }
    return None


def validate_openbrowser_base_url(value: str) -> str:
    raw = str(value or "").strip().rstrip("/")
    parsed = urlparse(raw)
    if (
        parsed.scheme != "http"
        or str(parsed.hostname or "").casefold() not in _LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("OpenBrowser API URL must be a loopback HTTP origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("OpenBrowser API URL has an invalid port") from exc
    if port is None or not 1 <= port <= 65535:
        raise ValueError("OpenBrowser API URL must include a valid port")
    host = f"[{parsed.hostname}]" if ":" in str(parsed.hostname or "") else parsed.hostname
    return f"http://{host}:{port}"


def validate_openbrowser_profile_id(value: Any) -> str:
    profile_id = str(value or "").strip()
    if not _PROFILE_ID_RE.fullmatch(profile_id):
        raise ValueError("OpenBrowser profile ID is invalid")
    return profile_id


def parse_openbrowser_profile_ids(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        raw_values = re.split(r"[\s,]+", value.strip()) if value.strip() else []
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        raw_values = list(value)
    else:
        raise ValueError("OpenBrowser profile pool is invalid")
    profile_ids: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        profile_id = validate_openbrowser_profile_id(raw_value)
        if profile_id in seen:
            continue
        profile_ids.append(profile_id)
        seen.add(profile_id)
    if len(profile_ids) > 200:
        raise ValueError("OpenBrowser profile pool is too large")
    return tuple(profile_ids)


def choose_openbrowser_profile(
    profiles: Iterable[OpenBrowserProfile],
    configured_ids: Sequence[str],
    bound_ids: Iterable[str],
    *,
    existing_id: str = "",
) -> OpenBrowserProfile:
    by_id = {profile.profile_id: profile for profile in profiles}
    if existing_id:
        profile_id = validate_openbrowser_profile_id(existing_id)
        profile = by_id.get(profile_id)
        if profile is None:
            raise OpenBrowserError("bound OpenBrowser profile is unavailable")
        return profile
    bound = {validate_openbrowser_profile_id(value) for value in bound_ids if value}
    for raw_profile_id in configured_ids:
        profile_id = validate_openbrowser_profile_id(raw_profile_id)
        profile = by_id.get(profile_id)
        if profile is not None and not profile.running and profile_id not in bound:
            return profile
    raise OpenBrowserError("no unused OpenBrowser profile is available")


class OpenBrowserClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 10.0,
        session: Any = None,
    ) -> None:
        self.base_url = validate_openbrowser_base_url(base_url)
        self.api_key = str(api_key or "").strip()
        if not self.api_key:
            raise ValueError("OpenBrowser API key is required")
        self.timeout = max(0.1, float(timeout))
        import requests

        self._request_errors = (requests.RequestException, OSError, TimeoutError)
        if session is None:
            self._session = requests.Session()
            self._owns_session = True
        else:
            self._session = session
            self._owns_session = False

    def close(self) -> None:
        if self._owns_session:
            self._session.close()

    def __enter__(self) -> "OpenBrowserClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        try:
            response = self._session.request(
                method,
                f"{self.base_url}{path}",
                headers={"api-key": self.api_key, "Accept": "application/json"},
                json=None if payload is None else dict(payload),
                timeout=self.timeout,
            )
        except self._request_errors as exc:
            raise OpenBrowserError("OpenBrowser Local API is unavailable") from exc
        if not 200 <= int(response.status_code) < 300:
            raise OpenBrowserError(
                f"OpenBrowser Local API returned HTTP {int(response.status_code)}"
            )
        try:
            envelope = response.json()
        except Exception as exc:
            raise OpenBrowserError("OpenBrowser Local API returned invalid JSON") from exc
        if not isinstance(envelope, Mapping):
            raise OpenBrowserError("OpenBrowser Local API returned an invalid envelope")
        try:
            code = int(envelope.get("code"))
        except (TypeError, ValueError) as exc:
            raise OpenBrowserError("OpenBrowser Local API returned an invalid envelope") from exc
        if code != 0:
            raise OpenBrowserError(f"OpenBrowser Local API rejected the request ({code})")
        return envelope.get("data")

    def version(self) -> str:
        data = self._request("GET", "/api/getVersion")
        if not isinstance(data, Mapping):
            raise OpenBrowserError("OpenBrowser version response is invalid")
        version = str(data.get("version") or "").strip()
        if not version:
            raise OpenBrowserError("OpenBrowser version response is incomplete")
        return version

    def list_profiles(self) -> list[OpenBrowserProfile]:
        data = self._request("GET", "/api/v1/user/list")
        raw_profiles = data.get("list") if isinstance(data, Mapping) else None
        if not isinstance(raw_profiles, list):
            raise OpenBrowserError("OpenBrowser profile response is invalid")
        profiles: list[OpenBrowserProfile] = []
        for item in raw_profiles:
            if not isinstance(item, Mapping):
                raise OpenBrowserError("OpenBrowser profile response is invalid")
            try:
                profile_id = validate_openbrowser_profile_id(
                    item.get("profile_id") or item.get("user_id")
                )
            except ValueError as exc:
                raise OpenBrowserError("OpenBrowser profile response is invalid") from exc
            status = str(item.get("status") or "").strip().casefold()
            raw_port = item.get("debug_port")
            debug_port = None
            if raw_port not in {None, ""}:
                try:
                    parsed_port = int(raw_port)
                except (TypeError, ValueError) as exc:
                    raise OpenBrowserError("OpenBrowser profile response is invalid") from exc
                if not 1 <= parsed_port <= 65535:
                    raise OpenBrowserError("OpenBrowser profile response is invalid")
                debug_port = parsed_port
            running = status == "active"
            if running and debug_port is None:
                raise OpenBrowserError("OpenBrowser active profile has no debug port")
            profiles.append(
                OpenBrowserProfile(
                    profile_id=profile_id,
                    name=str(item.get("name") or "").strip(),
                    running=running,
                    debug_port=debug_port,
                )
            )
        return profiles

    def start_profile(self, profile_id: str) -> OpenBrowserProfile:
        clean_id = validate_openbrowser_profile_id(profile_id)
        data = self._request(
            "POST", "/api/v1/browser/start", payload={"user_id": clean_id}
        )
        if not isinstance(data, Mapping):
            raise OpenBrowserError("OpenBrowser start response is invalid")
        returned_id = validate_openbrowser_profile_id(
            data.get("profile_id") or data.get("user_id")
        )
        if returned_id != clean_id:
            raise OpenBrowserError("OpenBrowser started an unexpected profile")
        try:
            debug_port = int(data.get("debug_port") or 0)
        except (TypeError, ValueError) as exc:
            raise OpenBrowserError("OpenBrowser start response has no debug port") from exc
        if not 1 <= debug_port <= 65535:
            raise OpenBrowserError("OpenBrowser start response has no debug port")
        return OpenBrowserProfile(
            profile_id=clean_id,
            name="",
            running=True,
            debug_port=debug_port,
        )

    def stop_profile(self, profile_id: str) -> None:
        clean_id = validate_openbrowser_profile_id(profile_id)
        data = self._request(
            "POST", "/api/v1/browser/stop", payload={"user_id": clean_id}
        )
        if not isinstance(data, Mapping):
            raise OpenBrowserError("OpenBrowser stop response is invalid")
        returned_id = validate_openbrowser_profile_id(
            data.get("profile_id") or data.get("user_id")
        )
        if returned_id != clean_id:
            raise OpenBrowserError("OpenBrowser stopped an unexpected profile")


class OpenBrowserManualLogin:
    def __init__(
        self,
        client: OpenBrowserClient,
        profile_id: str,
        *,
        expected_email: str,
        timeout_seconds: float,
        poll_seconds: float = 1.0,
        login_url: str = DEFAULT_OPENBROWSER_LOGIN_URL,
        status_callback: Callable[[str], Any] | None = None,
        playwright_factory: Callable[[], Any] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.profile_id = validate_openbrowser_profile_id(profile_id)
        self.expected_email = str(expected_email or "").strip().casefold()
        if self.expected_email.count("@") != 1:
            raise ValueError("expected OpenBrowser login email is invalid")
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.poll_seconds = max(0.1, float(poll_seconds))
        parsed_login_url = urlparse(str(login_url or ""))
        if (
            parsed_login_url.scheme != "https"
            or str(parsed_login_url.hostname or "").casefold()
            not in (_CHATGPT_HOSTS | _AUTH_HOSTS)
        ):
            raise ValueError("OpenBrowser login URL is not an official auth page")
        self.login_url = str(login_url)
        self.status_callback = status_callback
        self.playwright_factory = playwright_factory
        self.monotonic = monotonic

    def _status(self, value: str) -> None:
        if self.status_callback is not None:
            self.status_callback(str(value))

    @staticmethod
    def _page_for_manual_login(context: Any, login_url: str) -> Any:
        pages = list(getattr(context, "pages", []) or [])
        for page in reversed(pages):
            host = str(urlparse(str(getattr(page, "url", "") or "")).hostname or "").casefold()
            if host in (_CHATGPT_HOSTS | _AUTH_HOSTS):
                try:
                    page.bring_to_front()
                except Exception:
                    pass
                return page
        page = context.new_page()
        page.goto(login_url, wait_until="domcontentloaded", timeout=30_000)
        try:
            page.bring_to_front()
        except Exception:
            pass
        return page

    def wait(
        self,
        *,
        session_validator: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        login_runner: Callable[[Any, Any], Mapping[str, Any]] | None = None,
        stop_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        if not callable(session_validator):
            raise TypeError("OpenBrowser session validator is required")
        started = self.client.start_profile(self.profile_id)
        if started.debug_port is None:
            raise OpenBrowserError("OpenBrowser start response has no debug port")
        self._status("profile_started")
        try:
            if self.playwright_factory is None:
                from playwright.sync_api import sync_playwright

                playwright_factory = sync_playwright
            else:
                playwright_factory = self.playwright_factory
            deadline = self.monotonic() + self.timeout_seconds
            with playwright_factory() as playwright:
                try:
                    browser = playwright.chromium.connect_over_cdp(
                        f"http://127.0.0.1:{started.debug_port}", timeout=30_000
                    )
                except Exception as exc:
                    raise OpenBrowserError("OpenBrowser CDP connection failed") from exc
                contexts = list(getattr(browser, "contexts", []) or [])
                if len(contexts) != 1:
                    raise OpenBrowserError("OpenBrowser profile context is unavailable")
                context = contexts[0]
                page = self._page_for_manual_login(context, self.login_url)
                if stop_event is not None and stop_event.is_set():
                    raise OpenBrowserError("OpenBrowser automatic login was cancelled")
                if not bool(browser.is_connected()):
                    raise OpenBrowserError("OpenBrowser profile was closed")
                session = read_chatgpt_session(context)
                if session is not None and (
                    str(session.get("email") or "").strip().casefold()
                    != self.expected_email
                ):
                    self._status("wrong_account")
                    raise OpenBrowserError(
                        "OpenBrowser profile is logged in to a different account"
                    )
                if session is None:
                    if not callable(login_runner):
                        raise OpenBrowserError(
                            "OpenBrowser automatic login runner is unavailable"
                        )
                    self._status("automating_login")
                    session = login_runner(context, page)
                    if not isinstance(session, Mapping):
                        raise OpenBrowserError(
                            "OpenBrowser automatic login returned invalid session data"
                        )
                    session = dict(session)
                    if (
                        str(session.get("email") or "").strip().casefold()
                        != self.expected_email
                    ):
                        self._status("wrong_account")
                        raise OpenBrowserError(
                            "OpenBrowser automatic login returned a different account"
                        )
                waiting_for_team_reported = False
                while True:
                    if stop_event is not None and stop_event.is_set():
                        raise OpenBrowserError("OpenBrowser automatic login was cancelled")
                    if not bool(browser.is_connected()):
                        raise OpenBrowserError("OpenBrowser profile was closed")
                    latest_session = read_chatgpt_session(context)
                    if latest_session is not None:
                        session = latest_session
                    if session is not None:
                        if str(session.get("email") or "").strip().casefold() != self.expected_email:
                            self._status("wrong_account")
                            raise OpenBrowserError(
                                "OpenBrowser profile is logged in to a different account"
                            )
                        else:
                            try:
                                validated = session_validator(session)
                            except Exception:
                                if not waiting_for_team_reported:
                                    self._status("waiting_for_team")
                                    waiting_for_team_reported = True
                            else:
                                if not isinstance(validated, Mapping):
                                    raise OpenBrowserError(
                                        "OpenBrowser session validator returned invalid data"
                                    )
                                self._status("verified")
                                return dict(validated)
                    if self.monotonic() >= deadline:
                        break
                    wait_page = page
                    if bool(getattr(wait_page, "is_closed", lambda: False)()):
                        pages = list(getattr(context, "pages", []) or [])
                        if not pages:
                            raise OpenBrowserError("OpenBrowser automatic login page was closed")
                        wait_page = pages[-1]
                        page = wait_page
                    wait_page.wait_for_timeout(int(self.poll_seconds * 1000))
            raise OpenBrowserError("OpenBrowser automatic login timed out")
        finally:
            self.client.stop_profile(self.profile_id)
            self._status("profile_stopped")
