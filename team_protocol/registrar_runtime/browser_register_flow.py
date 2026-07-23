from __future__ import annotations

import queue
import threading
import time
from typing import Any, Dict, Optional, Sequence
from urllib.parse import parse_qs, urlparse

from ..playwright_proxy import PlaywrightProxyLease, apply_playwright_proxy
from .fingerprint_profiles import SessionProfile, create_session_profile
from .sentinel_browser import create_browserforge_context


CHATGPT_BASE = "https://chatgpt.com"
AUTH_BASE = "https://auth.openai.com"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_CHATGPT_WARMUP_WAIT_MS = 2500
DEFAULT_CHATGPT_READY_TIMEOUT_SECONDS = 30
DEFAULT_CHATGPT_READY_POLL_INTERVAL_MS = 250
DEFAULT_STAGE_TIMEOUT_SECONDS = 30
DEFAULT_OTP_AUTO_SUBMIT_GRACE_MS = 750
DEFAULT_FLOW_TIMEOUT_BUFFER_SECONDS = 90
MAX_DISCOVERED_CONTROLS = 16

_CHALLENGE_MARKERS = (
    "just a moment",
    "performing security verification",
    "security verification",
    "verify you are human",
    "captcha",
    "cf-turnstile",
    "challenge-platform",
    "cf_chl",
)

_PHONE_MARKERS = (
    "add-phone",
    "phone verification",
    "phone_verification",
    "phone-required",
    "verify your phone",
)

_MANUAL_CONFIRMATION_PATH_MARKERS = (
    "terms-confirmation",
    "confirm-terms",
    "age-verification",
    "verify-age",
)

_AUTH_MANUAL_SELECTION_PATH_MARKERS = (
    "/consent",
    "/workspace",
    "/organization",
)

_SESSION_COOKIE_NAMES = (
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
)

_EMAIL_SELECTORS = (
    'input[type="email"][name="email"]',
    'input[autocomplete="email"]',
    'input[type="email"]',
)

_PASSWORD_SELECTORS = (
    'input[type="password"][name="password"]',
    'input[autocomplete="new-password"]',
    'input[type="password"]',
)

_OTP_COMBINED_SELECTORS = (
    'input[autocomplete="one-time-code"]',
    'input[name="code"]',
    'input[name="otp"]',
    'input[name="otp_code"]',
    'input[name="verification_code"]',
    'input[inputmode="numeric"][maxlength="6"]',
)

_OTP_SEGMENT_SELECTORS = (
    'input[inputmode="numeric"][maxlength="1"]',
    'input[autocomplete="one-time-code"][maxlength="1"]',
)

_PROFILE_NAME_SELECTORS = (
    'input[name="name"]',
    'input[name="full_name"]',
    'input[name="full-name"]',
    'input[name="fullName"]',
    'input[autocomplete="name"]',
)

_PROFILE_BIRTHDATE_SELECTORS = (
    'input[name="birthdate"]',
    'input[name="birthday"]',
    'input[name="dob"]',
    'input[name="date_of_birth"]',
    'input[autocomplete="bday"]',
    'input[type="date"]',
)

_BIRTH_MONTH_SELECTORS = (
    'input[name="birth-month"]',
    'input[name="birth_month"]',
    'input[name*="birth"][name*="month"]',
    'input[autocomplete="bday-month"]',
    'input[placeholder="MM"]',
)

_BIRTH_DAY_SELECTORS = (
    'input[name="birth-day"]',
    'input[name="birth_day"]',
    'input[name*="birth"][name*="day"]',
    'input[autocomplete="bday-day"]',
    'input[placeholder="DD"]',
)

_BIRTH_YEAR_SELECTORS = (
    'input[name="birth-year"]',
    'input[name="birth_year"]',
    'input[name*="birth"][name*="year"]',
    'input[autocomplete="bday-year"]',
    'input[placeholder="YYYY"]',
)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _first_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _contains_any(value: Any, markers: Sequence[str]) -> bool:
    text = str(value or "").strip().casefold()
    return any(marker in text for marker in markers)


def _looks_like_challenge_page(title: str, body_text: str) -> bool:
    return _contains_any(f"{title}\n{body_text}", _CHALLENGE_MARKERS)


def _looks_phone_gate(*values: Any) -> bool:
    return _contains_any("\n".join(str(value or "") for value in values), _PHONE_MARKERS)


class PlaywrightBrowserFlow:
    def __init__(
        self,
        *,
        config: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
        user_agent: str = "",
        session_profile: Optional[SessionProfile] = None,
        emitter: Any = None,
    ) -> None:
        self.config = dict(config or {})
        self.proxy = str(proxy or "").strip()
        supplied_user_agent = str(user_agent or "").strip()
        self.session_profile = session_profile or create_session_profile(
            user_agent=supplied_user_agent
        )
        if supplied_user_agent and supplied_user_agent != self.session_profile.user_agent:
            raise ValueError("user_agent conflicts with the supplied SessionProfile")
        self.user_agent = self.session_profile.user_agent
        self.emitter = emitter
        self._profile_dir = str(self.config.get("profile_dir") or "").strip()
        self._cleanup_profile_dir = False
        self._playwright_cm = None
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._proxy_lease = None

    def _log(self, level: str, message: str, step: str = "browser_flow") -> None:
        emitter = self.emitter
        if emitter is None:
            return
        try:
            getattr(emitter, level)(message, step=step)
        except Exception:
            try:
                emitter.emit(level, message, step=step)
            except Exception:
                pass

    def _resolve_profile_dir(self) -> Optional[str]:
        if self._profile_dir:
            return self._profile_dir
        return None

    def _navigation_timeout_ms(self) -> int:
        configured = self.config.get("navigation_timeout_seconds")
        if configured is None:
            configured = min(
                30.0,
                float(self.config.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS),
            )
        return max(1000, int(float(configured) * 1000))

    def _stage_timeout_seconds(self) -> float:
        return max(
            0.01,
            float(
                self.config.get("stage_timeout_seconds")
                or DEFAULT_STAGE_TIMEOUT_SECONDS
            ),
        )

    def _flow_timeout_seconds(self) -> float:
        configured = self.config.get("flow_timeout_seconds")
        if configured is not None:
            return max(1.0, float(configured))
        return max(
            60.0,
            float(self.config.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
            + DEFAULT_FLOW_TIMEOUT_BUFFER_SECONDS,
        )

    def open(self) -> None:
        if self._context is not None and self._page is not None:
            return
        from playwright.sync_api import sync_playwright

        self._playwright_cm = sync_playwright()
        self._playwright = self._playwright_cm.start()
        launch_options: Dict[str, Any] = {
            "headless": _coerce_bool(self.config.get("headless", False), default=False)
        }
        self._proxy_lease = PlaywrightProxyLease(self.proxy)
        self._proxy_lease.__enter__()
        launch_options = apply_playwright_proxy(launch_options, self._proxy_lease)
        self._browser = self._playwright.chromium.launch(**launch_options)
        self._context = create_browserforge_context(
            self._browser,
            fingerprint_scope=self.session_profile.scope,
            session_profile=self.session_profile,
        )
        self._page = self._context.new_page()

    def close(self) -> None:
        for resource_name in ("_page", "_context", "_browser"):
            resource = getattr(self, resource_name, None)
            if resource is None:
                continue
            try:
                resource.close()
            except Exception:
                pass
            setattr(self, resource_name, None)
        if self._playwright_cm is not None:
            try:
                self._playwright_cm.stop()
            except Exception:
                pass
        self._playwright_cm = None
        self._playwright = None
        if self._proxy_lease is not None:
            self._proxy_lease.close()
        self._proxy_lease = None

    def _ensure_page_origin(self, origin: str):
        self.open()
        if self._page is None:
            raise RuntimeError("browser page unavailable")
        page = self._page
        if str(origin or "").strip().lower() == "chatgpt":
            target_base = CHATGPT_BASE
            allowed_hosts = {"chatgpt.com", "www.chatgpt.com"}
        else:
            target_base = AUTH_BASE
            allowed_hosts = {"auth.openai.com"}
        current_url = str(getattr(page, "url", "") or "").strip()
        parsed = urlparse(current_url)
        if (
            str(parsed.scheme or "").casefold() != "https"
            or str(parsed.hostname or "").casefold() not in allowed_hosts
        ):
            page.goto(
                f"{target_base}/",
                wait_until="domcontentloaded",
                timeout=self._navigation_timeout_ms(),
            )
        return page

    def _page_title(self, page: Any) -> str:
        try:
            return str(page.title() or "").strip()
        except Exception:
            return ""

    def _page_text_excerpt(self, page: Any) -> str:
        try:
            return str(page.locator("body").inner_text(timeout=3000) or "").strip()[:600]
        except Exception:
            return ""

    @staticmethod
    def _safe_page_location(page: Any) -> str:
        parsed = urlparse(str(getattr(page, "url", "") or ""))
        host = str(parsed.hostname or "unknown").casefold()
        path = str(parsed.path or "/")
        return f"{host}{path}"

    def _warm_chatgpt_page(self):
        page = self._ensure_page_origin("chatgpt")
        page.goto(
            f"{CHATGPT_BASE}/auth/login_with?screen_hint=signup",
            wait_until="domcontentloaded",
            timeout=self._navigation_timeout_ms(),
        )
        warmup_ms = max(
            0,
            int(
                self.config.get(
                    "chatgpt_warmup_wait_ms", DEFAULT_CHATGPT_WARMUP_WAIT_MS
                )
            ),
        )
        if warmup_ms:
            page.wait_for_timeout(warmup_ms)
        return page

    def _visible_locators(self, page: Any, selector: str) -> list[Any]:
        locator = page.locator(selector)
        count = int(locator.count())
        if count > MAX_DISCOVERED_CONTROLS:
            raise RuntimeError("browser flow page contains too many matching controls")
        visible = []
        for index in range(count):
            candidate = locator.nth(index)
            try:
                if candidate.is_visible():
                    visible.append(candidate)
            except Exception:
                continue
        return visible

    def _unique_visible_locator(
        self,
        page: Any,
        selectors: Sequence[str],
        *,
        label: str,
        required: bool = True,
    ) -> Any:
        for selector in selectors:
            matches = self._visible_locators(page, selector)
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise RuntimeError(f"browser flow ambiguous {label} control")
        if required:
            raise RuntimeError(f"browser flow missing {label} control")
        return None

    def _has_visible(self, page: Any, selectors: Sequence[str]) -> bool:
        for selector in selectors:
            if self._visible_locators(page, selector):
                return True
        return False

    def _profile_controls_present(self, page: Any) -> bool:
        if not self._has_visible(page, _PROFILE_NAME_SELECTORS):
            return False
        if self._has_visible(page, _PROFILE_BIRTHDATE_SELECTORS):
            return True
        return all(
            self._has_visible(page, selectors)
            for selectors in (
                _BIRTH_MONTH_SELECTORS,
                _BIRTH_DAY_SELECTORS,
                _BIRTH_YEAR_SELECTORS,
            )
        )

    def _classify_stage(self, page: Any) -> str:
        raw_url = str(getattr(page, "url", "") or "")
        parsed = urlparse(raw_url)
        host = str(parsed.hostname or "").casefold()
        path = str(parsed.path or "/").casefold()
        title = self._page_title(page)
        excerpt = self._page_text_excerpt(page)

        if _looks_like_challenge_page(title, excerpt):
            return "challenge"
        if _looks_phone_gate(path, title, excerpt):
            return "phone"
        if any(marker in path for marker in _MANUAL_CONFIRMATION_PATH_MARKERS):
            return "manual_confirmation"

        if host in {"chatgpt.com", "www.chatgpt.com"}:
            if path.startswith("/auth/login_with"):
                return "entry"
            if self._is_callback_url(raw_url):
                return "complete"
            if path.startswith("/auth/"):
                return "entry"
            return "complete"

        if host != "auth.openai.com":
            return "unknown"
        if any(marker in path for marker in _AUTH_MANUAL_SELECTION_PATH_MARKERS):
            return "manual_confirmation"
        if self._has_visible(
            page, ('input[type="checkbox"]', 'input[type="radio"]')
        ):
            return "manual_confirmation"
        if path.rstrip("/") in {"/log-in", "/login"}:
            return "login"
        if "email-verification" in path or "email-otp" in path:
            return "otp"
        if path.startswith("/create-account/password"):
            return "password"
        if self._has_visible(page, _PASSWORD_SELECTORS):
            return "password"
        if path.startswith("/about-you") or self._profile_controls_present(page):
            return "profile"
        if path.rstrip("/") == "/create-account" and self._has_visible(
            page, _EMAIL_SELECTORS
        ):
            return "email"
        return "unknown"

    @staticmethod
    def _check_cancel(stop_event: Any) -> None:
        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            raise RuntimeError("browser flow cancelled")

    def _raise_gate(self, stage: str, page: Any) -> None:
        location = self._safe_page_location(page)
        if stage == "challenge":
            raise RuntimeError(f"browser flow security challenge at {location}")
        if stage == "phone":
            raise RuntimeError(f"browser flow phone verification required at {location}")
        if stage == "manual_confirmation":
            raise RuntimeError(f"browser flow manual confirmation required at {location}")

    def _wait_for_stage(
        self,
        page: Any,
        allowed: Sequence[str],
        *,
        overall_deadline: float,
        label: str,
        stop_event: Any = None,
    ) -> str:
        stage_deadline = min(
            overall_deadline, time.monotonic() + self._stage_timeout_seconds()
        )
        last_stage = "unknown"
        while True:
            self._check_cancel(stop_event)
            last_stage = self._classify_stage(page)
            self._raise_gate(last_stage, page)
            if last_stage in allowed:
                return last_stage
            now = time.monotonic()
            if now >= stage_deadline:
                location = self._safe_page_location(page)
                raise RuntimeError(
                    f"browser flow unexpected page during {label}: "
                    f"{location} ({last_stage})"
                )
            wait_ms = min(
                int(self.config.get("stage_poll_interval_ms") or 250),
                max(1, int((stage_deadline - now) * 1000)),
            )
            page.wait_for_timeout(wait_ms)

    def _click_signup_link(
        self,
        page: Any,
        *,
        overall_deadline: float,
        stop_event: Any = None,
    ) -> None:
        stage = self._wait_for_stage(
            page,
            ("login", "email"),
            overall_deadline=overall_deadline,
            label="signup entry",
            stop_event=stop_event,
        )
        if stage == "email":
            return
        signup_link = self._unique_visible_locator(
            page,
            (
                'a[href="/create-account"]',
                'a[href^="/create-account?"]',
                'a[href*="auth.openai.com/create-account"]',
            ),
            label="signup link",
        )
        signup_link.click()
        self._wait_for_stage(
            page,
            ("email",),
            overall_deadline=overall_deadline,
            label="signup form",
            stop_event=stop_event,
        )

    def _submit_form(
        self,
        page: Any,
        *,
        label: str,
        required: bool = True,
    ) -> bool:
        submit = self._unique_visible_locator(
            page,
            (
                'button[type="submit"]',
                'input[type="submit"]',
                'form button:not([name="intent"])',
            ),
            label=f"{label} submit",
            required=required,
        )
        if submit is None:
            return False
        try:
            if not submit.is_enabled():
                raise RuntimeError(f"browser flow {label} submit control is disabled")
        except AttributeError:
            pass
        submit.click()
        return True

    def _fill_unique_input(
        self,
        page: Any,
        selectors: Sequence[str],
        value: str,
        *,
        label: str,
    ) -> Any:
        if not str(value or ""):
            raise RuntimeError(f"browser flow {label} value is missing")
        locator = self._unique_visible_locator(page, selectors, label=label)
        try:
            if not locator.is_editable():
                raise RuntimeError(f"browser flow {label} control is not editable")
        except AttributeError:
            pass
        locator.fill(value)
        return locator

    def _fill_otp(self, page: Any, otp_code: str) -> None:
        code = str(otp_code or "").strip()
        if not code or not code.isdigit() or len(code) > 8:
            raise RuntimeError("browser flow otp has invalid format")

        segments: list[Any] = []
        for selector in _OTP_COMBINED_SELECTORS:
            matches = self._visible_locators(page, selector)
            if len(matches) == 1:
                maxlength = str(matches[0].get_attribute("maxlength") or "").strip()
                if maxlength != "1":
                    matches[0].fill(code)
                    return
            if matches:
                segments = matches
                break
        for selector in _OTP_SEGMENT_SELECTORS:
            matches = self._visible_locators(page, selector)
            if matches:
                segments = matches
                break
        if len(segments) != len(code):
            raise RuntimeError("browser flow missing or ambiguous otp controls")
        for locator, digit in zip(segments, code):
            locator.fill(digit)

    def _wait_for_otp_auto_submit(
        self,
        page: Any,
        *,
        overall_deadline: float,
        stop_event: Any = None,
    ) -> str:
        configured_grace_ms = self.config.get("otp_auto_submit_grace_ms")
        if configured_grace_ms is None:
            configured_grace_ms = DEFAULT_OTP_AUTO_SUBMIT_GRACE_MS
        grace_ms = max(0, int(configured_grace_ms))
        grace_deadline = min(
            overall_deadline,
            time.monotonic() + (grace_ms / 1000.0),
        )
        while True:
            self._check_cancel(stop_event)
            stage = self._classify_stage(page)
            self._raise_gate(stage, page)
            if stage != "otp":
                return stage
            now = time.monotonic()
            if now >= grace_deadline:
                return stage
            wait_ms = min(
                int(self.config.get("stage_poll_interval_ms") or 250),
                max(1, int((grace_deadline - now) * 1000)),
            )
            page.wait_for_timeout(wait_ms)

    @staticmethod
    def _birthdate_parts(raw_birthdate: Any) -> tuple[str, str, str]:
        value = str(raw_birthdate or "").strip()
        parts = value.split("-")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            raise RuntimeError("browser flow profile birthdate is invalid")
        year, month, day = parts
        if not (
            len(year) == 4
            and 1 <= int(month) <= 12
            and 1 <= int(day) <= 31
        ):
            raise RuntimeError("browser flow profile birthdate is invalid")
        return year, month.zfill(2), day.zfill(2)

    def _fill_profile(self, page: Any, profile: Dict[str, Any]) -> None:
        name = _first_text(profile.get("name"))
        if not name:
            raise RuntimeError("browser flow profile name is missing")
        year, month, day = self._birthdate_parts(profile.get("birthdate"))
        self._fill_unique_input(
            page,
            _PROFILE_NAME_SELECTORS,
            name,
            label="profile name",
        )

        birthdate = self._unique_visible_locator(
            page,
            _PROFILE_BIRTHDATE_SELECTORS,
            label="profile birthdate",
            required=False,
        )
        if birthdate is not None:
            input_type = str(birthdate.get_attribute("type") or "").casefold()
            placeholder = str(birthdate.get_attribute("placeholder") or "").upper()
            if input_type == "date":
                value = f"{year}-{month}-{day}"
            elif "MM" in placeholder and "DD" in placeholder:
                if placeholder.index("DD") < placeholder.index("MM"):
                    value = f"{day}/{month}/{year}"
                else:
                    value = f"{month}/{day}/{year}"
            else:
                value = f"{year}-{month}-{day}"
            birthdate.fill(value)
            return

        month_input = self._unique_visible_locator(
            page, _BIRTH_MONTH_SELECTORS, label="birth month"
        )
        day_input = self._unique_visible_locator(
            page, _BIRTH_DAY_SELECTORS, label="birth day"
        )
        year_input = self._unique_visible_locator(
            page, _BIRTH_YEAR_SELECTORS, label="birth year"
        )
        month_input.fill(month)
        day_input.fill(day)
        year_input.fill(year)

    def _cookies(self) -> list[dict]:
        self.open()
        if self._context is None:
            return []
        try:
            cookies = self._context.cookies()
        except Exception:
            cookies = []
        return cookies if isinstance(cookies, list) else []

    def _session_cookie_token(self) -> str:
        cookies = self._cookies()
        values = {
            str(cookie.get("name") or "").strip(): str(
                cookie.get("value") or ""
            ).strip()
            for cookie in cookies
            if isinstance(cookie, dict)
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

    @staticmethod
    def _is_callback_url(target_url: str) -> bool:
        parsed = urlparse(str(target_url or ""))
        if str(parsed.hostname or "").casefold() not in {
            "chatgpt.com",
            "www.chatgpt.com",
        }:
            return False
        if parsed.path.rstrip("/") != "/api/auth/callback/openai":
            return False
        query = parse_qs(parsed.query)
        return bool(query.get("code") and query.get("state"))

    def _wait_for_otp(
        self,
        *,
        mail_provider: Any,
        mail_auth_credential: str,
        email: str,
        stop_event: Any = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        sent_at_ts: Optional[float] = None,
    ) -> str:
        if mail_provider is None:
            raise RuntimeError("browser flow otp wait requires mail provider")
        try:
            return str(
                mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=self.proxy,
                    timeout=int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS),
                    stop_event=stop_event,
                    sent_at_ts=sent_at_ts,
                )
                or ""
            ).strip()
        except TypeError:
            return str(
                mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=self.proxy,
                    stop_event=stop_event,
                )
                or ""
            ).strip()

    def _try_get_chatgpt_session(self) -> Optional[Dict[str, Any]]:
        try:
            self.open()
            page = self._page
            if page is None:
                return None
            parsed = urlparse(str(getattr(page, "url", "") or ""))
            if (
                str(parsed.scheme or "").casefold() != "https"
                or str(parsed.hostname or "").casefold()
                not in {"chatgpt.com", "www.chatgpt.com"}
            ):
                return None
            result = page.evaluate(
                """async () => {
                    const resp = await fetch('/api/auth/session', { credentials: 'include' });
                    const text = await resp.text();
                    let data = null;
                    try {
                        data = text ? JSON.parse(text) : null;
                    } catch (error) {
                        data = null;
                    }
                    return { status: resp.status, json: data, text };
                }"""
            )
            if int(result.get("status") or 0) != 200:
                return None
            payload = result.get("json") if isinstance(result.get("json"), dict) else {}
            access_token = _first_text(payload.get("accessToken"))
            if not access_token:
                return None
            session_token = _first_text(
                payload.get("sessionToken"),
                self._session_cookie_token(),
            )
            if not session_token:
                return None
            email = _first_text(
                (payload.get("user") or {}).get("email")
                if isinstance(payload.get("user"), dict)
                else ""
            )
            return {
                "access_token": access_token,
                "refresh_token": "",
                "session_token": session_token,
                "email": email,
                "token_source": "chatgpt_session",
                "type": "codex",
            }
        except Exception:
            return None

    def _wait_for_chatgpt_session(
        self,
        page: Any,
        *,
        overall_deadline: float,
        stop_event: Any = None,
    ) -> Dict[str, Any]:
        ready_timeout = max(
            1.0,
            float(
                self.config.get(
                    "chatgpt_ready_timeout_seconds",
                    DEFAULT_CHATGPT_READY_TIMEOUT_SECONDS,
                )
            ),
        )
        deadline = min(overall_deadline, time.monotonic() + ready_timeout)
        while True:
            self._check_cancel(stop_event)
            stage = self._classify_stage(page)
            self._raise_gate(stage, page)
            session = self._try_get_chatgpt_session() if stage == "complete" else None
            if isinstance(session, dict) and session:
                return session
            now = time.monotonic()
            if now >= deadline:
                raise RuntimeError("browser flow ChatGPT session was not established")
            wait_ms = min(
                int(
                    self.config.get("chatgpt_ready_poll_interval_ms")
                    or DEFAULT_CHATGPT_READY_POLL_INTERVAL_MS
                ),
                max(1, int((deadline - now) * 1000)),
            )
            page.wait_for_timeout(wait_ms)

    def _run_registration_and_oauth_sync(
        self,
        *,
        email: str,
        account_password: str,
        mail_provider: Any,
        mail_auth_credential: str,
        random_profile: Optional[Dict[str, Any]] = None,
        stop_event: Any = None,
    ) -> Dict[str, Any]:
        overall_deadline = time.monotonic() + self._flow_timeout_seconds()
        try:
            self.open()
            self._log("info", "浏览器全流程：打开官方注册页面")
            page = self._warm_chatgpt_page()
            self._click_signup_link(
                page,
                overall_deadline=overall_deadline,
                stop_event=stop_event,
            )

            email_submitted_at = time.time()
            self._fill_unique_input(
                page,
                _EMAIL_SELECTORS,
                str(email or "").strip(),
                label="email",
            )
            self._submit_form(page, label="email")
            stage = self._wait_for_stage(
                page,
                ("password", "otp"),
                overall_deadline=overall_deadline,
                label="email submission",
                stop_event=stop_event,
            )

            existing_identity = stage == "otp"
            otp_requested_at = email_submitted_at
            if stage == "password":
                self._fill_unique_input(
                    page,
                    _PASSWORD_SELECTORS,
                    str(account_password or ""),
                    label="password",
                )
                otp_requested_at = time.time()
                self._submit_form(page, label="password")
                self._wait_for_stage(
                    page,
                    ("otp",),
                    overall_deadline=overall_deadline,
                    label="password submission",
                    stop_event=stop_event,
                )

            self._log("info", "浏览器全流程：官方 OTP 页面已就绪，等待邮件")
            remaining_seconds = max(
                1,
                int(
                    min(
                        float(
                            self.config.get("timeout_seconds")
                            or DEFAULT_TIMEOUT_SECONDS
                        ),
                        max(1.0, overall_deadline - time.monotonic()),
                    )
                ),
            )
            otp_code = self._wait_for_otp(
                mail_provider=mail_provider,
                mail_auth_credential=mail_auth_credential,
                email=email,
                stop_event=stop_event,
                timeout_seconds=remaining_seconds,
                sent_at_ts=otp_requested_at,
            )
            if not otp_code:
                raise RuntimeError("browser flow otp missing")
            self._check_cancel(stop_event)
            if time.monotonic() >= overall_deadline:
                raise RuntimeError("browser flow total timeout before otp entry")
            if self._classify_stage(page) != "otp":
                raise RuntimeError("browser flow otp page changed before code entry")
            self._fill_otp(page, otp_code)
            stage_after_otp_fill = self._wait_for_otp_auto_submit(
                page,
                overall_deadline=overall_deadline,
                stop_event=stop_event,
            )
            if stage_after_otp_fill == "otp":
                self._submit_form(page, label="otp", required=False)
            elif stage_after_otp_fill not in {"profile", "complete"}:
                raise RuntimeError("browser flow unexpected page after otp entry")
            stage = self._wait_for_stage(
                page,
                ("profile", "complete"),
                overall_deadline=overall_deadline,
                label="otp submission",
                stop_event=stop_event,
            )

            if stage == "profile":
                existing_identity = False
                profile = dict(
                    random_profile
                    or {"name": "Alex Wilson", "birthdate": "1994-05-17"}
                )
                self._fill_profile(page, profile)
                self._submit_form(page, label="profile")
                stage = self._wait_for_stage(
                    page,
                    ("complete",),
                    overall_deadline=overall_deadline,
                    label="profile submission",
                    stop_event=stop_event,
                )

            session_token_data = self._wait_for_chatgpt_session(
                page,
                overall_deadline=overall_deadline,
                stop_event=stop_event,
            )
            expected_email = str(email or "").strip().casefold()
            session_email = _first_text(session_token_data.get("email")).casefold()
            if not session_email:
                raise RuntimeError("browser flow session email is missing")
            if session_email != expected_email:
                raise RuntimeError("browser flow session email does not match registration email")
            branch_label = "已有身份登录" if existing_identity else "新账号注册"
            self._log("success", f"浏览器全流程：{branch_label}完成，会话已导出")
            return {
                "session_token_data": session_token_data,
                "identity_branch": (
                    "existing_identity" if existing_identity else "new_account"
                ),
            }
        finally:
            self.close()

    def run_registration_and_oauth(
        self,
        *,
        email: str,
        account_password: str,
        mail_provider: Any,
        mail_auth_credential: str,
        random_profile: Optional[Dict[str, Any]] = None,
        stop_event: Any = None,
    ) -> Dict[str, Any]:
        result_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1)

        def _runner() -> None:
            try:
                result = self._run_registration_and_oauth_sync(
                    email=email,
                    account_password=account_password,
                    mail_provider=mail_provider,
                    mail_auth_credential=mail_auth_credential,
                    random_profile=random_profile,
                    stop_event=stop_event,
                )
                result_queue.put({"ok": True, "result": result})
            except Exception as exc:
                result_queue.put({"ok": False, "error": str(exc)})

        thread = threading.Thread(
            target=_runner,
            name="browser-register-flow",
            daemon=True,
        )
        thread.start()
        thread.join(timeout=self._flow_timeout_seconds() + 15.0)
        if thread.is_alive():
            raise RuntimeError("browser flow thread timeout")
        item = result_queue.get_nowait()
        if not item.get("ok"):
            raise RuntimeError(str(item.get("error") or "browser flow failed"))
        return item["result"]
