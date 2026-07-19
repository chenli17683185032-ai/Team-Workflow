"""Visible-browser capture of one validated iCloud HME list request."""

from __future__ import annotations

import hashlib
import os
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .icloud_hme import (
    CORE_SESSION_COOKIE_NAMES,
    HmeSessionError,
    ICloudHmeSession,
    parse_hme_request,
)


DEFAULT_ICLOUD_CAPTURE_URL = "https://www.icloud.com.cn/"
DEFAULT_ICLOUD_CAPTURE_TIMEOUT_SECONDS = 15 * 60
_ACTIVE_STATES = frozenset(
    {"starting", "waiting_login", "verifying", "cancelling"}
)
_PROXY_ENVIRONMENT_KEYS = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)


class HmeCaptureError(RuntimeError):
    code = "hme_capture_error"


class HmeCaptureBusyError(HmeCaptureError):
    code = "hme_capture_busy"


class HmeCaptureUnavailableError(HmeCaptureError):
    code = "hme_capture_unavailable"


class HmeCaptureNoListRequestError(HmeCaptureError):
    code = "hme_capture_no_list_request"


class HmeCaptureSessionRejectedError(HmeCaptureError):
    code = "hme_capture_session_rejected"


@dataclass(frozen=True)
class HmeCaptureStatus:
    mailbox_id: str
    state: str
    message: str
    started_at: str | None = None
    finished_at: str | None = None
    error_code: str | None = None

    @property
    def active(self) -> bool:
        return self.state in _ACTIVE_STATES

    def as_dict(self) -> dict[str, Any]:
        return {
            "mailbox_id": self.mailbox_id,
            "state": self.state,
            "active": self.active,
            "message": self.message,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error_code": self.error_code,
        }


@dataclass
class _CaptureJob:
    status: HmeCaptureStatus
    cancel_event: threading.Event
    thread: threading.Thread | None = None


@dataclass(frozen=True)
class _ExternalBrowser:
    endpoint: str
    pid: int


CaptureRunner = Callable[..., ICloudHmeSession]
SessionConsumer = Callable[[str, ICloudHmeSession], Any]
StatusConsumer = Callable[[dict[str, Any]], Any]
SessionTemplateProvider = Callable[[str], ICloudHmeSession]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _ensure_private_directory(path: Path) -> Path:
    directory = path.expanduser()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    except OSError as exc:
        raise HmeCaptureUnavailableError(
            "无法创建安全的 iCloud 登录资料目录"
        ) from exc
    return directory


def _prepare_capture_profile(
    profile_dir: str | Path | None,
) -> tuple[Path, bool]:
    if profile_dir is not None:
        return _ensure_private_directory(Path(profile_dir)), False
    try:
        temporary = Path(tempfile.mkdtemp(prefix="teamworkflow-icloud-login-"))
        temporary.chmod(0o700)
    except OSError as exc:
        raise HmeCaptureUnavailableError(
            "无法创建安全的 iCloud 登录资料目录"
        ) from exc
    return temporary, True


def _browser_executable() -> Path | None:
    configured = str(os.environ.get("TEAM_WORKFLOW_ICLOUD_BROWSER") or "").strip()
    candidates = [
        configured,
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ]
    for value in candidates:
        if value and Path(value).expanduser().is_file():
            return Path(value).expanduser().resolve()
    return None


def _browser_app_bundle(executable: str | Path) -> Path | None:
    path = Path(executable).expanduser().resolve()
    for candidate in (path, *path.parents):
        if candidate.suffix.casefold() == ".app" and candidate.is_dir():
            return candidate
    return None


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _macos_browser_command(
    app_bundle: Path,
    profile_dir: Path,
    port: int,
) -> list[str]:
    return [
        "/usr/bin/open",
        "-na",
        str(app_bundle),
        "--args",
        f"--user-data-dir={profile_dir}",
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={int(port)}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-popup-blocking",
        "--no-proxy-server",
        "--lang=zh-CN",
        "--window-size=1360,860",
        DEFAULT_ICLOUD_CAPTURE_URL,
    ]


def _browser_pid_for_port(port: int) -> int | None:
    try:
        result = subprocess.run(
            ["lsof", f"-tiTCP:{int(port)}", "-sTCP:LISTEN"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        try:
            pid = int(line.strip())
        except ValueError:
            continue
        if pid > 1:
            return pid
    return None


def _terminate_browser_process(pid: int | None, timeout: float = 5.0) -> None:
    if pid is None or pid <= 1:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        return
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        except OSError:
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _launch_macos_browser(playwright: Any, profile_dir: Path) -> _ExternalBrowser:
    configured = str(os.environ.get("TEAM_WORKFLOW_ICLOUD_BROWSER") or "").strip()
    candidates = [configured, str(playwright.chromium.executable_path or "")]
    app_bundle = next(
        (
            bundle
            for value in candidates
            if value and (bundle := _browser_app_bundle(value)) is not None
        ),
        None,
    )
    if app_bundle is None:
        raise HmeCaptureUnavailableError(
            "macOS 可见捕获浏览器不可用，请安装 Playwright Chromium"
        )
    port = _reserve_loopback_port()
    try:
        result = subprocess.run(
            _macos_browser_command(app_bundle, profile_dir, port),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=_direct_browser_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HmeCaptureUnavailableError("macOS 无法打开 iCloud 登录窗口") from exc
    if result.returncode != 0:
        raise HmeCaptureUnavailableError("macOS 无法打开 iCloud 登录窗口")

    endpoint = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                f"{endpoint}/json/version",
                timeout=1.0,
            ) as response:
                if int(getattr(response, "status", 0) or 0) == 200:
                    pid = _browser_pid_for_port(port)
                    if pid is not None:
                        return _ExternalBrowser(endpoint=endpoint, pid=pid)
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    pid = _browser_pid_for_port(port)
    _terminate_browser_process(pid)
    raise HmeCaptureUnavailableError("iCloud 登录窗口启动超时")


def _direct_browser_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key not in _PROXY_ENVIRONMENT_KEYS
    }


def _select_capture_page(context: Any) -> Any:
    """Keep one visible tab so navigation cannot continue in the background."""

    pages = list(context.pages)
    page = pages[-1] if pages else context.new_page()
    for extra in pages[:-1]:
        try:
            extra.close()
        except Exception:
            pass
    try:
        page.bring_to_front()
    except Exception:
        pass
    return page


def _is_authenticated_setup_response(url: str, status: int) -> bool:
    if int(status or 0) != 200:
        return False
    parsed = urllib.parse.urlparse(str(url or ""))
    return (
        parsed.scheme == "https"
        and str(parsed.hostname or "").casefold()
        in {"setup.icloud.com", "setup.icloud.com.cn"}
        and parsed.path == "/setup/ws/1/validate"
    )


def _session_from_authenticated_context(
    context: Any,
    page: Any,
    template: ICloudHmeSession | None,
) -> ICloudHmeSession | None:
    if template is None:
        return None
    origin = (
        "https://www.icloud.com.cn"
        if template.host.endswith(".icloud.com.cn")
        else "https://www.icloud.com"
    )
    urls = [f"https://{template.host}/", f"{origin}/"]
    cookies = context.cookies(urls)
    values = {
        str(item.get("name") or "").strip(): str(item.get("value") or "").strip()
        for item in cookies
        if isinstance(item, dict)
    }
    if not CORE_SESSION_COOKIE_NAMES.issubset(values):
        try:
            all_cookies = context.cookies()
        except Exception:
            all_cookies = ()
        values.update(
            {
                str(item.get("name") or "").strip(): str(
                    item.get("value") or ""
                ).strip()
                for item in all_cookies
                if isinstance(item, dict)
            }
        )
    if not CORE_SESSION_COOKIE_NAMES.issubset(values):
        return None
    data = template.as_secret_dict()
    data.update(
        {
            "cookie": "; ".join(
                f"{name}={values[name]}" for name in sorted(CORE_SESSION_COOKIE_NAMES)
            ),
            "origin": origin,
            "referer": f"{origin}/",
        }
    )
    try:
        user_agent = str(page.evaluate("navigator.userAgent") or "").strip()
    except Exception:
        user_agent = ""
    if user_agent:
        data["user_agent"] = user_agent
    return ICloudHmeSession.from_mapping(data)


def capture_hme_session(
    *,
    cancel_event: threading.Event,
    on_waiting: Callable[[], Any],
    on_authenticated: Callable[[], Any] | None = None,
    timeout_seconds: float = DEFAULT_ICLOUD_CAPTURE_TIMEOUT_SECONDS,
    start_url: str = DEFAULT_ICLOUD_CAPTURE_URL,
    session_template: ICloudHmeSession | None = None,
    profile_dir: str | Path | None = None,
) -> ICloudHmeSession:
    """Open a visible browser and wait for a valid HME list response."""

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise HmeCaptureUnavailableError("Playwright is unavailable") from exc

    profile_path, cleanup_profile = _prepare_capture_profile(profile_dir)
    context: Any = None
    browser: Any = None
    external_browser: _ExternalBrowser | None = None
    captured: list[ICloudHmeSession] = []
    captured_event = threading.Event()
    authenticated_event = threading.Event()
    list_responses = 0
    rejected_sessions = 0

    def mark_authenticated() -> None:
        if authenticated_event.is_set():
            return
        authenticated_event.set()
        if on_authenticated is not None:
            try:
                on_authenticated()
            except Exception:
                pass

    def handle_response(response: Any) -> None:
        nonlocal list_responses, rejected_sessions
        if captured_event.is_set() or cancel_event.is_set():
            return
        try:
            response_url = str(response.url)
            if _is_authenticated_setup_response(
                response_url,
                int(getattr(response, "status", 0) or 0),
            ):
                mark_authenticated()
                return
            parsed_url = urllib.parse.urlparse(response_url)
            if parsed_url.path != "/v2/hme/list":
                return
            list_responses += 1
            if int(getattr(response, "status", 0) or 0) != 200:
                rejected_sessions += 1
                return
            request = response.request
            if str(getattr(request, "method", "GET") or "GET").upper() != "GET":
                rejected_sessions += 1
                return
            headers = request.all_headers()
            cookies = ()
            if not str(headers.get("cookie") or "").strip():
                cookies = context.cookies(response_url)
            session = parse_hme_request(
                response_url,
                headers,
                cookies=cookies,
            )
        except HmeSessionError:
            rejected_sessions += 1
            return
        except Exception:
            return
        captured.append(session)
        captured_event.set()

    try:
        with sync_playwright() as playwright:
            if cancel_event.is_set():
                raise HmeCaptureError("iCloud HME capture was cancelled")
            if sys.platform == "darwin":
                external_browser = _launch_macos_browser(playwright, profile_path)
                browser = playwright.chromium.connect_over_cdp(
                    external_browser.endpoint,
                    timeout=15_000,
                )
                if not browser.contexts:
                    raise HmeCaptureUnavailableError(
                        "iCloud 登录窗口没有可用的浏览器上下文"
                    )
                context = browser.contexts[0]
            else:
                launch_options: dict[str, Any] = {
                    "headless": False,
                    "locale": "zh-CN",
                    "viewport": {"width": 1360, "height": 860},
                    "accept_downloads": False,
                    "env": _direct_browser_environment(),
                    "args": ["--no-first-run", "--no-default-browser-check"],
                }
                executable = _browser_executable()
                if executable is not None:
                    launch_options["executable_path"] = str(executable)
                context = playwright.chromium.launch_persistent_context(
                    str(profile_path),
                    **launch_options,
                )
            context.on("response", handle_response)
            page = _select_capture_page(context)
            on_waiting()
            try:
                page.goto(
                    str(start_url),
                    wait_until="domcontentloaded",
                    timeout=20_000,
                )
            except PlaywrightTimeoutError:
                pass
            except PlaywrightError:
                # A navigation interrupted by an iCloud redirect still leaves
                # the visible page usable for login and HME navigation.
                pass
            try:
                page.bring_to_front()
            except PlaywrightError:
                pass
            _click_icloud_sign_in(page)
            deadline = time.monotonic() + max(30.0, float(timeout_seconds))
            while time.monotonic() < deadline:
                if cancel_event.wait(0.25):
                    raise HmeCaptureError("iCloud HME capture was cancelled")
                if captured_event.is_set() and captured:
                    return captured[0]
                if session_template is not None:
                    session = _session_from_authenticated_context(
                        context,
                        page,
                        session_template,
                    )
                    if session is not None:
                        mark_authenticated()
                        return session
                try:
                    has_pages = bool(context.pages)
                except PlaywrightError:
                    has_pages = False
                if not has_pages:
                    raise HmeCaptureError("iCloud login browser was closed")
            raise _capture_timeout_error(list_responses, rejected_sessions)
    except HmeCaptureError:
        raise
    except PlaywrightError as exc:
        raise HmeCaptureUnavailableError("iCloud login browser failed") from exc
    except Exception as exc:
        raise HmeCaptureUnavailableError("iCloud login browser failed") from exc
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if external_browser is not None:
            _terminate_browser_process(external_browser.pid)
        if cleanup_profile:
            shutil.rmtree(profile_path, ignore_errors=True)


def _click_icloud_sign_in(page: Any) -> bool:
    """Open Apple's sign-in form without entering or submitting credentials."""

    for label in ("登录", "Sign In"):
        try:
            button = page.get_by_role("button", name=label, exact=True)
            if button.count() != 1:
                continue
            button.click(timeout=5_000)
            return True
        except Exception:
            continue
    return False


def _capture_timeout_error(
    list_responses: int,
    rejected_sessions: int,
) -> HmeCaptureError:
    if list_responses <= 0:
        return HmeCaptureNoListRequestError(
            "未检测到登录完成后的 HME 会话，请确认在捕获窗口完成 Apple 登录"
        )
    if rejected_sessions > 0:
        return HmeCaptureSessionRejectedError(
            "已检测到隐藏邮箱列表请求，但 Apple 会话字段不完整或已拒绝"
        )
    return HmeCaptureError("iCloud HME capture timed out")


class ICloudHmeCaptureManager:
    def __init__(
        self,
        *,
        on_session: SessionConsumer,
        on_status: StatusConsumer | None = None,
        get_session_template: SessionTemplateProvider | None = None,
        runner: CaptureRunner = capture_hme_session,
        timeout_seconds: float = DEFAULT_ICLOUD_CAPTURE_TIMEOUT_SECONDS,
        profile_root: str | Path | None = None,
    ) -> None:
        self.on_session = on_session
        self.on_status = on_status
        self.get_session_template = get_session_template
        self.runner = runner
        self.timeout_seconds = max(30.0, float(timeout_seconds))
        self.profile_root = (
            None
            if profile_root is None
            else _ensure_private_directory(Path(profile_root).expanduser().resolve())
        )
        self._lock = threading.RLock()
        self._jobs: dict[str, _CaptureJob] = {}
        self._active_mailbox_id: str | None = None

    def _profile_dir(self, mailbox_id: str) -> Path | None:
        if self.profile_root is None:
            return None
        root = _ensure_private_directory(self.profile_root)
        digest = hashlib.sha256(mailbox_id.encode("utf-8")).hexdigest()
        return _ensure_private_directory(root / digest)

    def _publish(self, status: HmeCaptureStatus) -> HmeCaptureStatus:
        with self._lock:
            job = self._jobs.get(status.mailbox_id)
            if job is not None:
                job.status = status
        if self.on_status is not None:
            try:
                self.on_status(status.as_dict())
            except Exception:
                pass
        return status

    def _transition(
        self,
        mailbox_id: str,
        state: str,
        message: str,
        *,
        error_code: str | None = None,
        finished: bool = False,
    ) -> HmeCaptureStatus:
        with self._lock:
            existing = self._jobs[mailbox_id].status
        return self._publish(
            HmeCaptureStatus(
                mailbox_id=mailbox_id,
                state=state,
                message=message,
                started_at=existing.started_at,
                finished_at=_now() if finished else None,
                error_code=error_code,
            )
        )

    def start(self, mailbox_id: str) -> dict[str, Any]:
        normalized = str(mailbox_id or "").strip()
        if not normalized:
            raise ValueError("mailbox_id is required")
        with self._lock:
            if self._active_mailbox_id is not None:
                active = self._jobs.get(self._active_mailbox_id)
                if active is not None and active.status.active:
                    raise HmeCaptureBusyError(
                        "another iCloud HME capture is already running"
                    )
            status = HmeCaptureStatus(
                mailbox_id=normalized,
                state="starting",
                message="正在打开 iCloud 登录窗口",
                started_at=_now(),
            )
            job = _CaptureJob(status=status, cancel_event=threading.Event())
            thread = threading.Thread(
                target=self._run,
                args=(normalized,),
                name=f"icloud-hme-capture-{normalized[:8]}",
                daemon=True,
            )
            job.thread = thread
            self._jobs[normalized] = job
            self._active_mailbox_id = normalized
        self._publish(status)
        thread.start()
        return status.as_dict()

    def _run(self, mailbox_id: str) -> None:
        with self._lock:
            job = self._jobs[mailbox_id]

        def waiting() -> None:
            self._transition(
                mailbox_id,
                "waiting_login",
                "请在打开的窗口中完成 iCloud 登录和双重验证，登录成功后会自动验证 HME",
            )

        def authenticated() -> None:
            self._transition(
                mailbox_id,
                "verifying",
                "已检测到 Apple 登录，正在验证 HME Session",
            )

        try:
            session_template = (
                self.get_session_template(mailbox_id)
                if self.get_session_template is not None
                else None
            )
            runner_options: dict[str, Any] = {
                "cancel_event": job.cancel_event,
                "on_waiting": waiting,
                "on_authenticated": authenticated,
                "timeout_seconds": self.timeout_seconds,
                "start_url": DEFAULT_ICLOUD_CAPTURE_URL,
                "session_template": session_template,
            }
            profile_dir = self._profile_dir(mailbox_id)
            if profile_dir is not None:
                runner_options["profile_dir"] = profile_dir
            session = self.runner(
                **runner_options,
            )
            if job.cancel_event.is_set():
                self._transition(
                    mailbox_id,
                    "cancelled",
                    "已取消 iCloud HME 捕获",
                    error_code="hme_capture_cancelled",
                    finished=True,
                )
                return
            self.on_session(mailbox_id, session)
            self._transition(
                mailbox_id,
                "captured",
                "HME Session 已自动捕获并安全保存",
                finished=True,
            )
        except HmeCaptureUnavailableError as exc:
            self._transition(
                mailbox_id,
                "failed",
                str(exc),
                error_code=exc.code,
                finished=True,
            )
        except HmeCaptureError as exc:
            cancelled = job.cancel_event.is_set() or "cancelled" in str(exc).casefold()
            self._transition(
                mailbox_id,
                "cancelled" if cancelled else "failed",
                "已取消 iCloud HME 捕获" if cancelled else str(exc),
                error_code="hme_capture_cancelled" if cancelled else exc.code,
                finished=True,
            )
        except Exception:
            self._transition(
                mailbox_id,
                "failed",
                "HME Session 保存失败",
                error_code="hme_capture_save_failed",
                finished=True,
            )
        finally:
            with self._lock:
                if self._active_mailbox_id == mailbox_id:
                    self._active_mailbox_id = None

    def status(self, mailbox_id: str) -> dict[str, Any]:
        normalized = str(mailbox_id or "").strip()
        with self._lock:
            job = self._jobs.get(normalized)
            if job is not None:
                return job.status.as_dict()
        return HmeCaptureStatus(
            mailbox_id=normalized,
            state="idle",
            message="尚未启动 HME 自动捕获",
        ).as_dict()

    def cancel(self, mailbox_id: str) -> dict[str, Any]:
        normalized = str(mailbox_id or "").strip()
        with self._lock:
            job = self._jobs.get(normalized)
            if job is None or not job.status.active:
                return self.status(normalized)
            job.cancel_event.set()
        return self._transition(
            normalized,
            "cancelling",
            "正在关闭 iCloud 登录窗口",
        ).as_dict()

    def shutdown(self, timeout: float = 8.0) -> bool:
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            if job.status.active:
                job.cancel_event.set()
        deadline = time.monotonic() + max(0.0, float(timeout))
        stopped = True
        for job in jobs:
            thread = job.thread
            if thread is None or not thread.is_alive():
                continue
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            stopped = stopped and not thread.is_alive()
        return stopped


__all__ = [
    "DEFAULT_ICLOUD_CAPTURE_TIMEOUT_SECONDS",
    "DEFAULT_ICLOUD_CAPTURE_URL",
    "HmeCaptureBusyError",
    "HmeCaptureError",
    "HmeCaptureNoListRequestError",
    "HmeCaptureSessionRejectedError",
    "HmeCaptureStatus",
    "HmeCaptureUnavailableError",
    "ICloudHmeCaptureManager",
    "capture_hme_session",
]
