from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
import unittest
import tempfile
from pathlib import Path

from team_protocol.icloud_hme import CORE_SESSION_COOKIE_NAMES, parse_hme_request
from team_protocol.icloud_hme_capture import (
    HmeCaptureBusyError,
    HmeCaptureError,
    HmeCaptureNoListRequestError,
    HmeCaptureSessionRejectedError,
    ICloudHmeCaptureManager,
    _capture_timeout_error,
    _browser_app_bundle,
    _click_icloud_sign_in,
    _is_authenticated_setup_response,
    _macos_browser_command,
    _prepare_capture_profile,
    _session_from_authenticated_context,
)


URL = (
    "https://p217-maildomainws.icloud.com.cn/v2/hme/list?"
    "clientBuildNumber=2536Project32&clientMasteringNumber=2536B20&"
    "clientId=client-capture&dsid=dsid-capture"
)
COOKIE = (
    "X-APPLE-DS-WEB-SESSION-TOKEN=captured-session-secret; "
    "X-APPLE-WEBAUTH-USER=captured-user-secret; "
    "X-APPLE-WEBAUTH-TOKEN=captured-auth-secret"
)


def captured_session():
    return parse_hme_request(
        URL,
        {
            "Cookie": COOKIE,
            "Origin": "https://www.icloud.com.cn",
            "Referer": "https://www.icloud.com.cn/",
            "User-Agent": "Capture Test Browser",
        },
    )


class ICloudHmeCaptureTests(unittest.TestCase):
    @staticmethod
    def wait_for_terminal(manager, mailbox_id, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = manager.status(mailbox_id)
            if not status["active"]:
                return status
            time.sleep(0.01)
        raise AssertionError("capture manager did not reach a terminal state")

    def test_manager_publishes_waiting_then_saves_a_validated_session(self):
        saved = []
        statuses = []

        def runner(**kwargs):
            kwargs["on_waiting"]()
            return captured_session()

        manager = ICloudHmeCaptureManager(
            on_session=lambda mailbox_id, session: saved.append((mailbox_id, session)),
            on_status=statuses.append,
            get_session_template=lambda _mailbox_id: captured_session(),
            runner=runner,
        )

        started = manager.start("mailbox-one")
        terminal = self.wait_for_terminal(manager, "mailbox-one")

        self.assertEqual(started["state"], "starting")
        self.assertEqual(terminal["state"], "captured")
        self.assertEqual(saved[0][0], "mailbox-one")
        self.assertEqual(saved[0][1].host, "p217-maildomainws.icloud.com.cn")
        self.assertEqual(
            statuses[0]["mailbox_id"],
            "mailbox-one",
        )
        self.assertIn("waiting_login", [item["state"] for item in statuses])
        serialized = json.dumps(statuses, ensure_ascii=False)
        self.assertNotIn("captured-session-secret", serialized)
        self.assertTrue(manager.shutdown())

    def test_manager_reuses_one_private_hashed_profile_per_mailbox(self):
        observed_profiles = []

        def runner(**kwargs):
            profile_dir = Path(kwargs["profile_dir"])
            observed_profiles.append(profile_dir)
            (profile_dir / "profile-state").write_text("kept", encoding="utf-8")
            kwargs["on_waiting"]()
            return captured_session()

        with tempfile.TemporaryDirectory() as directory:
            profile_root = Path(directory) / "icloud-hme"
            manager = ICloudHmeCaptureManager(
                on_session=lambda *_args: None,
                runner=runner,
                profile_root=profile_root,
            )

            manager.start("mailbox-one")
            self.assertEqual(
                self.wait_for_terminal(manager, "mailbox-one")["state"],
                "captured",
            )
            manager.start("mailbox-one")
            self.assertEqual(
                self.wait_for_terminal(manager, "mailbox-one")["state"],
                "captured",
            )
            manager.start("mailbox-two")
            self.assertEqual(
                self.wait_for_terminal(manager, "mailbox-two")["state"],
                "captured",
            )

            first, repeated, second = observed_profiles
            self.assertEqual(first, repeated)
            self.assertNotEqual(first, second)
            self.assertEqual(
                first.name,
                hashlib.sha256(b"mailbox-one").hexdigest(),
            )
            self.assertNotIn("mailbox-one", str(first))
            self.assertEqual((first / "profile-state").read_text(), "kept")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(profile_root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o700)
            self.assertTrue(manager.shutdown())

    def test_capture_profile_cleanup_only_applies_to_internal_temporary_dirs(self):
        with tempfile.TemporaryDirectory() as directory:
            persistent = Path(directory) / "persistent"
            prepared, should_cleanup = _prepare_capture_profile(persistent)

            self.assertEqual(prepared, persistent)
            self.assertFalse(should_cleanup)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(prepared.stat().st_mode), 0o700)

        temporary, should_cleanup = _prepare_capture_profile(None)
        try:
            self.assertTrue(should_cleanup)
            self.assertTrue(temporary.is_dir())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(temporary.stat().st_mode), 0o700)
        finally:
            temporary.rmdir()

    def test_manager_rejects_concurrent_capture_and_cancels_cleanly(self):
        entered = threading.Event()

        def runner(**kwargs):
            kwargs["on_waiting"]()
            entered.set()
            kwargs["cancel_event"].wait(2.0)
            raise HmeCaptureError("iCloud HME capture was cancelled")

        manager = ICloudHmeCaptureManager(
            on_session=lambda *_args: None,
            runner=runner,
        )
        manager.start("mailbox-one")
        self.assertTrue(entered.wait(1.0))
        with self.assertRaises(HmeCaptureBusyError):
            manager.start("mailbox-two")

        cancelling = manager.cancel("mailbox-one")
        terminal = self.wait_for_terminal(manager, "mailbox-one")

        self.assertEqual(cancelling["state"], "cancelling")
        self.assertEqual(terminal["state"], "cancelled")
        self.assertTrue(manager.shutdown())

    def test_capture_opens_the_icloud_sign_in_form_without_credentials(self):
        clicked = []

        class Locator:
            def __init__(self, label):
                self.label = label

            def count(self):
                return int(self.label == "登录")

            def click(self, **kwargs):
                clicked.append((self.label, kwargs))

        class Page:
            def get_by_role(self, role, *, name, exact):
                self.assertions.append((role, name, exact))
                return Locator(name)

            assertions = []

        page = Page()

        self.assertTrue(_click_icloud_sign_in(page))
        self.assertEqual(clicked, [("登录", {"timeout": 5_000})])
        self.assertEqual(page.assertions[0], ("button", "登录", True))

    def test_capture_timeout_distinguishes_missing_and_rejected_list_requests(self):
        missing = _capture_timeout_error(0, 0)
        rejected = _capture_timeout_error(1, 1)
        generic = _capture_timeout_error(1, 0)

        self.assertIsInstance(missing, HmeCaptureNoListRequestError)
        self.assertIsInstance(rejected, HmeCaptureSessionRejectedError)
        self.assertIsInstance(generic, HmeCaptureError)
        self.assertEqual(missing.code, "hme_capture_no_list_request")
        self.assertEqual(rejected.code, "hme_capture_session_rejected")

    def test_macos_capture_uses_a_distinct_visible_app_without_automation_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Google Chrome for Testing.app"
            executable = app / "Contents/MacOS/Google Chrome for Testing"
            executable.parent.mkdir(parents=True)
            executable.touch()
            command = _macos_browser_command(app, Path("/tmp/profile"), 43123)

            self.assertEqual(_browser_app_bundle(executable), app.resolve())
            self.assertEqual(
                command[:4], ["/usr/bin/open", "-na", str(app), "--args"]
            )
            self.assertIn("--remote-debugging-port=43123", command)
            self.assertIn("--no-proxy-server", command)
            self.assertNotIn("--enable-automation", command)
            self.assertNotIn("--disable-blink-features=AutomationControlled", command)
            self.assertNotIn("--remote-debugging-port=0", command)

    def test_authenticated_icloud_setup_builds_a_session_from_core_cookies(self):
        template = captured_session()

        class Context:
            @staticmethod
            def cookies(_urls):
                return [
                    {"name": name, "value": f"fresh-{index}"}
                    for index, name in enumerate(sorted(CORE_SESSION_COOKIE_NAMES))
                ]

        class Page:
            @staticmethod
            def evaluate(_expression):
                return "Fresh Browser"

        session = _session_from_authenticated_context(Context(), Page(), template)

        self.assertIsNotNone(session)
        self.assertEqual(session.host, template.host)
        self.assertEqual(session.client_id, template.client_id)
        self.assertEqual(session.user_agent, "Fresh Browser")
        self.assertIn("X-APPLE-WEBAUTH-TOKEN=fresh-1", session.cookie)
        self.assertTrue(
            _is_authenticated_setup_response(
                "https://setup.icloud.com.cn/setup/ws/1/validate?clientId=secret",
                200,
            )
        )
        self.assertFalse(
            _is_authenticated_setup_response(
                "https://setup.icloud.com.cn/setup/ws/1/validate",
                421,
            )
        )


if __name__ == "__main__":
    unittest.main()
