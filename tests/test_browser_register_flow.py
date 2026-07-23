import inspect
import json
import re
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_protocol.registrar_runtime import browser_register_flow, register


class _FakeElement:
    def __init__(self, tag, key, **attrs):
        self.tag = tag
        self.key = key
        self.attrs = {name.replace("_", "-"): str(value) for name, value in attrs.items()}
        self.visible = True
        self.editable = tag == "input"
        self.value = ""


class _FakeLocator:
    def __init__(self, page, elements, *, body=False):
        self.page = page
        self.elements = list(elements)
        self.body = body

    def count(self):
        return len(self.elements)

    def nth(self, index):
        return _FakeLocator(self.page, [self.elements[index]])

    def is_visible(self):
        return bool(self.elements and self.elements[0].visible)

    def is_editable(self):
        return bool(self.elements and self.elements[0].editable)

    def is_enabled(self):
        return bool(self.elements)

    def get_attribute(self, name):
        if not self.elements:
            return None
        if name == "tagName":
            return self.elements[0].tag
        return self.elements[0].attrs.get(name)

    def fill(self, value, **_kwargs):
        if len(self.elements) != 1:
            raise RuntimeError("fake locator is not unique")
        element = self.elements[0]
        element.value = value
        self.page.events.append(f"fill:{element.key}")
        self.page._filled(element)

    def click(self, **_kwargs):
        if len(self.elements) != 1:
            raise RuntimeError("fake locator is not unique")
        self.page._click(self.elements[0])

    def inner_text(self, **_kwargs):
        if not self.body:
            return ""
        return self.page.body_text


class _FakePage:
    def __init__(
        self,
        scenario="new",
        *,
        segmented_otp=False,
        segmented_birthdate=False,
        otp_auto_submit=False,
        otp_auto_submit_delay_polls=0,
        complete_checkbox=False,
    ):
        self.scenario = scenario
        self.segmented_otp = segmented_otp
        self.segmented_birthdate = segmented_birthdate
        self.otp_auto_submit = otp_auto_submit
        self.otp_auto_submit_delay_polls = int(otp_auto_submit_delay_polls)
        self.complete_checkbox = complete_checkbox
        self._pending_otp_submit_polls = 0
        self.stage = "login"
        self.url = f"{browser_register_flow.AUTH_BASE}/log-in"
        self.events = []
        self.closed = False
        self._elements = []
        self._render()

    @property
    def body_text(self):
        return {
            "challenge": "Performing security verification CAPTCHA",
            "phone": "Phone verification required",
            "terms": "Confirm terms before continuing",
            "unknown": "Unexpected authentication page",
        }.get(self.stage, self.stage)

    def title(self):
        return "Security verification" if self.stage == "challenge" else self.stage

    def goto(self, url, **_kwargs):
        self.events.append("goto")
        if url.startswith(f"{browser_register_flow.CHATGPT_BASE}/auth/login_with"):
            self._set_stage("login")
        elif url.startswith(browser_register_flow.CHATGPT_BASE):
            self._set_stage("complete")
        else:
            self.url = url

    def wait_for_timeout(self, milliseconds):
        if self._pending_otp_submit_polls:
            self._pending_otp_submit_polls -= 1
            if not self._pending_otp_submit_polls:
                self._set_stage("complete" if self.scenario == "existing" else "profile")
        time.sleep(min(float(milliseconds) / 1000.0, 0.005))

    def locator(self, selector):
        if selector == "body":
            return _FakeLocator(self, [_FakeElement("body", "body")], body=True)
        matches = [element for element in self._elements if self._matches(element, selector)]
        return _FakeLocator(self, matches)

    @staticmethod
    def _matches(element, selector):
        selector = selector.strip()
        tag_match = re.match(r"^(input|button|a)", selector)
        if tag_match and element.tag != tag_match.group(1):
            return False
        for name, operator, value in re.findall(
            r'\[([\w-]+)(?:(\^=|\*=|=)["\']?([^"\']*?)["\']?)?\]', selector
        ):
            actual = element.attrs.get(name)
            if not operator and actual is None:
                return False
            if operator == "=" and actual != value:
                return False
            if operator == "^=" and (actual is None or not actual.startswith(value)):
                return False
            if operator == "*=" and (actual is None or value not in actual):
                return False
        return True

    def _set_stage(self, stage):
        self.stage = stage
        self.url = {
            "login": f"{browser_register_flow.AUTH_BASE}/log-in",
            "email": f"{browser_register_flow.AUTH_BASE}/create-account",
            "password": f"{browser_register_flow.AUTH_BASE}/create-account/password",
            "otp": f"{browser_register_flow.AUTH_BASE}/email-verification/register",
            "profile": f"{browser_register_flow.AUTH_BASE}/about-you",
            "complete": (
                f"{browser_register_flow.CHATGPT_BASE}/api/auth/callback/openai"
                "?code=test-code&state=test-state"
            ),
            "challenge": f"{browser_register_flow.AUTH_BASE}/challenge",
            "phone": f"{browser_register_flow.AUTH_BASE}/add-phone",
            "terms": f"{browser_register_flow.AUTH_BASE}/terms-confirmation",
            "consent": f"{browser_register_flow.AUTH_BASE}/workspace",
            "unknown": f"{browser_register_flow.AUTH_BASE}/unexpected",
        }[stage]
        self._render()

    def _render(self):
        if self.stage == "login":
            self._elements = [_FakeElement("a", "signup", href="/create-account")]
        elif self.stage == "email":
            self._elements = [
                _FakeElement("input", "email", type="email", name="email", autocomplete="email"),
                _FakeElement("button", "submit-email", type="submit"),
            ]
        elif self.stage == "password":
            self._elements = [
                _FakeElement("input", "password", type="password", name="password"),
                _FakeElement("button", "submit-password", type="submit"),
            ]
        elif self.stage == "otp":
            if self.segmented_otp:
                self._elements = [
                    _FakeElement(
                        "input",
                        f"otp-{index}",
                        autocomplete="one-time-code",
                        inputmode="numeric",
                        maxlength="1",
                    )
                    for index in range(6)
                ]
            else:
                self._elements = [
                    _FakeElement(
                        "input",
                        "otp",
                        name="code",
                        autocomplete="one-time-code",
                        inputmode="numeric",
                    )
                ]
            self._elements.append(_FakeElement("button", "submit-otp", type="submit"))
        elif self.stage == "profile":
            self._elements = [
                _FakeElement("input", "name", name="name", autocomplete="name")
            ]
            if self.segmented_birthdate:
                self._elements.extend(
                    [
                        _FakeElement("input", "birth-month", name="birth-month", placeholder="MM"),
                        _FakeElement("input", "birth-day", name="birth-day", placeholder="DD"),
                        _FakeElement("input", "birth-year", name="birth-year", placeholder="YYYY"),
                    ]
                )
            else:
                self._elements.append(
                    _FakeElement("input", "birthdate", name="birthdate", type="date")
                )
            self._elements.append(_FakeElement("button", "submit-profile", type="submit"))
        elif self.stage == "terms":
            self._elements = [_FakeElement("input", "terms", type="checkbox")]
        elif self.stage == "complete" and self.complete_checkbox:
            self._elements = [_FakeElement("input", "app-option", type="checkbox")]
        else:
            self._elements = []

    def _click(self, element):
        self.events.append(f"click:{element.key}")
        if element.key == "signup":
            self._set_stage("email")
            return
        if element.key == "submit-email":
            next_stage = {
                "new": "password",
                "segmented": "password",
                "existing": "otp",
                "challenge": "challenge",
                "phone": "phone",
                "terms": "terms",
                "consent": "otp",
                "unknown": "unknown",
            }[self.scenario]
            self._set_stage(next_stage)
        elif element.key == "submit-password":
            self._set_stage("otp")
        elif element.key == "submit-otp":
            if self.scenario == "existing":
                self._set_stage("complete")
            elif self.scenario == "consent":
                self._set_stage("consent")
            else:
                self._set_stage("profile")
        elif element.key == "submit-profile":
            self._set_stage("complete")

    def _filled(self, element):
        if not self.otp_auto_submit:
            return
        if element.key == "otp" or element.key == "otp-5":
            if self.otp_auto_submit_delay_polls:
                self._pending_otp_submit_polls = self.otp_auto_submit_delay_polls
            else:
                self._set_stage("complete" if self.scenario == "existing" else "profile")


class _FakeCookies(dict):
    def set(self, name, value, **_kwargs):
        self[name] = value


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.cookies = _FakeCookies()
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        if url == "https://cloudflare.com/cdn-cgi/trace":
            return SimpleNamespace(
                status_code=200,
                text="ip=192.0.2.1\nloc=US\n",
                url=url,
                headers={},
                cookies={},
            )
        raise AssertionError(f"legacy HTTP registration request: {url}")

    def close(self):
        return None


class _FakeMailProvider:
    def create_mailbox(self, **_kwargs):
        return "new-child@example.test", "mail-credential"


class _FakeProfile:
    impersonate = "chrome"
    user_agent = "TestBrowser/1.0"
    scope = "auto_desktop"
    http_headers = {
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Test";v="1"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "User-Agent": "TestBrowser/1.0",
    }

    def validate(self):
        return self


class BrowserRegisterFlowTests(unittest.TestCase):
    def _flow(
        self,
        scenario="new",
        *,
        session_email="new-child@example.test",
        **page_kwargs,
    ):
        flow = browser_register_flow.PlaywrightBrowserFlow(
            config={
                "chatgpt_warmup_wait_ms": 0,
                "otp_auto_submit_grace_ms": 5,
                "stage_timeout_seconds": 0.03,
                "timeout_seconds": 1,
            }
        )
        page = _FakePage(scenario, **page_kwargs)
        flow.open = lambda: None
        flow.close = lambda: setattr(page, "closed", True)
        flow._warm_chatgpt_page = lambda: page
        flow._cookies = lambda: []
        flow._session_reads = []

        def get_session():
            flow._session_reads.append(page.url)
            return {
                "access_token": "test-access-token",
                "session_token": "test-session-token",
                "email": session_email,
            }

        flow._try_get_chatgpt_session = get_session

        def wait_for_otp(**_kwargs):
            self.assertEqual(page.stage, "otp")
            page.events.append("mail:otp")
            return "123456"

        flow._wait_for_otp = wait_for_otp
        return flow, page

    @staticmethod
    def _run(flow):
        return flow._run_registration_and_oauth_sync(
            email="new-child@example.test",
            account_password="password-value",
            mail_provider=object(),
            mail_auth_credential="mail-credential",
            random_profile={"name": "Test User", "birthdate": "1994-05-17"},
        )

    def test_new_identity_uses_only_official_page_forms(self):
        flow, page = self._flow("new")

        result = self._run(flow)

        self.assertEqual(
            page.events,
            [
                "click:signup",
                "fill:email",
                "click:submit-email",
                "fill:password",
                "click:submit-password",
                "mail:otp",
                "fill:otp",
                "click:submit-otp",
                "fill:name",
                "fill:birthdate",
                "click:submit-profile",
            ],
        )
        self.assertEqual(result["identity_branch"], "new_account")
        self.assertEqual(result["session_token_data"]["access_token"], "test-access-token")
        self.assertTrue(page.closed)

    def test_existing_identity_skips_password_and_profile(self):
        flow, page = self._flow("existing")

        result = self._run(flow)

        self.assertEqual(
            page.events,
            [
                "click:signup",
                "fill:email",
                "click:submit-email",
                "mail:otp",
                "fill:otp",
                "click:submit-otp",
            ],
        )
        self.assertEqual(result["identity_branch"], "existing_identity")

    def test_segmented_otp_and_birthdate_are_filled_semantically(self):
        flow, page = self._flow(
            "segmented", segmented_otp=True, segmented_birthdate=True
        )

        self._run(flow)

        self.assertEqual(
            [event for event in page.events if event.startswith("fill:otp-")],
            [f"fill:otp-{index}" for index in range(6)],
        )
        self.assertEqual(
            [event for event in page.events if event.startswith("fill:birth-")],
            ["fill:birth-month", "fill:birth-day", "fill:birth-year"],
        )

    def test_auto_submitted_otp_does_not_click_the_next_form(self):
        flow, page = self._flow("new", otp_auto_submit=True)

        self._run(flow)

        self.assertNotIn("click:submit-otp", page.events)
        self.assertIn("click:submit-profile", page.events)

    def test_asynchronous_auto_submitted_otp_is_not_clicked_twice(self):
        flow, page = self._flow(
            "new",
            otp_auto_submit=True,
            otp_auto_submit_delay_polls=1,
        )

        self._run(flow)

        self.assertNotIn("click:submit-otp", page.events)
        self.assertEqual(page.events.count("fill:otp"), 1)

    def test_post_auth_selection_is_a_manual_gate(self):
        flow, page = self._flow("consent")

        with self.assertRaisesRegex(RuntimeError, "manual confirmation"):
            self._run(flow)

        self.assertEqual(flow._session_reads, [])
        self.assertTrue(page.closed)

    def test_final_session_must_match_registration_email(self):
        for session_email in ("", "other-child@example.test"):
            with self.subTest(session_email=session_email):
                flow, page = self._flow("new", session_email=session_email)

                with self.assertRaisesRegex(RuntimeError, "session email"):
                    self._run(flow)

                self.assertTrue(page.closed)

    def test_chatgpt_app_controls_do_not_reopen_manual_confirmation(self):
        flow, _page = self._flow("new", complete_checkbox=True)

        result = self._run(flow)

        self.assertEqual(result["session_token_data"]["email"], "new-child@example.test")

    def test_security_and_manual_gates_fail_before_otp(self):
        for scenario, expected in (
            ("challenge", "security challenge"),
            ("phone", "phone verification"),
            ("terms", "manual confirmation"),
        ):
            with self.subTest(scenario=scenario):
                flow, page = self._flow(scenario)

                with self.assertRaisesRegex(RuntimeError, expected):
                    self._run(flow)

                self.assertNotIn("mail:otp", page.events)
                self.assertTrue(page.closed)

    def test_unknown_page_fails_with_shared_timeout(self):
        flow, page = self._flow("unknown")

        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "unexpected page"):
            self._run(flow)

        self.assertLess(time.monotonic() - started, 0.5)
        self.assertNotIn("mail:otp", page.events)
        self.assertTrue(page.closed)

    def test_registration_source_contains_no_private_registration_requests(self):
        source = inspect.getsource(browser_register_flow.PlaywrightBrowserFlow)

        for forbidden in (
            "/api/accounts/authorize/continue",
            "/api/accounts/user/register",
            "/api/accounts/email-otp/send",
            "/api/accounts/email-otp/validate",
            "/api/accounts/create_account",
            "SentinelSDK",
        ):
            self.assertNotIn(forbidden, source)

    def test_registration_entrypoint_contains_no_private_registration_protocol(self):
        forbidden_urls = (
            "/api/accounts/authorize/continue",
            "/api/accounts/user/register",
            "/api/accounts/email-otp/send",
            "/api/accounts/email-otp/validate",
            "/api/accounts/create_account",
        )
        source = inspect.getsource(register.run)
        for forbidden in forbidden_urls:
            self.assertNotIn(forbidden, source)

        compiled_strings = []

        def collect_strings(code):
            for value in code.co_consts:
                if isinstance(value, str):
                    compiled_strings.append(value)
                elif hasattr(value, "co_consts"):
                    collect_strings(value)

        collect_strings(register.run.__code__)
        for forbidden in forbidden_urls:
            self.assertFalse(
                any(forbidden in value for value in compiled_strings),
                forbidden,
            )

    def test_registration_loader_never_executes_cached_bytecode(self):
        source = inspect.getsource(register._load_browser_register_flow_class)

        self.assertNotIn("__pycache__", source)
        self.assertNotIn("SourcelessFileLoader", source)

    def test_callback_url_is_restricted_to_chatgpt(self):
        self.assertTrue(
            browser_register_flow.PlaywrightBrowserFlow._is_callback_url(
                "https://chatgpt.com/api/auth/callback/openai?code=x&state=y"
            )
        )
        self.assertFalse(
            browser_register_flow.PlaywrightBrowserFlow._is_callback_url(
                "https://example.test/api/auth/callback/openai?code=x&state=y"
            )
        )

    def test_chatgpt_origin_check_rejects_lookalike_host(self):
        flow = browser_register_flow.PlaywrightBrowserFlow()
        page = _FakePage()
        page.url = "https://chatgpt.com.example.test/fake"
        flow._context = object()
        flow._page = page

        flow._ensure_page_origin("chatgpt")

        self.assertIn("goto", page.events)

    def test_session_probe_does_not_navigate_away_from_auth(self):
        flow = browser_register_flow.PlaywrightBrowserFlow()
        page = _FakePage("consent")
        page._set_stage("consent")
        flow._context = object()
        flow._page = page

        self.assertIsNone(flow._try_get_chatgpt_session())
        self.assertNotIn("goto", page.events)

    def test_browser_session_short_circuits_mismatched_callback_exchange(self):
        callback = (
            "https://chatgpt.com/api/auth/callback/openai"
            "?code=test-code&state=chatgpt-state"
        )

        class FakeFlow:
            def __init__(self, **_kwargs):
                pass

            def run_registration_and_oauth(self, **_kwargs):
                return {
                    "device_id": "device-id",
                    "callback_url": callback,
                    "consent_url": callback,
                    "cookies": [],
                    "session_token_data": {
                        "access_token": "test-access-token",
                        "session_token": "test-session-token",
                        "email": "new-child@example.test",
                        "token_source": "chatgpt_session",
                    },
                }

        emitter = SimpleNamespace(
            warn=lambda *_args, **_kwargs: None,
            info=lambda *_args, **_kwargs: None,
            success=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
        )
        with (
            patch.object(
                register,
                "_load_browser_register_flow_class",
                return_value=FakeFlow,
            ),
            patch.object(register, "submit_callback_url") as callback_exchange,
            patch.object(register, "exchange_codex_tokens_from_session") as cookie_exchange,
            patch.object(register.requests, "Session") as session_factory,
        ):
            token_json = register._run_browser_full_registration_flow(
                email="new-child@example.test",
                account_password="password-value",
                mail_provider=object(),
                mail_auth_credential="{}",
                emitter=emitter,
                stop_event=None,
                proxy=None,
                user_agent=_FakeProfile.user_agent,
                browser_entry_config={"enabled": True},
                browser_sentinel_config={},
                mail_provider_name="icloud_hme_imap",
                session_profile=_FakeProfile(),
            )

        payload = json.loads(token_json)
        self.assertEqual(payload["access_token"], "test-access-token")
        self.assertEqual(payload["token_source"], "chatgpt_session")
        self.assertTrue(payload["session_only"])
        callback_exchange.assert_not_called()
        cookie_exchange.assert_not_called()
        session_factory.assert_not_called()

    def test_browser_result_without_session_never_uses_token_exchange_fallbacks(self):
        class FakeFlow:
            def __init__(self, **_kwargs):
                pass

            def run_registration_and_oauth(self, **_kwargs):
                return {
                    "device_id": "device-id",
                    "callback_url": (
                        "https://chatgpt.com/api/auth/callback/openai"
                        "?code=test-code&state=test-state"
                    ),
                    "consent_url": "https://auth.openai.com/workspace",
                    "cookies": [],
                }

        emitter = SimpleNamespace(
            warn=lambda *_args, **_kwargs: None,
            info=lambda *_args, **_kwargs: None,
            success=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
        )
        with (
            patch.object(
                register,
                "_load_browser_register_flow_class",
                return_value=FakeFlow,
            ),
            patch.object(register, "generate_oauth_url") as oauth_factory,
            patch.object(register, "submit_callback_url") as callback_exchange,
            patch.object(register, "exchange_codex_tokens_from_session") as cookie_exchange,
            patch.object(register.requests, "Session") as session_factory,
        ):
            token_json = register._run_browser_full_registration_flow(
                email="new-child@example.test",
                account_password="password-value",
                mail_provider=object(),
                mail_auth_credential="{}",
                emitter=emitter,
                stop_event=None,
                proxy=None,
                user_agent=_FakeProfile.user_agent,
                browser_entry_config={"enabled": True},
                browser_sentinel_config={},
                mail_provider_name="icloud_hme_imap",
                session_profile=_FakeProfile(),
            )

        self.assertIsNone(token_json)
        oauth_factory.assert_not_called()
        callback_exchange.assert_not_called()
        cookie_exchange.assert_not_called()
        session_factory.assert_not_called()

    def test_browser_integration_rejects_mismatched_session_identity(self):
        class FakeFlow:
            def __init__(self, **_kwargs):
                pass

            def run_registration_and_oauth(self, **_kwargs):
                return {
                    "session_token_data": {
                        "access_token": "test-access-token",
                        "session_token": "test-session-token",
                        "email": "other-child@example.test",
                    }
                }

        emitter = SimpleNamespace(
            warn=lambda *_args, **_kwargs: None,
            info=lambda *_args, **_kwargs: None,
            success=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
        )
        with patch.object(
            register,
            "_load_browser_register_flow_class",
            return_value=FakeFlow,
        ):
            token_json = register._run_browser_full_registration_flow(
                email="new-child@example.test",
                account_password="password-value",
                mail_provider=object(),
                mail_auth_credential="{}",
                emitter=emitter,
                stop_event=None,
                proxy=None,
                user_agent=_FakeProfile.user_agent,
                browser_entry_config={"enabled": True},
                browser_sentinel_config={},
                mail_provider_name="icloud_hme_imap",
                session_profile=_FakeProfile(),
            )

        self.assertIsNone(token_json)

    def test_chatgpt_session_uses_cookie_when_payload_omits_session_token(self):
        flow = browser_register_flow.PlaywrightBrowserFlow()
        page = SimpleNamespace(
            url="https://chatgpt.com/",
            evaluate=lambda *_args, **_kwargs: {
                "status": 200,
                "json": {
                    "accessToken": "test-access-token",
                    "user": {"email": "new-child@example.test"},
                },
                "text": "",
            }
        )
        flow._context = object()
        flow._page = page
        flow._cookies = lambda: [
            {
                "name": "__Secure-next-auth.session-token",
                "value": "test-session-token",
            }
        ]

        session = flow._try_get_chatgpt_session()

        self.assertEqual(session["access_token"], "test-access-token")
        self.assertEqual(session["session_token"], "test-session-token")

    def test_run_uses_browser_protocol_before_legacy_http_registration(self):
        fake_session = _FakeSession()
        profile = _FakeProfile()
        expected = json.dumps({"access_token": "browser-token"})

        with (
            patch.object(register.requests, "Session", return_value=fake_session),
            patch.object(register, "_resolve_session_profile", return_value=profile),
            patch.object(
                register,
                "_run_browser_full_registration_flow",
                return_value=expected,
            ) as browser_flow,
        ):
            result = register.run(
                None,
                mail_provider=_FakeMailProvider(),
                mail_provider_name="icloud_hme_imap",
                session_profile=profile,
            )

        self.assertEqual(result, expected)
        browser_flow.assert_called_once()
        self.assertEqual(fake_session.urls, ["https://cloudflare.com/cdn-cgi/trace"])

    def test_run_does_not_fallback_to_legacy_http_registration(self):
        fake_session = _FakeSession()
        profile = _FakeProfile()

        with (
            patch.object(register.requests, "Session", return_value=fake_session),
            patch.object(register, "_resolve_session_profile", return_value=profile),
            patch.object(
                register,
                "_run_browser_full_registration_flow",
                return_value=None,
            ) as browser_flow,
        ):
            result = register.run(
                None,
                mail_provider=_FakeMailProvider(),
                mail_provider_name="icloud_hme_imap",
                session_profile=profile,
            )

        self.assertIsNone(result)
        browser_flow.assert_called_once()
        self.assertEqual(fake_session.urls, ["https://cloudflare.com/cdn-cgi/trace"])

    def test_capture_fixture_contains_only_protocol_shapes(self):
        fixture_path = Path(__file__).parent / "fixtures" / "group1_auth_protocol_shapes.json"
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(
            [
                item.get("network_error")
                for item in payload["existing_identity_incognito"]
                if item.get("network_error")
            ],
            ["ERR_HTTP2_PING_FAILED", "ERR_SOCKS_CONNECTION_FAILED"],
        )
        serialized = json.dumps(payload)
        self.assertNotIn("@icloud.com", serialized)
        self.assertNotIn("authorization", serialized.casefold())
        self.assertNotIn("cookie", serialized.casefold())


if __name__ == "__main__":
    unittest.main()
