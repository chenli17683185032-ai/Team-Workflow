import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_protocol.registrar_runtime import browser_register_flow, register


class _FakePage:
    def __init__(self):
        self.url = f"{browser_register_flow.AUTH_BASE}/create-account"
        self.navigations = []

    def goto(self, url, **_kwargs):
        self.navigations.append(url)
        if "/api/accounts/authorize" in url:
            self.url = f"{browser_register_flow.AUTH_BASE}/create-account"
        elif "/api/auth/callback/openai" in url:
            self.url = f"{browser_register_flow.CHATGPT_BASE}/"
        else:
            self.url = url
        return None


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
    def _flow(self, responses):
        flow = browser_register_flow.PlaywrightBrowserFlow(
            config={"transient_fetch_retry_delay_ms": 0}
        )
        page = _FakePage()
        calls = []

        flow.open = lambda: None
        flow.close = lambda: None
        flow._warm_chatgpt_page = lambda: page
        flow._ensure_page_origin = lambda _origin: page
        flow._device_id = lambda: "device-id"
        flow._generate_sentinel_bundle = lambda _flows: {
            "token": "sentinel-token",
            "so_token": "sentinel-so-token",
        }
        flow._wait_for_otp = lambda **_kwargs: "123456"
        flow._try_get_chatgpt_session = lambda: {
            "access_token": "test-access-token",
            "session_token": "test-session-token",
            "email": "new-child@example.test",
        }
        flow._cookies = lambda: []

        def fetch_json(**kwargs):
            calls.append(kwargs)
            endpoint = kwargs["url"].split("?", 1)[0]
            response = responses[endpoint]
            if isinstance(response, list):
                item = response.pop(0)
            else:
                item = response
            if isinstance(item, Exception):
                raise item
            return item

        flow._fetch_json = fetch_json
        return flow, page, calls

    @staticmethod
    def _run(flow):
        return flow._run_registration_and_oauth_sync(
            email="new-child@example.test",
            account_password="password-value",
            mail_provider=object(),
            mail_auth_credential="mail-credential",
            codex_auth_url="https://auth.openai.com/oauth/authorize?state=codex-state",
            random_profile={"name": "Test User", "birthdate": "1994-05-17"},
            signup_flow_candidates=("signup", "authorize_continue"),
            register_flow_candidates=("username_password_create",),
            email_verification_flow_candidates=("email_verification",),
            create_account_flow_candidates=("oauth_create_account",),
            password_verify_flow_candidates=("password_verify",),
        )

    def test_new_identity_uses_explicit_signup_state_machine(self):
        auth = browser_register_flow.AUTH_BASE
        chatgpt = browser_register_flow.CHATGPT_BASE
        callback = f"{chatgpt}/api/auth/callback/openai?code=test-code&state=test-state"
        flow, page, calls = self._flow(
            {
                f"{chatgpt}/api/auth/csrf": {
                    "status": 200,
                    "json": {"csrfToken": "csrf-token"},
                },
                f"{chatgpt}/api/auth/signin/openai": {
                    "status": 200,
                    "json": {"url": f"{auth}/api/accounts/authorize?state=test-state"},
                },
                f"{auth}/api/accounts/authorize/continue": {
                    "status": 200,
                    "json": {
                        "page": {"type": "create_account_password"},
                        "continue_url": "/create-account/password",
                    },
                },
                f"{auth}/api/accounts/user/register": {
                    "status": 200,
                    "json": {"page": {"type": "email_otp_send"}},
                },
                f"{auth}/api/accounts/email-otp/send": {
                    "status": 200,
                    "json": {"page": {"type": "email_otp_verification"}},
                },
                f"{auth}/api/accounts/email-otp/validate": {
                    "status": 200,
                    "json": {
                        "page": {"type": "create_account_start"},
                        "continue_url": "/about-you",
                    },
                },
                f"{auth}/api/accounts/create_account": {
                    "status": 200,
                    "json": {"continue_url": callback},
                },
            }
        )

        result = self._run(flow)

        protocol_calls = [
            (call.get("method", "GET"), call["url"].split("?", 1)[0])
            for call in calls
        ]
        self.assertEqual(
            protocol_calls,
            [
                ("GET", f"{chatgpt}/api/auth/csrf"),
                ("POST", f"{chatgpt}/api/auth/signin/openai"),
                ("POST", f"{auth}/api/accounts/authorize/continue"),
                ("POST", f"{auth}/api/accounts/user/register"),
                ("GET", f"{auth}/api/accounts/email-otp/send"),
                ("POST", f"{auth}/api/accounts/email-otp/validate"),
                ("POST", f"{auth}/api/accounts/create_account"),
            ],
        )
        authorize_call = calls[2]
        self.assertIn("screen_hint=signup", calls[1]["url"])
        self.assertEqual(authorize_call["json_body"]["screen_hint"], "signup")
        self.assertEqual(result["callback_url"], callback)
        self.assertIn(callback, page.navigations)
        self.assertFalse(
            flow._is_callback_url(
                "https://example.test/api/auth/callback/openai?code=x&state=y"
            )
        )

    def test_existing_identity_callback_skips_register_and_create_account(self):
        auth = browser_register_flow.AUTH_BASE
        chatgpt = browser_register_flow.CHATGPT_BASE
        callback = f"{chatgpt}/api/auth/callback/openai?code=test-code&state=test-state"
        flow, _page, calls = self._flow(
            {
                f"{chatgpt}/api/auth/csrf": {
                    "status": 200,
                    "json": {"csrfToken": "csrf-token"},
                },
                f"{chatgpt}/api/auth/signin/openai": {
                    "status": 200,
                    "json": {"url": f"{auth}/api/accounts/authorize?state=test-state"},
                },
                f"{auth}/api/accounts/authorize/continue": {
                    "status": 200,
                    "json": {
                        "page": {"type": "email_otp_verification"},
                        "continue_url": "/email-verification",
                    },
                },
                f"{auth}/api/accounts/email-otp/validate": {
                    "status": 200,
                    "json": {"continue_url": callback},
                },
            }
        )

        result = self._run(flow)

        paths = [call["url"].split("?", 1)[0] for call in calls]
        self.assertIn(f"{auth}/api/accounts/authorize/continue", paths)
        self.assertNotIn(f"{auth}/api/accounts/user/register", paths)
        self.assertNotIn(f"{auth}/api/accounts/email-otp/send", paths)
        self.assertNotIn(f"{auth}/api/accounts/create_account", paths)
        self.assertEqual(result["callback_url"], callback)

    def test_otp_validate_retries_only_transient_network_failures(self):
        auth = browser_register_flow.AUTH_BASE
        flow, _page, calls = self._flow(
            {
                f"{auth}/api/accounts/email-otp/validate": [
                    RuntimeError("net::ERR_HTTP2_PING_FAILED"),
                    RuntimeError("net::ERR_SOCKS_CONNECTION_FAILED"),
                    {"status": 200, "json": {}},
                ]
            }
        )

        response = flow._fetch_json_with_transient_retries(
            origin="auth",
            url=f"{auth}/api/accounts/email-otp/validate",
            method="POST",
            json_body={"code": "123456"},
            max_attempts=3,
        )

        self.assertEqual(response["status"], 200)
        self.assertEqual(len(calls), 3)

    def test_otp_validate_transient_retry_is_bounded(self):
        auth = browser_register_flow.AUTH_BASE
        flow, _page, calls = self._flow(
            {
                f"{auth}/api/accounts/email-otp/validate": [
                    RuntimeError("net::ERR_SOCKS_CONNECTION_FAILED"),
                    RuntimeError("net::ERR_SOCKS_CONNECTION_FAILED"),
                    RuntimeError("net::ERR_SOCKS_CONNECTION_FAILED"),
                ]
            }
        )

        with self.assertRaisesRegex(RuntimeError, "ERR_SOCKS_CONNECTION_FAILED"):
            flow._fetch_json_with_transient_retries(
                origin="auth",
                url=f"{auth}/api/accounts/email-otp/validate",
                method="POST",
                json_body={"code": "123456"},
                max_attempts=3,
            )

        self.assertEqual(len(calls), 3)

    def test_otp_validate_does_not_retry_non_transient_failure(self):
        auth = browser_register_flow.AUTH_BASE
        flow, _page, calls = self._flow(
            {
                f"{auth}/api/accounts/email-otp/validate": RuntimeError(
                    "request rejected with HTTP 403"
                )
            }
        )

        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            flow._fetch_json_with_transient_retries(
                origin="auth",
                url=f"{auth}/api/accounts/email-otp/validate",
                method="POST",
                json_body={"code": "123456"},
                max_attempts=3,
            )

        self.assertEqual(len(calls), 1)

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

    def test_chatgpt_session_uses_cookie_when_payload_omits_session_token(self):
        flow = browser_register_flow.PlaywrightBrowserFlow()
        page = SimpleNamespace(
            evaluate=lambda *_args, **_kwargs: {
                "status": 200,
                "json": {
                    "accessToken": "test-access-token",
                    "user": {"email": "new-child@example.test"},
                },
                "text": "",
            }
        )
        flow._ensure_page_origin = lambda _origin: page
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
            [item.get("network_error") for item in payload["existing_identity_incognito"] if item.get("network_error")],
            ["ERR_HTTP2_PING_FAILED", "ERR_SOCKS_CONNECTION_FAILED"],
        )
        serialized = json.dumps(payload)
        self.assertNotIn("@icloud.com", serialized)
        self.assertNotIn("authorization", serialized.casefold())
        self.assertNotIn("cookie", serialized.casefold())


if __name__ == "__main__":
    unittest.main()
