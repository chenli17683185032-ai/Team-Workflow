import unittest

from team_protocol.openbrowser import (
    OpenBrowserClient,
    OpenBrowserError,
    OpenBrowserManualLogin,
    OpenBrowserProfile,
    choose_openbrowser_profile,
    parse_openbrowser_profile_ids,
    read_chatgpt_session,
    validate_openbrowser_base_url,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class QueueSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def wrapped(data):
    return FakeResponse({"code": 0, "msg": "success", "data": data})


class OpenBrowserClientTests(unittest.TestCase):
    def test_requires_loopback_http_origin(self):
        self.assertEqual(
            validate_openbrowser_base_url("http://127.0.0.1:50325/"),
            "http://127.0.0.1:50325",
        )
        self.assertEqual(
            validate_openbrowser_base_url("http://[::1]:50325"),
            "http://[::1]:50325",
        )
        for value in (
            "https://127.0.0.1:50325",
            "http://example.com:50325",
            "http://127.0.0.1:50325/api",
            "http://name:secret@127.0.0.1:50325",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_openbrowser_base_url(value)

    def test_parses_unique_explicit_profile_pool(self):
        self.assertEqual(
            parse_openbrowser_profile_ids("team_01, team_02\nteam_01"),
            ("team_01", "team_02"),
        )
        with self.assertRaises(ValueError):
            parse_openbrowser_profile_ids("team.profile")

    def test_lists_starts_and_stops_one_profile(self):
        session = QueueSession(
            [
                wrapped(
                    {
                        "list": [
                            {
                                "profile_id": "team_01",
                                "name": "Team 01",
                                "status": "Inactive",
                                "debug_port": None,
                            }
                        ]
                    }
                ),
                wrapped(
                    {
                        "profile_id": "team_01",
                        "debug_port": 53123,
                    }
                ),
                wrapped({"profile_id": "team_01"}),
            ]
        )
        client = OpenBrowserClient(
            "http://127.0.0.1:50325", "local-secret", session=session
        )

        profiles = client.list_profiles()
        started = client.start_profile("team_01")
        client.stop_profile("team_01")

        self.assertEqual(profiles[0].profile_id, "team_01")
        self.assertFalse(profiles[0].running)
        self.assertTrue(started.running)
        self.assertEqual(started.debug_port, 53123)
        self.assertEqual(
            [call[1] for call in session.calls],
            [
                "http://127.0.0.1:50325/api/v1/user/list",
                "http://127.0.0.1:50325/api/v1/browser/start",
                "http://127.0.0.1:50325/api/v1/browser/stop",
            ],
        )
        for _method, _url, kwargs in session.calls:
            self.assertEqual(kwargs["headers"]["api-key"], "local-secret")

    def test_rejects_api_error_without_exposing_response_or_key(self):
        session = QueueSession(
            [
                FakeResponse(
                    {
                        "code": 401,
                        "msg": "rejected local-secret cookie-secret",
                        "data": None,
                    }
                )
            ]
        )
        client = OpenBrowserClient(
            "http://127.0.0.1:50325", "local-secret", session=session
        )

        with self.assertRaises(OpenBrowserError) as caught:
            client.list_profiles()

        message = str(caught.exception)
        self.assertIn("(401)", message)
        self.assertNotIn("local-secret", message)
        self.assertNotIn("cookie-secret", message)

    def test_selects_only_unbound_inactive_profile_and_reuses_binding(self):
        profiles = [
            OpenBrowserProfile("team_01", "One", False),
            OpenBrowserProfile("team_02", "Two", False),
            OpenBrowserProfile("team_03", "Three", True, 53123),
        ]

        selected = choose_openbrowser_profile(
            profiles,
            ("team_01", "team_02", "team_03"),
            {"team_01"},
        )
        rebound = choose_openbrowser_profile(
            profiles,
            ("team_01",),
            {"team_01", "team_02"},
            existing_id="team_03",
        )

        self.assertEqual(selected.profile_id, "team_02")
        self.assertEqual(rebound.profile_id, "team_03")
        with self.assertRaisesRegex(OpenBrowserError, "no unused"):
            choose_openbrowser_profile(
                profiles,
                ("team_01", "team_03"),
                {"team_01"},
            )


class FakePage:
    def __init__(self, url, result=None):
        self.url = url
        self.result = result
        self.waits = []
        self.front = False

    def evaluate(self, _script):
        if isinstance(self.result, list):
            return self.result.pop(0) if len(self.result) > 1 else self.result[0]
        return self.result

    def bring_to_front(self):
        self.front = True

    def is_closed(self):
        return False

    def wait_for_timeout(self, value):
        self.waits.append(value)


class FakeContext:
    def __init__(self, pages, cookies=None):
        self.pages = list(pages)
        self._cookies = list(cookies or [])

    def cookies(self, _urls=None):
        return self._cookies

    def new_page(self):
        page = FakePage("about:blank")
        page.goto = lambda url, **_kwargs: setattr(page, "url", url)
        self.pages.append(page)
        return page


class FakeBrowser:
    def __init__(self, context, *, connected=True):
        self.contexts = [context]
        self.connected = connected

    def is_connected(self):
        return self.connected


class FakeChromium:
    def __init__(self, browser):
        self.browser = browser
        self.calls = []

    def connect_over_cdp(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.browser


class FakePlaywrightContext:
    def __init__(self, chromium):
        self.chromium = chromium

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class FakeOpenBrowserClient:
    def __init__(self):
        self.calls = []

    def start_profile(self, profile_id):
        self.calls.append(("start", profile_id))
        return OpenBrowserProfile(profile_id, "", True, 53123)

    def stop_profile(self, profile_id):
        self.calls.append(("stop", profile_id))


class OpenBrowserManualLoginTests(unittest.TestCase):
    def session_page(self, email="child@example.com"):
        return FakePage(
            "https://chatgpt.com/",
            {
                "status": 200,
                "data": {
                    "accessToken": "access-secret",
                    "user": {"email": email},
                },
            },
        )

    @staticmethod
    def session_result(email):
        return {
            "status": 200,
            "data": {
                "accessToken": "access-secret",
                "user": {"email": email},
            },
        }

    def test_reads_session_cookie_chunks_from_chatgpt_page(self):
        context = FakeContext(
            [FakePage("https://auth.openai.com/log-in"), self.session_page()],
            [
                {
                    "name": "__Secure-next-auth.session-token.1",
                    "value": "two",
                },
                {
                    "name": "__Secure-next-auth.session-token.0",
                    "value": "one",
                },
            ],
        )

        session = read_chatgpt_session(context)

        self.assertEqual(session["email"], "child@example.com")
        self.assertEqual(session["session_token"], "onetwo")
        self.assertEqual(session["token_source"], "openbrowser_manual")

    def test_reuses_existing_session_validates_and_stops_only_target(self):
        client = FakeOpenBrowserClient()
        context = FakeContext(
            [self.session_page()],
            [
                {
                    "name": "__Secure-next-auth.session-token",
                    "value": "session-secret",
                }
            ],
        )
        chromium = FakeChromium(FakeBrowser(context))
        statuses = []
        validator_calls = []
        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=30,
            status_callback=statuses.append,
            playwright_factory=lambda: FakePlaywrightContext(chromium),
        )

        result = login.wait(
            session_validator=lambda session: validator_calls.append(dict(session))
            or {**session, "account_id": "workspace-1"}
        )

        self.assertEqual(result["account_id"], "workspace-1")
        self.assertEqual(client.calls, [("start", "team_01"), ("stop", "team_01")])
        self.assertEqual(
            statuses,
            ["profile_started", "verified", "profile_stopped"],
        )
        self.assertEqual(len(validator_calls), 1)
        self.assertNotIn("access-secret", str(statuses))
        self.assertNotIn("session-secret", str(statuses))

    def test_cancel_stops_target_profile(self):
        client = FakeOpenBrowserClient()
        context = FakeContext([FakePage("https://chatgpt.com/")])
        chromium = FakeChromium(FakeBrowser(context))
        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=30,
            playwright_factory=lambda: FakePlaywrightContext(chromium),
        )
        stop_event = __import__("threading").Event()
        stop_event.set()

        with self.assertRaisesRegex(OpenBrowserError, "cancelled"):
            login.wait(session_validator=lambda session: session, stop_event=stop_event)

        self.assertEqual(client.calls, [("start", "team_01"), ("stop", "team_01")])

    def test_wrong_account_fails_without_clearing_or_replacing_the_profile(self):
        client = FakeOpenBrowserClient()
        page = FakePage(
            "https://chatgpt.com/",
            [
                self.session_result("wrong@example.com"),
                self.session_result("child@example.com"),
            ],
        )
        context = FakeContext(
            [page],
            [
                {
                    "name": "__Secure-next-auth.session-token",
                    "value": "session-secret",
                }
            ],
        )
        statuses = []
        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=30,
            status_callback=statuses.append,
            playwright_factory=lambda: FakePlaywrightContext(
                FakeChromium(FakeBrowser(context))
            ),
        )

        with self.assertRaisesRegex(OpenBrowserError, "different account"):
            login.wait(session_validator=lambda session: dict(session))

        self.assertEqual(statuses.count("wrong_account"), 1)
        self.assertEqual(client.calls, [("start", "team_01"), ("stop", "team_01")])

    def test_empty_profile_runs_automatic_login_driver_once(self):
        client = FakeOpenBrowserClient()
        page = FakePage("https://chatgpt.com/", None)
        context = FakeContext(
            [page],
            [
                {
                    "name": "__Secure-next-auth.session-token",
                    "value": "session-secret",
                }
            ],
        )
        statuses = []
        login_calls = []
        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=30,
            status_callback=statuses.append,
            playwright_factory=lambda: FakePlaywrightContext(
                FakeChromium(FakeBrowser(context))
            ),
        )

        result = login.wait(
            login_runner=lambda browser_context, login_page: login_calls.append(
                (browser_context, login_page)
            )
            or {
                "access_token": "access-secret",
                "session_token": "session-secret",
                "email": "child@example.com",
            },
            session_validator=lambda session: {
                **session,
                "account_id": "workspace-1",
            },
        )

        self.assertEqual(result["account_id"], "workspace-1")
        self.assertEqual(login_calls, [(context, page)])
        self.assertIn("automating_login", statuses)
        self.assertNotIn("waiting_for_user", statuses)
        self.assertEqual(client.calls, [("start", "team_01"), ("stop", "team_01")])

    def test_team_validation_retries_until_the_target_team_appears(self):
        client = FakeOpenBrowserClient()
        context = FakeContext(
            [self.session_page()],
            [
                {
                    "name": "__Secure-next-auth.session-token",
                    "value": "session-secret",
                }
            ],
        )
        statuses = []
        attempts = []

        def validator(session):
            attempts.append(dict(session))
            if len(attempts) == 1:
                raise RuntimeError("Team has not appeared yet")
            return dict(session)

        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=30,
            status_callback=statuses.append,
            playwright_factory=lambda: FakePlaywrightContext(
                FakeChromium(FakeBrowser(context))
            ),
            monotonic=lambda: 0.0,
        )

        login.wait(session_validator=validator)

        self.assertEqual(len(attempts), 2)
        self.assertIn("waiting_for_team", statuses)
        self.assertEqual(statuses[-2:], ["verified", "profile_stopped"])

    def test_closed_browser_fails_and_stops_only_the_target_profile(self):
        client = FakeOpenBrowserClient()
        context = FakeContext([FakePage("https://chatgpt.com/")])
        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=30,
            playwright_factory=lambda: FakePlaywrightContext(
                FakeChromium(FakeBrowser(context, connected=False))
            ),
        )

        with self.assertRaisesRegex(OpenBrowserError, "profile was closed"):
            login.wait(session_validator=lambda session: session)

        self.assertEqual(client.calls, [("start", "team_01"), ("stop", "team_01")])

    def test_automatic_login_timeout_is_bounded_and_stops_the_profile(self):
        client = FakeOpenBrowserClient()
        context = FakeContext([FakePage("https://chatgpt.com/")])
        clock = iter((0.0, 0.0, 2.0))
        login = OpenBrowserManualLogin(
            client,
            "team_01",
            expected_email="child@example.com",
            timeout_seconds=1,
            playwright_factory=lambda: FakePlaywrightContext(
                FakeChromium(FakeBrowser(context))
            ),
            monotonic=lambda: next(clock),
        )

        with self.assertRaisesRegex(OpenBrowserError, "timed out"):
            login.wait(
                login_runner=lambda _context, _page: {
                    "access_token": "access-secret",
                    "session_token": "session-secret",
                    "email": "child@example.com",
                },
                session_validator=lambda _session: (_ for _ in ()).throw(
                    RuntimeError("Team has not appeared yet")
                ),
            )

        self.assertEqual(client.calls, [("start", "team_01"), ("stop", "team_01")])


if __name__ == "__main__":
    unittest.main()
