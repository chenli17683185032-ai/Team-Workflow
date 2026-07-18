from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from team_protocol.icloud_hme import (
    HmeClient,
    HmeError,
    HmeSessionError,
    ICloudHmeSession,
    parse_hme_session_import,
)


COOKIE = (
    "X-APPLE-DS-WEB-SESSION-TOKEN=session-secret; "
    "X-APPLE-WEBAUTH-USER=user-secret; "
    "X-APPLE-WEBAUTH-TOKEN=auth-secret"
)
URL = (
    "https://p68-maildomainws.icloud.com/v2/hme/list?"
    "clientBuildNumber=2536Project32&clientMasteringNumber=2536B20&"
    "clientId=client-123&dsid=dsid-456"
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class ICloudHmeTests(unittest.TestCase):
    def test_parse_curl_extracts_only_required_session_fields(self):
        session = parse_hme_session_import(
            f"curl '{URL}' -H 'Cookie: {COOKIE}' "
            "-H 'Origin: https://www.icloud.com' "
            "-H 'Referer: https://www.icloud.com/' -H 'User-Agent: Browser Test'"
        )

        self.assertEqual(session.host, "p68-maildomainws.icloud.com")
        self.assertEqual(session.client_id, "client-123")
        self.assertEqual(session.dsid, "dsid-456")
        self.assertEqual(session.cookie, COOKIE)
        self.assertEqual(session.user_agent, "Browser Test")

    def test_parse_har_builds_cookie_header_and_supports_china_region(self):
        china_url = URL.replace(
            "p68-maildomainws.icloud.com", "p217-maildomainws.icloud.com.cn"
        )
        document = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": china_url,
                            "headers": [
                                {"name": "Origin", "value": "https://www.icloud.com.cn"},
                                {"name": "Referer", "value": "https://www.icloud.com.cn/"},
                            ],
                            "cookies": [
                                {"name": name, "value": f"value-{index}"}
                                for index, name in enumerate(sorted({
                                    "X-APPLE-DS-WEB-SESSION-TOKEN",
                                    "X-APPLE-WEBAUTH-USER",
                                    "X-APPLE-WEBAUTH-TOKEN",
                                }))
                            ],
                        }
                    }
                ]
            }
        }

        session = parse_hme_session_import(json.dumps(document))

        self.assertEqual(session.host, "p217-maildomainws.icloud.com.cn")
        self.assertEqual(session.origin, "https://www.icloud.com.cn")
        self.assertIn("X-APPLE-DS-WEB-SESSION-TOKEN=", session.cookie)

    def test_import_rejects_host_injection_path_and_incomplete_cookie(self):
        cases = (
            URL.replace("icloud.com", "icloud.com.attacker.invalid"),
            URL.replace("/v2/hme/list", "/account/settings"),
        )
        for url in cases:
            with self.subTest(url=url), self.assertRaises(HmeSessionError):
                parse_hme_session_import(f"curl '{url}' -H 'Cookie: {COOKIE}'")
        with self.assertRaises(HmeSessionError):
            parse_hme_session_import(
                f"curl '{URL}' -H 'Cookie: X-APPLE-WEBAUTH-USER=only-one'"
            )

    def test_mapping_validation_rejects_header_injection(self):
        session = parse_hme_session_import(f"curl '{URL}' -H 'Cookie: {COOKIE}'")
        payload = session.as_secret_dict()
        payload["cookie"] += "\r\nX-Injected: yes"
        with self.assertRaises(HmeSessionError):
            ICloudHmeSession.from_mapping(payload)

    def test_client_generates_reserves_and_uses_the_profile_proxy(self):
        requests = []
        responses = [
            FakeResponse({"success": True, "result": {"hme": "first@icloud.com"}}),
            FakeResponse(
                {
                    "success": True,
                    "result": {
                        "hme": {
                            "hme": "first@icloud.com",
                            "anonymousId": "remote-secret-id",
                            "isActive": True,
                        }
                    },
                }
            ),
        ]

        def requester(method, url, **kwargs):
            requests.append((method, url, kwargs))
            return responses.pop(0)

        session = parse_hme_session_import(f"curl '{URL}' -H 'Cookie: {COOKIE}'")
        client = HmeClient(
            session,
            proxy="socks5h://parent:proxy-password@proxy.invalid:1080",
            requester=requester,
        )

        alias = client.create_alias(label="Team Workflow", note="profile-id")

        self.assertEqual(alias["hme"], "first@icloud.com")
        self.assertEqual([item[0] for item in requests], ["POST", "POST"])
        self.assertTrue(requests[0][1].startswith("https://p68-maildomainws.icloud.com/v1/hme/generate?"))
        self.assertEqual(
            requests[0][2]["proxies"]["https"],
            "socks5h://parent:proxy-password@proxy.invalid:1080",
        )
        self.assertEqual(json.loads(requests[1][2]["data"])["hme"], "first@icloud.com")
        self.assertEqual(requests[0][2]["headers"]["Cookie"], COOKIE)

    def test_empty_proxy_forces_direct_request_without_environment_proxy(self):
        calls = []

        class DirectSession:
            def __init__(self):
                self.trust_env = True

            def request(self, method, url, **kwargs):
                calls.append((self.trust_env, method, url, kwargs))
                return FakeResponse(
                    {"success": True, "result": {"hmeEmails": []}}
                )

        session = parse_hme_session_import(f"curl '{URL}' -H 'Cookie: {COOKIE}'")
        with patch("team_protocol.icloud_hme.requests.Session", DirectSession):
            self.assertEqual(HmeClient(session).list_aliases(), [])

        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0][0])
        self.assertIsNone(calls[0][3]["proxies"])

    def test_client_errors_never_include_cookie_or_response_text(self):
        secret_response = "response-secret-canary"

        def requester(*_args, **_kwargs):
            return FakeResponse(
                {"success": False, "error": {"errorMessage": secret_response}},
                status_code=200,
            )

        session = parse_hme_session_import(f"curl '{URL}' -H 'Cookie: {COOKIE}'")
        with self.assertRaises(HmeError) as caught:
            HmeClient(session, requester=requester).generate_alias()
        message = str(caught.exception)
        self.assertNotIn("session-secret", message)
        self.assertNotIn(secret_response, message)

    def test_expired_status_maps_to_session_error(self):
        session = parse_hme_session_import(f"curl '{URL}' -H 'Cookie: {COOKIE}'")
        with self.assertRaises(HmeSessionError):
            HmeClient(
                session,
                requester=lambda *_args, **_kwargs: FakeResponse({}, status_code=421),
            ).list_aliases()


if __name__ == "__main__":
    unittest.main()
