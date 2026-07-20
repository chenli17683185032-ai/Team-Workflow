import base64
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from team_protocol.cpa import OPENAI_AUTH_CLAIM, OPENAI_PROFILE_CLAIM
from team_protocol.sub2api import (
    SUB2API_PUSH_CONCURRENCY,
    SUB2API_PUSH_LOAD_FACTOR,
    Sub2APIClient,
    Sub2APIError,
    _totp_code,
    build_sub2api_account,
    build_sub2api_export,
    build_sub2api_filename,
)


TOTP_TEST_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")


def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def access_token():
    payload = {
        "exp": 1_900_000_000,
        OPENAI_AUTH_CLAIM: {
            "chatgpt_account_id": "workspace-1",
            "chatgpt_plan_type": "team",
            "chatgpt_user_id": "user-1",
        },
        OPENAI_PROFILE_CLAIM: {"email": "user@example.com"},
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.signature"


def account_payload(token="at-test", group_id=None):
    return build_sub2api_account(
        {
            "accessToken": access_token(),
            "sessionToken": "session-token",
            "user": {"id": "user-1", "email": "user@example.com"},
            "account": {"id": "workspace-1", "planType": "team"},
        },
        personal_access_token=token,
        concurrency=10,
        priority=1,
        group_id=group_id,
        now=datetime(2026, 7, 12, 9, 0, tzinfo=timezone.utc),
    )


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.reason = "OK"

    def json(self):
        return self.payload


class QueueSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def wrapped(data):
    return FakeResponse({"code": 0, "data": data})


class Sub2APIAccountTests(unittest.TestCase):
    def test_builds_codex_pat_account(self):
        account = account_payload()

        self.assertEqual(account["platform"], "openai")
        self.assertEqual(account["type"], "oauth")
        self.assertEqual(account["name"], "user@example.com")
        self.assertEqual(account["credentials"]["access_token"], "at-test")
        self.assertEqual(account["credentials"]["auth_mode"], "personalAccessToken")
        self.assertEqual(account["credentials"]["openai_auth_mode"], "personal_access_token")
        self.assertEqual(account["credentials"]["chatgpt_account_id"], "workspace-1")
        self.assertEqual(account["credentials"]["email"], "user@example.com")
        self.assertEqual(account["extra"]["email_key"], "user_example_com")
        self.assertEqual(account["extra"]["source"], "chatgpt_web_session")
        self.assertIn("expires_at", account["credentials"])
        self.assertIsInstance(account["credentials"]["expires_in"], int)
        self.assertNotIn("auto_pause_on_expired", account)
        self.assertEqual(account["concurrency"], 10)
        self.assertEqual(account["priority"], 1)
        self.assertNotIn("session-token", json.dumps(account))

    def test_builds_reference_sub2api_export_with_pat_credentials(self):
        now = datetime(2026, 7, 12, 9, 0, tzinfo=timezone.utc)
        session = {
            "accessToken": access_token(),
            "sessionToken": "must-not-leak",
            "user": {"id": "user-1", "email": "user@example.com"},
            "account": {"id": "workspace-1", "planType": "team"},
        }

        document = build_sub2api_export(
            session,
            personal_access_token="Bearer at-team-pat",
            personal_access_token_expires_at=1_900_000_000,
            now=now,
        )

        self.assertEqual(list(document), ["exported_at", "proxies", "accounts"])
        self.assertEqual(document["exported_at"], "2026-07-12T09:00:00.000Z")
        self.assertEqual(document["proxies"], [])
        self.assertEqual(len(document["accounts"]), 1)
        credentials = document["accounts"][0]["credentials"]
        self.assertEqual(credentials["access_token"], "at-team-pat")
        self.assertEqual(credentials["auth_mode"], "personalAccessToken")
        self.assertEqual(credentials["chatgpt_account_id"], "workspace-1")
        self.assertNotIn("must-not-leak", json.dumps(document))

    def test_builds_load_factor_and_multiple_deduplicated_groups(self):
        account = build_sub2api_account(
            {
                "accessToken": access_token(),
                "user": {"id": "user-1", "email": "user@example.com"},
                "account": {"id": "workspace-1", "planType": "team"},
            },
            personal_access_token="at-test",
            load_factor=9999,
            group_id=3,
            group_ids=[9, 2, 3],
        )

        self.assertEqual(account["load_factor"], 9999)
        self.assertEqual(account["group_ids"], [2, 3, 9])

        with self.assertRaisesRegex(ValueError, "load factor"):
            build_sub2api_account(
                {"accessToken": access_token()},
                personal_access_token="at-test",
                load_factor=10001,
            )

    def test_sub2api_filename_matches_converter_download_shape(self):
        local_time = datetime(2026, 7, 12, 9, 0, tzinfo=timezone.utc)

        self.assertEqual(
            build_sub2api_filename("user@example.com", local_time=local_time),
            "user@example.sub2api.2026-07-12_09-00-00.json",
        )

    def test_api_key_auth_skips_login_and_sets_admin_header(self):
        session = QueueSession(
            [wrapped([{"id": 3, "name": "K12", "platform": "openai"}])]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            api_key="admin-key",
            session=session,
        )

        groups = client.list_groups(include_inactive=True)

        self.assertEqual([group["id"] for group in groups], [3])
        self.assertEqual(len(session.calls), 1)
        headers = session.calls[0][2]["headers"]
        self.assertEqual(headers["x-api-key"], "admin-key")
        self.assertEqual(headers["X-Admin-UI-Request"], "1")
        self.assertNotIn("Authorization", headers)

    def test_totp_session_is_verified_and_preferred_over_api_key(self):
        session = QueueSession(
            [
                wrapped(
                    {
                        "requires_2fa": True,
                        "temp_token": "temporary-token",
                        "user_email_masked": "a***@example.com",
                    }
                ),
                wrapped({"access_token": "verified-admin-token"}),
                wrapped([{"id": 3, "name": "K12", "platform": "openai"}]),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            api_key="admin-key",
            totp_secret=TOTP_TEST_SECRET,
            session=session,
        )

        with patch("team_protocol.sub2api.time.time", return_value=59):
            groups = client.list_groups(include_inactive=True)

        self.assertEqual([group["id"] for group in groups], [3])
        self.assertTrue(session.calls[0][1].endswith("/auth/login"))
        self.assertTrue(session.calls[1][1].endswith("/auth/login/2fa"))
        self.assertEqual(
            session.calls[1][2]["json"],
            {"temp_token": "temporary-token", "totp_code": "287082"},
        )
        headers = session.calls[2][2]["headers"]
        self.assertEqual(headers["Authorization"], "Bearer verified-admin-token")
        self.assertNotIn("x-api-key", headers)

    def test_totp_code_accepts_otpauth_uri(self):
        uri = (
            "otpauth://totp/Sub2API:admin@example.com?"
            f"secret={TOTP_TEST_SECRET}&issuer=Sub2API"
        )

        self.assertEqual(_totp_code(uri, at=59), "287082")

    def test_push_performs_totp_step_up_before_protected_create(self):
        account = account_payload()
        session = QueueSession(
            [
                wrapped({"requires_2fa": True, "temp_token": "temporary-token"}),
                wrapped({"access_token": "verified-admin-token"}),
                wrapped({"verified": True}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "accounts": []}),
                wrapped({"id": 42, "name": account["name"]}),
                wrapped(
                    {
                        "exported_at": "2026-07-12T09:00:01Z",
                        "accounts": [account],
                    }
                ),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            totp_secret=TOTP_TEST_SECRET,
            session=session,
        )

        with patch("team_protocol.sub2api.time.time", return_value=59):
            result = client.push_account(account)

        self.assertTrue(result.verified)
        self.assertTrue(session.calls[2][1].endswith("/user/totp/step-up"))
        self.assertEqual(session.calls[2][2]["json"], {"code": "287082"})
        self.assertEqual(
            session.calls[2][2]["headers"]["X-User-UI-Request"],
            "1",
        )
        self.assertTrue(
            session.calls[4][1].endswith("/admin/openai/create-from-codex-pat")
        )
        self.assertEqual(
            session.calls[4][2]["headers"]["X-Admin-UI-Request"],
            "1",
        )

    def test_push_creates_and_verifies_new_account(self):
        account = account_payload()
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "proxies": [], "accounts": []}),
                wrapped({"id": 42, "name": account["name"]}),
                wrapped(
                    {
                        "exported_at": "2026-07-12T09:00:01Z",
                        "proxies": [],
                        "accounts": [account],
                    }
                ),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        result = client.push_account(account)

        self.assertEqual(result.action, "created")
        self.assertTrue(result.verified)
        create_call = session.calls[2]
        self.assertTrue(create_call[1].endswith("/admin/openai/create-from-codex-pat"))
        self.assertEqual(create_call[2]["json"]["access_token"], "at-test")
        self.assertFalse(create_call[2]["json"]["skip_default_group_bind"])
        self.assertEqual(
            create_call[2]["json"]["credential_extras"]["chatgpt_account_id"],
            "workspace-1",
        )

    def test_push_assigns_and_verifies_explicit_group(self):
        account = account_payload(group_id=3)
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "accounts": []}),
                wrapped({"id": 42, "name": account["name"]}),
                wrapped(
                    {
                        "exported_at": "2026-07-12T09:00:01Z",
                        "accounts": [account],
                    }
                ),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        result = client.push_account(account)

        self.assertTrue(result.verified)
        create_payload = session.calls[2][2]["json"]
        self.assertEqual(create_payload["group_ids"], [3])
        self.assertTrue(create_payload["skip_default_group_bind"])

    def test_push_skips_exact_remote_account(self):
        account = account_payload()
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "proxies": [], "accounts": [account]}),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        result = client.push_account(account)

        self.assertEqual(result.action, "skipped")
        self.assertTrue(result.verified)
        self.assertEqual(len(session.calls), 2)

    def test_lists_all_groups_including_inactive(self):
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped(
                    [
                        {"id": 3, "name": "K12", "platform": "openai"},
                        {"id": 4, "name": "Disabled", "status": "inactive"},
                    ]
                ),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        groups = client.list_groups(include_inactive=True)

        self.assertEqual([group["id"] for group in groups], [3, 4])
        self.assertTrue(
            session.calls[1][1].endswith(
                "/admin/groups/all?include_inactive=true"
            )
        )

    def test_push_rejects_same_identity_with_different_token(self):
        account = account_payload()
        remote = account_payload(token="at-other")
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "proxies": [], "accounts": [remote]}),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        with self.assertRaisesRegex(Sub2APIError, "different token"):
            client.push_account(account)

        self.assertEqual(len(session.calls), 2)

    def test_production_push_updates_existing_account_and_verifies_settings(self):
        account = account_payload()
        remote_export = account_payload()
        remote_detail = {
            **account,
            "id": 42,
            "concurrency": 10,
            "load_factor": None,
            "group_ids": [2],
        }
        verified_detail = {
            **remote_detail,
            "concurrency": SUB2API_PUSH_CONCURRENCY,
            "load_factor": SUB2API_PUSH_LOAD_FACTOR,
            "group_ids": [2, 3, 9],
        }
        session = QueueSession(
            [
                wrapped(
                    [
                        {"id": 9, "platform": "openai", "status": "active"},
                        {"id": 2, "platform": "openai", "status": "active"},
                        {"id": 3, "platform": "openai", "status": "active"},
                        {"id": 8, "platform": "openai", "status": "inactive"},
                        {"id": 7, "platform": "claude", "status": "active"},
                    ]
                ),
                wrapped({"exported_at": "now", "accounts": [remote_export]}),
                wrapped({"items": [remote_detail], "total": 1}),
                wrapped(verified_detail),
                wrapped(verified_detail),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example", api_key="admin-key", session=session
        )

        result = client.push_production_account(account)

        self.assertEqual(result.action, "updated")
        self.assertTrue(result.verified)
        self.assertEqual(result.account_id, 42)
        self.assertEqual(result.group_count, 3)
        update_call = session.calls[3]
        self.assertEqual(update_call[0], "PUT")
        self.assertTrue(update_call[1].endswith("/admin/accounts/42"))
        self.assertEqual(
            update_call[2]["json"],
            {
                "concurrency": 9999,
                "load_factor": 9999,
                "group_ids": [2, 3, 9],
                "confirm_mixed_channel_risk": True,
            },
        )

    def test_production_push_dry_run_reports_update_without_writing(self):
        account = account_payload()
        remote_detail = {
            **account,
            "id": 42,
            "load_factor": None,
            "group_ids": [2],
        }
        session = QueueSession(
            [
                wrapped([{"id": 2, "platform": "openai", "status": "active"}]),
                wrapped({"exported_at": "now", "accounts": [account]}),
                wrapped({"items": [remote_detail], "total": 1}),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example", api_key="admin-key", session=session
        )

        result = client.push_production_account(account, dry_run=True)

        self.assertEqual(result.action, "would-update")
        self.assertFalse(result.verified)
        self.assertEqual(len(session.calls), 3)

    def test_production_push_creates_with_fixed_settings_and_all_groups(self):
        account = account_payload()
        verified_detail = {
            **account,
            "id": 51,
            "concurrency": SUB2API_PUSH_CONCURRENCY,
            "load_factor": SUB2API_PUSH_LOAD_FACTOR,
            "group_ids": [2, 3],
        }
        session = QueueSession(
            [
                wrapped(
                    [
                        {"id": 3, "platform": "openai", "status": "active"},
                        {"id": 2, "platform": "openai", "status": "active"},
                    ]
                ),
                wrapped({"exported_at": "now", "accounts": []}),
                wrapped({"id": 51, "name": account["name"]}),
                wrapped(verified_detail),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example", api_key="admin-key", session=session
        )

        result = client.push_production_account(account)

        self.assertEqual(result.action, "created")
        create_payload = session.calls[2][2]["json"]
        self.assertEqual(create_payload["concurrency"], 9999)
        self.assertEqual(create_payload["load_factor"], 9999)
        self.assertEqual(create_payload["group_ids"], [2, 3])
        self.assertTrue(create_payload["confirm_mixed_channel_risk"])
        self.assertTrue(create_payload["skip_default_group_bind"])

    def test_production_push_rejects_empty_selectable_group_set(self):
        session = QueueSession(
            [
                wrapped(
                    [
                        {"id": 2, "platform": "openai", "status": "inactive"},
                        {"id": 3, "platform": "claude", "status": "active"},
                    ]
                )
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example", api_key="admin-key", session=session
        )

        with self.assertRaisesRegex(Sub2APIError, "no selectable"):
            client.push_production_account(account_payload())

        self.assertEqual(len(session.calls), 1)

    def test_production_push_rejects_post_update_drift(self):
        account = account_payload()
        remote_detail = {**account, "id": 42, "group_ids": [2]}
        session = QueueSession(
            [
                wrapped([{"id": 2, "platform": "openai", "status": "active"}]),
                wrapped({"exported_at": "now", "accounts": [account]}),
                wrapped({"items": [remote_detail], "total": 1}),
                wrapped(remote_detail),
                wrapped(remote_detail),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example", api_key="admin-key", session=session
        )

        with self.assertRaisesRegex(Sub2APIError, "post-update verification"):
            client.push_production_account(account)


if __name__ == "__main__":
    unittest.main()
