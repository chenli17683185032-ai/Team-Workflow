import base64
import json
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import team_protocol.workflow as workflow_module
from team_protocol.chatgpt import ChatGPTApiError
from team_protocol.cpa import OPENAI_AUTH_CLAIM, OPENAI_PROFILE_CLAIM
from team_protocol.registrar import MailboxCredentials, RegistrarIdentityError
from team_protocol.workflow import (
    AccountNetworkSpec,
    AccountSpec,
    CurrentAccountRefreshRunner,
    RescueWorkflowRunner,
    WorkflowCancelled,
    WorkflowConfig,
    WorkflowIdentityError,
    WorkflowRunner,
)


def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def access_token(email, account_id, user_id):
    payload = {
        "exp": 1_900_000_000,
        OPENAI_AUTH_CLAIM: {
            "chatgpt_account_id": account_id,
            "chatgpt_plan_type": "team",
            "chatgpt_user_id": user_id,
            "user_id": user_id,
        },
        OPENAI_PROFILE_CLAIM: {"email": email},
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.signature"


class FakeFingerprintProfile:
    def __init__(
        self,
        profile_id="fingerprint-1",
        *,
        geo_country_code="",
        geo_source="",
        locale="en-US",
        timezone_id="America/New_York",
        os="windows",
    ):
        self.profile_id = profile_id
        self.impersonate = "chrome131"
        self.user_agent = "profile-user-agent"
        self.geo_country_code = geo_country_code
        self.geo_source = geo_source
        self.locale = locale
        self.timezone_id = timezone_id
        self.os = os
        self.http_headers = {
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.8",
            "sec-ch-ua": '"Chromium";v="131"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }

    def to_legacy_dict(self):
        return {
            "profile_id": self.profile_id,
            "impersonate": self.impersonate,
            "user_agent": self.user_agent,
            "http_headers": dict(self.http_headers),
            "geo_country_code": self.geo_country_code,
            "geo_source": self.geo_source,
            "locale": self.locale,
            "timezone_id": self.timezone_id,
            "os": self.os,
        }

    @classmethod
    def from_mapping(cls, value):
        return cls(
            profile_id=str(value["profile_id"]),
            geo_country_code=str(value.get("geo_country_code") or ""),
            geo_source=str(value.get("geo_source") or ""),
            locale=str(value.get("locale") or "en-US"),
            timezone_id=str(value.get("timezone_id") or "America/New_York"),
            os=str(value.get("os") or "windows"),
        )


class FakeRegistrar:
    def __init__(self):
        self.calls = []
        self.login_profiles = []
        self.resolved_profiles = []
        self.restored_profile = False
        self.mailboxes = []
        self.provider_initial_states = []
        self.geo_calls = []
        self.profile_geo_hints = []

    def resolve_proxy_geo(self, proxy):
        self.geo_calls.append(proxy)
        return {
            "resolved": True,
            "source": "test",
            "country_code": "DE",
            "continent_code": "EU",
            "timezone_id": "Europe/Berlin",
            "locale": "de-DE",
            "accept_language": "de-DE,de;q=0.9,en;q=0.8",
            "profile_scope": "windows",
        }

    def resolve_session_profile(self, serialized=None, geo_hint=None):
        self.restored_profile = isinstance(serialized, dict)
        self.profile_geo_hints.append(
            None if geo_hint is None else dict(geo_hint)
        )
        profile = (
            FakeFingerprintProfile.from_mapping(serialized)
            if self.restored_profile
            else FakeFingerprintProfile(
                geo_country_code=str((geo_hint or {}).get("country_code") or ""),
                geo_source=str((geo_hint or {}).get("source") or ""),
                locale=str((geo_hint or {}).get("locale") or "en-US"),
                timezone_id=str(
                    (geo_hint or {}).get("timezone_id") or "America/New_York"
                ),
            )
        )
        self.resolved_profiles.append(profile)
        return profile

    @staticmethod
    def serialize_session_profile(profile):
        return profile.to_legacy_dict()

    def login(self, **kwargs):
        email = kwargs["email"]
        self.calls.append((email, kwargs.get("proxy")))
        self.login_profiles.append(kwargs.get("session_profile"))
        self.mailboxes.append(kwargs.get("mailbox"))
        self.provider_initial_states.append(kwargs.get("provider_initial_state"))
        provider_state_callback = kwargs.get("provider_state_callback")
        if provider_state_callback is not None:
            provider_state_callback(
                {
                    "version": 1,
                    "completed_aliases": {
                        email: {"email": email, "status": "success"},
                    },
                }
            )
        role = "old" if "+2@" in email else "new"
        return {"email": email, "session_token": f"{role}-login-session"}


class FakeChatGPT:
    def __init__(self, workspace_id, old_email, new_email, member_state=None):
        self.workspace_id = workspace_id
        self.old_email = old_email
        self.new_email = new_email
        self.calls = []
        self.owner_user_id = "user-owner"
        self.old_user_id = "user-old"
        self.new_user_id = "user-new"
        self.member_state = member_state or {
            "members": {
                self.owner_user_id: {
                    "id": self.owner_user_id,
                    "email": "owner@example.com",
                },
                self.old_user_id: {
                    "id": self.old_user_id,
                    "email": self.old_email,
                },
            },
            "invites": set(),
        }

    def close(self):
        self.calls.append(("close",))

    def refresh_session(self, session_token, account_id=None):
        self.calls.append(("refresh", session_token, account_id))
        is_old = session_token.startswith("old-")
        email = self.old_email if is_old else self.new_email
        user_id = self.old_user_id if is_old else self.new_user_id
        if not is_old and account_id == self.workspace_id:
            self.member_state["members"][self.new_user_id] = {
                "id": self.new_user_id,
                "email": self.new_email,
            }
            self.member_state["invites"].discard(self.new_email.casefold())
        return {
            "user": {"id": user_id, "email": email},
            "account": {"id": self.workspace_id, "planType": "team"},
            "accessToken": access_token(email, self.workspace_id, user_id),
            "sessionToken": f"{'old' if is_old else 'new'}-workspace-session",
        }

    def get_members(self, access_token_value, account_id):
        del access_token_value
        self.calls.append(("members", account_id))
        items = list(self.member_state["members"].values())
        return {"items": items, "total": len(items)}

    def get_invites(self, access_token_value, account_id):
        del access_token_value
        self.calls.append(("invites", account_id))
        items = [
            {"email": email, "status": "pending"}
            for email in sorted(self.member_state["invites"])
        ]
        return {"items": items, "total": len(items)}

    def invite(self, access_token_value, account_id, email):
        del access_token_value
        self.calls.append(("invite", account_id, email))
        self.member_state["invites"].add(email.casefold())
        return {"ok": True}

    def leave(self, access_token_value, account_id, user_id):
        del access_token_value
        self.calls.append(("leave", account_id, user_id))
        self.member_state["members"].pop(user_id, None)
        return {"ok": True}

    def remove_member(self, access_token_value, account_id, user_id):
        del access_token_value
        self.calls.append(("remove", account_id, user_id))
        self.member_state["members"].pop(user_id, None)
        return {"ok": True}

    def create_personal_access_token(self, access_token_value, account_id, *, name, ttl):
        del access_token_value
        self.calls.append(("pat", account_id, name, ttl))
        return {
            "access_token": "at-test",
            "workspace_id": account_id,
            "expires_at": 1_900_000_000,
        }


class FakeManagement:
    def __init__(self):
        self.calls = []

    def push_file(self, path, *, remote_name=None, replace=False):
        self.calls.append((Path(path), remote_name, replace))
        return SimpleNamespace(
            action="uploaded",
            filename=remote_name or Path(path).name,
            verified=True,
            message="uploaded",
        )


class FakeSub2API:
    def __init__(self):
        self.calls = []

    def push_account(self, account):
        self.calls.append(account)
        return SimpleNamespace(
            action="created",
            account_name=str(account.get("name") or ""),
            verified=True,
            message="created and verified",
        )


class InMemoryCheckpoint:
    def __init__(self, initial=None):
        self.values = dict(initial or {})
        self.writes = []

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        serialized = json.loads(json.dumps(value))
        self.values[name] = serialized
        self.writes.append((name, serialized))


class FalsyCheckpoint(InMemoryCheckpoint):
    def __bool__(self):
        return False


class CancelDuringWait:
    def __init__(self):
        self.wait_calls = []

    def is_set(self):
        return False

    def wait(self, timeout):
        self.wait_calls.append(timeout)
        return True


def make_workflow_config(
    root,
    *,
    proxy="",
    push=True,
    sub2api_push=True,
    sub2api_email="admin@example.com",
    sub2api_password="secret",
    sub2api_api_key="",
    sub2api_totp_secret="totp-secret",
    sub2api_load_factor=None,
    sub2api_all_groups=False,
    invite_settle_seconds=0,
    new_account_registered=False,
    old_session_token="",
    persist_old_session=None,
    clear_old_session=None,
    persist_new_session=None,
    openbrowser_base_url="",
    openbrowser_api_key="",
    openbrowser_profile_id="",
    openbrowser_manual_timeout_seconds=1800,
):
    return WorkflowConfig(
        old_account=AccountSpec("main+2@example.com"),
        new_account=AccountSpec("main+3@example.com"),
        workspace_id="workspace-1",
        proxy=proxy,
        pat_name="workflow-pat",
        pat_ttl=5_184_000,
        output_dir=root / "output",
        management_base_url="https://upic.invalid",
        management_key="key",
        push=push,
        replace=False,
        remote_name="",
        invite_settle_seconds=invite_settle_seconds,
        sub2api_base_url="https://sub2api.example",
        sub2api_email=sub2api_email,
        sub2api_password=sub2api_password,
        sub2api_api_key=sub2api_api_key,
        sub2api_totp_secret=sub2api_totp_secret,
        sub2api_push=sub2api_push,
        sub2api_load_factor=sub2api_load_factor,
        sub2api_all_groups=sub2api_all_groups,
        new_account_registered=new_account_registered,
        old_session_token=old_session_token,
        persist_old_session=persist_old_session,
        clear_old_session=clear_old_session,
        persist_new_session=persist_new_session,
        openbrowser_base_url=openbrowser_base_url,
        openbrowser_api_key=openbrowser_api_key,
        openbrowser_profile_id=openbrowser_profile_id,
        openbrowser_manual_timeout_seconds=openbrowser_manual_timeout_seconds,
    )


def make_mailboxes(config):
    return (
        MailboxCredentials(
            primary_email="main@example.com",
            registration_email=config.old_account.email,
            client_id="old-client",
            refresh_token="old-refresh",
        ),
        MailboxCredentials(
            primary_email="main@example.com",
            registration_email=config.new_account.email,
            client_id="new-client",
            refresh_token="new-refresh",
        ),
    )


def run_dependencies(config, checkpoint=None):
    old_mailbox, new_mailbox = make_mailboxes(config)
    return {
        "checkpoint_store": InMemoryCheckpoint() if checkpoint is None else checkpoint,
        "old_mailbox": old_mailbox,
        "new_mailbox": new_mailbox,
    }


class WorkflowTests(unittest.TestCase):
    def test_close_isolates_failures_across_owned_clients_and_proxy_leases(self):
        closed = []

        class Resource:
            def __init__(self, name, *, fail=False):
                self.name = name
                self.fail = fail

            def close(self):
                closed.append(self.name)
                if self.fail:
                    raise RuntimeError(f"{self.name} close failed")

        runner = WorkflowRunner.__new__(WorkflowRunner)
        runner._owned_chatgpt_clients = [
            Resource("old-client", fail=True),
            Resource("new-client"),
        ]
        runner._proxy_leases = [
            Resource("old-proxy", fail=True),
            Resource("new-proxy"),
        ]

        runner.close()

        self.assertEqual(
            closed,
            ["old-client", "new-client", "old-proxy", "new-proxy"],
        )

    def test_login_adds_current_or_next_role_to_structured_identity_error(self):
        for step, role, code in (
            ("old_login", "current", "alias_disabled"),
            ("new_login", "next", "mailbox_credentials_invalid"),
        ):
            with self.subTest(step=step), tempfile.TemporaryDirectory() as directory:
                config = make_workflow_config(Path(directory))
                registrar = FakeRegistrar()

                def fail_login(**_kwargs):
                    raise RegistrarIdentityError(code)

                registrar.login = fail_login
                runner = WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=registrar,
                    chatgpt=FakeChatGPT(
                        config.workspace_id,
                        config.old_account.email,
                        config.new_account.email,
                    ),
                    verbose=False,
                )
                try:
                    with self.assertRaises(WorkflowIdentityError) as caught:
                        runner._login(
                            config.old_account if step == "old_login" else config.new_account,
                            step,
                        )
                finally:
                    runner.close()
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.role, role)

    def test_openbrowser_manual_login_verifies_team_before_pat_without_registrar(self):
        with tempfile.TemporaryDirectory() as directory:
            persisted_sessions = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                persist_new_session=persisted_sessions.append,
                openbrowser_base_url="http://127.0.0.1:50325",
                openbrowser_api_key="openbrowser-secret",
                openbrowser_profile_id="profile_manual",
                openbrowser_manual_timeout_seconds=900,
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            client_calls = []
            manual_calls = []
            status_events = []
            logs = []

            class FakeOpenBrowserClient:
                def __init__(self, base_url, api_key, **kwargs):
                    client_calls.append((base_url, api_key, kwargs))

                @staticmethod
                def list_profiles():
                    return [
                        SimpleNamespace(
                            profile_id=config.openbrowser_profile_id,
                            running=False,
                        )
                    ]

                @staticmethod
                def close():
                    client_calls.append(("closed",))

            class FakeManualLogin:
                def __init__(self, client, profile_id, **kwargs):
                    del client
                    manual_calls.append((profile_id, dict(kwargs)))
                    self.status_callback = kwargs["status_callback"]
                    self.expected_email = kwargs["expected_email"]

                def wait(self, *, session_validator, stop_event=None):
                    self.status_callback("profile_started")
                    self.status_callback("waiting_for_user")
                    self.assert_stop_event = stop_event
                    validated = session_validator(
                        {
                            "email": self.expected_email,
                            "session_token": "manual-browser-session",
                        }
                    )
                    self.status_callback("verified")
                    self.status_callback("profile_stopped")
                    return validated

            runner = WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=registrar,
                chatgpt=chatgpt,
                management=FakeManagement(),
                sub2api=FakeSub2API(),
                openbrowser_client_factory=FakeOpenBrowserClient,
                openbrowser_manual_login_factory=FakeManualLogin,
                verbose=False,
                logger=logs.append,
                event_callback=lambda event: status_events.append(dict(event)),
            )
            try:
                result = runner.run()
            finally:
                runner.close()

        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertEqual(client_calls[0][0], config.openbrowser_base_url)
        self.assertEqual(client_calls[0][1], config.openbrowser_api_key)
        self.assertEqual(client_calls[-1], ("closed",))
        self.assertEqual(client_calls.count(("closed",)), 2)
        self.assertEqual(manual_calls[0][0], config.openbrowser_profile_id)
        self.assertEqual(
            manual_calls[0][1]["expected_email"], config.new_account.email
        )
        self.assertEqual(
            manual_calls[0][1]["timeout_seconds"],
            config.openbrowser_manual_timeout_seconds,
        )
        self.assertEqual(
            persisted_sessions,
            [checkpoint.get("new_login")["sessionToken"]],
        )
        self.assertEqual(
            checkpoint.get("new_workspace")["account"]["id"],
            config.workspace_id,
        )
        self.assertTrue(any(call[0] == "pat" for call in chatgpt.calls))
        self.assertLess(
            chatgpt.calls.index(
                ("refresh", "manual-browser-session", config.workspace_id)
            ),
            next(index for index, call in enumerate(chatgpt.calls) if call[0] == "pat"),
        )
        self.assertTrue(str(result["cpa_path"]).endswith(".json"))
        self.assertEqual(
            [
                event["state"]
                for event in status_events
                if event.get("type") == "manual_login"
            ],
            ["profile_started", "waiting_for_user", "verified", "profile_stopped"],
        )
        self.assertFalse(any("openbrowser-secret" in message for message in logs))

    def test_openbrowser_execution_preflight_stops_before_old_login_and_team_writes(self):
        for profile in (None, SimpleNamespace(profile_id="profile_manual", running=True)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                config = make_workflow_config(
                    Path(directory),
                    push=False,
                    sub2api_push=False,
                    openbrowser_base_url="http://127.0.0.1:50325",
                    openbrowser_api_key="openbrowser-secret",
                    openbrowser_profile_id="profile_manual",
                )
                registrar = FakeRegistrar()
                chatgpt = FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                )

                class PreflightClient:
                    @staticmethod
                    def list_profiles():
                        return [] if profile is None else [profile]

                    @staticmethod
                    def close():
                        return None

                runner = WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=registrar,
                    chatgpt=chatgpt,
                    openbrowser_client_factory=lambda *_args, **_kwargs: PreflightClient(),
                    verbose=False,
                )
                try:
                    with self.assertRaisesRegex(
                        RuntimeError, "unavailable|already running"
                    ):
                        runner.run()
                finally:
                    runner.close()

                self.assertEqual(registrar.calls, [])
                self.assertEqual(chatgpt.calls, [])

    def test_openbrowser_manual_mode_never_falls_back_to_otp_workspace_login(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                openbrowser_base_url="http://127.0.0.1:50325",
                openbrowser_api_key="openbrowser-secret",
                openbrowser_profile_id="profile_manual",
            )
            registrar = FakeRegistrar()
            runner = WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            )
            runner._switch_workspace = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                workflow_module._WorkspaceSwitchError("wrong workspace")
            )
            try:
                with self.assertRaises(workflow_module._WorkspaceSwitchError):
                    runner._new_workspace_session(
                        {
                            "email": config.new_account.email,
                            "session_token": "manual-session",
                        }
                    )
            finally:
                runner.close()

        self.assertEqual(registrar.calls, [])

    def test_transient_login_error_is_not_promoted_to_identity_error(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(Path(directory))
            registrar = FakeRegistrar()

            def fail_login(**_kwargs):
                raise RuntimeError("proxy timeout")

            registrar.login = fail_login
            runner = WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            )
            try:
                with self.assertRaisesRegex(RuntimeError, "proxy timeout") as caught:
                    runner._login(config.old_account, "old_login")
            finally:
                runner.close()
        self.assertNotIsInstance(caught.exception, WorkflowIdentityError)

    def test_old_account_invites_and_leaves_before_new_account_login(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )
            timeline = []

            class OrderedRegistrar(FakeRegistrar):
                def login(self, **kwargs):
                    timeline.append(
                        ("login", kwargs["email"], kwargs.get("workspace_id"))
                    )
                    return super().login(**kwargs)

            class OrderedChatGPT(FakeChatGPT):
                def refresh_session(self, session_token, account_id=None):
                    timeline.append(("refresh", session_token, account_id))
                    return super().refresh_session(session_token, account_id=account_id)

                def invite(self, access_token_value, account_id, email):
                    timeline.append(("invite", email))
                    return super().invite(access_token_value, account_id, email)

                def leave(self, access_token_value, account_id, user_id):
                    timeline.append(("leave", user_id))
                    return super().leave(access_token_value, account_id, user_id)

            WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=OrderedRegistrar(),
                chatgpt=OrderedChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            ).run()

        new_login = ("login", config.new_account.email, None)
        invite = ("invite", config.new_account.email)
        leave = ("leave", "user-old")
        new_workspace = ("refresh", "new-login-session", config.workspace_id)
        self.assertIn(
            ("login", config.old_account.email, config.workspace_id),
            timeline,
        )
        self.assertLess(timeline.index(invite), timeline.index(leave))
        self.assertLess(timeline.index(leave), timeline.index(new_workspace))
        self.assertLess(timeline.index(leave), timeline.index(new_login))
        self.assertLess(timeline.index(new_login), timeline.index(new_workspace))

    def test_saved_child_browser_cookie_is_reused_and_new_cookie_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            old_sessions = []
            new_sessions = []
            cleared = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                old_session_token="old-browser-cookie",
                persist_old_session=old_sessions.append,
                clear_old_session=lambda: cleared.append(True),
                persist_new_session=new_sessions.append,
            )
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )

            WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=registrar,
                chatgpt=chatgpt,
                verbose=False,
            ).run()

        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.new_account.email],
        )
        self.assertIn(
            ("refresh", "old-browser-cookie", config.workspace_id),
            chatgpt.calls,
        )
        self.assertEqual(old_sessions, ["old-workspace-session"])
        self.assertEqual(new_sessions, ["new-login-session"])
        self.assertEqual(cleared, [])

    def test_expired_child_browser_cookie_clears_and_falls_back_to_login(self):
        with tempfile.TemporaryDirectory() as directory:
            cleared = []
            persisted = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                old_session_token="old-expired-cookie",
                clear_old_session=lambda: cleared.append(True),
                persist_old_session=persisted.append,
            )

            class ExpiringChatGPT(FakeChatGPT):
                def refresh_session(self, session_token, account_id=None):
                    if session_token == "old-expired-cookie":
                        raise ChatGPTApiError("expired", status_code=401)
                    return super().refresh_session(
                        session_token, account_id=account_id
                    )

            registrar = FakeRegistrar()
            WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=registrar,
                chatgpt=ExpiringChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            ).run()

        self.assertEqual(cleared, [True])
        self.assertEqual(persisted, ["old-login-session"])
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email, config.new_account.email],
        )

    def test_current_account_refresh_reuses_cookie_creates_pat_and_exports_json(self):
        with tempfile.TemporaryDirectory() as directory:
            persisted = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                old_session_token="old-browser-cookie",
                persist_old_session=persisted.append,
            )
            config = replace(config, new_account=config.old_account)
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            old_mailbox, _new_mailbox = make_mailboxes(config)

            result = CurrentAccountRefreshRunner(
                config,
                checkpoint_store=InMemoryCheckpoint(),
                old_mailbox=old_mailbox,
                new_mailbox=old_mailbox,
                registrar=registrar,
                chatgpt=chatgpt,
                verbose=False,
            ).run()

            export_path = Path(result["sub2api_path"])
            exported = json.loads(export_path.read_text(encoding="utf-8"))

        self.assertEqual(registrar.calls, [])
        self.assertEqual(persisted, ["old-workspace-session"])
        self.assertIn(
            ("refresh", "old-browser-cookie", config.workspace_id),
            chatgpt.calls,
        )
        self.assertIn(
            ("pat", config.workspace_id, config.pat_name, config.pat_ttl),
            chatgpt.calls,
        )
        self.assertFalse(any(call[0] in {"invite", "leave", "members"} for call in chatgpt.calls))
        self.assertEqual(
            exported["accounts"][0]["credentials"]["access_token"],
            "at-test",
        )
        self.assertNotIn("sessionToken", json.dumps(exported))

    def test_current_refresh_relogs_in_fresh_environment_after_invalidated_saved_session(self):
        with tempfile.TemporaryDirectory() as directory:
            cleared = []
            persisted = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                old_session_token="old-browser-cookie",
                persist_old_session=persisted.append,
                clear_old_session=lambda: cleared.append(True),
            )
            config = replace(config, new_account=config.old_account)

            class InvalidatedOnceChatGPT(FakeChatGPT):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.pat_attempts = 0

                def create_personal_access_token(
                    self, access_token_value, account_id, *, name, ttl
                ):
                    self.pat_attempts += 1
                    if self.pat_attempts == 1:
                        self.calls.append(("pat", account_id, name, ttl))
                        raise ChatGPTApiError(
                            "saved session token was invalidated",
                            status_code=401,
                            error_code="token_invalidated",
                        )
                    return super().create_personal_access_token(
                        access_token_value,
                        account_id,
                        name=name,
                        ttl=ttl,
                    )

            class FreshLoginRegistrar(FakeRegistrar):
                def login(self, **kwargs):
                    super().login(**kwargs)
                    return {
                        "user": {
                            "id": "user-old",
                            "email": config.old_account.email,
                        },
                        "account": {"id": config.workspace_id, "planType": "team"},
                        "accessToken": access_token(
                            config.old_account.email,
                            config.workspace_id,
                            "user-old",
                        ),
                        "sessionToken": "old-login-session",
                    }

            registrar = FreshLoginRegistrar()
            chatgpt = InvalidatedOnceChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            old_mailbox, _new_mailbox = make_mailboxes(config)

            result = CurrentAccountRefreshRunner(
                config,
                checkpoint_store=InMemoryCheckpoint(),
                old_mailbox=old_mailbox,
                new_mailbox=old_mailbox,
                registrar=registrar,
                chatgpt=chatgpt,
                verbose=False,
            ).run()

            self.assertTrue(Path(result["sub2api_path"]).is_file())

        self.assertEqual(cleared, [True])
        self.assertEqual(
            persisted,
            ["old-workspace-session", "old-login-session"],
        )
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertEqual(
            [call for call in chatgpt.calls if call[0] == "refresh"],
            [("refresh", "old-browser-cookie", config.workspace_id)],
        )
        self.assertEqual(
            len([call for call in chatgpt.calls if call[0] == "pat"]),
            2,
        )

    def test_current_refresh_does_not_relogin_for_other_pat_401(self):
        with tempfile.TemporaryDirectory() as directory:
            cleared = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                old_session_token="old-browser-cookie",
                clear_old_session=lambda: cleared.append(True),
            )
            config = replace(config, new_account=config.old_account)

            class OtherUnauthorizedChatGPT(FakeChatGPT):
                def create_personal_access_token(
                    self, access_token_value, account_id, *, name, ttl
                ):
                    del access_token_value, account_id, name, ttl
                    raise ChatGPTApiError(
                        "unauthorized",
                        status_code=401,
                        error_code="other_unauthorized",
                    )

            registrar = FakeRegistrar()
            old_mailbox, _new_mailbox = make_mailboxes(config)

            with self.assertRaises(ChatGPTApiError):
                CurrentAccountRefreshRunner(
                    config,
                    checkpoint_store=InMemoryCheckpoint(),
                    old_mailbox=old_mailbox,
                    new_mailbox=old_mailbox,
                    registrar=registrar,
                    chatgpt=OtherUnauthorizedChatGPT(
                        config.workspace_id,
                        config.old_account.email,
                        config.new_account.email,
                    ),
                    verbose=False,
                ).run()

        self.assertEqual(cleared, [])
        self.assertEqual(registrar.calls, [])

    def test_current_refresh_does_not_relogin_without_a_saved_session(self):
        with tempfile.TemporaryDirectory() as directory:
            cleared = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                clear_old_session=lambda: cleared.append(True),
            )
            config = replace(config, new_account=config.old_account)

            class InvalidatedFreshLoginChatGPT(FakeChatGPT):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.pat_attempts = 0

                def create_personal_access_token(
                    self, access_token_value, account_id, *, name, ttl
                ):
                    del access_token_value, account_id, name, ttl
                    self.pat_attempts += 1
                    raise ChatGPTApiError(
                        "fresh token was invalidated",
                        status_code=401,
                        error_code="token_invalidated",
                    )

            registrar = FakeRegistrar()
            chatgpt = InvalidatedFreshLoginChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            old_mailbox, _new_mailbox = make_mailboxes(config)

            with self.assertRaises(ChatGPTApiError):
                CurrentAccountRefreshRunner(
                    config,
                    checkpoint_store=InMemoryCheckpoint(),
                    old_mailbox=old_mailbox,
                    new_mailbox=old_mailbox,
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

        self.assertEqual(cleared, [])
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertEqual(chatgpt.pat_attempts, 1)

    def test_current_refresh_stops_after_one_fresh_login_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            cleared = []
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                old_session_token="old-browser-cookie",
                clear_old_session=lambda: cleared.append(True),
            )
            config = replace(config, new_account=config.old_account)

            class AlwaysInvalidatedChatGPT(FakeChatGPT):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self.pat_attempts = 0

                def create_personal_access_token(
                    self, access_token_value, account_id, *, name, ttl
                ):
                    del access_token_value, account_id, name, ttl
                    self.pat_attempts += 1
                    raise ChatGPTApiError(
                        "token remained invalidated",
                        status_code=401,
                        error_code="token_invalidated",
                    )

            registrar = FakeRegistrar()
            chatgpt = AlwaysInvalidatedChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            old_mailbox, _new_mailbox = make_mailboxes(config)

            with self.assertRaises(ChatGPTApiError):
                CurrentAccountRefreshRunner(
                    config,
                    checkpoint_store=InMemoryCheckpoint(),
                    old_mailbox=old_mailbox,
                    new_mailbox=old_mailbox,
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

        self.assertEqual(cleared, [True])
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertEqual(chatgpt.pat_attempts, 2)

    def test_new_account_uses_registration_when_adapter_supports_it(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )

            class RegisteringRegistrar(FakeRegistrar):
                def __init__(self):
                    super().__init__()
                    self.registered = []

                def register(self, **kwargs):
                    self.registered.append(kwargs["email"])
                    return {
                        "email": kwargs["email"],
                        "session_token": "new-login-session",
                    }

            registrar = RegisteringRegistrar()
            dependencies = run_dependencies(config)
            dependencies["new_mailbox"] = MailboxCredentials(
                primary_email="forwarding@example.com",
                registration_email=config.new_account.email,
                client_id="",
                refresh_token="",
                provider="icloud_hme_imap",
                forwarding_email="forwarding@example.com",
                imap_host="imap.example.com",
                imap_username="forwarding@example.com",
                imap_password="imap-secret",
            )
            WorkflowRunner(
                config,
                **dependencies,
                registrar=registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            ).run()

        self.assertEqual(registrar.registered, [config.new_account.email])
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )

    def test_registered_icloud_new_account_uses_existing_login(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                new_account_registered=True,
            )

            class RegisteringRegistrar(FakeRegistrar):
                def __init__(self):
                    super().__init__()
                    self.registered = []

                def register(self, **kwargs):
                    self.registered.append(kwargs["email"])
                    return super().login(**kwargs)

            registrar = RegisteringRegistrar()
            dependencies = run_dependencies(config)
            dependencies["new_mailbox"] = MailboxCredentials(
                primary_email="forwarding@example.com",
                registration_email=config.new_account.email,
                client_id="",
                refresh_token="",
                provider="icloud_hme_imap",
                forwarding_email="forwarding@example.com",
                imap_host="imap.example.com",
                imap_username="forwarding@example.com",
                imap_password="imap-secret",
            )
            WorkflowRunner(
                config,
                **dependencies,
                registrar=registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            ).run()

        self.assertEqual(registrar.registered, [])
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email, config.new_account.email],
        )

    def test_existing_non_icloud_new_account_still_uses_login(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )

            class RegistrarWithRegistration(FakeRegistrar):
                def __init__(self):
                    super().__init__()
                    self.registered = []

                def register(self, **kwargs):
                    self.registered.append(kwargs["email"])
                    return super().login(**kwargs)

            registrar = RegistrarWithRegistration()
            WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
            ).run()

        self.assertEqual(registrar.registered, [])
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email, config.new_account.email],
        )

    def test_personal_workspace_refresh_reauthenticates_new_account_after_invite(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )
            checkpoint = InMemoryCheckpoint()

            class ReauthRegistrar(FakeRegistrar):
                def __init__(self):
                    super().__init__()
                    self.login_requests = []

                def login(self, **kwargs):
                    self.login_requests.append(
                        (kwargs["email"], kwargs.get("workspace_id"))
                    )
                    return super().login(**kwargs)

            class PersonalThenTeamChatGPT(FakeChatGPT):
                def __init__(self, *args):
                    super().__init__(*args)
                    self.returned_personal = False

                def refresh_session(self, session_token, account_id=None):
                    if session_token.startswith("new-") and not self.returned_personal:
                        self.returned_personal = True
                        self.calls.append(("refresh", session_token, account_id))
                        return {
                            "user": {"id": self.new_user_id, "email": self.new_email},
                            "account": {"id": "personal-workspace", "planType": "free"},
                            "accessToken": access_token(
                                self.new_email,
                                "personal-workspace",
                                self.new_user_id,
                            ),
                            "sessionToken": "new-personal-session",
                        }
                    return super().refresh_session(
                        session_token,
                        account_id=account_id,
                    )

            registrar = ReauthRegistrar()
            chatgpt = PersonalThenTeamChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )

            WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=registrar,
                chatgpt=chatgpt,
                verbose=False,
            ).run()

        self.assertEqual(
            registrar.login_requests,
            [
                (config.old_account.email, config.workspace_id),
                (config.new_account.email, None),
                (config.new_account.email, config.workspace_id),
            ],
        )
        self.assertIsInstance(checkpoint.get("new_workspace_login"), dict)
        self.assertEqual(
            len(
                [
                    call
                    for call in chatgpt.calls
                    if call[:2] == ("refresh", "new-login-session")
                ]
            ),
            2,
        )

    def test_new_account_identity_failure_happens_after_invite_and_leave(self):
        for code in (
            "alias_disabled",
            "account_deactivated",
            "mailbox_credentials_invalid",
        ):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                config = make_workflow_config(
                    Path(directory),
                    push=False,
                    sub2api_push=False,
                )
                checkpoint = InMemoryCheckpoint()
                registrar = FakeRegistrar()
                login_attempts = []
                original_login = registrar.login

                def fail_new_login(**kwargs):
                    login_attempts.append(
                        (kwargs["email"], kwargs.get("workspace_id"))
                    )
                    if kwargs["email"] == config.new_account.email:
                        raise RegistrarIdentityError(code)
                    return original_login(**kwargs)

                registrar.login = fail_new_login
                chatgpt = FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                )
                runner = WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                )

                with self.assertRaises(WorkflowIdentityError) as caught:
                    runner.run()

                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.role, "next")
                self.assertEqual(
                    login_attempts,
                    [
                        (config.old_account.email, config.workspace_id),
                        (config.new_account.email, None),
                    ],
                )
                self.assertTrue(any(call[0] == "invite" for call in chatgpt.calls))
                self.assertTrue(any(call[0] == "leave" for call in chatgpt.calls))
                self.assertIsInstance(checkpoint.get("invite"), dict)
                self.assertIsInstance(checkpoint.get("old_leave"), dict)
                self.assertIsNone(checkpoint.get("new_login"))

    def test_invalid_cached_new_login_is_checked_after_invite_and_leave(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )
            checkpoint = InMemoryCheckpoint()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            runner = WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=FakeRegistrar(),
                chatgpt=chatgpt,
                verbose=False,
            )
            checkpoint.set(
                "new_login",
                {"email": config.new_account.email, "session_token": ""},
            )

            with self.assertRaisesRegex(RuntimeError, "no session_token"):
                runner.run()

        self.assertTrue(any(call[0] == "invite" for call in chatgpt.calls))
        self.assertTrue(any(call[0] == "leave" for call in chatgpt.calls))
        self.assertIsInstance(checkpoint.get("invite"), dict)
        self.assertIsInstance(checkpoint.get("old_leave"), dict)

    def test_complete_flow_and_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_email = "main+2@example.com"
            new_email = "main+3@example.com"
            workspace_id = "workspace-1"
            config = WorkflowConfig(
                old_account=AccountSpec(old_email),
                new_account=AccountSpec(new_email),
                workspace_id=workspace_id,
                proxy="",
                pat_name="workflow-pat",
                pat_ttl=5_184_000,
                output_dir=root / "output",
                management_base_url="https://upic.invalid",
                management_key="key",
                push=True,
                replace=False,
                remote_name="",
                invite_settle_seconds=0,
                sub2api_base_url="https://sub2api.example",
                sub2api_email="admin@example.com",
                sub2api_password="secret",
                sub2api_totp_secret="totp-secret",
                sub2api_push=True,
                sub2api_group_id=3,
            )
            checkpoint = InMemoryCheckpoint()
            dependencies = run_dependencies(config, checkpoint)
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(workspace_id, old_email, new_email)
            management = FakeManagement()
            sub2api = FakeSub2API()
            logs = []
            result = WorkflowRunner(
                config,
                **dependencies,
                registrar=registrar,
                chatgpt=chatgpt,
                management=management,
                sub2api=sub2api,
                verbose=False,
                logger=logs.append,
            ).run()

            self.assertEqual(registrar.calls, [(old_email, None), (new_email, None)])
            self.assertIs(registrar.login_profiles[0], registrar.login_profiles[1])
            self.assertEqual(result["invite"], "invited")
            self.assertEqual(result["old_leave"], "left")
            self.assertEqual(
                result["member_guard"],
                {
                    "verified": True,
                    "active_members": 2,
                    "member_limit": 2,
                    "old_child_absent": True,
                    "new_child_present": True,
                },
            )
            self.assertTrue(Path(result["cpa_path"]).exists())
            self.assertEqual(Path(result["cpa_path"]).stat().st_mode & 0o777, 0o600)
            cpa = json.loads(Path(result["cpa_path"]).read_text(encoding="utf-8"))
            self.assertEqual(cpa["access_token"], "at-test")
            self.assertNotIn("session_token", cpa)
            self.assertNotIn("expired", cpa)
            self.assertNotIn("headers", cpa)
            self.assertTrue(Path(result["sub2api_path"]).exists())
            self.assertEqual(
                Path(result["sub2api_path"]).stat().st_mode & 0o777,
                0o600,
            )
            sub2api_export = json.loads(
                Path(result["sub2api_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(
                list(sub2api_export), ["exported_at", "proxies", "accounts"]
            )
            self.assertEqual(sub2api_export["proxies"], [])
            self.assertEqual(
                sub2api_export["accounts"][0]["credentials"]["access_token"],
                "at-test",
            )
            self.assertNotIn("session-token", json.dumps(sub2api_export))
            self.assertEqual(result["push"]["action"], "uploaded")
            self.assertEqual(result["sub2api"]["action"], "created")
            self.assertEqual(len(sub2api.calls), 1)
            self.assertEqual(
                sub2api.calls[0]["credentials"]["auth_mode"],
                "personalAccessToken",
            )
            self.assertEqual(sub2api.calls[0]["group_ids"], [3])
            self.assertIn(("invite", workspace_id, new_email), chatgpt.calls)
            self.assertIn(("leave", workspace_id, "user-old"), chatgpt.calls)
            self.assertIn(f"[login] {old_email}", logs)
            self.assertIn(f"[register] {new_email}", logs)
            self.assertTrue(any(message.startswith("[cpa]") for message in logs))
            self.assertTrue(
                any(message.startswith("[sub2api-export]") for message in logs)
            )

            Path(result["sub2api_path"]).unlink()

            second_registrar = FakeRegistrar()
            second_chatgpt = FakeChatGPT(
                workspace_id,
                old_email,
                new_email,
                chatgpt.member_state,
            )
            second_management = FakeManagement()
            second_sub2api = FakeSub2API()
            resumed = WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=second_registrar,
                chatgpt=second_chatgpt,
                management=second_management,
                sub2api=second_sub2api,
                verbose=False,
            ).run()
            self.assertEqual(resumed["cpa_path"], result["cpa_path"])
            self.assertEqual(resumed["sub2api_path"], result["sub2api_path"])
            self.assertTrue(Path(resumed["sub2api_path"]).exists())
            self.assertEqual(second_registrar.calls, [])
            self.assertEqual(second_management.calls, [])
            self.assertEqual(second_sub2api.calls, [])
            self.assertTrue(second_registrar.restored_profile)
            self.assertEqual(
                second_registrar.resolved_profiles[0].profile_id,
                registrar.resolved_profiles[0].profile_id,
            )

    def test_ten_stage_event_order_marks_disabled_pushes_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )
            checkpoint = InMemoryCheckpoint()
            events = []
            result = WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=FakeRegistrar(),
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                verbose=False,
                event_callback=events.append,
            ).run()

        self.assertEqual(
            [(event["step"], event["state"]) for event in events],
            [
                ("old_login", "active"),
                ("old_login", "done"),
                ("invite", "active"),
                ("invite", "done"),
                ("old_leave", "active"),
                ("old_leave", "done"),
                ("new_login", "active"),
                ("new_login", "done"),
                ("member_verify", "active"),
                ("member_verify", "done"),
                ("pat", "active"),
                ("pat", "done"),
                ("cpa", "active"),
                ("cpa", "done"),
                ("sub2api_export", "active"),
                ("sub2api_export", "done"),
                ("push", "active"),
                ("push", "skipped"),
                ("push_sub2api", "active"),
                ("push_sub2api", "skipped"),
            ],
        )
        self.assertIsNone(result["push"])
        self.assertIsNone(result["sub2api"])

    def test_member_limit_blocks_before_any_handoff_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            chatgpt.member_state["members"]["user-third"] = {
                "id": "user-third",
                "email": "third@example.com",
            }

            with self.assertRaisesRegex(RuntimeError, "member limit exceeded"):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

        self.assertFalse(
            any(call[0] in {"invite", "leave", "pat"} for call in chatgpt.calls)
        )
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertIsNone(checkpoint.get("invite"))
        self.assertIsNone(checkpoint.get("new_login"))

    def test_unrelated_pending_invite_blocks_target_invite(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            chatgpt.member_state["invites"].add("other@example.com")

            with self.assertRaisesRegex(RuntimeError, "unrelated pending invites"):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

        self.assertFalse(any(call[0] == "invite" for call in chatgpt.calls))
        self.assertFalse(any(call[0] == "leave" for call in chatgpt.calls))
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )

    def test_leave_failure_prevents_new_child_login(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()

            class FailingLeaveChatGPT(FakeChatGPT):
                def leave(self, access_token_value, account_id, user_id):
                    del access_token_value
                    self.calls.append(("leave", account_id, user_id))
                    raise RuntimeError("leave request failed")

            chatgpt = FailingLeaveChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )

            with self.assertRaisesRegex(RuntimeError, "leave request failed"):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertEqual(checkpoint.get("old_leave")["action"], "started")
        self.assertIsNone(checkpoint.get("new_login"))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))

    def test_old_child_residue_blocks_new_login_before_join(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()

            class NonRemovingLeaveChatGPT(FakeChatGPT):
                def leave(self, access_token_value, account_id, user_id):
                    del access_token_value
                    self.calls.append(("leave", account_id, user_id))
                    return {"ok": True}

            chatgpt = NonRemovingLeaveChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )

            with patch(
                "team_protocol.workflow._MEMBER_FEEDBACK_TIMEOUT_SECONDS", 0
            ):
                with self.assertRaisesRegex(RuntimeError, "old child is still active"):
                    WorkflowRunner(
                        config,
                        **run_dependencies(config, checkpoint),
                        registrar=registrar,
                        chatgpt=chatgpt,
                        verbose=False,
                    ).run()

        self.assertIsNone(checkpoint.get("new_login"))
        self.assertIsNone(checkpoint.get("member_verify"))
        self.assertIsNone(checkpoint.get("pat"))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )

    def test_no_free_slot_after_old_leave_blocks_new_login(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()

            class ConcurrentMemberChatGPT(FakeChatGPT):
                def leave(self, access_token_value, account_id, user_id):
                    result = super().leave(access_token_value, account_id, user_id)
                    self.member_state["members"]["user-third"] = {
                        "id": "user-third",
                        "email": "third@example.com",
                    }
                    return result

            chatgpt = ConcurrentMemberChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )

            with patch(
                "team_protocol.workflow._MEMBER_FEEDBACK_TIMEOUT_SECONDS", 0
            ):
                with self.assertRaisesRegex(RuntimeError, "no free member slot"):
                    WorkflowRunner(
                        config,
                        **run_dependencies(config, checkpoint),
                        registrar=registrar,
                        chatgpt=chatgpt,
                        verbose=False,
                    ).run()

        self.assertIsNone(checkpoint.get("new_login"))
        self.assertIsNone(checkpoint.get("member_verify"))
        self.assertIsNone(checkpoint.get("pat"))
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )

    def test_resume_after_leave_crash_accepts_revoked_old_access(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()

            class CrashAfterLeaveChatGPT(FakeChatGPT):
                def leave(self, access_token_value, account_id, user_id):
                    super().leave(access_token_value, account_id, user_id)
                    raise RuntimeError("simulated crash after leave")

            first_chatgpt = CrashAfterLeaveChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            with self.assertRaisesRegex(RuntimeError, "simulated crash after leave"):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=FakeRegistrar(),
                    chatgpt=first_chatgpt,
                    verbose=False,
                ).run()

            self.assertEqual(checkpoint.get("old_leave")["action"], "started")
            self.assertIsNone(checkpoint.get("new_login"))

            class RevokedOldAccessChatGPT(FakeChatGPT):
                def get_members(self, access_token_value, account_id):
                    old_token = access_token(
                        self.old_email,
                        self.workspace_id,
                        self.old_user_id,
                    )
                    if access_token_value == old_token:
                        self.calls.append(("members", account_id))
                        raise ChatGPTApiError("HTTP 403", status_code=403)
                    return super().get_members(access_token_value, account_id)

            resumed_chatgpt = RevokedOldAccessChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                first_chatgpt.member_state,
            )
            resumed_registrar = FakeRegistrar()
            result = WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=resumed_registrar,
                chatgpt=resumed_chatgpt,
                verbose=False,
            ).run()

        self.assertTrue(result["member_guard"]["verified"])
        self.assertEqual(
            checkpoint.get("old_leave")["departure_guard"]["measurement"],
            "access-revoked",
        )
        self.assertEqual(
            [email for email, _proxy in resumed_registrar.calls],
            [config.new_account.email],
        )
        self.assertFalse(
            any(call[0] in {"invite", "leave"} for call in resumed_chatgpt.calls)
        )

    def test_member_verification_rejects_missing_new_child(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()

            class MissingJoinChatGPT(FakeChatGPT):
                def refresh_session(self, session_token, account_id=None):
                    result = super().refresh_session(
                        session_token, account_id=account_id
                    )
                    if (
                        session_token.startswith("new-")
                        and account_id == self.workspace_id
                    ):
                        self.member_state["members"].pop(self.new_user_id, None)
                    return result

            chatgpt = MissingJoinChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )

            with self.assertRaisesRegex(RuntimeError, "new child is missing"):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=FakeRegistrar(),
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

        self.assertIsNone(checkpoint.get("member_verify"))
        self.assertIsNone(checkpoint.get("pat"))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))

    def test_resume_with_pat_checkpoint_still_rechecks_member_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory), push=False, sub2api_push=False
            )
            checkpoint = InMemoryCheckpoint()
            first_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=FakeRegistrar(),
                chatgpt=first_chatgpt,
                verbose=False,
            ).run()
            self.assertIsInstance(checkpoint.get("pat"), dict)
            first_chatgpt.member_state["members"]["user-third"] = {
                "id": "user-third",
                "email": "third@example.com",
            }
            resumed_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                first_chatgpt.member_state,
            )

            with self.assertRaisesRegex(RuntimeError, "member limit exceeded"):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=FakeRegistrar(),
                    chatgpt=resumed_chatgpt,
                    verbose=False,
                ).run()

        self.assertFalse(
            any(
                call[0] in {"invite", "leave", "pat", "refresh"}
                for call in resumed_chatgpt.calls
            )
        )

    def test_sub2api_export_rejects_embedded_session_material(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.sub2api.json"
            path.write_text(
                json.dumps(
                    {
                        "exported_at": "2026-07-19T00:00:00.000Z",
                        "proxies": [],
                        "accounts": [
                            {
                                "credentials": {"access_token": "at-test"},
                                "extra": {"sessionToken": "must-not-leak"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "forbidden session material"):
                WorkflowRunner._sub2api_account_from_file(path)

    def test_sub2api_push_passes_totp_session_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_api_key="admin-key",
                sub2api_totp_secret="totp-secret",
            )
            client = SimpleNamespace(
                push_account=lambda _account: SimpleNamespace(
                    action="created",
                    account_name="main+3@example.com",
                    verified=True,
                    message="created",
                ),
                close=lambda: None,
            )
            with patch("team_protocol.workflow.Sub2APIClient", return_value=client) as client_class:
                result = WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=FakeRegistrar(),
                    chatgpt=FakeChatGPT(
                        config.workspace_id,
                        config.old_account.email,
                        config.new_account.email,
                    ),
                    management=FakeManagement(),
                    verbose=False,
                ).run()

        self.assertEqual(result["sub2api"]["action"], "created")
        client_class.assert_called_once_with(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            api_key="admin-key",
            totp_secret="totp-secret",
        )

    def test_sub2api_all_groups_push_accepts_admin_api_key_only(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_email="",
                sub2api_password="",
                sub2api_api_key="admin-key",
                sub2api_totp_secret="",
                sub2api_load_factor=9999,
                sub2api_all_groups=True,
            )
            client = SimpleNamespace(
                push_production_account=lambda _account: SimpleNamespace(
                    action="updated",
                    account_name="main+3@example.com",
                    verified=True,
                    message="updated",
                    account_id=42,
                    group_count=4,
                    concurrency=9999,
                    load_factor=9999,
                ),
                close=lambda: None,
            )
            with patch(
                "team_protocol.workflow.Sub2APIClient", return_value=client
            ) as client_class:
                result = WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=FakeRegistrar(),
                    chatgpt=FakeChatGPT(
                        config.workspace_id,
                        config.old_account.email,
                        config.new_account.email,
                    ),
                    management=FakeManagement(),
                    verbose=False,
                ).run()

        self.assertEqual(
            result["sub2api"],
            {
                "action": "updated",
                "account_name": "main+3@example.com",
                "verified": True,
                "message": "updated",
                "account_id": 42,
                "group_count": 4,
                "concurrency": 9999,
                "load_factor": 9999,
            },
        )
        client_class.assert_called_once_with(
            "https://sub2api.example", "", "", api_key="admin-key"
        )

    def test_in_memory_checkpoint_prevents_duplicate_mutations_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(Path(directory))
            checkpoint = InMemoryCheckpoint()
            first_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            first_management = FakeManagement()
            first_sub2api = FakeSub2API()
            WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=FakeRegistrar(),
                chatgpt=first_chatgpt,
                management=first_management,
                sub2api=first_sub2api,
                verbose=False,
            ).run()

            resumed_registrar = FakeRegistrar()
            resumed_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                first_chatgpt.member_state,
            )
            resumed_management = FakeManagement()
            resumed_sub2api = FakeSub2API()
            WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=resumed_registrar,
                chatgpt=resumed_chatgpt,
                management=resumed_management,
                sub2api=resumed_sub2api,
                verbose=False,
            ).run()

        self.assertIn(("invite", config.workspace_id, config.new_account.email), first_chatgpt.calls)
        self.assertIn(("leave", config.workspace_id, "user-old"), first_chatgpt.calls)
        self.assertTrue(any(call[0] == "pat" for call in first_chatgpt.calls))
        self.assertEqual(len(first_management.calls), 1)
        self.assertEqual(len(first_sub2api.calls), 1)
        self.assertEqual(resumed_registrar.calls, [])
        self.assertFalse(
            any(
                call[0] in {"invite", "leave", "pat", "refresh"}
                for call in resumed_chatgpt.calls
            )
        )
        self.assertEqual(resumed_management.calls, [])
        self.assertEqual(resumed_sub2api.calls, [])
        for name in (
            "invite",
            "old_leave",
            "member_verify",
            "pat",
            "sub2api_export",
            "push",
            "push_sub2api",
        ):
            self.assertIsInstance(checkpoint.get(name), dict)

    def test_one_fingerprint_and_one_expanded_proxy_cover_the_full_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                proxy="proxy-{worker}-{rand}.example:9000",
                push=False,
                sub2api_push=False,
            )
            checkpoint = InMemoryCheckpoint()
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            with (
                patch(
                    "team_protocol.registrar._render_proxy_template",
                    return_value="proxy-1-fixed.example:9000",
                ) as render_proxy,
                patch(
                    "team_protocol.workflow.ChatGPTClient",
                    return_value=chatgpt,
                ) as client_class,
            ):
                WorkflowRunner(
                    config,
                    **run_dependencies(config, checkpoint),
                    registrar=registrar,
                    verbose=False,
                ).run()

        render_proxy.assert_called_once_with(config.proxy, 1)
        client_class.assert_called_once()
        chatgpt_profile = client_class.call_args.kwargs["session_profile"]
        self.assertEqual(
            client_class.call_args.kwargs["proxy"],
            "http://proxy-1-fixed.example:9000",
        )
        self.assertEqual(
            registrar.calls,
            [
                (config.old_account.email, "http://proxy-1-fixed.example:9000"),
                (config.new_account.email, "http://proxy-1-fixed.example:9000"),
            ],
        )
        self.assertIs(registrar.login_profiles[0], chatgpt_profile)
        self.assertIs(registrar.login_profiles[1], chatgpt_profile)
        self.assertEqual(
            checkpoint.get("_fingerprint_profile"),
            chatgpt_profile.to_legacy_dict(),
        )

    def test_account_networks_isolate_old_and_new_proxy_profile_and_client(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
            )
            registrar = FakeRegistrar()
            old_profile = FakeFingerprintProfile(
                "old-account-profile",
                geo_country_code="DE",
                locale="de-DE",
                timezone_id="Europe/Berlin",
            )
            new_profile = FakeFingerprintProfile(
                "new-account-profile",
                geo_country_code="DE",
                locale="de-DE",
                timezone_id="Europe/Berlin",
            )
            geo = {
                "resolved": True,
                "source": "test",
                "country_code": "DE",
                "timezone_id": "Europe/Berlin",
                "locale": "de-DE",
                "profile_scope": "windows",
            }
            old_network = AccountNetworkSpec(
                proxy="socks5://tenant-region-DE-sid-old-t-60:pass@proxy.example:1000",
                proxy_sid="old",
                proxy_geo=geo,
                fingerprint_profile=old_profile.to_legacy_dict(),
            )
            new_network = AccountNetworkSpec(
                proxy="socks5://tenant-region-DE-sid-new-t-60:pass@proxy.example:1000",
                proxy_sid="new",
                proxy_geo=geo,
                fingerprint_profile=new_profile.to_legacy_dict(),
            )
            member_state = {
                "members": {
                    "user-owner": {"id": "user-owner", "email": "owner@example.com"},
                    "user-old": {"id": "user-old", "email": config.old_account.email},
                },
                "invites": set(),
            }
            old_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                member_state,
            )
            new_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                member_state,
            )

            with patch(
                "team_protocol.workflow.ChatGPTClient",
                side_effect=[old_chatgpt, new_chatgpt],
            ) as client_class:
                WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=registrar,
                    old_network=old_network,
                    new_network=new_network,
                    verbose=False,
                ).run()

        self.assertEqual(
            registrar.calls,
            [
                (config.old_account.email, old_network.proxy),
                (config.new_account.email, new_network.proxy),
            ],
        )
        self.assertEqual(
            [profile.profile_id for profile in registrar.login_profiles],
            ["old-account-profile", "new-account-profile"],
        )
        self.assertEqual(client_class.call_count, 2)
        self.assertEqual(client_class.call_args_list[0].kwargs["proxy"], old_network.proxy)
        self.assertEqual(client_class.call_args_list[1].kwargs["proxy"], new_network.proxy)
        self.assertIn(("invite", config.workspace_id, config.new_account.email), old_chatgpt.calls)
        self.assertIn(("leave", config.workspace_id, "user-old"), old_chatgpt.calls)
        self.assertFalse(any(call[0] == "pat" for call in old_chatgpt.calls))
        self.assertTrue(any(call[0] == "pat" for call in new_chatgpt.calls))
        self.assertFalse(any(call[0] in {"invite", "leave"} for call in new_chatgpt.calls))

    def test_account_geo_drift_keeps_the_locked_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(Path(directory))
            registrar = FakeRegistrar()
            registrar.resolve_proxy_geo = lambda _proxy: {
                "resolved": True,
                "source": "test",
                "country_code": "BR",
                "timezone_id": "America/Sao_Paulo",
                "locale": "pt-BR",
                "profile_scope": "windows",
            }
            stored_geo = {
                "resolved": True,
                "source": "test",
                "country_code": "DE",
                "timezone_id": "Europe/Berlin",
                "locale": "de-DE",
                "profile_scope": "windows",
            }
            profile = FakeFingerprintProfile(
                "locked-profile",
                geo_country_code="DE",
                locale="de-DE",
                timezone_id="Europe/Berlin",
            ).to_legacy_dict()
            old_network = AccountNetworkSpec(
                proxy="socks5://tenant-sid-OldSid90:pass@proxy.example:1000",
                proxy_sid="OldSid90",
                proxy_geo=stored_geo,
                fingerprint_profile=profile,
            )
            new_network = AccountNetworkSpec(
                proxy="socks5://tenant-sid-NewSid90:pass@proxy.example:1000",
                proxy_sid="NewSid90",
                proxy_geo=stored_geo,
                fingerprint_profile=profile,
            )

            with patch("team_protocol.workflow.ChatGPTClient") as client_class:
                runner = WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=registrar,
                    old_network=old_network,
                    new_network=new_network,
                    verbose=False,
                )

            self.assertEqual(client_class.call_count, 2)
            self.assertEqual(runner._networks["old"].proxy_geo, stored_geo)
            self.assertEqual(runner._networks["new"].proxy_geo, stored_geo)
            self.assertEqual(
                [profile.timezone_id for profile in registrar.resolved_profiles],
                ["Europe/Berlin", "Europe/Berlin"],
            )

    def test_primary_geo_clock_skew_fails_before_chatgpt_clients_are_created(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(Path(directory))
            registrar = FakeRegistrar()
            registrar.resolve_proxy_geo = lambda _proxy: {
                "resolved": True,
                "source": "ipwho.is",
                "country_code": "DE",
                "timezone_id": "Europe/Berlin",
                "timezone_exact": True,
                "locale": "de-DE",
                "profile_scope": "windows",
                "clock_checked": True,
                "clock_skew_seconds": 61.0,
            }
            old_network = AccountNetworkSpec(
                proxy="socks5://tenant-sid-OldSid90:pass@proxy.example:1000",
                proxy_sid="OldSid90",
            )
            new_network = AccountNetworkSpec(
                proxy="socks5://tenant-sid-NewSid90:pass@proxy.example:1000",
                proxy_sid="NewSid90",
            )

            with patch("team_protocol.workflow.ChatGPTClient") as client_class:
                with self.assertRaisesRegex(RuntimeError, "more than 60 seconds"):
                    WorkflowRunner(
                        config,
                        **run_dependencies(config),
                        registrar=registrar,
                        old_network=old_network,
                        new_network=new_network,
                        verbose=False,
                    )

            client_class.assert_not_called()

    def test_proxy_geo_hint_is_checkpointed_and_reused_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                proxy="proxy-{rand}.example:9000",
                push=False,
                sub2api_push=False,
            )
            checkpoint = InMemoryCheckpoint()
            fixed_proxy = "http://fixed-user:fixed-pass@proxy.example:9000"
            first_registrar = FakeRegistrar()

            first_chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                expanded_proxy=fixed_proxy,
                registrar=first_registrar,
                chatgpt=first_chatgpt,
                verbose=False,
            ).run()

            stored_geo = checkpoint.get("_proxy_geo")
            self.assertEqual(first_registrar.geo_calls, [fixed_proxy])
            self.assertEqual(stored_geo["country_code"], "DE")
            self.assertEqual(stored_geo["timezone_id"], "Europe/Berlin")
            self.assertEqual(first_registrar.profile_geo_hints, [stored_geo])
            self.assertEqual(
                checkpoint.get("_fingerprint_profile")["geo_country_code"],
                "DE",
            )

            resumed_registrar = FakeRegistrar()
            WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                expanded_proxy=fixed_proxy,
                registrar=resumed_registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                    first_chatgpt.member_state,
                ),
                verbose=False,
            ).run()

        self.assertEqual(resumed_registrar.geo_calls, [])
        self.assertEqual(resumed_registrar.profile_geo_hints, [stored_geo])
        self.assertTrue(resumed_registrar.restored_profile)

    def test_injected_run_dependencies_create_only_explicit_export_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_workflow_config(
                root,
                proxy="proxy-{worker}-{rand}.example:9000",
                push=False,
                sub2api_push=False,
            )
            checkpoint = FalsyCheckpoint()
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            old_mailbox = MailboxCredentials(
                primary_email="main@example.com",
                registration_email=config.old_account.email,
                client_id="old-client",
                refresh_token="old-refresh",
            )
            new_mailbox = MailboxCredentials(
                primary_email="main@example.com",
                registration_email=config.new_account.email,
                client_id="new-client",
                refresh_token="new-refresh",
            )
            before = {
                path.relative_to(root)
                for path in root.rglob("*")
                if path.is_file()
            }

            with patch(
                "team_protocol.registrar._render_proxy_template"
            ) as render_proxy:
                result = WorkflowRunner(
                    config,
                    checkpoint_store=checkpoint,
                    old_mailbox=old_mailbox,
                    new_mailbox=new_mailbox,
                    expanded_proxy="http://fixed-user:fixed-pass@proxy.example:9000",
                    registrar=registrar,
                    chatgpt=chatgpt,
                    verbose=False,
                ).run()

            created = {
                path.relative_to(root)
                for path in root.rglob("*")
                if path.is_file()
            } - before
            render_proxy.assert_not_called()
            self.assertEqual(registrar.mailboxes, [old_mailbox, new_mailbox])
            self.assertEqual(
                registrar.calls,
                [
                    (
                        config.old_account.email,
                        "http://fixed-user:fixed-pass@proxy.example:9000",
                    ),
                    (
                        config.new_account.email,
                        "http://fixed-user:fixed-pass@proxy.example:9000",
                    ),
                ],
            )
            self.assertEqual(registrar.provider_initial_states[0], {})
            self.assertIn(
                config.old_account.email,
                registrar.provider_initial_states[1]["completed_aliases"],
            )
            self.assertIsInstance(checkpoint.get("_registrar_provider_state"), dict)
            self.assertFalse((config.output_dir / ".registrar").exists())
            self.assertEqual(
                created,
                {
                    Path(result["cpa_path"]).resolve().relative_to(root.resolve()),
                    Path(result["sub2api_path"])
                    .resolve()
                    .relative_to(root.resolve()),
                },
            )
            self.assertFalse(
                any(
                    "state" in path.name.casefold()
                    or "session" in path.name.casefold()
                    or "token" in path.name.casefold()
                    for path in created
                )
            )

    def test_cancelled_before_first_step(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(Path(directory))
            stop_event = threading.Event()
            stop_event.set()
            registrar = FakeRegistrar()
            events = []
            runner = WorkflowRunner(
                config,
                **run_dependencies(config),
                registrar=registrar,
                chatgpt=FakeChatGPT(
                    config.workspace_id,
                    config.old_account.email,
                    config.new_account.email,
                ),
                management=FakeManagement(),
                verbose=False,
                stop_event=stop_event,
                event_callback=events.append,
            )
            with self.assertRaises(WorkflowCancelled):
                runner.run()
            self.assertEqual(registrar.calls, [])
            self.assertEqual(events, [])

    def test_cancel_during_invite_wait_checkpoints_invite_and_stops_next_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                push=False,
                sub2api_push=False,
                invite_settle_seconds=9.5,
            )
            checkpoint = InMemoryCheckpoint()
            stop_event = CancelDuringWait()
            registrar = FakeRegistrar()
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
            )
            events = []
            runner = WorkflowRunner(
                config,
                **run_dependencies(config, checkpoint),
                registrar=registrar,
                chatgpt=chatgpt,
                verbose=False,
                stop_event=stop_event,
                event_callback=events.append,
            )
            with self.assertRaises(WorkflowCancelled):
                runner.run()

        self.assertEqual(stop_event.wait_calls, [9.5])
        self.assertEqual(checkpoint.get("invite")["action"], "invited")
        self.assertIsNone(checkpoint.get("old_leave"))
        self.assertIsNone(checkpoint.get("new_login"))
        self.assertEqual(
            registrar.calls,
            [
                (config.old_account.email, None),
            ],
        )
        self.assertNotIn(("leave", config.workspace_id, "user-old"), chatgpt.calls)
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))
        self.assertEqual(
            [(event["step"], event["state"]) for event in events],
            [
                ("old_login", "active"),
                ("old_login", "done"),
                ("invite", "active"),
                ("invite", "cancelled"),
            ],
        )

    def test_workflow_proxy_is_shared_by_login_and_owned_chatgpt_client(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_workflow_config(
                Path(directory),
                proxy="proxy-{worker}.example:9000",
            )
            registrar = FakeRegistrar()

            with patch("team_protocol.workflow.ChatGPTClient") as client_class:
                runner = WorkflowRunner(
                    config,
                    **run_dependencies(config),
                    registrar=registrar,
                    verbose=False,
                )
                runner._login(config.old_account, "old_login")
                runner.close()

            client_class.assert_called_once_with(
                proxy="http://proxy-1.example:9000",
                session_profile=registrar.resolved_profiles[0],
            )

        self.assertEqual(
            registrar.calls,
            [("main+2@example.com", "http://proxy-1.example:9000")],
        )
        self.assertIs(registrar.login_profiles[0], registrar.resolved_profiles[0])


class RescueWorkflowTests(unittest.TestCase):
    @staticmethod
    def member_state(*, include_third=False):
        members = {
            "user-owner": {"id": "user-owner", "email": "main+2@example.com"},
            "user-broken": {
                "id": "user-broken",
                "email": "broken-child@example.com",
            },
        }
        if include_third:
            members["user-third"] = {
                "id": "user-third",
                "email": "third@example.com",
            }
        return {"members": members, "invites": set()}

    @staticmethod
    def runner(root, checkpoint, chatgpt, registrar=None):
        config = make_workflow_config(
            root,
            push=False,
            sub2api_push=False,
        )
        return RescueWorkflowRunner(
            config,
            **run_dependencies(config, checkpoint),
            registrar=registrar or FakeRegistrar(),
            chatgpt=chatgpt,
            verbose=False,
        )

    def test_rescue_clears_every_non_owner_before_invite_and_finishes_with_two(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            chatgpt = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(include_third=True),
            )

            result = self.runner(root, checkpoint, chatgpt).run()

        self.assertEqual(result["mode"], "rescue")
        self.assertEqual(result["clear"]["removed_members"], 2)
        self.assertEqual(result["member_guard"]["active_members"], 2)
        self.assertEqual(
            set(chatgpt.member_state["members"]),
            {"user-owner", "user-new"},
        )
        remove_indexes = [
            index for index, call in enumerate(chatgpt.calls) if call[0] == "remove"
        ]
        invite_index = next(
            index for index, call in enumerate(chatgpt.calls) if call[0] == "invite"
        )
        self.assertEqual(len(remove_indexes), 2)
        self.assertTrue(all(index < invite_index for index in remove_indexes))
        self.assertTrue(any(call[0] == "pat" for call in chatgpt.calls))

    def test_rescue_remove_failure_stops_before_invite_new_login_and_pat(self):
        class FailingRemovalChatGPT(FakeChatGPT):
            def remove_member(self, access_token_value, account_id, user_id):
                del access_token_value
                self.calls.append(("remove", account_id, user_id))
                raise RuntimeError("member removal failed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            registrar = FakeRegistrar()
            chatgpt = FailingRemovalChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(),
            )

            with self.assertRaisesRegex(RuntimeError, "member removal failed"):
                self.runner(root, checkpoint, chatgpt, registrar).run()

        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )
        self.assertFalse(any(call[0] == "invite" for call in chatgpt.calls))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))
        self.assertIsNone(checkpoint.get("rescue_invite"))
        self.assertIsNone(checkpoint.get("new_login"))

    def test_rescue_residual_member_feedback_stops_before_invite(self):
        class NonRemovingChatGPT(FakeChatGPT):
            def remove_member(self, access_token_value, account_id, user_id):
                del access_token_value
                self.calls.append(("remove", account_id, user_id))
                return {"ok": True}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            chatgpt = NonRemovingChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(),
            )
            with patch(
                "team_protocol.workflow._MEMBER_FEEDBACK_TIMEOUT_SECONDS", 0
            ):
                with self.assertRaisesRegex(RuntimeError, "was not confirmed"):
                    self.runner(root, checkpoint, chatgpt).run()

        self.assertFalse(any(call[0] == "invite" for call in chatgpt.calls))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))

    def test_rescue_member_change_after_clear_blocks_invite_and_new_login(self):
        class JoinAfterClearChatGPT(FakeChatGPT):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.invite_reads = 0

            def get_invites(self, access_token_value, account_id):
                result = super().get_invites(access_token_value, account_id)
                self.invite_reads += 1
                if self.invite_reads == 1:
                    self.member_state["members"]["user-third"] = {
                        "id": "user-third",
                        "email": "third@example.com",
                    }
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            registrar = FakeRegistrar()
            chatgpt = JoinAfterClearChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(),
            )

            with self.assertRaisesRegex(RuntimeError, "member count changed"):
                self.runner(root, checkpoint, chatgpt, registrar).run()

        self.assertFalse(any(call[0] == "invite" for call in chatgpt.calls))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))
        self.assertEqual(
            [email for email, _proxy in registrar.calls],
            [config.old_account.email],
        )

    def test_rescue_final_three_member_feedback_blocks_pat_and_rotation_result(self):
        class ConcurrentJoinChatGPT(FakeChatGPT):
            def refresh_session(self, session_token, account_id=None):
                result = super().refresh_session(session_token, account_id)
                if not session_token.startswith("old-") and account_id == self.workspace_id:
                    self.member_state["members"]["user-third"] = {
                        "id": "user-third",
                        "email": "third@example.com",
                    }
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            chatgpt = ConcurrentJoinChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(),
            )

            with self.assertRaisesRegex(RuntimeError, "exactly the owner and new child"):
                self.runner(root, checkpoint, chatgpt).run()

        self.assertIsNone(checkpoint.get("rescue_verify"))
        self.assertIsNone(checkpoint.get("pat"))
        self.assertFalse(any(call[0] == "pat" for call in chatgpt.calls))

    def test_rescue_resume_after_remove_crash_does_not_repeat_removal(self):
        class CrashAfterRemovalChatGPT(FakeChatGPT):
            def remove_member(self, access_token_value, account_id, user_id):
                result = super().remove_member(
                    access_token_value,
                    account_id,
                    user_id,
                )
                raise RuntimeError("crash after remote removal")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            first = CrashAfterRemovalChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(),
            )
            with self.assertRaisesRegex(RuntimeError, "crash after remote removal"):
                self.runner(root, checkpoint, first).run()

            resumed = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                first.member_state,
            )
            result = self.runner(root, checkpoint, resumed).run()

        self.assertEqual(result["member_guard"]["active_members"], 2)
        self.assertEqual(
            sum(call[0] == "remove" for call in first.calls + resumed.calls),
            1,
        )

    def test_rescue_resume_after_invite_crash_reuses_remote_invite(self):
        class CrashAfterInviteChatGPT(FakeChatGPT):
            def invite(self, access_token_value, account_id, email):
                result = super().invite(access_token_value, account_id, email)
                raise RuntimeError("crash after remote invite")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkpoint = InMemoryCheckpoint()
            config = make_workflow_config(root, push=False, sub2api_push=False)
            first = CrashAfterInviteChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                self.member_state(),
            )
            with self.assertRaisesRegex(RuntimeError, "crash after remote invite"):
                self.runner(root, checkpoint, first).run()

            resumed = FakeChatGPT(
                config.workspace_id,
                config.old_account.email,
                config.new_account.email,
                first.member_state,
            )
            result = self.runner(root, checkpoint, resumed).run()

        self.assertEqual(result["invite"], "already-invited")
        self.assertEqual(
            sum(call[0] == "invite" for call in first.calls + resumed.calls),
            1,
        )


if __name__ == "__main__":
    unittest.main()
