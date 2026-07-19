from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from team_protocol.database import Database, StateConflictError
from team_protocol.icloud_hme import HmeError, HmeSessionError, parse_hme_request
from team_protocol.icloud_hme_capture import HmeCaptureSessionRejectedError
from team_protocol.migration import CleanupFailure, CleanupResult, cleanup_plaintext
from team_protocol.proxy_chain import (
    LokiProxyEndpoint,
    OwnerChainConfig,
    ProxyConfigurationError,
)
from team_protocol.web_console import (
    ConsoleAlreadyRunningError,
    WebConsoleController,
    _ConsoleInstanceLock,
    _event_stream,
    _next_icloud_child_label,
    create_app,
    serve_web_console,
)


class MemorySecretStore:
    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        key = purpose.encode("utf-8") or b"x"
        return b"test:" + bytes(
            value ^ key[index % len(key)] for index, value in enumerate(plaintext)
        )

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        payload = bytes(ciphertext)
        if not payload.startswith(b"test:"):
            raise ValueError("invalid ciphertext")
        key = purpose.encode("utf-8") or b"x"
        return bytes(
            value ^ key[index % len(key)]
            for index, value in enumerate(payload[5:])
        )


class FakeTaskQueue:
    def __init__(self, database: Database) -> None:
        self.database = database
        self._condition = threading.Condition()
        self._revision = 0
        self.started = 0
        self.shutdown_calls = 0

    @property
    def revision(self):
        with self._condition:
            return self._revision

    def notify_change(self):
        with self._condition:
            self._revision += 1
            self._condition.notify_all()
            return self._revision

    def wait_for_change(self, after_revision, timeout=None):
        with self._condition:
            self._condition.wait_for(
                lambda: self._revision > after_revision,
                timeout=timeout,
            )
            return self._revision

    def start(self):
        self.started += 1
        self.notify_change()
        return ()

    def shutdown(self, timeout=None):
        del timeout
        self.shutdown_calls += 1
        self.notify_change()
        return True

    def snapshot(self):
        return {
            "paused": self.database.is_queue_paused(),
            "active_run_id": None,
            "items": self.database.list_queue(),
            "revision": self.revision,
            "started": bool(self.started),
            "closing": False,
            "last_worker_error": None,
        }

    def enqueue(self, workspace_ids):
        result = self.database.enqueue_workspaces(workspace_ids)
        for run in result:
            self.database.append_run_event(
                run["id"], step=None, level="info", message="run queued"
            )
        self.notify_change()
        return result

    def enqueue_rescue(self, workspace_id):
        result = self.database.enqueue_rescue_workspace(workspace_id)
        self.database.append_run_event(
            result["id"],
            step=None,
            level="warning",
            message="emergency rescue queued",
        )
        self.notify_change()
        return result

    def reorder(self, queue_item_ids):
        result = self.database.reorder_queue(queue_item_ids)
        self.notify_change()
        return result

    def set_paused(self, paused):
        result = self.database.set_queue_paused(paused)
        self.notify_change()
        return result

    def stop(self, run_id):
        result = self.database.request_stop(run_id)
        self.notify_change()
        return result

    def retry(self, run_id):
        result = self.database.retry_run(run_id)
        self.notify_change()
        return result

    def retry_registered_account(self, run_id, account_id):
        result = self.database.retry_run(
            run_id,
            registered_account_id=account_id,
        )
        self.notify_change()
        return result


class WebConsoleTests(unittest.TestCase):
    def test_next_icloud_child_label_increments_the_existing_group_sequence(self):
        self.assertEqual(
            _next_icloud_child_label("组 1-7", "组 1", 0),
            "组 1-8",
        )
        self.assertEqual(
            _next_icloud_child_label("group_2_7", "group 2", 0),
            "group_2_8",
        )
        self.assertEqual(
            _next_icloud_child_label("Current child", "Owner one team", 2),
            "Owner one team child 3",
        )

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.root = Path(self.temp_directory.name)
        self.store = MemorySecretStore()
        self.database = Database(self.root / "console.db", secret_store=self.store)
        self.queue = FakeTaskQueue(self.database)
        self.controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
        )
        self.origin_headers = {
            "Origin": "http://testserver",
            "X-Workflow-Token": self.controller.request_token,
        }

    def test_default_runtime_uses_local_relays_with_one_shared_clash_front(self):
        self.assertTrue(self.controller.enable_proxy_chains)
        self.assertEqual(
            self.controller.hme_capture.profile_root,
            (self.root / "browser-profiles" / "icloud-hme").resolve(),
        )
        self.assertTrue(self.controller.hme_capture.profile_root.is_dir())
        payload = self.controller.list_proxy_chain_nodes()
        self.assertTrue(payload["enabled"])
        self.assertTrue(payload["shared"])
        self.assertEqual(payload["local_proxy"], "http://127.0.0.1:7897")
        self.assertEqual(payload["nodes"], ["http://127.0.0.1:7897"])

    def account(self, suffix, *, primary=None):
        primary_email = primary or f"primary-{suffix}@example.com"
        return self.database.create_account(
            account_id=f"account-{suffix}",
            email=f"person+{suffix}@example.com",
            primary_email=primary_email,
            credentials={
                "mailbox_password": f"mail-secret-{suffix}",
                "client_id": f"client-{suffix}",
                "refresh_token": f"refresh-secret-{suffix}",
                "account_password": f"account-secret-{suffix}",
            },
            source="test",
        )

    def workspace(self, suffix="one"):
        current = self.account(f"{suffix}-current")
        next_account = self.account(f"{suffix}-next")
        workspace = self.database.create_workspace(
            workspace_id=f"workspace-{suffix}",
            name=f"Space {suffix}",
            workspace_uid=f"workspace-uid-{suffix}",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        return workspace, current, next_account

    @staticmethod
    def inventory_record(email, order=0):
        return {
            "primary_email": email,
            "client_id": f"client-{order}",
            "refresh_token": f"inventory-refresh-secret-{order}",
            "password": f"inventory-mail-secret-{order}",
            "source_order": order,
        }

    @staticmethod
    def icloud_payload():
        url = (
            "https://p68-maildomainws.icloud.com/v2/hme/list?"
            "clientBuildNumber=2536Project32&clientMasteringNumber=2536B20&"
            "clientId=client-icloud&dsid=dsid-icloud"
        )
        cookie = (
            "X-APPLE-DS-WEB-SESSION-TOKEN=icloud-session-secret; "
            "X-APPLE-WEBAUTH-USER=icloud-user-secret; "
            "X-APPLE-WEBAUTH-TOKEN=icloud-auth-secret"
        )
        return {
            "name": "Apple parent",
            "forwarding_email": "forwarding@example.com",
            "session_import": f"curl '{url}' -H 'Cookie: {cookie}'",
            "imap_host": "imap.example.com",
            "imap_port": 993,
            "imap_username": "forwarding@example.com",
            "imap_password": "imap-password-secret",
            "imap_folder": "INBOX",
            "proxy": "socks5h://parent:proxy-password-secret@proxy.invalid:1080",
        }

    def failed_icloud_handoff(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "refresh-owner@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "refresh-owner@icloud.com",
                        "anonymousId": "refresh-owner-remote-secret",
                    },
                },
                {
                    "email": "refresh-current@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "refresh-owner@icloud.com",
                    "remote_metadata": {
                        "hme": "refresh-current@icloud.com",
                        "anonymousId": "refresh-current-remote-secret",
                    },
                },
                {
                    "email": "refresh-next@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "refresh-owner@icloud.com",
                    "remote_metadata": {
                        "hme": "refresh-next@icloud.com",
                        "anonymousId": "refresh-next-remote-secret",
                    },
                },
            ],
        )
        owner = next(item for item in imported if item["role"] == "team_owner")
        children = [
            item for item in imported if item["role"] == "rotating_child"
        ]
        workspace = self.database.create_workspace(
            name="Refresh Team",
            workspace_uid="refresh-team-workspace",
            owner_alias_id=owner["id"],
            current_account_id=children[0]["account_id"],
            next_account_id=children[1]["account_id"],
        )
        run = self.queue.enqueue([workspace["id"]])[0]
        claimed = self.database.claim_next_queue_item()
        self.assertEqual(claimed["run_id"], run["id"])
        self.database.fail_run(run["id"], "registrar registration failed")
        return (
            self.database.get_workspace(workspace["id"]),
            self.database.get_account(children[1]["account_id"]),
            self.database.get_run(run["id"]),
        )

    def write_sub2api_refresh_file(
        self,
        workspace,
        account,
        *,
        access_token="pat-refresh-canary",
        auth_mode="personalAccessToken",
        workspace_uid=None,
    ):
        path = self.root / "refreshed-account.sub2api.json"
        path.write_text(
            json.dumps(
                {
                    "exported_at": "2026-07-20T00:00:00.000Z",
                    "proxies": [],
                    "accounts": [
                        {
                            "platform": "openai",
                            "type": "oauth",
                            "credentials": {
                                "access_token": access_token,
                                "auth_mode": auth_mode,
                                "chatgpt_account_id": (
                                    workspace["workspace_uid"]
                                    if workspace_uid is None
                                    else workspace_uid
                                ),
                                "email": account["email"],
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def legacy_fixture(self):
        config = self.root / "workflow.json"
        mail = self.root / "hotmail.txt"
        mail.write_text(
            "main@example.com----mail-pass----client-main----refresh-main\n",
            encoding="utf-8",
        )
        config.write_text(
            json.dumps(
                {
                    "mail_account_file": str(mail),
                    "workspace_id": "legacy-workspace",
                    "old_account": {"email": "main+1@example.com"},
                    "new_account": {"email": "main+2@example.com"},
                    "output_dir": str(self.root / "output"),
                    "management": {"push": False},
                    "sub2api": {"push": False},
                }
            ),
            encoding="utf-8",
        )
        return config, mail

    def test_console_instance_lock_rejects_second_owner_and_releases(self):
        first = _ConsoleInstanceLock(self.root)
        second = _ConsoleInstanceLock(self.root)
        first.acquire()
        try:
            first.set_owner_url("http://127.0.0.1:9012")
            with self.assertRaises(ConsoleAlreadyRunningError) as caught:
                second.acquire()
            self.assertEqual(caught.exception.url, "http://127.0.0.1:9012")
        finally:
            first.release()

        second.acquire()
        second.release()

    def test_console_instance_lock_is_released_when_owner_process_exits(self):
        script = (
            "import sys, time\n"
            "from team_protocol.web_console import _ConsoleInstanceLock\n"
            "lock = _ConsoleInstanceLock(sys.argv[1])\n"
            "lock.acquire()\n"
            "lock.set_owner_url('http://127.0.0.1:9014')\n"
            "print('locked', flush=True)\n"
            "time.sleep(30)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(self.root)],
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        contender = _ConsoleInstanceLock(self.root)
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            with self.assertRaises(ConsoleAlreadyRunningError) as caught:
                contender.acquire()
            self.assertEqual(caught.exception.url, "http://127.0.0.1:9014")
        finally:
            process.terminate()
            process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

        contender.acquire()
        contender.release()

    def test_second_server_uses_existing_instance_without_starting_controller(self):
        owner = _ConsoleInstanceLock(self.root)
        owner.acquire()
        owner.set_owner_url("http://127.0.0.1:9013")
        try:
            with (
                patch(
                    "team_protocol.web_console.WebConsoleController",
                    side_effect=AssertionError("second instance constructed a controller"),
                ),
                patch("team_protocol.web_console.webbrowser.open") as open_browser,
            ):
                result = serve_web_console(
                    port=9012,
                    open_browser=True,
                    app_dir=self.root,
                )
        finally:
            owner.release()

        self.assertEqual(result, 0)
        open_browser.assert_called_once_with("http://127.0.0.1:9013")

    def test_bootstrap_is_domain_shaped_and_redacts_all_secrets(self):
        self.workspace()
        self.database.set_secret_setting("proxy", "http://user:proxy-secret@proxy.invalid")
        self.database.set_secret_setting("management_api_key", "management-canary")

        payload = self.controller.bootstrap()
        serialized = json.dumps(payload)

        self.assertIn("workspaces", payload)
        self.assertIn("accounts", payload)
        self.assertIn("queue", payload)
        self.assertNotIn("config_path", serialized)
        self.assertNotIn("credential_blob", serialized)
        self.assertNotIn("mail-secret", serialized)
        self.assertNotIn("refresh-secret", serialized)
        self.assertNotIn("proxy-secret", serialized)
        self.assertNotIn("management-canary", serialized)
        self.assertTrue(payload["settings"]["secrets"]["proxy"])

    def test_icloud_api_import_check_generate_and_deactivate_is_secret_safe(self):
        created_remote = []
        deactivated = []
        checked_configs = []

        class FakeHmeClient:
            def list_settings(self):
                return {
                    "selectedForwardTo": "forwarding@example.com",
                    "hmeEmails": [{"hme": "existing@icloud.com"}],
                }

            def create_alias(self, *, label, note):
                index = len(created_remote) + 1
                item = {
                    "hme": f"generated-{index}@icloud.com",
                    "anonymousId": f"remote-anonymous-secret-{index}",
                    "recipientMailId": f"remote-recipient-secret-{index}",
                    "label": label,
                    "note": note,
                }
                created_remote.append(item)
                return item

            def activate_alias(self, anonymous_id):
                del anonymous_id

            def deactivate_alias(self, anonymous_id):
                deactivated.append(anonymous_id)

        clients = []

        def factory(session, **kwargs):
            clients.append((session, kwargs))
            return FakeHmeClient()

        self.controller.hme_client_factory = factory
        self.controller.imap_checker = (
            lambda config, **_kwargs: checked_configs.append(config)
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            imported = client.post(
                "/api/icloud-mailboxes",
                json=self.icloud_payload(),
                headers=self.origin_headers,
            )
            self.assertEqual(imported.status_code, 201, imported.text)
            profile = imported.json()
            self.assertEqual(profile["status"], "unchecked")
            self.assertTrue(profile["proxy_configured"])

            checked = client.post(
                f"/api/icloud-mailboxes/{profile['id']}/check",
                headers=self.origin_headers,
            )
            self.assertEqual(checked.status_code, 200, checked.text)
            self.assertEqual(checked.json()["mailbox"]["status"], "ready")
            self.assertEqual(checked.json()["remote_alias_count"], 1)

            renamed = client.patch(
                f"/api/icloud-mailboxes/{profile['id']}",
                json={
                    "name": "Apple parent renamed",
                    "forwarding_email": "forwarding@example.com",
                },
                headers=self.origin_headers,
            )
            self.assertEqual(renamed.status_code, 200, renamed.text)
            self.assertEqual(renamed.json()["status"], "ready")

            generated = client.post(
                f"/api/icloud-mailboxes/{profile['id']}/aliases",
                json={"count": 2, "label_prefix": "Team child"},
                headers=self.origin_headers,
            )
            self.assertEqual(generated.status_code, 201, generated.text)
            result = generated.json()
            self.assertEqual(result["created"], 2)
            self.assertFalse(result["stopped"])

            aliases = client.get(
                f"/api/icloud-mailboxes/{profile['id']}/aliases",
                headers=self.origin_headers,
            )
            self.assertEqual(aliases.status_code, 200)
            first_alias = aliases.json()[0]
            disabled = client.patch(
                f"/api/icloud-aliases/{first_alias['id']}/state",
                json={"state": "inactive"},
                headers=self.origin_headers,
            )
            self.assertEqual(disabled.status_code, 200, disabled.text)
            self.assertEqual(disabled.json()["state"], "inactive")

            profiles = client.get(
                "/api/icloud-mailboxes", headers=self.origin_headers
            )
            accounts = client.get("/api/accounts", headers=self.origin_headers)

        self.assertEqual(len(checked_configs), 1)
        self.assertEqual(checked_configs[0].password, "imap-password-secret")
        self.assertEqual(
            checked_configs[0].proxy,
            "socks5h://parent:proxy-password-secret@proxy.invalid:1080",
        )
        self.assertEqual(clients[0][1]["proxy"], checked_configs[0].proxy)
        self.assertIn(first_alias["email"], {
            item["email"] for item in accounts.json()
        })
        disabled_account = self.database.get_account(first_alias["account_id"])
        self.assertEqual(disabled_account["status"], "disabled")
        self.assertEqual(deactivated, ["remote-anonymous-secret-2"])
        serialized = json.dumps(
            {
                "imported": imported.json(),
                "checked": checked.json(),
                "generated": generated.json(),
                "aliases": aliases.json(),
                "profiles": profiles.json(),
                "accounts": accounts.json(),
            }
        )
        for secret in (
            "icloud-session-secret",
            "icloud-user-secret",
            "icloud-auth-secret",
            "imap-password-secret",
            "proxy-password-secret",
            "remote-anonymous-secret",
            "remote-recipient-secret",
        ):
            self.assertNotIn(secret, serialized)
            for path in self.root.glob("console.db*"):
                if path.is_file():
                    self.assertNotIn(secret.encode(), path.read_bytes())

    def test_icloud_hme_capture_api_updates_only_the_encrypted_session(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        before = self.database.get_icloud_mailbox_secrets(profile["id"])
        china_url = (
            "https://p217-maildomainws.icloud.com.cn/v2/hme/list?"
            "clientBuildNumber=2536Project32&clientMasteringNumber=2536B20&"
            "clientId=captured-client&dsid=captured-dsid"
        )
        captured_cookie = (
            "X-APPLE-DS-WEB-SESSION-TOKEN=captured-session-secret; "
            "X-APPLE-WEBAUTH-USER=captured-user-secret; "
            "X-APPLE-WEBAUTH-TOKEN=captured-auth-secret"
        )
        captured = parse_hme_request(
            china_url,
            {
                "Cookie": captured_cookie,
                "Origin": "https://www.icloud.com.cn",
                "Referer": "https://www.icloud.com.cn/",
                "User-Agent": "Captured Browser",
            },
        )
        validated = []

        class ValidatingClient:
            @staticmethod
            def list_aliases():
                validated.append(True)
                return [{"hme": "validated@icloud.com"}]

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: ValidatingClient()
        )

        self.controller._save_captured_hme_session(profile["id"], captured)

        self.assertEqual(validated, [True])
        after = self.database.get_icloud_mailbox_secrets(profile["id"])
        self.assertEqual(after["session"]["host"], "p217-maildomainws.icloud.com.cn")
        self.assertEqual(after["session"]["client_id"], "captured-client")
        self.assertEqual(after["imap"], before["imap"])
        self.assertEqual(after["proxy"], before["proxy"])
        self.assertEqual(
            self.database.get_icloud_mailbox(profile["id"])["status"],
            "unchecked",
        )
        for path in self.root.glob("console.db*"):
            if path.is_file():
                self.assertNotIn(b"captured-session-secret", path.read_bytes())

        class FakeCaptureManager:
            def __init__(self):
                self.value = {
                    "mailbox_id": profile["id"],
                    "state": "idle",
                    "active": False,
                    "message": "idle",
                    "started_at": None,
                    "finished_at": None,
                    "error_code": None,
                }

            def start(self, mailbox_id):
                self.value = {
                    **self.value,
                    "mailbox_id": mailbox_id,
                    "state": "waiting_login",
                    "active": True,
                    "message": "waiting",
                }
                return dict(self.value)

            def status(self, mailbox_id):
                return {**self.value, "mailbox_id": mailbox_id}

            def cancel(self, mailbox_id):
                self.value = {
                    **self.value,
                    "mailbox_id": mailbox_id,
                    "state": "cancelled",
                    "active": False,
                    "message": "cancelled",
                }
                return dict(self.value)

        self.controller.hme_capture = FakeCaptureManager()
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            started = client.post(
                f"/api/icloud-mailboxes/{profile['id']}/hme-capture",
                headers=self.origin_headers,
            )
            status = client.get(
                f"/api/icloud-mailboxes/{profile['id']}/hme-capture",
                headers=self.origin_headers,
            )
            cancelled = client.post(
                f"/api/icloud-mailboxes/{profile['id']}/hme-capture/cancel",
                headers=self.origin_headers,
            )

        self.assertEqual(started.status_code, 202, started.text)
        self.assertEqual(started.json()["state"], "waiting_login")
        self.assertEqual(status.status_code, 200, status.text)
        self.assertTrue(status.json()["active"])
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["state"], "cancelled")
        serialized = started.text + status.text + cancelled.text
        self.assertNotIn("captured-session-secret", serialized)

    def test_rejected_captured_hme_session_does_not_replace_existing_secret(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        before = self.database.get_icloud_mailbox_secrets(profile["id"])
        captured = parse_hme_request(
            (
                "https://p217-maildomainws.icloud.com.cn/v2/hme/list?"
                "clientBuildNumber=2536Project32&clientMasteringNumber=2536B20&"
                "clientId=rejected-client&dsid=rejected-dsid"
            ),
            {
                "Cookie": (
                    "X-APPLE-DS-WEB-SESSION-TOKEN=rejected-session-secret; "
                    "X-APPLE-WEBAUTH-USER=rejected-user-secret; "
                    "X-APPLE-WEBAUTH-TOKEN=rejected-auth-secret"
                ),
                "Origin": "https://www.icloud.com.cn",
                "Referer": "https://www.icloud.com.cn/",
                "User-Agent": "Rejected Browser",
            },
        )

        class RejectingClient:
            @staticmethod
            def list_aliases():
                raise HmeSessionError("rejected-secret-must-not-leak")

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: RejectingClient()
        )

        with self.assertRaises(HmeCaptureSessionRejectedError):
            self.controller._save_captured_hme_session(profile["id"], captured)

        self.assertEqual(
            self.database.get_icloud_mailbox_secrets(profile["id"]),
            before,
        )
        self.assertEqual(
            self.database.get_icloud_mailbox(profile["id"])["status"],
            "ready",
        )

    def test_icloud_generation_reports_partial_success_and_session_failure_safely(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        calls = []

        class PartialClient:
            def create_alias(self, **_kwargs):
                calls.append(1)
                if len(calls) == 2:
                    raise HmeError("response-secret-that-must-not-leak")
                return {
                    "hme": "partial@icloud.com",
                    "anonymousId": "partial-remote-secret",
                }

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: PartialClient()
        )
        result = self.controller.generate_icloud_aliases(
            profile["id"], {"count": 3, "label_prefix": "Partial"}
        )

        self.assertEqual(result["created"], 1)
        self.assertTrue(result["stopped"])
        self.assertEqual(result["failure_code"], "hme_request_failed")
        self.assertEqual(
            self.database.get_icloud_mailbox(profile["id"])["status"], "unchecked"
        )
        self.assertNotIn("response-secret", json.dumps(result))

        class ExpiredClient:
            def list_settings(self):
                raise HmeSessionError("expired with cookie-secret-canary")

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: ExpiredClient()
        )
        with self.assertRaises(StateConflictError) as caught:
            self.controller.check_icloud_mailbox(profile["id"])
        self.assertNotIn("cookie-secret-canary", str(caught.exception))
        self.assertEqual(
            self.database.get_icloud_mailbox(profile["id"])["status"],
            "session_invalid",
        )

    def test_icloud_existing_alias_import_and_on_demand_handoff_are_owner_scoped(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        remote_aliases = [
            {
                "hme": "owner-one@icloud.com",
                "anonymousId": "remote-owner-one-secret",
                "isActive": True,
                "label": "Owner one",
            },
            {
                "hme": "owner-two@icloud.com",
                "anonymousId": "remote-owner-two-secret",
                "isActive": True,
                "label": "Owner two",
            },
            {
                "hme": "current-one@icloud.com",
                "anonymousId": "remote-current-one-secret",
                "isActive": True,
                "label": "组 1-7",
            },
            {
                "hme": "current-two@icloud.com",
                "anonymousId": "remote-current-two-secret",
                "isActive": True,
                "label": "组 2-7",
            },
            {
                "hme": "obsolete@icloud.com",
                "anonymousId": "remote-obsolete-secret",
                "isActive": True,
                "label": "Obsolete",
            },
        ]
        generated = []

        class OwnerScopedClient:
            def list_aliases(self):
                return list(remote_aliases)

            def create_alias(self, *, label, note):
                item = {
                    "hme": "fresh-handoff@icloud.com",
                    "anonymousId": "remote-fresh-handoff-secret",
                    "isActive": True,
                    "label": label,
                    "note": note,
                }
                generated.append(item)
                return item

            def deactivate_alias(self, anonymous_id):
                raise AssertionError(f"unexpected compensation for {anonymous_id}")

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: OwnerScopedClient()
        )
        app = create_app(self.controller, testing=True)
        owner_one_proxy = (
            "socks5h://owner-one:owner-one-secret@proxy-one.invalid:1080"
        )
        owner_two_proxy = (
            "socks5h://owner-two:owner-two-secret@proxy-two.invalid:1080"
        )
        with TestClient(app) as client:
            preview = client.get(
                f"/api/icloud-mailboxes/{profile['id']}/remote-aliases",
                headers=self.origin_headers,
            )
            self.assertEqual(preview.status_code, 200, preview.text)
            self.assertEqual(len(preview.json()), 5)
            self.assertNotIn("anonymousId", preview.text)

            imported_response = client.post(
                f"/api/icloud-mailboxes/{profile['id']}/aliases/import",
                json={
                    "items": [
                        {
                            "email": "owner-one@icloud.com",
                            "role": "team_owner",
                            "owner_proxy": owner_one_proxy,
                        },
                        {
                            "email": "owner-two@icloud.com",
                            "role": "team_owner",
                            "owner_proxy": owner_two_proxy,
                        },
                        {
                            "email": "current-one@icloud.com",
                            "role": "rotating_child",
                            "parent_owner_email": "owner-one@icloud.com",
                        },
                        {
                            "email": "current-two@icloud.com",
                            "role": "rotating_child",
                            "parent_owner_email": "owner-two@icloud.com",
                        },
                    ]
                },
                headers=self.origin_headers,
            )
            self.assertEqual(imported_response.status_code, 201, imported_response.text)
            imported = imported_response.json()
            self.assertEqual(len(imported), 4)
            self.assertNotIn("obsolete@icloud.com", imported_response.text)
            owner_one = next(
                item for item in imported if item["email"] == "owner-one@icloud.com"
            )
            owner_two = next(
                item for item in imported if item["email"] == "owner-two@icloud.com"
            )
            current_one = next(
                item for item in imported if item["email"] == "current-one@icloud.com"
            )
            current_two = next(
                item for item in imported if item["email"] == "current-two@icloud.com"
            )

            created_workspace = client.post(
                "/api/workspaces",
                json={
                    "name": "组 1",
                    "workspace_uid": "owner-one-team-uid",
                    "owner_alias_id": owner_one["id"],
                    "current_account_id": current_one["account_id"],
                },
                headers=self.origin_headers,
            )
            self.assertEqual(created_workspace.status_code, 201, created_workspace.text)
            workspace = created_workspace.json()
            self.assertEqual(workspace["status"], "needs_account")

            handoff = client.post(
                f"/api/workspaces/{workspace['id']}/replace-icloud-child",
                json={"version": workspace["version"]},
                headers=self.origin_headers,
            )
            self.assertEqual(handoff.status_code, 202, handoff.text)
            handoff_payload = handoff.json()
            self.assertTrue(handoff_payload["created"])
            self.assertEqual(handoff_payload["run"]["state"], "queued")

            second_workspace_response = client.post(
                "/api/workspaces",
                json={
                    "name": "组 2",
                    "workspace_uid": "owner-two-team-uid",
                    "owner_alias_id": owner_two["id"],
                    "current_account_id": current_two["account_id"],
                },
                headers=self.origin_headers,
            )
            self.assertEqual(
                second_workspace_response.status_code,
                201,
                second_workspace_response.text,
            )
            second_workspace = second_workspace_response.json()
            compensated = []

            class MalformedCreateClient:
                def create_alias(self, *, label, note):
                    del label, note
                    return {"anonymousId": "malformed-remote-secret"}

                def deactivate_alias(self, anonymous_id):
                    compensated.append(anonymous_id)

            self.controller.hme_client_factory = (
                lambda _session, **_kwargs: MalformedCreateClient()
            )
            malformed = client.post(
                f"/api/workspaces/{second_workspace['id']}/replace-icloud-child",
                json={"version": second_workspace["version"]},
                headers=self.origin_headers,
            )
            self.assertEqual(malformed.status_code, 409, malformed.text)
            self.assertNotIn("malformed-remote-secret", malformed.text)

        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0]["label"], "组 1-8")
        self.assertEqual(compensated, ["malformed-remote-secret"])
        self.assertEqual(len(self.database.list_icloud_aliases(profile["id"])), 5)
        fresh = self.database.get_icloud_alias(handoff_payload["alias"]["id"])
        self.assertEqual(fresh["parent_owner_alias_id"], owner_one["id"])
        owner_one_effective = self.database.get_icloud_owner_proxy(owner_one["id"])
        owner_two_effective = self.database.get_icloud_owner_proxy(owner_two["id"])
        self.assertEqual(
            self.database.get_account_proxy(fresh["account_id"]), owner_one_effective
        )
        self.assertEqual(
            self.database.get_account_proxy(current_two["account_id"]),
            owner_two_effective,
        )
        self.assertNotEqual(owner_one_effective, owner_two_effective)
        serialized = json.dumps(
            {"preview": preview.json(), "imported": imported, "handoff": handoff_payload}
        )
        for secret in (
            "remote-owner-one-secret",
            "remote-owner-two-secret",
            "remote-current-one-secret",
            "remote-current-two-secret",
            "remote-obsolete-secret",
            "remote-fresh-handoff-secret",
            "owner-one-secret",
            "owner-two-secret",
        ):
            self.assertNotIn(secret, serialized)

    def test_icloud_owner_rescue_creates_one_child_and_retries_same_checkpoint(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        owner_proxy = "socks5h://rescue:rescue-secret@proxy.invalid:1080"
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "rescue-owner@icloud.com",
                    "role": "team_owner",
                    "owner_proxy": owner_proxy,
                    "remote_metadata": {
                        "hme": "rescue-owner@icloud.com",
                        "anonymousId": "rescue-owner-remote-secret",
                    },
                },
                {
                    "email": "broken-child@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "rescue-owner@icloud.com",
                    "remote_metadata": {
                        "hme": "broken-child@icloud.com",
                        "anonymousId": "broken-child-remote-secret",
                    },
                },
            ],
        )
        owner = next(item for item in imported if item["role"] == "team_owner")
        child = next(item for item in imported if item["role"] == "rotating_child")
        workspace = self.database.create_workspace(
            name="Rescue Team",
            workspace_uid="rescue-team-uid",
            owner_alias_id=owner["id"],
            current_account_id=child["account_id"],
        )
        generated = []

        class RescueHmeClient:
            def create_alias(self, *, label, note):
                item = {
                    "hme": "fresh-rescue@icloud.com",
                    "anonymousId": "fresh-rescue-remote-secret",
                    "isActive": True,
                    "label": label,
                    "note": note,
                }
                generated.append(item)
                return item

            def deactivate_alias(self, anonymous_id):
                raise AssertionError(f"unexpected compensation for {anonymous_id}")

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: RescueHmeClient()
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            first = client.post(
                f"/api/workspaces/{workspace['id']}/rescue-icloud-child",
                json={"version": workspace["version"]},
                headers=self.origin_headers,
            )
            self.assertEqual(first.status_code, 202, first.text)
            first_payload = first.json()
            self.assertEqual(first_payload["mode"], "rescue")
            self.assertTrue(first_payload["created"])
            self.assertEqual(first_payload["run"]["kind"], "rescue")

            claimed = self.database.claim_next_queue_item()
            self.assertEqual(claimed["run_id"], first_payload["run"]["id"])
            self.database.fail_run(first_payload["run"]["id"], "simulated failure")
            failed_workspace = self.database.get_workspace(workspace["id"])
            retried = client.post(
                f"/api/workspaces/{workspace['id']}/rescue-icloud-child",
                json={"version": failed_workspace["version"]},
                headers=self.origin_headers,
            )
            protected_owner = client.patch(
                f"/api/icloud-aliases/{owner['id']}/state",
                json={"state": "inactive"},
                headers=self.origin_headers,
            )

        self.assertEqual(retried.status_code, 202, retried.text)
        retried_payload = retried.json()
        self.assertTrue(retried_payload["resumed"])
        self.assertEqual(protected_owner.status_code, 409, protected_owner.text)
        self.assertEqual(
            self.database.get_icloud_alias(owner["id"])["state"],
            "active",
        )
        self.assertFalse(retried_payload["created"])
        self.assertEqual(
            retried_payload["run"]["id"],
            first_payload["run"]["id"],
        )
        self.assertEqual(len(generated), 1)
        self.assertEqual(
            len(self.database.list_icloud_aliases(profile["id"])),
            3,
        )
        for secret in (
            "rescue-secret",
            "rescue-owner-remote-secret",
            "broken-child-remote-secret",
            "fresh-rescue-remote-secret",
        ):
            self.assertNotIn(secret, first.text + retried.text)

    def test_icloud_team_import_is_selective_idempotent_and_secret_safe(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        remote_aliases = [
            {
                "hme": "team-owner@icloud.com",
                "anonymousId": "team-owner-remote-secret",
                "isActive": True,
                "label": "Team owner",
            },
            {
                "hme": "current-child@icloud.com",
                "anonymousId": "current-child-remote-secret",
                "isActive": True,
                "label": "组 1-7",
            },
            {
                "hme": "obsolete@icloud.com",
                "anonymousId": "obsolete-remote-secret",
                "isActive": True,
                "label": "Unused",
            },
        ]
        list_calls = []

        class TeamImportClient:
            def list_aliases(self):
                list_calls.append(1)
                return list(remote_aliases)

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: TeamImportClient()
        )
        owner_proxy = (
            "socks5h://team-owner:team-proxy-secret@proxy.invalid:1080"
        )
        request = {
            "mailbox_id": profile["id"],
            "name": "组 1",
            "workspace_uid": "team-workspace-uid",
            "owner_email": "team-owner@icloud.com",
            "current_child_email": "current-child@icloud.com",
            "owner_proxy_mode": "direct",
            "owner_proxy": owner_proxy,
        }
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            preview_before = client.get(
                f"/api/icloud-mailboxes/{profile['id']}/remote-aliases",
                headers=self.origin_headers,
            )
            created = client.post(
                "/api/icloud-teams/import",
                json=request,
                headers=self.origin_headers,
            )
            preview_after = client.get(
                f"/api/icloud-mailboxes/{profile['id']}/remote-aliases",
                headers=self.origin_headers,
            )

            class UnexpectedRemoteClient:
                @staticmethod
                def list_aliases():
                    raise AssertionError("idempotent Team import reread iCloud")

            self.controller.hme_client_factory = (
                lambda _session, **_kwargs: UnexpectedRemoteClient()
            )
            repeated = client.post(
                "/api/icloud-teams/import",
                json=request,
                headers=self.origin_headers,
            )
            conflict = client.post(
                "/api/icloud-teams/import",
                json={**request, "current_child_email": "obsolete@icloud.com"},
                headers=self.origin_headers,
            )

        self.assertEqual(preview_before.status_code, 200, preview_before.text)
        self.assertEqual(len(preview_before.json()), 3)
        self.assertEqual(created.status_code, 201, created.text)
        self.assertTrue(created.json()["created"])
        self.assertEqual(created.json()["workspace"]["status"], "needs_account")
        self.assertEqual(repeated.status_code, 201, repeated.text)
        self.assertFalse(repeated.json()["created"])
        self.assertEqual(
            repeated.json()["workspace"]["id"],
            created.json()["workspace"]["id"],
        )
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(len(self.database.list_workspaces()), 1)
        aliases = self.database.list_icloud_aliases(profile["id"])
        self.assertEqual(len(aliases), 2)
        self.assertNotIn("obsolete@icloud.com", {item["email"] for item in aliases})
        owner = next(item for item in aliases if item["role"] == "team_owner")
        current = next(item for item in aliases if item["role"] == "rotating_child")
        self.assertEqual(current["parent_owner_alias_id"], owner["id"])
        self.assertEqual(self.database.get_icloud_owner_proxy(owner["id"]), owner_proxy)
        after_by_email = {item["email"]: item for item in preview_after.json()}
        self.assertTrue(after_by_email["team-owner@icloud.com"]["imported"])
        self.assertTrue(
            after_by_email["team-owner@icloud.com"]["proxy_configured"]
        )
        self.assertEqual(
            after_by_email["current-child@icloud.com"]["workspace_name"],
            "组 1",
        )
        self.assertEqual(len(list_calls), 3)
        serialized = created.text + repeated.text + preview_after.text
        for secret in (
            "team-owner-remote-secret",
            "current-child-remote-secret",
            "obsolete-remote-secret",
            "team-proxy-secret",
        ):
            self.assertNotIn(secret, serialized)

    def test_icloud_team_workspace_lookup_uses_child_network_and_is_secret_safe(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        lookup_calls = []

        class FakeWorkspaceLookup:
            @staticmethod
            def lookup(**kwargs):
                lookup_calls.append(kwargs)
                return {
                    "workspace_uid": "looked-up-team",
                    "member_count": 2,
                    "verified": True,
                    "session_token": "must-not-leak-session",
                    "access_token": "must-not-leak-access",
                    "members": ["must-not-leak-member"],
                }

        self.controller.workspace_lookup_service = FakeWorkspaceLookup()
        request = {
            "mailbox_id": profile["id"],
            "owner_email": "lookup-owner@icloud.com",
            "current_child_email": "lookup-child@icloud.com",
            "owner_proxy_mode": "clash_chain",
            "owner_proxy_source_url": (
                "socks5://lookup-user:lookup-proxy-secret@proxy.invalid:1080"
            ),
            "owner_proxy_bootstrap": "http://127.0.0.1:7897",
        }
        app = create_app(self.controller, testing=True)

        with TestClient(app) as client:
            response = client.post(
                "/api/icloud-teams/workspace/lookup",
                json=request,
                headers=self.origin_headers,
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.json(),
            {
                "workspace_uid": "looked-up-team",
                "member_count": 2,
                "verified": True,
            },
        )
        self.assertEqual(len(lookup_calls), 1)
        self.assertEqual(lookup_calls[0]["owner_email"], "lookup-owner@icloud.com")
        self.assertEqual(lookup_calls[0]["child_email"], "lookup-child@icloud.com")
        self.assertEqual(lookup_calls[0]["proxy_mode"], "clash_chain")
        self.assertIn("imap", lookup_calls[0]["mailbox_secret"])
        for secret in (
            "lookup-proxy-secret",
            "imap-password-secret",
            "must-not-leak-session",
            "must-not-leak-access",
            "must-not-leak-member",
        ):
            self.assertNotIn(secret, response.text)

    def test_icloud_team_workspace_lookup_reuses_existing_binding_without_login(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "bound-owner@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "bound-owner@icloud.com",
                        "anonymousId": "bound-owner-remote",
                    },
                    "owner_proxy": "socks5://bound.invalid:1080",
                },
                {
                    "email": "bound-child@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "bound-owner@icloud.com",
                    "remote_metadata": {
                        "hme": "bound-child@icloud.com",
                        "anonymousId": "bound-child-remote",
                    },
                },
            ],
        )
        owner = next(item for item in imported if item["role"] == "team_owner")
        child = next(item for item in imported if item["role"] == "rotating_child")
        self.database.create_workspace(
            name="Bound Team",
            workspace_uid="bound-workspace-uid",
            current_account_id=child["account_id"],
            owner_alias_id=owner["id"],
        )

        class UnexpectedWorkspaceLookup:
            @staticmethod
            def lookup(**_kwargs):
                raise AssertionError("existing Team lookup performed a live login")

        self.controller.workspace_lookup_service = UnexpectedWorkspaceLookup()
        result = self.controller.lookup_icloud_team_workspace(
            {
                "mailbox_id": profile["id"],
                "owner_email": "bound-owner@icloud.com",
                "current_child_email": "bound-child@icloud.com",
            }
        )

        self.assertEqual(
            result,
            {
                "workspace_uid": "bound-workspace-uid",
                "member_count": 2,
                "verified": True,
                "source": "existing",
            },
        )

    def test_icloud_team_import_reuses_existing_unbound_owner_and_child(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        owner_proxy = "socks5h://existing:proxy-secret@proxy.invalid:1080"
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "existing-owner@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "existing-owner@icloud.com",
                        "anonymousId": "existing-owner-remote-secret",
                    },
                    "owner_proxy": owner_proxy,
                },
                {
                    "email": "existing-child@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "existing-owner@icloud.com",
                    "remote_metadata": {
                        "hme": "existing-child@icloud.com",
                        "anonymousId": "existing-child-remote-secret",
                    },
                },
            ],
        )

        class ExistingAliasClient:
            @staticmethod
            def list_aliases():
                return [
                    {
                        "hme": "existing-owner@icloud.com",
                        "anonymousId": "existing-owner-remote-secret",
                        "isActive": True,
                    },
                    {
                        "hme": "existing-child@icloud.com",
                        "anonymousId": "existing-child-remote-secret",
                        "isActive": True,
                    },
                ]

        self.controller.hme_client_factory = (
            lambda _session, **_kwargs: ExistingAliasClient()
        )
        result = self.controller.import_icloud_team(
            {
                "mailbox_id": profile["id"],
                "name": "组 1",
                "workspace_uid": "existing-team-uid",
                "owner_email": "existing-owner@icloud.com",
                "current_child_email": "existing-child@icloud.com",
            }
        )

        self.assertTrue(result["created"])
        self.assertEqual(result["workspace"]["name"], "组 1")
        self.assertEqual(len(self.database.list_icloud_aliases(profile["id"])), 2)
        self.assertEqual({item["id"] for item in imported}, {
            result["owner"]["id"],
            result["current_child"]["id"],
        })
        self.assertEqual(
            self.database.get_icloud_owner_proxy(result["owner"]["id"]),
            owner_proxy,
        )

    def test_remote_icloud_preview_exposes_session_refresh_code(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "session_invalid")
        app = create_app(self.controller, testing=True)

        with TestClient(app) as client:
            response = client.get(
                f"/api/icloud-mailboxes/{profile['id']}/remote-aliases",
                headers=self.origin_headers,
            )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(response.json()["detail"]["code"], "icloud_session_invalid")

    def test_cliproxy_http_api_applies_clash_chain_without_echoing_source(self):
        profile = self.controller.create_icloud_mailbox(self.icloud_payload())
        self.database.set_icloud_mailbox_status(profile["id"], "ready")
        owner = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "generated-api-owner@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "generated-api-owner@icloud.com",
                        "anonymousId": "generated-api-remote-secret",
                    },
                }
            ],
        )[0]

        class FakeProxyChains:
            def __init__(self):
                self.applied = 0
                self.refreshed = []

            def prepare(self, owner_id, source_url, bootstrap):
                return OwnerChainConfig(
                    owner_id=owner_id,
                    source_url=source_url,
                    bootstrap_proxy=bootstrap,
                    listener_port=18881,
                    effective_proxy="socks5h://127.0.0.1:18881",
                )

            def apply(self, cleanup=False):
                del cleanup
                self.applied += 1
                return {"applied": True}

            def refresh(self, owner_id, force=False):
                self.refreshed.append((owner_id, force))
                return LokiProxyEndpoint("203.0.113.44", 1080)

            def status(self, owner_id):
                return {
                    "configured": True,
                    "healthy": bool(self.refreshed),
                    "relay_running": True,
                    "error": None,
                    "listener": "127.0.0.1:18881",
                    "bootstrap_proxy": "http://127.0.0.1:7897",
                    "shared_bootstrap": True,
                }

            def available_nodes(self):
                return ["http://127.0.0.1:7897"]

        chains = FakeProxyChains()
        self.controller.proxy_chains = chains
        self.controller.enable_proxy_chains = True
        source_url = (
            "http://cliproxy-user:cliproxy-secret@proxy.example:3010"
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            configured = client.put(
                f"/api/icloud-team-owners/{owner['id']}/proxy",
                headers=self.origin_headers,
                json={
                    "mode": "clash_chain",
                    "source_url": source_url,
                    "bootstrap": "http://127.0.0.1:7897",
                },
            )
            status_response = client.get(
                f"/api/icloud-team-owners/{owner['id']}/proxy/status",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            nodes = client.get(
                "/api/proxy-chains/nodes",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            legacy_provider = client.get(
                f"/internal/proxy-chain/{owner['id']}/provider"
            )

        serialized = configured.text + status_response.text + nodes.text
        self.assertEqual(configured.status_code, 200, configured.text)
        self.assertEqual(configured.json()["proxy_mode"], "clash_chain")
        self.assertEqual(status_response.status_code, 200)
        self.assertTrue(status_response.json()["chain"]["healthy"])
        self.assertEqual(nodes.json()["nodes"], ["http://127.0.0.1:7897"])
        self.assertEqual(legacy_provider.status_code, 404)
        self.assertEqual(chains.applied, 2)  # startup plus saved chain
        self.assertEqual(chains.refreshed, [(owner["id"], True)])
        self.assertEqual(
            self.database.get_icloud_owner_proxy(owner["id"]),
            "socks5h://127.0.0.1:18881",
        )
        self.assertEqual(
            self.database.get_icloud_owner_proxy_config(owner["id"])["source_url"],
            source_url,
        )
        self.assertNotIn("cliproxy-secret", serialized)
        self.assertNotIn("proxy.example", serialized)

    def test_proxy_chain_nodes_retries_a_failed_startup_application(self):
        class FailingOnceProxyChains:
            provider_token = "local-provider-token"

            def __init__(self):
                self.applied = 0

            def apply(self, cleanup=False):
                del cleanup
                self.applied += 1
                if self.applied == 1:
                    raise ProxyConfigurationError("temporary startup failure")
                return {"applied": True}

            def available_nodes(self):
                return ["http://127.0.0.1:7897"]

        chains = FailingOnceProxyChains()
        self.controller.proxy_chains = chains
        self.controller.enable_proxy_chains = True
        self.controller.startup()
        self.assertEqual(
            self.controller.health()["proxy_chains"]["error"],
            "proxy_chain_configuration",
        )
        self.assertEqual(
            self.controller.list_proxy_chain_nodes()["nodes"],
            ["http://127.0.0.1:7897"],
        )
        self.assertEqual(chains.applied, 2)
        self.assertIsNone(self.controller.health()["proxy_chains"]["error"])

    def test_large_inventory_is_absent_from_bootstrap_and_sse_reset(self):
        before = len(json.dumps(self.controller.bootstrap(), sort_keys=True))
        records = [
            self.inventory_record(f"inventory-{index}@example.com", index)
            for index in range(250)
        ]
        self.database.import_mailbox_inventory(records)

        bootstrap = self.controller.bootstrap()
        reset = self.controller.event_reset()
        after = len(json.dumps(bootstrap, sort_keys=True))
        serialized = json.dumps({"bootstrap": bootstrap, "reset": reset})

        self.assertLess(after - before, 256)
        self.assertNotIn("mailbox_inventory", serialized)
        self.assertNotIn("inventory-249@example.com", serialized)
        self.assertNotIn("inventory-refresh-secret", serialized)
        self.assertNotIn("inventory-mail-secret", serialized)
        self.assertNotIn("client-249", serialized)

    def test_startup_repairs_overbroad_legacy_account_inventory(self):
        primary_email = "main@example.com"
        current = self.account("current", primary=primary_email)
        next_account = self.account("next", primary=primary_email)
        self.database.create_workspace(
            name="Legacy Space",
            workspace_uid="legacy-space",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        related_primary = self.database.create_account(
            email=primary_email,
            primary_email=primary_email,
            credentials={"client_id": "main-client", "refresh_token": "main-refresh"},
            source="legacy_txt",
        )
        orphan = self.database.create_account(
            email="orphan@example.com",
            primary_email="orphan@example.com",
            credentials={"client_id": "orphan-client", "refresh_token": "orphan-refresh"},
            source="legacy_txt",
        )
        manual = self.database.create_account(
            email="manual@example.com",
            primary_email="manual@example.com",
            credentials={"client_id": "manual-client", "refresh_token": "manual-refresh"},
            source="txt_import",
        )
        self.database.set_meta("migration_status", "complete")

        health = self.controller.startup()

        remaining = {account["id"] for account in self.database.list_accounts()}
        self.assertTrue(health["ready"])
        self.assertNotIn(orphan["id"], remaining)
        self.assertIn(related_primary["id"], remaining)
        self.assertIn(manual["id"], remaining)
        self.assertEqual(self.database.get_meta("legacy_account_scope_version"), "1")

    def test_security_middleware_requires_token_and_same_origin(self):
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            denied = client.post("/api/queue/pause", json={"paused": True})
            wrong_origin = client.post(
                "/api/queue/pause",
                json={"paused": True},
                headers={
                    "Origin": "https://evil.example",
                    "X-Workflow-Token": self.controller.request_token,
                },
            )
            allowed = client.post(
                "/api/queue/pause",
                json={"paused": True},
                headers=self.origin_headers,
            )
            bootstrap = client.get("/api/bootstrap")

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["detail"]["code"], "invalid_request_token")
        self.assertEqual(wrong_origin.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.json()["paused"])
        self.assertEqual(bootstrap.status_code, 200)
        self.assertEqual(self.queue.started, 1)
        self.assertEqual(self.queue.shutdown_calls, 1)

    def test_workspace_crud_binding_and_stale_version_errors(self):
        current = self.account("create-current")
        next_account = self.account("create-next")
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            created = client.post(
                "/api/workspaces",
                headers=self.origin_headers,
                json={
                    "name": "Created Space",
                    "workspace_uid": "uid-created",
                    "current_account_id": current["id"],
                    "next_account_id": next_account["id"],
                },
            )
            workspace = created.json()
            renamed = client.patch(
                f"/api/workspaces/{workspace['id']}",
                headers=self.origin_headers,
                json={"version": workspace["version"], "name": "Renamed Space"},
            )
            stale = client.patch(
                f"/api/workspaces/{workspace['id']}",
                headers=self.origin_headers,
                json={"version": workspace["version"], "name": "Stale"},
            )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.json()["name"], "Renamed Space")
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["code"], "stale_workspace_version")

    def test_account_import_populates_inventory_and_allocation_never_returns_credentials(self):
        txt = self.root / "hotmail.txt"
        txt.write_text(
            "primary@example.com----mail-password----client-id----refresh-token\n"
            "invalid-row-with-secret\n",
            encoding="utf-8",
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            imported = client.post(
                "/api/accounts/import",
                headers=self.origin_headers,
                json={"path": str(txt)},
            )
            inventory = client.get(
                "/api/mailbox-inventory?query=PRIMARY&limit=20",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            inventory_item = inventory.json()[0]
            alias = client.post(
                "/api/accounts/alias",
                headers=self.origin_headers,
                json={"inventory_id": inventory_item["id"]},
            )
            disabled = client.patch(
                f"/api/accounts/{alias.json()['id']}/status",
                headers=self.origin_headers,
                json={"status": "disabled"},
            )

            too_large = client.get(
                "/api/mailbox-inventory?query=primary&limit=21",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            bootstrap = client.get("/api/bootstrap")

        body = imported.text + inventory.text + alias.text + disabled.text + bootstrap.text
        self.assertEqual(imported.status_code, 201)
        self.assertEqual(imported.json()["imported"], 1)
        self.assertEqual(imported.json()["invalid"], 1)
        self.assertEqual(inventory.status_code, 200)
        self.assertEqual(len(inventory.json()), 1)
        self.assertEqual(alias.status_code, 201)
        self.assertEqual(alias.json()["email"], "primary+1@example.com")
        self.assertEqual(alias.json()["primary_email"], "primary@example.com")
        self.assertEqual(disabled.json()["status"], "disabled")
        self.assertEqual(too_large.status_code, 422)
        self.assertNotIn("mailbox_inventory", bootstrap.json())
        self.assertNotIn("inventory", bootstrap.json())
        self.assertNotIn("mail-password", body)
        self.assertNotIn("refresh-token", body)
        self.assertNotIn("client-id", body)

    def test_account_proxy_api_configures_clears_and_never_echoes_the_url(self):
        account = self.account("proxy-api")
        proxy = "s5://mother-user:proxy-api-secret@proxy.example:1080"
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            configured = client.put(
                f"/api/accounts/{account['id']}/proxy",
                headers=self.origin_headers,
                json={"proxy": proxy},
            )
            listed = client.get(
                "/api/accounts",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            invalid = client.put(
                f"/api/accounts/{account['id']}/proxy",
                headers=self.origin_headers,
                json={"proxy": "ftp://proxy.example:21"},
            )
            bootstrap = client.get("/api/bootstrap")
            stored_proxy = self.database.get_account_proxy(account["id"])
            cleared = client.put(
                f"/api/accounts/{account['id']}/proxy",
                headers=self.origin_headers,
                json={"proxy": ""},
            )

        serialized = configured.text + listed.text + invalid.text + bootstrap.text + cleared.text
        self.assertEqual(configured.status_code, 200)
        self.assertTrue(configured.json()["proxy_configured"])
        self.assertTrue(
            next(item for item in listed.json() if item["id"] == account["id"])[
                "proxy_configured"
            ]
        )
        self.assertEqual(
            stored_proxy,
            "socks5://mother-user:proxy-api-secret@proxy.example:1080",
        )
        self.assertEqual(invalid.status_code, 422)
        self.assertFalse(cleared.json()["proxy_configured"])
        self.assertNotIn("proxy-api-secret", serialized)
        self.assertNotIn("mother-user", serialized)

    def test_workspace_inventory_selection_and_replace_api_are_transactional(self):
        imported = self.database.import_mailbox_inventory(
            [
                self.inventory_record("rotate@example.com", 0),
                self.inventory_record("fallback@example.com", 1),
            ]
        )
        self.assertEqual(imported["imported"], 2)
        rotate = self.database.search_mailbox_inventory(query="rotate", limit=20)[0]
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            created = client.post(
                "/api/workspaces",
                headers=self.origin_headers,
                json={
                    "name": "Inventory Space",
                    "workspace_uid": "inventory-space",
                    "current_inventory_id": rotate["id"],
                    "next_inventory_id": rotate["id"],
                },
            )
            workspace = created.json()
            before_accounts = len(self.database.list_accounts())
            invalid_selection = client.post(
                "/api/workspaces",
                headers=self.origin_headers,
                json={
                    "name": "Invalid Space",
                    "workspace_uid": "invalid-space",
                    "current_account_id": workspace["current_account_id"],
                    "current_inventory_id": rotate["id"],
                },
            )
            replaced = client.post(
                f"/api/workspaces/{workspace['id']}/replace-account",
                headers=self.origin_headers,
                json={
                    "version": workspace["version"],
                    "role": "next",
                    "failure_code": "alias_disabled",
                },
            )
            invalid_role = client.post(
                f"/api/workspaces/{workspace['id']}/replace-account",
                headers=self.origin_headers,
                json={
                    "version": workspace["version"],
                    "role": "other",
                    "failure_code": "alias_disabled",
                },
            )
            queued = client.post(
                f"/api/workspaces/{workspace['id']}/enqueue",
                headers=self.origin_headers,
                json={},
            )
            active_replace = client.post(
                f"/api/workspaces/{workspace['id']}/replace-account",
                headers=self.origin_headers,
                json={
                    "version": replaced.json()["workspace"]["version"],
                    "role": "next",
                    "failure_code": "alias_disabled",
                },
            )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(invalid_selection.status_code, 422)
        self.assertEqual(len(self.database.list_accounts()), before_accounts + 1)
        self.assertEqual(replaced.status_code, 200)
        replaced_workspace = replaced.json()["workspace"]
        replacement = replaced.json()["replacement"]
        self.assertEqual(
            replaced_workspace["current_account_id"], workspace["current_account_id"]
        )
        self.assertEqual(replaced_workspace["next_account_id"], replacement["id"])
        self.assertEqual(replacement["email"], "rotate+3@example.com")
        self.assertEqual(invalid_role.status_code, 422)
        self.assertEqual(queued.status_code, 202)
        self.assertEqual(active_replace.status_code, 409)
        self.assertEqual(
            active_replace.json()["detail"]["code"], "workspace_active"
        )

    def test_workspace_advance_api_records_an_external_rotation(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("manual-first@example.com", 0),
                self.inventory_record("manual-second@example.com", 1),
            ]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(5)]
        workspace = self.database.create_workspace(
            name="Manual rotation",
            workspace_uid="manual-rotation-api",
            current_account_id=aliases[3]["id"],
            next_account_id=aliases[4]["id"],
        )
        app = create_app(self.controller, testing=True)

        with TestClient(app) as client:
            advanced = client.post(
                f"/api/workspaces/{workspace['id']}/advance",
                headers=self.origin_headers,
                json={"version": workspace["version"]},
            )
            stale = client.post(
                f"/api/workspaces/{workspace['id']}/advance",
                headers=self.origin_headers,
                json={"version": workspace["version"]},
            )
            queued = client.post(
                f"/api/workspaces/{workspace['id']}/enqueue",
                headers=self.origin_headers,
                json={},
            )
            active = client.post(
                f"/api/workspaces/{workspace['id']}/advance",
                headers=self.origin_headers,
                json={"version": advanced.json()["workspace"]["version"]},
            )

        self.assertEqual(advanced.status_code, 200)
        payload = advanced.json()
        self.assertEqual(payload["current"]["email"], "manual-first+5@example.com")
        self.assertEqual(payload["replacement"]["email"], "manual-second+1@example.com")
        self.assertEqual(payload["workspace"]["rotation_count"], 1)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["code"], "stale_workspace_version")
        self.assertEqual(queued.status_code, 202)
        self.assertEqual(active.status_code, 409)
        self.assertEqual(active.json()["detail"]["code"], "workspace_active")

    def test_queue_run_routes_and_sse_start_with_authoritative_reset(self):
        workspace, _, _ = self.workspace("queue")
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            enqueued = client.post(
                "/api/queue",
                headers=self.origin_headers,
                json={"workspace_ids": [workspace["id"]]},
            )
            run = enqueued.json()[0]
            queue = client.get("/api/queue", headers={"X-Workflow-Token": self.controller.request_token})
            detail = client.get(
                f"/api/runs/{run['id']}",
                headers={"X-Workflow-Token": self.controller.request_token},
            )

        class DisconnectedRequest:
            async def is_disconnected(self):
                return True

        async def first_frame():
            stream = _event_stream(self.controller, DisconnectedRequest())
            try:
                return await anext(stream)
            finally:
                await stream.aclose()

        frame = asyncio.run(first_frame())

        self.assertEqual(enqueued.status_code, 202)
        self.assertEqual(queue.json()["items"][0]["run_id"], run["id"])
        self.assertEqual(detail.json()["events"][0]["message"], "run queued")
        self.assertIn("event: reset", frame)
        self.assertIn('"workspaces"', frame)

    def test_sse_stops_when_server_shutdown_is_requested(self):
        class ConnectedRequest:
            async def is_disconnected(self):
                return False

        self.controller.set_shutdown_probe(lambda: True)

        async def frames():
            stream = _event_stream(self.controller, ConnectedRequest())
            try:
                first = await anext(stream)
                with self.assertRaises(StopAsyncIteration):
                    await anext(stream)
                return first
            finally:
                await stream.aclose()

        self.assertIn("event: reset", asyncio.run(frames()))

    def test_settings_empty_secret_preserves_and_explicit_clear_removes(self):
        self.database.set_secret_setting("sub2api_password", "secret-canary")
        self.database.set_secret_setting("sub2api_api_key", "api-key-canary")
        self.database.set_secret_setting("sub2api_totp_secret", "totp-canary")
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            preserved = client.put(
                "/api/settings",
                headers=self.origin_headers,
                json={
                    "values": {
                        "output_dir": str(self.root / "output"),
                        "sub2api_push": True,
                        "sub2api_group_id": 3,
                    },
                    "secrets": {
                        "sub2api_password": "",
                        "sub2api_api_key": "",
                        "sub2api_totp_secret": "",
                    },
                },
            )
            cleared = client.put(
                "/api/settings",
                headers=self.origin_headers,
                json={
                    "clear_secrets": [
                        "sub2api_password",
                        "sub2api_api_key",
                        "sub2api_totp_secret",
                    ]
                },
            )
            invalid = client.put(
                "/api/settings",
                headers=self.origin_headers,
                json={"values": {"unknown": "value"}},
            )

        self.assertTrue(preserved.json()["secrets"]["sub2api_password"])
        self.assertTrue(preserved.json()["secrets"]["sub2api_api_key"])
        self.assertTrue(preserved.json()["secrets"]["sub2api_totp_secret"])
        self.assertEqual(preserved.json()["values"]["sub2api_group_id"], "3")
        self.assertFalse(cleared.json()["secrets"]["sub2api_password"])
        self.assertFalse(cleared.json()["secrets"]["sub2api_api_key"])
        self.assertFalse(cleared.json()["secrets"]["sub2api_totp_secret"])
        self.assertNotIn("secret-canary", preserved.text + cleared.text)
        self.assertNotIn("api-key-canary", preserved.text + cleared.text)
        self.assertNotIn("totp-canary", preserved.text + cleared.text)
        self.assertEqual(invalid.status_code, 422)
        self.assertIn("values", invalid.json()["detail"]["fields"])

    def test_sub2api_groups_route_uses_saved_credentials_and_returns_safe_metadata(self):
        self.database.set_text_setting("sub2api_base_url", "https://sub2api.example")
        self.database.set_text_setting("sub2api_email", "admin@example.com")
        self.database.set_secret_setting("sub2api_password", "secret-canary")
        self.database.set_secret_setting("sub2api_totp_secret", "totp-canary")
        app = create_app(self.controller, testing=True)
        with patch("team_protocol.web_console.Sub2APIClient") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.list_groups.return_value = [
                {
                    "id": 3,
                    "name": "K12",
                    "platform": "openai",
                    "status": "active",
                    "is_exclusive": False,
                    "private_field": "not-returned",
                }
            ]
            with TestClient(app) as test_client:
                response = test_client.get(
                    "/api/sub2api/groups",
                    headers={"X-Workflow-Token": self.controller.request_token},
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "groups": [
                    {
                        "id": 3,
                        "name": "K12",
                        "platform": "openai",
                        "status": "active",
                        "is_exclusive": False,
                    }
                ]
            },
        )
        client_class.assert_called_once_with(
            "https://sub2api.example",
            "admin@example.com",
            "secret-canary",
            totp_secret="totp-canary",
        )
        client.list_groups.assert_called_once_with(include_inactive=True)

    def test_sub2api_groups_route_uses_saved_api_key_without_password(self):
        self.database.set_text_setting("sub2api_base_url", "https://sub2api.example")
        self.database.set_secret_setting("sub2api_api_key", "api-key-canary")
        app = create_app(self.controller, testing=True)
        with patch("team_protocol.web_console.Sub2APIClient") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.list_groups.return_value = []
            with TestClient(app) as test_client:
                response = test_client.get(
                    "/api/sub2api/groups",
                    headers={"X-Workflow-Token": self.controller.request_token},
                )

        self.assertEqual(response.status_code, 200)
        client_class.assert_called_once_with(
            "https://sub2api.example", "", "", api_key="api-key-canary"
        )
        self.assertNotIn("api-key-canary", response.text)

    def test_refresh_imported_child_verifies_local_json_and_retries_failed_run(self):
        workspace, account, run = self.failed_icloud_handoff()
        before_credentials = self.database.get_account_credentials(account["id"])
        path = self.write_sub2api_refresh_file(workspace, account)
        app = create_app(self.controller, testing=True)
        with TestClient(app) as test_client:
            response = test_client.post(
                f"/api/accounts/{account['id']}/refresh",
                json={"path": str(path)},
                headers=self.origin_headers,
            )

        self.assertEqual(response.status_code, 202, response.text)
        self.assertTrue(response.json()["verified"])
        self.assertEqual(response.json()["run"]["id"], run["id"])
        self.assertEqual(self.database.get_run(run["id"])["state"], "queued")
        self.assertEqual(
            self.database.get_workspace(workspace["id"])["status"], "queued"
        )
        after_credentials = self.database.get_account_credentials(account["id"])
        self.assertEqual(
            {
                key: value
                for key, value in after_credentials.items()
                if key != "registered_account"
            },
            before_credentials,
        )
        self.assertIs(after_credentials["registered_account"], True)
        self.assertNotIn("pat-refresh-canary", response.text)
        self.assertNotIn(str(path), response.text)

    def test_refresh_imported_child_rejects_wrong_json_workspace_without_writes(self):
        workspace, account, run = self.failed_icloud_handoff()
        before_credentials = self.database.get_account_credentials(account["id"])
        path = self.write_sub2api_refresh_file(
            workspace,
            account,
            access_token="pat-wrong-workspace-canary",
            workspace_uid="another-workspace",
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as test_client:
            response = test_client.post(
                f"/api/accounts/{account['id']}/refresh",
                json={"path": str(path)},
                headers=self.origin_headers,
            )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            self.database.get_account_credentials(account["id"]),
            before_credentials,
        )
        self.assertEqual(self.database.get_run(run["id"])["state"], "failed")
        self.assertEqual(
            self.database.get_workspace(workspace["id"])["status"], "failed"
        )
        self.assertNotIn("pat-wrong-workspace-canary", response.text)

    def test_refresh_imported_child_requires_personal_access_token(self):
        workspace, account, run = self.failed_icloud_handoff()
        before_credentials = self.database.get_account_credentials(account["id"])
        path = self.write_sub2api_refresh_file(
            workspace,
            account,
            access_token="oauth-token-canary",
            auth_mode="oauth",
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as test_client:
            response = test_client.post(
                f"/api/accounts/{account['id']}/refresh",
                json={"path": str(path)},
                headers=self.origin_headers,
            )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            self.database.get_account_credentials(account["id"]),
            before_credentials,
        )
        self.assertEqual(self.database.get_run(run["id"])["state"], "failed")
        self.assertNotIn("oauth-token-canary", response.text)

    def test_refresh_imported_child_rejects_non_icloud_account(self):
        workspace, _current, next_account = self.workspace("refresh-regular")
        run = self.queue.enqueue([workspace["id"]])[0]
        self.database.claim_next_queue_item()
        self.database.fail_run(run["id"], "failed")
        before_credentials = self.database.get_account_credentials(next_account["id"])
        app = create_app(self.controller, testing=True)
        with TestClient(app) as test_client:
            response = test_client.post(
                f"/api/accounts/{next_account['id']}/refresh",
                json={"path": str(self.root / "unused.json")},
                headers=self.origin_headers,
            )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            self.database.get_account_credentials(next_account["id"]),
            before_credentials,
        )
        self.assertEqual(self.database.get_run(run["id"])["state"], "failed")

    def test_static_traversal_and_legacy_config_routes_are_absent(self):
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            index = client.get("/")
            script = client.get("/static/app.js")
            style = client.get("/static/app.css")
            traversal = client.get("/static/../../workflow.example.json")
            old_load = client.post(
                "/api/config/load",
                headers=self.origin_headers,
                json={"path": "workflow.json"},
            )
            old_run = client.post(
                "/api/run",
                headers=self.origin_headers,
                json={"config_path": "workflow.json"},
            )

        self.assertEqual(index.status_code, 200)
        self.assertEqual(script.status_code, 200)
        self.assertEqual(style.status_code, 200)
        self.assertIn("refreshRequestToken", script.text)
        self.assertIn("invalid_request_token", script.text)
        self.assertIn("Content-Security-Policy", index.headers)
        self.assertIn('id="account-page-summary"', index.text)
        self.assertIn('data-action="account-page-next"', index.text)
        self.assertIn('name="sub2api_group_id"', index.text)
        self.assertIn('name="sub2api_api_key"', index.text)
        self.assertIn('name="sub2api_totp_secret"', index.text)
        self.assertIn('<select name="sub2api_group_id">', index.text)
        self.assertIn('id="icloud-sync-form"', index.text)
        self.assertIn('id="icloud-owner-proxy-form"', index.text)
        self.assertIn('id="icloud-team-workspace-status"', index.text)
        self.assertIn('name="workspace_uid" type="text" maxlength="500" readonly', index.text)
        self.assertIn('/api/sub2api/groups', script.text)
        self.assertIn('refresh-imported-child', script.text)
        self.assertIn('/api/accounts/${encodeURIComponent(id)}/refresh', script.text)
        self.assertIn('/api/icloud-teams/workspace/lookup', script.text)
        self.assertIn('submit.textContent = workspaceUid ? "导入 Team" : "识别并导入"', script.text)
        self.assertIn('form.id === "icloud-sync-form"', script.text)
        self.assertIn('form.id === "icloud-owner-proxy-form"', script.text)
        self.assertIn('#icloud-sync-dialog', style.text)
        self.assertIn('width: min(1240px, calc(100vw - 48px))', style.text)
        self.assertIn("const ACCOUNT_PAGE_SIZE = 50", script.text)
        self.assertIn("const MOBILE_ACCOUNT_PAGE_SIZE = 20", script.text)
        self.assertIn(traversal.status_code, {400, 404})
        self.assertEqual(old_load.status_code, 404)
        self.assertEqual(old_run.status_code, 404)
        self.assertNotIn("config_path", self.controller.bootstrap())

    def test_startup_migration_verifies_backup_before_cleanup_and_never_deletes_txt(self):
        config, mail = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
        )

        def assert_backup_exists(model, verified):
            backup_path = Path(controller.database.get_meta("migration_backup_path"))
            self.assertTrue(backup_path.is_file())
            return cleanup_plaintext(model, verified)

        with patch(
            "team_protocol.web_console.cleanup_plaintext",
            side_effect=assert_backup_exists,
        ):
            status = controller.startup()

        self.assertTrue(status["ready"])
        self.assertFalse(config.exists())
        self.assertTrue(mail.exists())
        self.assertTrue(Path(controller.database.get_meta("migration_backup_path")).is_file())
        self.assertTrue(
            Path(
                controller.database.get_meta(
                    "mailbox_inventory_prechange_backup_path"
                )
            ).is_file()
        )
        self.assertEqual(
            controller.database.get_meta("mailbox_inventory_migration_version"),
            "1",
        )
        self.assertEqual(controller.database.get_mailbox_inventory_summary()["total"], 1)
        self.assertEqual(self.queue.started, 1)

        second_database = Database(self.root / "console.db", secret_store=self.store)
        second_queue = FakeTaskQueue(second_database)
        second = WebConsoleController(
            database=second_database,
            secret_store=self.store,
            task_queue=second_queue,
            app_dir=self.root,
            legacy_config_path=config,
        )
        with (
            patch(
                "team_protocol.web_console.discover_legacy",
                side_effect=AssertionError("completed migration reread legacy source"),
            ),
            patch(
                "team_protocol.web_console.verify_backup",
                side_effect=AssertionError("completed inventory migration reread backup"),
            ),
        ):
            self.assertTrue(second.startup()["ready"])

    def test_inventory_backfill_count_mismatch_blocks_queue_without_marker(self):
        config, mail = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
            inventory_expected_count=2,
        )

        health = controller.startup()

        self.assertFalse(health["ready"])
        self.assertEqual(
            controller.migration_status()["status"], "inventory_migration_error"
        )
        self.assertEqual(self.queue.started, 0)
        self.assertIsNone(
            self.database.get_meta("mailbox_inventory_migration_version")
        )
        self.assertEqual(self.database.get_mailbox_inventory_summary()["total"], 0)
        self.assertTrue(mail.exists())
        prechange = self.database.get_text_setting("last_backup_path")
        self.assertTrue(prechange and Path(prechange).is_file())

        controller.inventory_expected_count = 1
        recovered = controller.retry_migration_cleanup()
        self.assertEqual(recovered["status"], "ready")
        self.assertEqual(self.queue.started, 1)
        self.assertEqual(
            self.database.get_meta("mailbox_inventory_migration_version"), "1"
        )

    def test_cleanup_blocked_exposes_only_recovery_then_retries_from_backup(self):
        config, mail = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
        )
        blocked = CleanupResult(
            status="cleanup_blocked",
            removed=(),
            preserved=(mail,),
            missing=(),
            failures=(CleanupFailure(path=config, code="remove_failed"),),
        )
        with patch("team_protocol.web_console.cleanup_plaintext", return_value=blocked):
            controller.startup()

        self.assertEqual(controller.migration_status()["status"], "cleanup_blocked")
        self.assertEqual(self.queue.started, 0)
        self.assertTrue(config.exists())
        app = create_app(controller, testing=True)
        with TestClient(app) as client:
            blocked_route = client.get(
                "/api/workspaces",
                headers={"X-Workflow-Token": controller.request_token},
            )
            recovered = client.post(
                "/api/migration/retry-cleanup",
                headers={
                    "Origin": "http://testserver",
                    "X-Workflow-Token": controller.request_token,
                },
            )

        self.assertEqual(blocked_route.status_code, 503)
        self.assertEqual(blocked_route.json()["detail"]["code"], "migration_blocked")
        self.assertEqual(recovered.json()["status"], "ready")
        self.assertFalse(config.exists())
        self.assertTrue(mail.exists())

    def test_encrypted_backup_restore_requires_paused_queue_and_reinitializes(self):
        self.controller.startup()
        original = self.account("backup-original")
        with self.assertRaisesRegex(Exception, "paused"):
            self.controller.restore_encrypted_backup(self.root / "missing.twbackup")
        self.queue.set_paused(True)
        backup = self.controller.create_encrypted_backup()
        settings = self.controller.get_settings()["values"]
        extra = self.account("backup-extra")

        restored = self.controller.restore_encrypted_backup(backup["path"])

        self.assertEqual(restored["status"], "restored")
        account_ids = {item["id"] for item in self.database.list_accounts()}
        self.assertIn(original["id"], account_ids)
        self.assertNotIn(extra["id"], account_ids)
        self.assertTrue(self.database.is_queue_paused())
        self.assertGreaterEqual(self.queue.shutdown_calls, 1)
        self.assertEqual(settings["last_backup_path"], backup["path"])
        self.assertTrue(settings["last_backup_at"])

    def test_custom_backup_directory_controls_default_backup_destination(self):
        backup_directory = self.root / "project-backups"
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            backup_dir=backup_directory,
        )
        controller.startup()

        backup = controller.create_encrypted_backup()

        backup_path = Path(backup["path"])
        self.assertEqual(backup_path.parent, backup_directory.resolve())
        self.assertTrue(backup_path.is_file())

    def test_restore_keeps_blocked_database_stopped(self):
        self.controller.startup()
        self.database.set_meta("migration_status", "cleanup_blocked")
        self.queue.set_paused(True)
        backup = self.controller.create_encrypted_backup()
        self.database.set_meta("migration_status", "ready")
        started_before = self.queue.started

        self.controller.restore_encrypted_backup(backup["path"])

        self.assertEqual(self.controller.migration_status()["status"], "cleanup_blocked")
        self.assertEqual(self.queue.started, started_before)

    def test_restored_verified_migration_snapshot_becomes_complete_without_legacy_read(self):
        config, _ = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
        )
        controller.startup()
        backup_path = controller.database.get_meta("migration_backup_path")
        controller.task_queue.set_paused(True)

        with patch(
            "team_protocol.web_console.discover_legacy",
            side_effect=AssertionError("restore reread legacy source"),
        ):
            restored = controller.restore_encrypted_backup(backup_path)

        self.assertEqual(restored["status"], "restored")
        self.assertEqual(controller.database.get_meta("migration_status"), "complete")
        self.assertEqual(controller.database.get_meta("migration_completed"), "1")
        self.assertEqual(controller.migration_status()["status"], "ready")
        self.assertGreaterEqual(self.queue.started, 2)

    def test_server_uses_project_legacy_path_internally_without_cli_argument(self):
        expected = (Path.cwd() / "workflow.example.json").resolve()
        with (
            patch("team_protocol.web_console._available_port", return_value=8765),
            patch("team_protocol.web_console.WebConsoleController") as controller_type,
            patch("team_protocol.web_console.create_app", return_value=object()),
            patch("team_protocol.web_console.uvicorn.Server") as server_type,
        ):
            server_type.return_value.run.return_value = None
            result = serve_web_console(open_browser=False, app_dir=self.root)

        self.assertEqual(result, 0)
        self.assertEqual(
            controller_type.call_args.kwargs["legacy_config_path"],
            expected,
        )
        config = server_type.call_args.args[0]
        self.assertEqual(config.timeout_graceful_shutdown, 10.0)
        probe = controller_type.return_value.set_shutdown_probe.call_args.args[0]
        server_type.return_value.should_exit = False
        self.assertFalse(probe())
        server_type.return_value.should_exit = True
        self.assertTrue(probe())


if __name__ == "__main__":
    unittest.main()
