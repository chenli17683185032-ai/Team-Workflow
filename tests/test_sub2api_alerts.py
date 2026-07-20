from __future__ import annotations

import json
import unittest
from email.message import EmailMessage

from team_protocol.database import StateConflictError
from team_protocol.registrar_runtime.icloud_imap_provider import ImapMailboxConfig
from team_protocol.sub2api_alerts import (
    ALERT_ACTIONS_SETTING,
    ALERT_CURSOR_SETTING,
    ALERT_ENABLED_SETTING,
    MailboxBatch,
    MailboxCursor,
    Sub2APIAlertCoordinator,
    Sub2APIAlertError,
    Sub2APIMonitorMailbox,
)


class FakeDatabase:
    def __init__(self) -> None:
        self.settings = {ALERT_ENABLED_SETTING: "1"}
        self.workspaces = [
            {
                "id": "workspace-local-1",
                "version": 3,
                "workspace_uid": "team-remote-1",
                "current_account_id": "account-local-1",
                "owner_alias_id": "owner-1",
                "last_run_id": None,
                "next_account_id": None,
            },
            {
                "id": "workspace-local-2",
                "version": 5,
                "workspace_uid": "team-remote-2",
                "current_account_id": "account-local-2",
                "owner_alias_id": "owner-2",
                "last_run_id": None,
                "next_account_id": None,
            },
        ]
        self.accounts = {
            "account-local-1": {
                "id": "account-local-1",
                "email": "child-one@icloud.com",
                "status": "bound_current",
                "icloud_role": "rotating_child",
            },
            "account-local-2": {
                "id": "account-local-2",
                "email": "child-two@icloud.com",
                "status": "bound_current",
                "icloud_role": "rotating_child",
            },
        }
        self.runs = {}

    def get_text_setting(self, key, default=None):
        return self.settings.get(key, default)

    def set_text_setting(self, key, value):
        self.settings[key] = str(value)

    def list_workspaces(self):
        return [dict(item) for item in self.workspaces]

    def get_workspace(self, workspace_id):
        return next(
            dict(item) for item in self.workspaces if item["id"] == workspace_id
        )

    def get_account(self, account_id):
        return dict(self.accounts[account_id])

    def get_run(self, run_id):
        return dict(self.runs[run_id])


class FakeSub2APIClient:
    def __init__(self) -> None:
        self.closed = False
        self.details = {
            "child-one@icloud.com": {
                "id": 500,
                "name": "child-one@icloud.com",
                "extra": {"email": "child-one@icloud.com"},
                "credentials": {
                    "email": "child-one@icloud.com",
                    "chatgpt_account_id": "team-remote-1",
                },
                "error_message": "",
            },
            "child-two@icloud.com": {
                "id": 501,
                "name": "child-two@icloud.com",
                "extra": {"email": "child-two@icloud.com"},
                "credentials": {
                    "email": "child-two@icloud.com",
                    "chatgpt_account_id": "team-remote-2",
                },
                "error_message": "",
            },
        }
        self.usage = {500: 20.0, 501: 20.0}

    def list_accounts(self, *, search, **_kwargs):
        detail = self.details.get(str(search).casefold())
        if detail is None:
            return []
        return [
            {
                "id": detail["id"],
                "name": detail["name"],
                "extra": dict(detail["extra"]),
            }
        ]

    def get_account(self, account_id):
        return dict(
            next(item for item in self.details.values() if item["id"] == account_id)
        )

    def get_account_usage(self, account_id):
        return {"primary": {"utilization": self.usage[account_id]}}

    def close(self):
        self.closed = True


class FakeMailbox:
    def __init__(self, batch):
        self.batch = batch
        self.cursors = []

    def fetch_after(self, cursor):
        self.cursors.append(cursor)
        return self.batch


class FakeIMAPConnection:
    def __init__(self, uids, messages, *, uid_validity="55") -> None:
        self.uids = list(uids)
        self.messages = dict(messages)
        self.uid_validity = uid_validity
        self.logged_out = False
        self.uid_validity_reads = 0

    def login(self, _username, _password):
        return "OK", [b"logged in"]

    def select(self, _folder, readonly=True):
        assert readonly
        return "OK", [str(len(self.uids)).encode("ascii")]

    def response(self, name):
        if name == "UIDVALIDITY":
            self.uid_validity_reads += 1
            if self.uid_validity_reads > 1:
                return None, []
            return "UIDVALIDITY", [self.uid_validity.encode("ascii")]
        return None, []

    def uid(self, command, *args):
        if command == "search":
            return "OK", [" ".join(str(uid) for uid in self.uids).encode("ascii")]
        if command == "fetch":
            uid = int(args[0])
            return "OK", [(b"header", self.messages[uid])]
        raise AssertionError(command)

    def logout(self):
        self.logged_out = True
        return "BYE", [b"logged out"]


def mail_headers(sender, subject):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "monitor@example.com"
    message["Subject"] = subject
    return message.as_bytes()


class Sub2APIAlertCoordinatorTests(unittest.TestCase):
    def make_coordinator(self, database=None, client=None, handoff=None, refresh=None):
        database = database or FakeDatabase()
        client = client or FakeSub2APIClient()
        handoff_calls = []
        refresh_calls = []

        def default_handoff(workspace_id, version):
            handoff_calls.append((workspace_id, version))
            return {"state": "queued"}

        def default_refresh(account_id):
            refresh_calls.append(account_id)
            return {"state": "succeeded"}

        coordinator = Sub2APIAlertCoordinator(
            database,
            client_factory=lambda: client,
            handoff_callback=handoff or default_handoff,
            refresh_callback=refresh or default_refresh,
            poll_interval=0.05,
        )
        return coordinator, database, client, handoff_calls, refresh_calls

    def test_usage_at_90_starts_only_matching_handoff_once(self):
        coordinator, database, client, handoffs, refreshes = self.make_coordinator()
        client.usage[500] = 90.0

        first = coordinator.reconcile()
        second = coordinator.reconcile()

        self.assertEqual(
            [("workspace-local-1", 3)],
            handoffs,
        )
        self.assertEqual([], refreshes)
        self.assertEqual([90.0, 20.0], [item.utilization for item in first])
        self.assertEqual([90.0, 20.0], [item.utilization for item in second])
        state = json.loads(database.settings[ALERT_ACTIONS_SETTING])
        self.assertEqual(
            "triggered",
            state["actions"][
                "handoff:workspace-local-1:account-local-1"
            ]["state"],
        )

    def test_new_current_child_gets_a_new_handoff_latch(self):
        coordinator, database, client, handoffs, _refreshes = self.make_coordinator()
        client.usage[500] = 95.0
        coordinator.reconcile()

        database.accounts["account-local-1"]["status"] = "retired"
        database.accounts["account-local-new"] = {
            "id": "account-local-new",
            "email": "child-new@icloud.com",
            "status": "bound_current",
            "icloud_role": "rotating_child",
        }
        database.workspaces[0]["current_account_id"] = "account-local-new"
        database.workspaces[0]["version"] = 4
        client.details["child-new@icloud.com"] = {
            "id": 502,
            "name": "child-new@icloud.com",
            "extra": {"email": "child-new@icloud.com"},
            "credentials": {
                "email": "child-new@icloud.com",
                "chatgpt_account_id": "team-remote-1",
            },
            "error_message": "",
        }
        client.usage[502] = 96.0

        coordinator.reconcile()

        self.assertEqual(
            [("workspace-local-1", 3), ("workspace-local-1", 4)],
            handoffs,
        )
        actions = json.loads(database.settings[ALERT_ACTIONS_SETTING])["actions"]
        self.assertNotIn(
            "handoff:workspace-local-1:account-local-1",
            actions,
        )
        self.assertIn(
            "handoff:workspace-local-1:account-local-new",
            actions,
        )

    def test_401_takes_priority_over_high_usage_and_refreshes_once(self):
        coordinator, _database, client, handoffs, refreshes = self.make_coordinator()
        client.usage[500] = 99.0
        client.details["child-one@icloud.com"]["error_message"] = (
            "Authentication failed (401): expired"
        )

        signals = coordinator.reconcile()
        coordinator.reconcile()

        self.assertEqual([], handoffs)
        self.assertEqual(["account-local-1"], refreshes)
        self.assertTrue(signals[0].unauthorized)
        self.assertIsNone(signals[0].utilization)

    def test_all_401_actions_run_before_any_90_percent_handoff(self):
        events = []

        def handoff(_workspace_id, _version):
            events.append("handoff")
            return {"state": "queued"}

        def refresh(_account_id):
            events.append("refresh")
            return {"state": "succeeded"}

        coordinator, _database, client, _handoffs, _refreshes = self.make_coordinator(
            handoff=handoff,
            refresh=refresh,
        )
        client.details["child-one@icloud.com"]["error_message"] = (
            "Authentication failed (401)"
        )
        client.usage[501] = 95.0

        coordinator.reconcile()

        self.assertEqual(["refresh", "handoff"], events)

    def test_refresh_latch_clears_after_recovery_and_allows_future_401(self):
        coordinator, _database, client, _handoffs, refreshes = self.make_coordinator()
        detail = client.details["child-one@icloud.com"]
        detail["error_message"] = "API returned 401: expired"
        coordinator.reconcile()

        detail["error_message"] = ""
        coordinator.reconcile()
        detail["error_message"] = "API returned 401: expired again"
        coordinator.reconcile()

        self.assertEqual(
            ["account-local-1", "account-local-1"],
            refreshes,
        )

    def test_workspace_identity_mismatch_never_starts_an_action(self):
        coordinator, _database, client, handoffs, refreshes = self.make_coordinator()
        client.details["child-one@icloud.com"]["credentials"][
            "chatgpt_account_id"
        ] = "another-team"
        client.usage[500] = 100.0

        with self.assertRaisesRegex(
            Sub2APIAlertError, "sub2api_current_child_mapping_ambiguous"
        ):
            coordinator.reconcile()

        self.assertEqual([], handoffs)
        self.assertEqual([], refreshes)

    def test_action_failure_does_not_advance_mail_cursor_or_leave_pending_latch(self):
        def blocked(_workspace_id, _version):
            raise StateConflictError("active workflow")

        coordinator, database, client, _handoffs, _refreshes = self.make_coordinator(
            handoff=blocked
        )
        client.usage[500] = 95.0
        database.settings[ALERT_CURSOR_SETTING] = json.dumps(
            {"uid_validity": "55", "last_uid": 8}
        )
        mailbox = FakeMailbox(
            MailboxBatch(MailboxCursor("55", 9), True, 1)
        )

        with self.assertRaises(StateConflictError):
            coordinator.poll_once(mailbox)

        cursor = json.loads(database.settings[ALERT_CURSOR_SETTING])
        self.assertEqual(8, cursor["last_uid"])
        actions = json.loads(database.settings[ALERT_ACTIONS_SETTING])["actions"]
        self.assertEqual({}, actions)

    def test_irrelevant_new_mail_only_advances_cursor(self):
        coordinator, database, _client, handoffs, refreshes = self.make_coordinator()
        database.settings[ALERT_CURSOR_SETTING] = json.dumps(
            {"uid_validity": "55", "last_uid": 8}
        )
        mailbox = FakeMailbox(
            MailboxBatch(MailboxCursor("55", 11), False, 3)
        )

        batch = coordinator.poll_once(mailbox)

        self.assertFalse(batch.should_reconcile)
        self.assertEqual([], handoffs)
        self.assertEqual([], refreshes)
        cursor = json.loads(database.settings[ALERT_CURSOR_SETTING])
        self.assertEqual(11, cursor["last_uid"])

    def test_requires_exactly_two_current_children(self):
        database = FakeDatabase()
        database.workspaces.pop()
        coordinator, *_rest = self.make_coordinator(database=database)

        with self.assertRaisesRegex(
            Sub2APIAlertError, "expected_two_current_children"
        ):
            coordinator.reconcile()


class Sub2APIMonitorMailboxTests(unittest.TestCase):
    def config(self):
        return ImapMailboxConfig(
            registration_email="monitor@example.com",
            forwarding_email="monitor@example.com",
            host="imap.example.com",
            port=993,
            username="monitor@example.com",
            password="secret",
        )

    def test_matching_sender_and_subject_wakes_reconciliation(self):
        connection = FakeIMAPConnection(
            [6, 7],
            {
                6: mail_headers("other@example.com", "[告警] 云贝 Sub2API 号池需要处理"),
                7: mail_headers(
                    "Yunbay <support@yunbay.xyz>",
                    "[定时] 云贝服务器资源与 Sub2API 状态",
                ),
            },
        )
        mailbox = Sub2APIMonitorMailbox(
            self.config(),
            "support@yunbay.xyz",
            connection_factory=lambda _config, _timeout: connection,
        )

        batch = mailbox.fetch_after(MailboxCursor("55", 5))
        mailbox.close()

        self.assertTrue(batch.should_reconcile)
        self.assertEqual(7, batch.cursor.last_uid)
        self.assertEqual(2, batch.new_message_count)
        self.assertTrue(connection.logged_out)

    def test_test_email_from_expected_sender_wakes_reconciliation(self):
        connection = FakeIMAPConnection(
            [8],
            {
                8: mail_headers(
                    "Yunbay <support@yunbay.xyz>",
                    "[测试] 云贝 Sub2API 监控邮件",
                )
            },
        )
        mailbox = Sub2APIMonitorMailbox(
            self.config(),
            "support@yunbay.xyz",
            connection_factory=lambda _config, _timeout: connection,
        )

        batch = mailbox.fetch_after(MailboxCursor("55", 7))
        mailbox.close()

        self.assertTrue(batch.should_reconcile)
        self.assertEqual(8, batch.cursor.last_uid)

    def test_uid_validity_change_baselines_mailbox_and_reconciles_once(self):
        connection = FakeIMAPConnection([10, 11], {}, uid_validity="66")
        mailbox = Sub2APIMonitorMailbox(
            self.config(),
            "support@yunbay.xyz",
            connection_factory=lambda _config, _timeout: connection,
        )

        batch = mailbox.fetch_after(MailboxCursor("old", 999))
        mailbox.close()

        self.assertTrue(batch.should_reconcile)
        self.assertEqual(MailboxCursor("66", 11), batch.cursor)
        self.assertEqual(0, batch.new_message_count)

    def test_uid_validity_is_cached_for_the_lifetime_of_the_connection(self):
        connection = FakeIMAPConnection([10, 11], {}, uid_validity="77")
        mailbox = Sub2APIMonitorMailbox(
            self.config(),
            "support@yunbay.xyz",
            connection_factory=lambda _config, _timeout: connection,
        )

        baseline = mailbox.fetch_after(None)
        second = mailbox.fetch_after(baseline.cursor)
        mailbox.close()

        self.assertEqual(1, connection.uid_validity_reads)
        self.assertFalse(second.should_reconcile)
        self.assertEqual(baseline.cursor, second.cursor)


if __name__ == "__main__":
    unittest.main()
