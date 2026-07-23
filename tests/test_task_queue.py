import json
import tempfile
import threading
import time
import unittest
from collections import deque
from pathlib import Path

from team_protocol.database import Database, StateConflictError
from team_protocol.task_queue import DatabaseCheckpointStore, TaskQueue, redact_text
from team_protocol.workflow import WorkflowCancelled, WorkflowIdentityError


class MemorySecretStore:
    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        body = bytes(plaintext)
        key = purpose.encode("utf-8") or b"x"
        return b"test:" + bytes(
            value ^ key[index % len(key)] for index, value in enumerate(body)
        )

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        payload = bytes(ciphertext)
        if not payload.startswith(b"test:"):
            raise ValueError("invalid ciphertext")
        body = payload[5:]
        key = purpose.encode("utf-8") or b"x"
        return bytes(value ^ key[index % len(key)] for index, value in enumerate(body))


def wait_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


class RunnerHarness:
    def __init__(self, *behaviors):
        self.behaviors = deque(behaviors)
        self.lock = threading.Lock()
        self.calls = []
        self.active = 0
        self.max_active = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def __call__(self, config, **kwargs):
        with self.lock:
            behavior = self.behaviors.popleft() if self.behaviors else "success"
            call = {
                "behavior": behavior,
                "config": config,
                "old_mailbox": kwargs["old_mailbox"],
                "new_mailbox": kwargs["new_mailbox"],
                "proxy": kwargs["expanded_proxy"],
                "old_network": kwargs["old_network"],
                "new_network": kwargs["new_network"],
                "checkpoint_before": kwargs["checkpoint_store"].snapshot(),
            }
            self.calls.append(call)
        return FakeRunner(self, behavior, config, kwargs)


class FakeRunner:
    def __init__(self, harness, behavior, config, kwargs):
        self.harness = harness
        self.behavior = behavior
        self.config = config
        self.kwargs = kwargs

    def run(self):
        with self.harness.lock:
            self.harness.active += 1
            self.harness.max_active = max(self.harness.max_active, self.harness.active)
        try:
            callback = self.kwargs["event_callback"]
            logger = self.kwargs["logger"]
            checkpoint = self.kwargs["checkpoint_store"]
            stop_event = self.kwargs["stop_event"]
            callback({"type": "step", "step": "old_login", "state": "active"})
            checkpoint.set(
                "old_login",
                {"attempt": len(self.harness.calls), "session": "session-checkpoint-canary"},
            )
            logger(
                "using "
                + self.config.proxy
                + " refresh="
                + self.kwargs["old_mailbox"].refresh_token
                + " old-network="
                + self.kwargs["old_network"].proxy
                + " new-network="
                + self.kwargs["new_network"].proxy
            )
            if isinstance(self.behavior, BaseException):
                raise self.behavior
            if self.behavior == "fail":
                raise RuntimeError(
                    "failed with "
                    + self.kwargs["old_mailbox"].refresh_token
                    + " at "
                    + self.config.proxy
                )
            if self.behavior == "block":
                self.harness.started.set()
                while not self.harness.release.is_set():
                    if stop_event.wait(0.01):
                        raise WorkflowCancelled("cancelled")
            elif self.behavior == "ignore-stop":
                self.harness.started.set()
                self.harness.release.wait(3.0)
            callback({"type": "step", "step": "old_login", "state": "done"})
            return {
                "status": "ok",
                "authenticated_url": self.config.proxy,
                "session": "session-checkpoint-canary",
            }
        finally:
            with self.harness.lock:
                self.harness.active -= 1


class TaskQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.database = Database(
            self.root / "console.db", secret_store=MemorySecretStore()
        )
        self.database.set_text_setting("output_dir", str(self.root / "output"))
        self.database.set_text_setting("management_push", "0")
        self.database.set_text_setting("sub2api_push", "0")
        self.database.set_secret_setting(
            "proxy",
            "http://proxy-user-region-BR-sid-seed-t-60:"
            "proxy-password@proxy.invalid:9000/{rand}",
        )
        self.database.set_text_setting(
            "openbrowser_base_url", "http://127.0.0.1:50325"
        )
        self.database.set_text_setting(
            "openbrowser_manual_timeout_seconds", "1800"
        )
        self.database.set_secret_setting(
            "openbrowser_api_key", "openbrowser-api-secret"
        )
        self.openbrowser_profiles = []
        self.queues = []

    def tearDown(self):
        for queue in self.queues:
            queue.shutdown(timeout=1.0)

    def make_workspace(self, suffix):
        current = self.database.create_account(
            account_id=f"account-{suffix}-current",
            email=f"person+{suffix}-current@example.com",
            primary_email=f"person-{suffix}@example.com",
            credentials={
                "mailbox_password": f"mailbox-password-{suffix}-current",
                "client_id": f"client-{suffix}-current",
                "refresh_token": f"refresh-{suffix}-current",
                "account_password": f"account-password-{suffix}-current",
            },
            source="test",
        )
        next_account = self.database.create_account(
            account_id=f"account-{suffix}-next",
            email=f"person+{suffix}-next@example.com",
            primary_email=f"person-{suffix}@example.com",
            credentials={
                "mailbox_password": f"mailbox-password-{suffix}-next",
                "client_id": f"client-{suffix}-next",
                "refresh_token": f"refresh-{suffix}-next",
                "account_password": f"account-password-{suffix}-next",
            },
            source="test",
        )
        self.bind_openbrowser(next_account["id"])
        workspace = self.database.create_workspace(
            workspace_id=f"workspace-{suffix}",
            name=f"Space {suffix}",
            workspace_uid=f"workspace-uid-{suffix}",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        return workspace, current, next_account

    def bind_openbrowser(self, account_id):
        profile_id = f"profile_{len(self.openbrowser_profiles) + 1:03d}"
        self.openbrowser_profiles.append(profile_id)
        self.database.set_text_setting(
            "openbrowser_profile_ids", "\n".join(self.openbrowser_profiles)
        )
        self.database.reserve_account_openbrowser_profile(
            account_id,
            [profile_id],
            proxy_sid=f"Browser{len(self.openbrowser_profiles):03d}",
        )
        return profile_id

    def make_queue(
        self,
        harness,
        *,
        rescue_harness=None,
        shutdown_timeout=1.0,
    ):
        queue = TaskQueue(
            self.database,
            runner_factory=harness,
            **(
                {"rescue_runner_factory": rescue_harness}
                if rescue_harness is not None
                else {}
            ),
            shutdown_timeout=shutdown_timeout,
        )
        self.queues.append(queue)
        return queue

    def test_database_checkpoint_store_persists_the_full_encrypted_document(self):
        workspace, _, _ = self.make_workspace("checkpoint")
        run = self.database.enqueue_workspace(workspace["id"])
        checkpoint = DatabaseCheckpointStore(self.database, run["id"])

        checkpoint.set("old_login", {"session": "checkpoint-secret-one"})
        checkpoint.set("invite", {"token": "checkpoint-secret-two"})

        self.assertEqual(
            self.database.get_run_checkpoint(run["id"]),
            {
                "old_login": {"session": "checkpoint-secret-one"},
                "invite": {"token": "checkpoint-secret-two"},
            },
        )
        self.assertEqual(self.database.get_run(run["id"])["current_step"], "invite")
        raw = b"".join(
            path.read_bytes() for path in self.root.glob("console.db*") if path.is_file()
        )
        self.assertNotIn(b"checkpoint-secret-one", raw)
        self.assertNotIn(b"checkpoint-secret-two", raw)

    def test_current_refresh_logs_each_stage_and_reuses_recent_success(self):
        calls = []

        class RefreshRunner:
            def __init__(self, **kwargs):
                self.callback = kwargs["event_callback"]
                self.logger = kwargs["logger"]

            def run(self):
                for step in ("old_login", "pat", "sub2api_export"):
                    self.callback({"type": "step", "step": step, "state": "active"})
                    self.logger(f"refresh detail for {step}")
                    self.callback({"type": "step", "step": step, "state": "done"})
                return {"sub2api_path": "/private/output/refreshed.json"}

        def refresh_factory(_config, **kwargs):
            calls.append(kwargs)
            return RefreshRunner(**kwargs)

        queue = TaskQueue(
            self.database,
            refresh_runner_factory=refresh_factory,
        )
        self.queues.append(queue)
        queue._build_current_refresh_inputs = lambda _account_id: (
            object(),
            object(),
            "",
            object(),
            (),
        )

        first = queue.refresh_current_account("current-account")
        first_snapshot = queue.snapshot()["credential_refresh"]
        second = queue.refresh_current_account("current-account")
        second_snapshot = queue.snapshot()["credential_refresh"]

        self.assertEqual(first["sub2api_path"], "/private/output/refreshed.json")
        self.assertEqual(first_snapshot["state"], "succeeded")
        self.assertEqual(
            first_snapshot["stages"],
            {
                "old_login": "done",
                "pat": "done",
                "sub2api_export": "done",
            },
        )
        first_messages = [item["message"] for item in first_snapshot["logs"]]
        self.assertEqual(first_messages[0], "credential refresh started")
        self.assertIn("refresh detail for old_login", first_messages)
        self.assertEqual(first_messages[-1], "credential refresh succeeded")
        self.assertTrue(all(item.get("created_at") for item in first_snapshot["logs"]))
        self.assertTrue(second["reused"])
        self.assertTrue(second_snapshot["reused"])
        self.assertEqual(
            [item["message"] for item in second_snapshot["logs"]],
            ["recent credential refresh result reused"],
        )
        self.assertEqual(len(calls), 1)

    def test_current_refresh_rejects_a_concurrent_second_request(self):
        started = threading.Event()
        release = threading.Event()
        results = []

        class BlockingRefreshRunner:
            def __init__(self, **kwargs):
                self.callback = kwargs["event_callback"]
                self.logger = kwargs["logger"]

            def run(self):
                self.callback(
                    {"type": "step", "step": "old_login", "state": "active"}
                )
                self.logger("waiting for mailbox feedback")
                started.set()
                release.wait(2.0)
                self.callback(
                    {"type": "step", "step": "old_login", "state": "done"}
                )
                return {"sub2api_path": "/private/output/one.json"}

        queue = TaskQueue(
            self.database,
            refresh_runner_factory=lambda _config, **kwargs: BlockingRefreshRunner(
                **kwargs
            ),
        )
        self.queues.append(queue)
        queue._build_current_refresh_inputs = lambda _account_id: (
            object(),
            object(),
            "",
            object(),
            (),
        )
        worker = threading.Thread(
            target=lambda: results.append(
                queue.refresh_current_account("current-account")
            )
        )
        worker.start()
        self.assertTrue(started.wait(1.0))

        with self.assertRaises(StateConflictError):
            queue.refresh_current_account("current-account")

        snapshot = queue.snapshot()["credential_refresh"]
        self.assertEqual(snapshot["state"], "running")
        self.assertEqual(snapshot["stages"]["old_login"], "running")
        self.assertEqual(snapshot["logs"][-1]["step"], "old_login")
        self.assertEqual(snapshot["logs"][-1]["message"], "waiting for mailbox feedback")
        release.set()
        worker.join(2.0)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)

    def test_current_refresh_failure_log_is_redacted_and_keeps_failed_stage(self):
        class FailingRefreshRunner:
            def __init__(self, **kwargs):
                self.callback = kwargs["event_callback"]
                self.logger = kwargs["logger"]

            def run(self):
                self.callback({"type": "step", "step": "pat", "state": "active"})
                self.logger("PAT request used refresh-secret-canary")
                raise RuntimeError("PAT failed with refresh-secret-canary")

        queue = TaskQueue(
            self.database,
            refresh_runner_factory=lambda _config, **kwargs: FailingRefreshRunner(
                **kwargs
            ),
        )
        self.queues.append(queue)
        queue._build_current_refresh_inputs = lambda _account_id: (
            object(),
            object(),
            "",
            object(),
            ("refresh-secret-canary",),
        )

        with self.assertRaises(StateConflictError) as caught:
            queue.refresh_current_account("current-account")

        snapshot = queue.snapshot()["credential_refresh"]
        self.assertEqual(snapshot["state"], "failed")
        self.assertEqual(snapshot["stages"]["pat"], "failed")
        self.assertNotIn("refresh-secret-canary", snapshot["error"])
        self.assertNotIn("refresh-secret-canary", str(caught.exception))
        self.assertIn("***", snapshot["error"])
        serialized_logs = json.dumps(snapshot["logs"])
        self.assertNotIn("refresh-secret-canary", serialized_logs)
        self.assertIn("***", serialized_logs)
        self.assertEqual(snapshot["logs"][-1]["level"], "error")

    def test_run_operation_logs_are_redacted_and_bounded(self):
        workspace, _, _ = self.make_workspace("bounded-logs")

        class ChattyRunner:
            def __init__(self, **kwargs):
                self.callback = kwargs["event_callback"]
                self.logger = kwargs["logger"]

            def run(self):
                self.callback({"type": "step", "step": "old_login", "state": "active"})
                for index in range(325):
                    self.logger(
                        f"detail {index} secret=refresh-bounded-logs-current"
                    )
                self.callback({"type": "step", "step": "old_login", "state": "done"})
                return {"status": "ok"}

        queue = TaskQueue(
            self.database,
            runner_factory=lambda _config, **kwargs: ChattyRunner(**kwargs),
        )
        self.queues.append(queue)
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(run["id"])["state"] == "succeeded"
                and queue.snapshot()["run_operation"]["state"] == "succeeded"
            )
        )

        operation = queue.snapshot()["run_operation"]
        self.assertEqual(operation["state"], "succeeded")
        self.assertEqual(len(operation["logs"]), 300)
        self.assertEqual(operation["logs"][-1]["message"], "run succeeded")
        self.assertIn("detail 324", operation["logs"][-3]["message"])
        self.assertTrue(all(item.get("created_at") for item in operation["logs"]))
        serialized_logs = json.dumps(operation["logs"])
        self.assertNotIn("refresh-bounded-logs-current", serialized_logs)
        self.assertIn("***", serialized_logs)

    def test_manual_login_state_is_visible_and_stop_cancels_without_secret_leak(self):
        workspace, _, _ = self.make_workspace("manual-state")
        started = threading.Event()

        class ManualStateRunner:
            def __init__(self, config, **kwargs):
                self.config = config
                self.callback = kwargs["event_callback"]
                self.logger = kwargs["logger"]
                self.stop_event = kwargs["stop_event"]

            def run(self):
                self.callback(
                    {"type": "step", "step": "new_login", "state": "active"}
                )
                self.callback(
                    {"type": "manual_login", "state": "waiting_for_user"}
                )
                self.logger(
                    f"waiting with api-key={self.config.openbrowser_api_key}"
                )
                started.set()
                self.stop_event.wait(3.0)
                raise WorkflowCancelled("cancelled")

        queue = self.make_queue(ManualStateRunner)
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(started.wait(2.0))
        operation = queue.snapshot()["run_operation"]
        self.assertEqual(operation["current_step"], "new_login")
        self.assertEqual(operation["manual_login_state"], "waiting_for_user")
        self.assertNotIn("openbrowser-api-secret", json.dumps(operation))

        self.assertEqual(queue.stop(run["id"]), "stopping")
        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(run["id"])["state"] == "cancelled"
            )
        )
        events = json.dumps(self.database.list_run_events(run_id=run["id"]))
        self.assertNotIn("openbrowser-api-secret", events)

    def test_fifo_single_active_failure_continues_and_redacts(self):
        first, _, _ = self.make_workspace("first")
        second, _, second_next = self.make_workspace("second")
        harness = RunnerHarness("fail", "success")
        queue = self.make_queue(harness)
        runs = queue.enqueue([first["id"], second["id"]])

        queue.start()

        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(runs[0]["id"])["state"] == "failed"
                and self.database.get_run(runs[1]["id"])["state"] == "succeeded"
            )
        )
        self.assertEqual(
            [call["config"].old_account.email for call in harness.calls],
            [runs[0]["current_email_snapshot"], runs[1]["current_email_snapshot"]],
        )
        self.assertEqual(harness.max_active, 1)
        self.assertEqual(
            self.database.get_workspace(second["id"])["current_account_id"],
            second_next["id"],
        )
        error = self.database.get_run(runs[0]["id"])["redacted_error"]
        self.assertNotIn("refresh-first-current", error)
        self.assertNotIn("proxy-password", error)
        self.assertIn("***", error)
        self.assertTrue(
            wait_until(
                lambda: any(
                    event["message"] == "run succeeded"
                    for event in self.database.list_run_events(run_id=runs[1]["id"])
                )
            )
        )
        serialized_events = json.dumps(
            self.database.list_run_events(), ensure_ascii=False
        )
        self.assertNotIn("refresh-first-current", serialized_events)
        self.assertNotIn("proxy-password", serialized_events)
        self.assertNotIn("proxy-user:", serialized_events)

    def test_pause_blocks_claim_until_resume(self):
        workspace, _, _ = self.make_workspace("paused")
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)
        queue.pause()
        run = queue.enqueue([workspace["id"]])[0]

        queue.start()
        time.sleep(0.08)

        self.assertEqual(harness.calls, [])
        self.assertEqual(self.database.get_run(run["id"])["state"], "queued")
        queue.resume()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )

    def test_active_and_queued_stop_never_start_the_cancelled_item(self):
        first, _, _ = self.make_workspace("stop-active")
        second, _, _ = self.make_workspace("stop-pending")
        harness = RunnerHarness("block", "success")
        queue = self.make_queue(harness)
        runs = queue.enqueue([first["id"], second["id"]])
        queue.start()
        self.assertTrue(harness.started.wait(2.0))

        self.assertEqual(queue.stop(runs[1]["id"]), "cancelled")
        self.assertEqual(queue.stop(runs[0]["id"]), "stopping")

        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(runs[0]["id"])["state"] == "cancelled"
            )
        )
        self.assertEqual(self.database.get_run(runs[1]["id"])["state"], "cancelled")
        self.assertEqual(len(harness.calls), 1)

    def test_retry_reuses_run_checkpoint_and_expanded_proxy(self):
        workspace, _, next_account = self.make_workspace("retry")
        harness = RunnerHarness("fail", "success")
        queue = self.make_queue(harness)
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        first_proxy = self.database.get_run_proxy(run["id"])

        retried = queue.retry(run["id"])

        self.assertEqual(retried["id"], run["id"])
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )
        self.assertEqual([call["proxy"] for call in harness.calls], [first_proxy, first_proxy])
        self.assertNotEqual(
            harness.calls[0]["old_network"].proxy,
            harness.calls[0]["new_network"].proxy,
        )
        self.assertEqual(
            [call["old_network"].proxy for call in harness.calls],
            [harness.calls[0]["old_network"].proxy] * 2,
        )
        self.assertEqual(
            [call["new_network"].proxy for call in harness.calls],
            [harness.calls[0]["new_network"].proxy] * 2,
        )
        current_identity = self.database.get_account_network_identity(
            workspace["current_account_id"]
        )
        next_identity = self.database.get_account_network_identity(next_account["id"])
        self.assertNotEqual(current_identity["proxy_sid"], next_identity["proxy_sid"])
        self.assertIn("old_login", harness.calls[1]["checkpoint_before"])
        self.assertEqual(
            self.database.get_workspace(workspace["id"])["current_account_id"],
            next_account["id"],
        )
        messages = [
            event["message"]
            for event in self.database.list_run_events(run_id=run["id"])
        ]
        self.assertIn("failed run queued for retry", messages)

    def test_account_specific_static_socks5_proxies_override_global_and_retry_stays_frozen(self):
        workspace, current, next_account = self.make_workspace("account-proxy")
        old_proxy = "s5://mother-a:old-proxy-secret@old.proxy.invalid:1080"
        new_proxy = "socks5h://mother-b:new-proxy-secret@new.proxy.invalid:1081"
        self.database.set_account_proxy(current["id"], old_proxy)
        self.database.set_account_proxy(next_account["id"], new_proxy)
        harness = RunnerHarness("fail", "success")
        queue = self.make_queue(harness)
        run = queue.enqueue([workspace["id"]])[0]

        queue.start()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        snapshot = self.database.get_run_account_proxy_snapshot(run["id"])
        first_old = harness.calls[0]["old_network"].proxy
        first_new = harness.calls[0]["new_network"].proxy
        self.assertEqual(
            first_old,
            "socks5://mother-a:old-proxy-secret@old.proxy.invalid:1080",
        )
        self.assertEqual(first_new, new_proxy)
        self.assertEqual(snapshot["current"]["source"], "account")
        self.assertEqual(snapshot["next"]["source"], "account")

        self.database.set_account_proxy(
            current["id"], "socks5://changed-old:changed@changed.invalid:1080"
        )
        self.database.set_account_proxy(
            next_account["id"], "socks5://changed-new:changed@changed.invalid:1080"
        )
        queue.retry(run["id"])

        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(run["id"])["state"] == "succeeded"
            )
        )
        self.assertEqual(
            [call["old_network"].proxy for call in harness.calls],
            [first_old, first_old],
        )
        self.assertEqual(
            [call["new_network"].proxy for call in harness.calls],
            [first_new, first_new],
        )
        events = json.dumps(self.database.list_run_events(run_id=run["id"]))
        self.assertNotIn("old-proxy-secret", events)
        self.assertNotIn("new-proxy-secret", events)

    def test_account_proxy_can_fall_back_to_global_template_per_side(self):
        workspace, current, next_account = self.make_workspace("proxy-fallback")
        self.database.set_account_proxy(
            current["id"], "socks5://static:secret@static.proxy.invalid:1080"
        )
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)
        run = queue.enqueue([workspace["id"]])[0]

        queue.start()
        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(run["id"])["state"] == "succeeded"
            )
        )

        call = harness.calls[0]
        snapshot = self.database.get_run_account_proxy_snapshot(run["id"])
        self.assertEqual(
            call["old_network"].proxy,
            "socks5://static:secret@static.proxy.invalid:1080",
        )
        self.assertIn(
            self.database.get_account_network_identity(next_account["id"])["proxy_sid"],
            call["new_network"].proxy,
        )
        self.assertEqual(snapshot["current"]["source"], "account")
        self.assertEqual(snapshot["next"]["source"], "global")

    def test_only_structured_identity_error_uses_atomic_replacement(self):
        workspace, _, _ = self.make_workspace("identity")
        identity_calls = []

        def fail_and_replace(run_id, *, role, failure_code, redacted_error):
            identity_calls.append((run_id, role, failure_code, redacted_error))
            return self.database.fail_run(run_id, redacted_error)

        self.database.fail_run_and_replace_account = fail_and_replace
        harness = RunnerHarness(
            WorkflowIdentityError("alias_disabled", "next"),
            "fail",
        )
        queue = self.make_queue(harness)
        identity_run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(identity_run["id"])["state"] == "failed"
            )
        )

        self.assertEqual(len(identity_calls), 1)
        self.assertEqual(identity_calls[0][0:3], (identity_run["id"], "next", "alias_disabled"))
        self.assertNotIn("refresh-identity", identity_calls[0][3])

    def test_transient_failure_never_calls_identity_replacement(self):
        workspace, _, _ = self.make_workspace("transient-identity")
        replacement_calls = []

        def unexpected_replacement(*args, **kwargs):
            replacement_calls.append((args, kwargs))
            raise AssertionError("transient failure attempted identity replacement")

        self.database.fail_run_and_replace_account = unexpected_replacement
        queue = self.make_queue(RunnerHarness("fail"))
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        self.assertEqual(replacement_calls, [])

    def test_structured_identity_failure_atomically_replaces_next_account(self):
        workspace, current, failed_next = self.make_workspace("identity-atomic")
        self.database.import_mailbox_inventory(
            [
                {
                    "primary_email": "replacement@example.com",
                    "client_id": "replacement-client",
                    "refresh_token": "replacement-refresh-secret",
                    "password": "replacement-mail-secret",
                    "source_order": 0,
                }
            ]
        )
        queue = self.make_queue(
            RunnerHarness(
                WorkflowIdentityError("alias_disabled", "next")
            )
        )
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        updated = self.database.get_workspace(workspace["id"])
        replacement = self.database.get_account(updated["next_account_id"])
        self.assertEqual(updated["current_account_id"], current["id"])
        self.assertNotEqual(updated["next_account_id"], failed_next["id"])
        self.assertEqual(replacement["email"], "replacement+1@example.com")
        self.assertEqual(replacement["status"], "bound_next")
        self.assertEqual(
            self.database.get_account(failed_next["id"])["status"], "disabled"
        )

    def test_identity_replacement_conflict_does_not_leave_run_running(self):
        primary = "same-primary@example.com"
        current = self.database.create_account(
            email="same-primary+1@example.com",
            primary_email=primary,
            credentials={
                "mailbox_password": "current-mail",
                "client_id": "current-client",
                "refresh_token": "current-refresh",
                "account_password": "current-account",
            },
            source="test",
        )
        next_account = self.database.create_account(
            email="same-primary+2@example.com",
            primary_email=primary,
            credentials={
                "mailbox_password": "next-mail",
                "client_id": "next-client",
                "refresh_token": "next-refresh",
                "account_password": "next-account",
            },
            source="test",
        )
        self.bind_openbrowser(next_account["id"])
        workspace = self.database.create_workspace(
            name="No replacement",
            workspace_uid="no-replacement",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        queue = self.make_queue(
            RunnerHarness(
                WorkflowIdentityError("mailbox_credentials_invalid", "current")
            )
        )
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        unresolved = self.database.get_workspace(workspace["id"])
        self.assertEqual(unresolved["current_account_id"], current["id"])
        self.assertIsNone(unresolved["next_account_id"])
        self.assertEqual(unresolved["status"], "needs_account")
        self.assertEqual(self.database.get_account(current["id"])["status"], "disabled")
        self.assertEqual(
            self.database.get_account(next_account["id"])["status"], "disabled"
        )
        self.assertEqual(
            self.database.list_queue(include_terminal=True)[0]["state"], "failed"
        )

    def test_startup_recovers_the_same_interrupted_run(self):
        workspace, _, _ = self.make_workspace("recovery")
        run = self.database.enqueue_workspace(workspace["id"])
        legacy_profile = {"profile_id": "legacy-shared-profile", "major": 142}
        legacy_geo = {
            "resolved": True,
            "country_code": "BR",
            "timezone_id": "America/Sao_Paulo",
            "locale": "pt-BR",
        }
        self.database.set_run_checkpoint(
            run["id"],
            {
                "new_login": {"done": True},
                "invite": {"done": True},
                "_fingerprint_profile": legacy_profile,
                "_proxy_geo": legacy_geo,
            },
        )
        self.database.set_run_proxy(
            run["id"], "http://fixed-user:fixed-password@proxy.invalid:9000"
        )
        self.database.claim_next_queue_item()
        self.database.request_stop(run["id"])
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)

        recovered = queue.start()

        self.assertEqual(recovered, (run["id"],))
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )
        self.assertEqual(harness.calls[0]["proxy"], self.database.get_run_proxy(run["id"]))
        self.assertEqual(harness.calls[0]["checkpoint_before"]["invite"], {"done": True})
        self.assertTrue(harness.calls[0]["old_network"].legacy_recovery)
        self.assertTrue(harness.calls[0]["new_network"].legacy_recovery)
        self.assertEqual(
            harness.calls[0]["old_network"].fingerprint_profile,
            legacy_profile,
        )
        self.assertEqual(
            harness.calls[0]["old_network"].proxy,
            self.database.get_run_proxy(run["id"]),
        )
        self.assertNotIn(
            "fingerprint_profile",
            self.database.get_account_network_identity(
                workspace["current_account_id"]
            ),
        )
        self.assertIn(
            "interrupted run recovered and requeued",
            [
                event["message"]
                for event in self.database.list_run_events(run_id=run["id"])
            ],
        )

    def test_shutdown_is_bounded_and_requests_cooperative_stop(self):
        workspace, _, _ = self.make_workspace("shutdown")
        harness = RunnerHarness("ignore-stop")
        queue = self.make_queue(harness, shutdown_timeout=0.05)
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(harness.started.wait(2.0))

        started = time.monotonic()
        stopped = queue.shutdown()
        elapsed = time.monotonic() - started

        self.assertFalse(stopped)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(self.database.get_run(run["id"])["state"], "stopping")
        harness.release.set()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "cancelled")
        )
        self.assertTrue(queue.shutdown(timeout=1.0))

    def test_wait_for_change_uses_monotonic_revision(self):
        harness = RunnerHarness()
        queue = self.make_queue(harness)
        before = queue.revision
        observed = []

        waiter = threading.Thread(
            target=lambda: observed.append(queue.wait_for_change(before, timeout=1.0))
        )
        waiter.start()
        time.sleep(0.02)
        changed = queue.notify_change()
        waiter.join(1.0)

        self.assertEqual(observed, [changed])
        self.assertGreater(changed, before)

    def test_default_runner_inputs_use_snapshot_credentials_and_settings(self):
        workspace, current, next_account = self.make_workspace("inputs")
        self.database.set_text_setting("pat_name", "database-pat")
        self.database.set_text_setting("pat_ttl", "600")
        self.database.set_text_setting("invite_settle_seconds", "4.5")
        self.database.set_text_setting("sub2api_group_id", "3")
        self.database.set_text_setting("sub2api_load_factor", "9999")
        self.database.set_text_setting("sub2api_all_groups", "1")
        self.database.set_secret_setting("management_api_key", "management-secret")
        self.database.set_secret_setting("sub2api_api_key", "sub2api-admin-key")
        self.database.set_secret_setting("sub2api_totp_secret", "totp-secret")
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)
        run = queue.enqueue([workspace["id"]])[0]

        queue.start()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )

        call = harness.calls[0]
        self.assertEqual(call["config"].workspace_id, workspace["workspace_uid"])
        self.assertEqual(call["config"].pat_name, "database-pat")
        self.assertEqual(call["config"].pat_ttl, 600)
        self.assertEqual(call["config"].invite_settle_seconds, 4.5)
        self.assertEqual(call["config"].management_key, "management-secret")
        self.assertEqual(call["config"].sub2api_api_key, "sub2api-admin-key")
        self.assertEqual(call["config"].sub2api_totp_secret, "totp-secret")
        self.assertFalse(call["config"].push)
        self.assertFalse(call["config"].sub2api_push)
        self.assertEqual(call["config"].sub2api_group_id, 3)
        self.assertEqual(call["config"].sub2api_concurrency, 9999)
        self.assertEqual(call["config"].sub2api_load_factor, 9999)
        self.assertTrue(call["config"].sub2api_all_groups)
        self.assertEqual(call["old_mailbox"].registration_email, current["email"])
        self.assertEqual(call["new_mailbox"].registration_email, next_account["email"])
        self.assertEqual(call["old_mailbox"].refresh_token, "refresh-inputs-current")

    def test_run_inputs_resolve_icloud_imap_provider_and_parent_proxy(self):
        parent_proxy = "socks5h://parent:parent-proxy-secret@proxy.invalid:1080"
        profile = self.database.create_icloud_mailbox(
            name="Apple parent",
            forwarding_email="forwarding@example.com",
            secrets={
                "session": {
                    "host": "p68-maildomainws.icloud.com",
                    "dsid": "dsid",
                    "client_id": "client",
                    "client_build_number": "2536Project32",
                    "client_mastering_number": "2536B20",
                    "cookie": "icloud-session-secret",
                },
                "imap": {
                    "host": "imap.example.com",
                    "port": 993,
                    "username": "forwarding@example.com",
                    "password": "icloud-imap-secret",
                    "folder": "INBOX",
                },
                "proxy": parent_proxy,
            },
            status="ready",
        )
        accounts = [
            self.database.create_icloud_alias(
                profile["id"],
                email=f"hidden-{index}@icloud.com",
                remote_metadata={"anonymousId": f"remote-{index}"},
                label=f"Team Workflow {index}",
            )["account"]
            for index in range(2)
        ]
        profile_id = self.bind_openbrowser(accounts[1]["id"])
        workspace = self.database.create_workspace(
            name="iCloud Space",
            workspace_uid="icloud-space",
            current_account_id=accounts[0]["id"],
            next_account_id=accounts[1]["id"],
        )
        run = self.database.enqueue_workspace(workspace["id"])
        queue = self.make_queue(RunnerHarness())

        inputs = queue._build_run_inputs(run["id"])
        config, old_mailbox, new_mailbox, secrets = (
            inputs[0], inputs[1], inputs[2], inputs[-1]
        )

        self.assertEqual(old_mailbox.provider, "icloud_hme_imap")
        self.assertEqual(new_mailbox.provider, "icloud_hme_imap")
        self.assertEqual(old_mailbox.registration_email, "hidden-0@icloud.com")
        self.assertEqual(old_mailbox.imap_password, "icloud-imap-secret")
        self.assertEqual(old_mailbox.mailbox_proxy, parent_proxy)
        self.assertIn("icloud-imap-secret", secrets)
        self.assertIn(parent_proxy, secrets)
        self.assertEqual(config.openbrowser_profile_id, profile_id)
        self.assertEqual(
            config.openbrowser_base_url, "http://127.0.0.1:50325"
        )
        self.assertEqual(config.openbrowser_api_key, "openbrowser-api-secret")
        self.assertEqual(config.openbrowser_manual_timeout_seconds, 1800)
        self.assertIn("openbrowser-api-secret", secrets)

    def test_team_owner_is_passive_and_never_enters_run_inputs(self):
        parent_proxy = "socks5h://owner:owner-proxy-secret@proxy.invalid:1080"
        profile = self.database.create_icloud_mailbox(
            name="Passive owner pool",
            forwarding_email="owner-forwarding@example.com",
            secrets={
                "session": {
                    "host": "p68-maildomainws.icloud.com",
                    "dsid": "owner-dsid",
                    "client_id": "owner-client",
                    "client_build_number": "2536Project32",
                    "client_mastering_number": "2536B20",
                    "cookie": "owner-icloud-session-secret",
                },
                "imap": {
                    "host": "imap.example.com",
                    "port": 993,
                    "username": "owner-forwarding@example.com",
                    "password": "owner-imap-secret",
                    "folder": "INBOX",
                },
                "proxy": "",
            },
            status="ready",
        )
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "passive-owner@icloud.com",
                    "role": "team_owner",
                    "owner_proxy": parent_proxy,
                    "remote_metadata": {"anonymousId": "passive-owner-remote"},
                },
                {
                    "email": "executing-child-a@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "passive-owner@icloud.com",
                    "remote_metadata": {"anonymousId": "child-a-remote"},
                },
                {
                    "email": "executing-child-b@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "passive-owner@icloud.com",
                    "remote_metadata": {"anonymousId": "child-b-remote"},
                },
            ],
        )
        owner = next(item for item in imported if item["role"] == "team_owner")
        children = [item for item in imported if item["role"] == "rotating_child"]
        self.bind_openbrowser(children[1]["account_id"])
        self.assertIsNone(owner["account_id"])
        workspace = self.database.create_workspace(
            name="Passive owner workspace",
            workspace_uid="passive-owner-workspace",
            owner_alias_id=owner["id"],
            current_account_id=children[0]["account_id"],
            next_account_id=children[1]["account_id"],
        )
        run = self.database.enqueue_workspace(workspace["id"])
        normal_harness = RunnerHarness()
        rescue_harness = RunnerHarness("success")
        queue = self.make_queue(
            normal_harness,
            rescue_harness=rescue_harness,
        )

        inputs = queue._build_run_inputs(run["id"])
        old_mailbox, new_mailbox = inputs[1], inputs[2]
        self.assertEqual(old_mailbox.registration_email, "executing-child-a@icloud.com")
        self.assertEqual(new_mailbox.registration_email, "executing-child-b@icloud.com")
        self.assertNotIn("passive-owner@icloud.com", {
            old_mailbox.registration_email,
            new_mailbox.registration_email,
        })

        self.assertEqual(self.database.request_stop(run["id"]), "cancelled")
        self.database.replace_account_credentials(children[0]["account_id"], {})
        rescue_run = queue.enqueue_rescue(workspace["id"])
        self.assertEqual(rescue_run["kind"], "rescue")
        queue.start()
        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(rescue_run["id"])["state"]
                == "succeeded"
            )
        )

        self.assertEqual(normal_harness.calls, [])
        self.assertEqual(len(rescue_harness.calls), 1)
        rescue_call = rescue_harness.calls[0]
        self.assertEqual(
            rescue_call["config"].old_account.email,
            "passive-owner@icloud.com",
        )
        self.assertEqual(
            rescue_call["old_mailbox"].registration_email,
            "passive-owner@icloud.com",
        )
        self.assertEqual(rescue_call["old_mailbox"].imap_password, "owner-imap-secret")
        self.assertEqual(
            rescue_call["new_mailbox"].registration_email,
            "executing-child-b@icloud.com",
        )
        self.assertTrue(
            self.database.get_icloud_owner_network_identity(owner["id"])
        )

    def test_redact_text_removes_known_secrets_and_url_userinfo(self):
        value = (
            "token=canary https://name:password@example.invalid/path"
            "?screen_hint=signup&state=oauth-state-secret&code=callback-code"
        )
        self.assertEqual(
            redact_text(value, ("canary",)),
            "token=*** https://***@example.invalid/path"
            "?screen_hint=signup&state=***&code=***",
        )


if __name__ == "__main__":
    unittest.main()
