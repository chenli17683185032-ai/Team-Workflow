import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from team_protocol.database import (
    BindingConflictError,
    ConflictError,
    Database,
    InventoryDisabledError,
    RestoreValidationError,
    StaleVersionError,
    StateConflictError,
    ValidationError,
    WorkspaceActiveError,
)
import team_protocol.database as database_module
from team_protocol.migration import (
    LegacyAccountBinding,
    LegacyConfig,
    LegacyImportModel,
    LegacyMailboxRow,
    LegacyManagementSettings,
    LegacySub2APISettings,
    VerifiedBackup,
)


class TestSecretStore:
    def __init__(self) -> None:
        self.key = hashlib.sha256(b"database-test-key").digest()

    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        nonce = os.urandom(16)
        seed = hashlib.sha256(self.key + purpose.encode("utf-8") + nonce).digest()
        body = bytes(value ^ seed[index % len(seed)] for index, value in enumerate(plaintext))
        tag = hmac.new(
            self.key, purpose.encode("utf-8") + nonce + body, hashlib.sha256
        ).digest()
        return b"TEST1" + nonce + tag + body

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        if not ciphertext.startswith(b"TEST1"):
            raise ValueError("invalid ciphertext")
        nonce = ciphertext[5:21]
        tag = ciphertext[21:53]
        body = ciphertext[53:]
        expected = hmac.new(
            self.key, purpose.encode("utf-8") + nonce + body, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("invalid ciphertext")
        seed = hashlib.sha256(self.key + purpose.encode("utf-8") + nonce).digest()
        return bytes(value ^ seed[index % len(seed)] for index, value in enumerate(body))


class FailingRotationDatabase(Database):
    fail_before_commit = False

    def _before_rotation_commit(self, connection, run_id):
        del connection, run_id
        if self.fail_before_commit:
            raise RuntimeError("injected rotation failure")


class FailingImportDatabase(Database):
    fail_import = False

    def _before_legacy_import_commit(self, connection, migration_id):
        del connection, migration_id
        if self.fail_import:
            raise RuntimeError("injected import failure")


class FailingSchemaUpgradeDatabase(Database):
    fail_upgrade = False

    def _before_schema_migration_commit(self, connection, from_version, to_version):
        del connection, from_version, to_version
        if self.fail_upgrade:
            raise RuntimeError("injected schema upgrade failure")


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / "nested" / "console.db"
        self.database = Database(self.path, secret_store=TestSecretStore())

    def create_account(self, suffix: str) -> dict:
        return self.database.create_account(
            account_id=f"account-{suffix}",
            email=f"person+{suffix}@example.com",
            primary_email="person@example.com",
            credentials={
                "password": f"password-{suffix}",
                "client_id": f"client-{suffix}",
                "refresh_token": f"refresh-{suffix}",
            },
            source="test",
        )

    def create_workspace(self, suffix: str) -> tuple[dict, dict, dict]:
        current = self.create_account(f"{suffix}-current")
        next_account = self.create_account(f"{suffix}-next")
        workspace = self.database.create_workspace(
            workspace_id=f"workspace-{suffix}",
            name=f"Space {suffix}",
            workspace_uid=f"workspace-uid-{suffix}",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        return workspace, current, next_account

    @staticmethod
    def inventory_record(primary_email: str, source_order: int = 0) -> dict:
        local = primary_email.split("@", 1)[0].casefold()
        return {
            "primary_email": primary_email,
            "password": f"mailbox-{local}",
            "client_id": f"client-{local}",
            "refresh_token": f"refresh-{local}",
            "source_order": source_order,
        }

    @staticmethod
    def icloud_secret(suffix: str, *, proxy: str | None = None) -> dict:
        return {
            "session": {
                "host": "p68-maildomainws.icloud.com",
                "dsid": f"dsid-{suffix}",
                "client_id": f"client-{suffix}",
                "client_build_number": "2536Project32",
                "client_mastering_number": "2536B20",
                "cookie": f"icloud-cookie-secret-{suffix}",
                "lang_code": "en-us",
                "origin": "https://www.icloud.com",
                "referer": "https://www.icloud.com/",
                "user_agent": "Browser Test",
            },
            "imap": {
                "host": "imap.example.com",
                "port": 993,
                "username": f"forward-{suffix}@example.com",
                "password": f"imap-password-secret-{suffix}",
                "folder": "INBOX",
            },
            "proxy": (
                f"socks5h://parent-{suffix}:proxy-password-secret-{suffix}@proxy.invalid:1080"
                if proxy is None
                else proxy
            ),
        }

    def assert_secret_absent_from_database_files(self, secret: str) -> None:
        encoded = secret.encode("utf-8")
        for path in self.path.parent.glob(f"{self.path.name}*"):
            if path.is_file():
                self.assertNotIn(encoded, path.read_bytes(), str(path))

    def test_default_app_dir_honors_override_and_macos_convention(self):
        with mock.patch.dict(
            os.environ,
            {"TEAM_WORKFLOW_APP_DIR": "~/custom-team-workflow"},
            clear=False,
        ):
            self.assertEqual(
                database_module.default_app_dir(),
                Path("~/custom-team-workflow").expanduser(),
            )

        environment = dict(os.environ)
        environment.pop("TEAM_WORKFLOW_APP_DIR", None)
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(database_module.sys, "platform", "darwin"),
            mock.patch.object(database_module.Path, "home", return_value=Path("/Users/tester")),
        ):
            self.assertEqual(
                database_module.default_app_dir(),
                Path("/Users/tester/Library/Application Support/TeamWorkflowConsole"),
            )

    def legacy_model(self, *, with_state: bool = True) -> LegacyImportModel:
        root = Path(self.temporary_directory.name) / "legacy"
        root.mkdir(parents=True, exist_ok=True)
        main = LegacyMailboxRow(
            primary_email="main@example.com",
            password="mailbox-secret-main",
            client_id="client-secret-main",
            refresh_token="refresh-secret-main",
        )
        other = LegacyMailboxRow(
            primary_email="other@example.com",
            password="mailbox-secret-other",
            client_id="client-secret-other",
            refresh_token="refresh-secret-other",
        )
        old = LegacyAccountBinding(
            registration_email="main+3@example.com",
            primary_email=main.primary_email,
            account_password="account-secret-old",
            mailbox=main,
        )
        new = LegacyAccountBinding(
            registration_email="main+4@example.com",
            primary_email=main.primary_email,
            account_password="account-secret-new",
            mailbox=main,
        )
        config = LegacyConfig(
            config_path=root / "workflow.json",
            mail_account_file=root / "hotmail.txt",
            workspace_id="legacy-workspace-uid",
            old_email=old.registration_email,
            new_email=new.registration_email,
            old_password=old.account_password,
            new_password=new.account_password,
            proxy="socks5h://user:proxy-secret@proxy.invalid:9000",
            pat_name="migration-pat",
            pat_ttl=3600,
            output_dir=root / "output",
            state_path=root / "output" / ".state" / "legacy.json",
            state_is_app_owned=True,
            invite_settle_seconds=3.5,
            management=LegacyManagementSettings(
                base_url="https://management.invalid",
                api_key="management-secret",
                push=False,
                replace=True,
                remote_name="remote.json",
            ),
            sub2api=LegacySub2APISettings(
                base_url="https://sub2api.invalid",
                email="admin@example.com",
                password="sub2-secret",
                api_key="sub2-api-key",
                totp_secret="sub2-totp-secret",
                push=True,
                concurrency=30,
                priority=2,
            ),
        )
        state = (
            {
                "version": 1,
                "steps": {
                    "_fingerprint_profile": {"profile_id": "fingerprint-secret"},
                    "old_login": {"session": "state-secret"},
                    "complete": {"workspace_id": config.workspace_id},
                },
            }
            if with_state
            else None
        )
        return LegacyImportModel(
            config=config,
            mailboxes=(main, other),
            old_binding=old,
            new_binding=new,
            state=state,
            migration_id=hashlib.sha256(b"database-legacy-fixture").hexdigest(),
        )

    def backup_candidate(self, database: Database, model: LegacyImportModel) -> VerifiedBackup:
        return VerifiedBackup(
            schema_version=int(database.get_meta("schema_version") or 0),
            instance_id=str(database.get_meta("instance_id")),
            created_at="2026-07-12T12:00:00Z",
            migration_id=model.migration_id,
            identity={
                "workspace_id": model.config.workspace_id,
                "old_email": model.config.old_email,
                "new_email": model.config.new_email,
            },
            sources=(),
            sqlite_snapshot=database.create_snapshot_bytes(),
            payload_sha256="fixture",
        )

    def test_schema_initialization_is_idempotent_and_uses_required_pragmas(self):
        instance_id = self.database.get_meta("instance_id")
        self.database.initialize()
        diagnostics = self.database.diagnostics()

        self.assertEqual(diagnostics["schema_version"], database_module.SCHEMA_VERSION)
        self.assertEqual(diagnostics["journal_mode"], "wal")
        self.assertTrue(diagnostics["foreign_keys"])
        self.assertEqual(diagnostics["busy_timeout_ms"], 5000)
        self.assertEqual(self.database.get_meta("instance_id"), instance_id)

    def test_text_and_encrypted_settings_never_share_storage_columns(self):
        canary = "setting-secret-canary-923847"
        self.database.set_text_setting("output_dir", "output")
        self.database.set_secret_setting("proxy", canary)

        self.assertEqual(self.database.get_text_setting("output_dir"), "output")
        self.assertEqual(self.database.get_secret_setting("proxy"), canary.encode())
        self.assertEqual(
            self.database.list_settings(),
            [
                {
                    "key": "output_dir",
                    "value": "output",
                    "encrypted": False,
                    "configured": False,
                    "updated_at": self.database.list_settings()[0]["updated_at"],
                },
                {
                    "key": "proxy",
                    "value": None,
                    "encrypted": True,
                    "configured": True,
                    "updated_at": self.database.list_settings()[1]["updated_at"],
                },
            ],
        )
        self.assertNotIn(canary.encode(), self.path.read_bytes())
        with self.assertRaises(StateConflictError):
            self.database.get_text_setting("proxy")
        self.assertTrue(self.database.delete_setting("proxy"))
        self.assertFalse(self.database.delete_setting("proxy"))
        self.assertNotIn("proxy", {row["key"] for row in self.database.list_settings()})

    def test_icloud_mailbox_alias_and_resolved_credentials_are_encrypted(self):
        profile = self.database.create_icloud_mailbox(
            mailbox_id="icloud-profile-one",
            name="Apple parent one",
            forwarding_email="forward-one@example.com",
            secrets=self.icloud_secret("one"),
            status="ready",
        )
        created = self.database.create_icloud_alias(
            profile["id"],
            email="hidden-one@icloud.com",
            remote_metadata={
                "hme": "hidden-one@icloud.com",
                "anonymousId": "remote-anonymous-secret-one",
                "recipientMailId": "remote-recipient-secret-one",
            },
            label="Team Workflow one",
        )
        account = created["account"]

        self.assertEqual(profile["status"], "ready")
        self.assertTrue(profile["session_configured"])
        self.assertTrue(profile["imap_configured"])
        self.assertTrue(profile["proxy_configured"])
        self.assertEqual(self.database.get_icloud_mailbox(profile["id"])["alias_count"], 1)
        self.assertEqual(account["source"], "icloud_hme")
        self.assertTrue(account["proxy_configured"])
        base_credentials = self.database.get_account_credentials(account["id"])
        self.assertEqual(base_credentials["icloud_mailbox_id"], profile["id"])
        self.assertNotIn("imap_password", base_credentials)
        resolved = self.database.get_resolved_account_credentials(account["id"])
        self.assertEqual(resolved["provider"], "icloud_hme_imap")
        self.assertEqual(resolved["imap_password"], "imap-password-secret-one")
        self.assertEqual(
            resolved["mailbox_proxy"],
            "socks5h://parent-one:proxy-password-secret-one@proxy.invalid:1080",
        )
        remote = self.database.get_icloud_alias_remote(created["alias"]["id"])
        self.assertEqual(remote["anonymousId"], "remote-anonymous-secret-one")
        serialized_views = json.dumps(
            {
                "profiles": self.database.list_icloud_mailboxes(),
                "aliases": self.database.list_icloud_aliases(profile["id"]),
                "account": account,
            }
        )
        for secret in (
            "icloud-cookie-secret-one",
            "imap-password-secret-one",
            "proxy-password-secret-one",
            "remote-anonymous-secret-one",
            "remote-recipient-secret-one",
        ):
            self.assertNotIn(secret, serialized_views)
            self.assert_secret_absent_from_database_files(secret)

    def test_icloud_profile_updates_are_resolved_without_duplicating_account_secrets(self):
        profile = self.database.create_icloud_mailbox(
            name="Apple parent",
            forwarding_email="forward-update@example.com",
            secrets=self.icloud_secret("before"),
            status="ready",
        )
        account = self.database.create_icloud_alias(
            profile["id"],
            email="hidden-update@icloud.com",
            remote_metadata={"anonymousId": "remote-update"},
            label="Team Workflow update",
        )["account"]
        before = self.database.get_account_credentials(account["id"])

        updated_secret = self.icloud_secret("after")
        updated = self.database.update_icloud_mailbox(
            profile["id"], name="Apple parent refreshed", secrets=updated_secret
        )
        self.assertEqual(updated["status"], "unchecked")
        with self.assertRaises(StateConflictError):
            self.database.get_resolved_account_credentials(account["id"])
        self.database.set_icloud_mailbox_status(profile["id"], "ready", checked=True)
        resolved = self.database.get_resolved_account_credentials(account["id"])

        self.assertEqual(
            self.database.get_account_credentials(account["id"]), before
        )
        self.assertEqual(resolved["imap_password"], "imap-password-secret-after")
        self.assertEqual(resolved["forwarding_email"], "forward-update@example.com")
        with self.assertRaises(StateConflictError):
            self.database.update_icloud_mailbox(
                profile["id"], forwarding_email="different@example.com"
            )

    def test_icloud_name_only_update_preserves_detection_status(self):
        profile = self.database.create_icloud_mailbox(
            name="Apple parent",
            forwarding_email="forward-name@example.com",
            secrets=self.icloud_secret("name-only"),
            status="ready",
        )
        checked = self.database.set_icloud_mailbox_status(
            profile["id"], "ready", checked=True
        )

        updated = self.database.update_icloud_mailbox(
            profile["id"], name="Apple parent renamed"
        )

        self.assertEqual(updated["name"], "Apple parent renamed")
        self.assertEqual(updated["status"], "ready")
        self.assertEqual(updated["last_checked_at"], checked["last_checked_at"])

    def test_icloud_invalid_profile_is_skipped_during_binding_and_replacement(self):
        first_profile = self.database.create_icloud_mailbox(
            name="First Apple parent",
            forwarding_email="shared-forward@example.com",
            secrets=self.icloud_secret("first"),
            status="ready",
        )
        first_accounts = [
            self.database.create_icloud_alias(
                first_profile["id"],
                email=f"first-hidden-{index}@icloud.com",
                remote_metadata={"anonymousId": f"remote-first-{index}"},
                label=f"Team Workflow first {index}",
            )["account"]
            for index in range(2)
        ]
        second_profile = self.database.create_icloud_mailbox(
            name="Second Apple parent",
            forwarding_email="other-forward@example.com",
            secrets=self.icloud_secret("second"),
            status="ready",
        )
        second_account = self.database.create_icloud_alias(
            second_profile["id"],
            email="second-hidden@icloud.com",
            remote_metadata={"anonymousId": "remote-second"},
            label="Team Workflow second",
        )["account"]
        workspace = self.database.create_workspace(
            name="iCloud rotation",
            workspace_uid="icloud-rotation",
            current_account_id=first_accounts[0]["id"],
            next_account_id=first_accounts[1]["id"],
        )

        result = self.database.replace_workspace_account(
            workspace["id"],
            role="next",
            failure_code="mailbox_credentials_invalid",
            expected_version=workspace["version"],
        )

        self.assertEqual(result["replacement"]["id"], second_account["id"])
        self.assertEqual(
            self.database.get_icloud_mailbox(first_profile["id"])["status"],
            "imap_invalid",
        )
        with self.assertRaises(StateConflictError):
            self.database.get_resolved_account_credentials(first_accounts[0]["id"])
        spare_profile = self.database.create_icloud_mailbox(
            name="Unchecked Apple parent",
            forwarding_email="unchecked@example.com",
            secrets=self.icloud_secret("unchecked"),
            status="ready",
        )
        spare = self.database.create_icloud_alias(
            spare_profile["id"],
            email="unchecked-hidden@icloud.com",
            remote_metadata={"anonymousId": "remote-unchecked"},
            label="Team Workflow unchecked",
        )["account"]
        self.database.set_icloud_mailbox_status(spare_profile["id"], "session_invalid")
        with self.assertRaises(InventoryDisabledError):
            self.database.create_workspace(
                name="Blocked",
                workspace_uid="blocked-icloud-profile",
                current_account_id=spare["id"],
            )

    def test_icloud_team_owner_children_and_used_pool_form_a_closed_handoff(self):
        profile = self.database.create_icloud_mailbox(
            name="Shared Apple pool",
            forwarding_email="forward-team@example.com",
            secrets=self.icloud_secret("shared-team"),
            status="ready",
        )
        owner_proxy = (
            "socks5h://team-owner-a:owner-proxy-secret@proxy.invalid:1080"
        )
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "owner-a@icloud.com",
                    "role": "team_owner",
                    "owner_proxy": owner_proxy,
                    "remote_metadata": {
                        "hme": "owner-a@icloud.com",
                        "anonymousId": "owner-a-remote-secret",
                        "isActive": True,
                        "label": "Team owner A",
                    },
                },
                {
                    "email": "current-a@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "owner-a@icloud.com",
                    "remote_metadata": {
                        "hme": "current-a@icloud.com",
                        "anonymousId": "current-a-remote-secret",
                        "isActive": True,
                        "label": "Current child A",
                    },
                },
            ],
        )
        owner = next(item for item in imported if item["role"] == "team_owner")
        current_alias = next(
            item for item in imported if item["role"] == "rotating_child"
        )
        self.assertIsNone(owner["account_id"])
        self.assertTrue(owner["proxy_configured"])
        self.assertEqual(current_alias["parent_owner_alias_id"], owner["id"])
        self.assertEqual(
            self.database.get_account_proxy(current_alias["account_id"]), owner_proxy
        )

        workspace = self.database.create_workspace(
            name="Team owner A workspace",
            workspace_uid="team-owner-a-workspace",
            owner_alias_id=owner["id"],
            current_account_id=current_alias["account_id"],
        )
        self.assertEqual(workspace["status"], "needs_account")
        self.assertIsNone(workspace["next_account_id"])

        prepared = self.database.prepare_icloud_workspace_handoff(
            workspace["id"],
            expected_version=workspace["version"],
            email="fresh-a@icloud.com",
            remote_metadata={
                "hme": "fresh-a@icloud.com",
                "anonymousId": "fresh-a-remote-secret",
                "isActive": True,
            },
            label="Team owner A handoff 1",
        )
        fresh_alias = prepared["alias"]
        self.assertEqual(prepared["workspace"]["status"], "ready")
        self.assertEqual(
            prepared["workspace"]["next_account_id"], fresh_alias["account_id"]
        )
        self.assertEqual(fresh_alias["parent_owner_alias_id"], owner["id"])
        self.assertEqual(
            self.database.get_account_proxy(fresh_alias["account_id"]), owner_proxy
        )

        run = self.database.enqueue_rescue_workspace(workspace["id"])
        self.assertEqual(run["kind"], "rescue")
        self.database.claim_next_queue_item()
        self.database.complete_run_and_rotate(run["id"])
        rotated = self.database.get_workspace(workspace["id"])
        used = self.database.get_icloud_alias(current_alias["id"])

        self.assertEqual(rotated["current_account_id"], fresh_alias["account_id"])
        self.assertIsNone(rotated["next_account_id"])
        self.assertEqual(rotated["status"], "needs_account")
        self.assertEqual(rotated["used_child_count"], 1)
        self.assertIsNotNone(used["used_at"])
        self.assertEqual(used["state"], "active")
        self.assertEqual(
            self.database.get_account(current_alias["account_id"])["status"],
            "retired",
        )
        with self.assertRaises(StateConflictError):
            self.database.transition_account_status(
                current_alias["account_id"], "available"
            )

    def test_generated_owner_proxy_config_is_encrypted_and_updates_active_children(self):
        profile = self.database.create_icloud_mailbox(
            name="Generated source pool",
            forwarding_email="generated-forward@example.com",
            secrets=self.icloud_secret("generated-owner", proxy=""),
            status="ready",
        )
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "generated-owner@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "generated-owner@icloud.com",
                        "anonymousId": "generated-owner-remote",
                    },
                },
                {
                    "email": "generated-child@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "generated-owner@icloud.com",
                    "remote_metadata": {
                        "hme": "generated-child@icloud.com",
                        "anonymousId": "generated-child-remote",
                    },
                },
            ],
        )
        owner = next(item for item in imported if item["role"] == "team_owner")
        child = next(item for item in imported if item["role"] == "rotating_child")
        source_url = (
            "https://gen.lokiproxy.com/gen?region=JP&token=owner-source-secret"
        )
        listener = "socks5://127.0.0.1:18881"

        updated = self.database.set_icloud_owner_proxy_config(
            owner["id"],
            {
                "version": 1,
                "mode": "lokiproxy_generator",
                "owner_id": owner["id"],
                "source_url": source_url,
                "bootstrap_name": "JP 22 GMO",
                "bootstrap_port": 18781,
                "listener_port": 18881,
                "effective_proxy": listener,
            },
        )

        self.assertTrue(updated["proxy_configured"])
        self.assertEqual(self.database.get_icloud_owner_proxy(owner["id"]), listener)
        self.assertEqual(self.database.get_account_proxy(child["account_id"]), listener)
        config = self.database.get_icloud_owner_proxy_config(owner["id"])
        self.assertEqual(config["mode"], "clash_chain")
        self.assertEqual(config["source_url"], source_url)
        self.assertEqual(len(self.database.list_icloud_owner_proxy_configs()), 1)
        self.assertFalse(
            any(
                str(item["key"]).startswith("icloud-owner-proxy-config:")
                for item in self.database.list_settings()
            )
        )
        self.assert_secret_absent_from_database_files("owner-source-secret")

        direct = "socks5://direct-user:direct-secret@proxy.invalid:1080"
        self.database.set_icloud_owner_proxy(owner["id"], direct)
        self.assertEqual(
            self.database.get_icloud_owner_proxy_config(owner["id"])["mode"],
            "direct",
        )
        self.assertEqual(self.database.get_account_proxy(child["account_id"]), direct)
        self.assertEqual(self.database.list_icloud_owner_proxy_configs(), [])

        first_identity = self.database.ensure_icloud_owner_network_identity(
            owner["id"], proxy_sid="OwnerRescue90"
        )
        second_identity = self.database.ensure_icloud_owner_network_identity(
            owner["id"], proxy_sid="IgnoredRescue91"
        )
        self.assertEqual(first_identity, second_identity)
        merged_identity = self.database.merge_icloud_owner_network_identity(
            owner["id"],
            {
                "proxy_geo": {
                    "resolved": True,
                    "country_code": "JP",
                    "timezone_id": "Asia/Tokyo",
                    "locale": "ja-JP",
                }
            },
        )
        self.assertEqual(merged_identity["proxy_sid"], "OwnerRescue90")
        self.assertFalse(
            any(
                str(item["key"]).startswith("icloud-owner-runtime-identity:")
                for item in self.database.list_settings()
            )
        )
        self.assert_secret_absent_from_database_files("OwnerRescue90")

    def test_icloud_team_owner_workspace_rejects_another_owners_child(self):
        profile = self.database.create_icloud_mailbox(
            name="Shared Apple pool",
            forwarding_email="forward-reject@example.com",
            secrets=self.icloud_secret("shared-reject"),
            status="ready",
        )
        imported = self.database.import_icloud_aliases(
            profile["id"],
            [
                {
                    "email": "owner-one@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "owner-one@icloud.com",
                        "anonymousId": "owner-one-id",
                    },
                },
                {
                    "email": "owner-two@icloud.com",
                    "role": "team_owner",
                    "remote_metadata": {
                        "hme": "owner-two@icloud.com",
                        "anonymousId": "owner-two-id",
                    },
                },
                {
                    "email": "child-two@icloud.com",
                    "role": "rotating_child",
                    "parent_owner_email": "owner-two@icloud.com",
                    "remote_metadata": {
                        "hme": "child-two@icloud.com",
                        "anonymousId": "child-two-id",
                    },
                },
            ],
        )
        owner_one = next(
            item for item in imported if item["email"] == "owner-one@icloud.com"
        )
        child_two = next(
            item for item in imported if item["email"] == "child-two@icloud.com"
        )

        with self.assertRaises(StateConflictError):
            self.database.create_workspace(
                name="Mismatched team",
                workspace_uid="mismatched-team",
                owner_alias_id=owner_one["id"],
                current_account_id=child_two["account_id"],
            )

    def test_v5_icloud_aliases_upgrade_to_unassigned_rotating_children(self):
        legacy_path = Path(self.temporary_directory.name) / "v5-upgrade.db"
        store = TestSecretStore()
        with mock.patch.object(database_module, "SCHEMA_VERSION", 5):
            Database(legacy_path, secret_store=store)
            mailbox_id = "legacy-v5-mailbox"
            account_id = "legacy-v5-account"
            alias_id = "legacy-v5-alias"
            remote_purpose = f"icloud-alias:{alias_id}:remote"
            remote_blob = store.encrypt(
                json.dumps(
                    {"anonymousId": "legacy-child-remote"},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode(),
                remote_purpose,
            )
            mailbox_purpose = f"icloud-mailbox:{mailbox_id}:secrets"
            mailbox_blob = store.encrypt(
                json.dumps(
                    self.icloud_secret("legacy-v5"),
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode(),
                mailbox_purpose,
            )
            account_purpose = f"account:{account_id}:credentials"
            account_blob = store.encrypt(
                json.dumps(
                    {"provider": "icloud_hme_imap"},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode(),
                account_purpose,
            )
            timestamp = database_module._now()
            connection = sqlite3.connect(legacy_path)
            try:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    """
                    INSERT INTO icloud_mailboxes(
                        id, name, forwarding_email, secret_blob, secret_purpose,
                        proxy_configured, status, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, 1, 'ready', ?, ?)
                    """,
                    (
                        mailbox_id,
                        "Legacy Apple pool",
                        "legacy-forward@example.com",
                        sqlite3.Binary(mailbox_blob),
                        mailbox_purpose,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO accounts(
                        id, email, primary_email, credential_blob, status, source,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, ?, 'available', 'icloud_hme', ?, ?)
                    """,
                    (
                        account_id,
                        "legacy-child@icloud.com",
                        "legacy-forward@example.com",
                        sqlite3.Binary(account_blob),
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO icloud_aliases(
                        id, mailbox_id, account_id, email, remote_blob,
                        remote_purpose, state, label, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                    """,
                    (
                        alias_id,
                        mailbox_id,
                        account_id,
                        "legacy-child@icloud.com",
                        sqlite3.Binary(remote_blob),
                        remote_purpose,
                        "Legacy child",
                        timestamp,
                        timestamp,
                    ),
                )
                connection.commit()
            finally:
                connection.close()

        upgraded = Database(legacy_path, secret_store=store)
        alias = upgraded.get_icloud_alias(alias_id)

        self.assertEqual(upgraded.diagnostics()["schema_version"], 7)
        self.assertEqual(alias["role"], "rotating_child")
        self.assertIsNone(alias["parent_owner_alias_id"])
        self.assertIsNone(alias["used_at"])
        self.assertEqual(alias["account_id"], account_id)

    def test_account_credentials_are_encrypted_and_email_is_case_insensitive_unique(self):
        account = self.create_account("one")
        credentials = self.database.get_account_credentials(account["id"])

        self.assertEqual(credentials["refresh_token"], "refresh-one")
        self.assertNotIn(b"refresh-one", self.path.read_bytes())
        with self.assertRaises(ConflictError):
            self.database.create_account(
                email="PERSON+ONE@EXAMPLE.COM",
                primary_email="person@example.com",
                credentials={"password": "other"},
                source="test",
            )

    def test_account_network_identity_is_encrypted_stable_and_write_once(self):
        account = self.create_account("network")
        first = self.database.ensure_account_network_identity(
            account["id"],
            proxy_sid="Account90",
        )
        second = self.database.ensure_account_network_identity(
            account["id"],
            proxy_sid="Ignored99",
        )
        geo = {
            "resolved": True,
            "country_code": "BR",
            "timezone_id": "America/Sao_Paulo",
            "locale": "pt-BR",
        }
        profile = {
            "profile_id": "account-fingerprint-90",
            "major": 145,
            "timezone_id": "America/Sao_Paulo",
        }

        updated = self.database.merge_account_network_identity(
            account["id"],
            {"proxy_geo": geo, "fingerprint_profile": profile},
        )
        repeated = self.database.merge_account_network_identity(
            account["id"],
            {"proxy_geo": geo, "fingerprint_profile": profile},
        )

        self.assertEqual(first["proxy_sid"], "Account90")
        self.assertEqual(second["proxy_sid"], "Account90")
        self.assertEqual(updated, repeated)
        self.assertEqual(updated["version"], 1)
        self.assertEqual(updated["proxy_geo"], geo)
        self.assertEqual(updated["fingerprint_profile"], profile)
        self.assertEqual(
            self.database.get_account_network_identity(account["id"]),
            updated,
        )
        self.database.replace_account_credentials(
            account["id"],
            {"refresh_token": "replacement-refresh"},
        )
        self.assertEqual(
            self.database.get_account_network_identity(account["id"]),
            updated,
        )
        raw = b"".join(
            path.read_bytes() for path in self.path.parent.glob("console.db*")
            if path.is_file()
        )
        self.assertNotIn(b"Account90", raw)
        self.assertNotIn(b"account-fingerprint-90", raw)

        with self.assertRaises(StateConflictError):
            self.database.merge_account_network_identity(
                account["id"],
                {"proxy_sid": "Different90"},
            )

    def test_account_manual_lifecycle_blocks_bound_accounts(self):
        current = self.create_account("current")
        next_account = self.create_account("next")
        self.database.create_workspace(
            name="Space",
            workspace_uid="workspace-uid",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )

        with self.assertRaises(StateConflictError):
            self.database.transition_account_status(current["id"], "retired")
        spare = self.create_account("spare")
        self.database.transition_account_status(spare["id"], "disabled")
        self.assertEqual(
            self.database.transition_account_status(spare["id"], "available")["status"],
            "available",
        )

    def test_workspace_creation_assigns_roles_and_derives_readiness(self):
        current = self.create_account("current")
        next_account = self.create_account("next")
        workspace = self.database.create_workspace(
            workspace_id="workspace-1",
            name="Primary space",
            workspace_uid="workspace-uid",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )

        self.assertEqual(workspace["status"], "ready")
        self.assertEqual(workspace["version"], 1)
        self.assertEqual(self.database.get_account(current["id"])["status"], "bound_current")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "bound_next")

    def test_every_cross_role_binding_conflict_is_rejected(self):
        first_current = self.create_account("first-current")
        first_next = self.create_account("first-next")
        second_current = self.create_account("second-current")
        second_next = self.create_account("second-next")
        self.database.create_workspace(
            name="First",
            workspace_uid="first-uid",
            current_account_id=first_current["id"],
            next_account_id=first_next["id"],
        )

        for current_id, next_id in (
            (first_current["id"], second_next["id"]),
            (first_next["id"], second_next["id"]),
            (second_current["id"], first_current["id"]),
            (second_current["id"], first_next["id"]),
        ):
            with self.subTest(current=current_id, next=next_id):
                with self.assertRaises(BindingConflictError):
                    self.database.create_workspace(
                        name="Conflicting",
                        workspace_uid=f"conflict-{current_id}-{next_id}",
                        current_account_id=current_id,
                        next_account_id=next_id,
                    )

    def test_binding_update_is_optimistic_and_releases_replaced_accounts(self):
        old_current = self.create_account("old-current")
        old_next = self.create_account("old-next")
        new_current = self.create_account("new-current")
        workspace = self.database.create_workspace(
            name="Space",
            workspace_uid="workspace-uid",
            current_account_id=old_current["id"],
            next_account_id=old_next["id"],
        )

        updated = self.database.update_workspace_bindings(
            workspace["id"],
            current_account_id=new_current["id"],
            next_account_id=None,
            expected_version=workspace["version"],
        )

        self.assertEqual(updated["version"], 2)
        self.assertEqual(updated["status"], "needs_account")
        self.assertEqual(self.database.get_account(old_current["id"])["status"], "available")
        self.assertEqual(self.database.get_account(old_next["id"])["status"], "available")
        self.assertEqual(self.database.get_account(new_current["id"])["status"], "bound_current")
        with self.assertRaises(StaleVersionError):
            self.database.update_workspace_bindings(
                workspace["id"],
                current_account_id=new_current["id"],
                next_account_id=None,
                expected_version=workspace["version"],
            )

    def test_unified_workspace_update_preserves_uid_and_supports_explicit_next_clear(self):
        workspace, current, next_account = self.create_workspace("unified")

        renamed = self.database.update_workspace(
            workspace["id"],
            expected_version=workspace["version"],
            name="Renamed space",
        )
        self.assertEqual(renamed["name"], "Renamed space")
        self.assertEqual(renamed["workspace_uid"], workspace["workspace_uid"])
        self.assertEqual(renamed["status"], "ready")
        self.assertEqual(renamed["next_account_id"], next_account["id"])

        cleared = self.database.update_workspace(
            workspace["id"],
            expected_version=renamed["version"],
            next_account_id=None,
        )
        self.assertEqual(cleared["current_account_id"], current["id"])
        self.assertIsNone(cleared["next_account_id"])
        self.assertEqual(cleared["status"], "needs_account")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "available")

    def test_batch_enqueue_is_atomic_and_snapshots_identity(self):
        first, first_current, first_next = self.create_workspace("first")
        second, _, _ = self.create_workspace("second")

        runs = self.database.enqueue_workspaces([first["id"], second["id"]])

        self.assertEqual([run["position"] for run in runs], [0, 1])
        self.assertEqual(runs[0]["current_account_id"], first_current["id"])
        self.assertEqual(runs[0]["next_account_id"], first_next["id"])
        self.assertEqual(runs[0]["workspace_uid_snapshot"], first["workspace_uid"])
        self.assertEqual(self.database.get_workspace(first["id"])["status"], "queued")
        self.assertEqual(self.database.get_workspace(second["id"])["status"], "queued")

        valid, _, _ = self.create_workspace("valid")
        current = self.create_account("not-ready-current")
        not_ready = self.database.create_workspace(
            name="Not ready",
            workspace_uid="not-ready-uid",
            current_account_id=current["id"],
        )
        before = len(self.database.list_runs())
        with self.assertRaises(StateConflictError):
            self.database.enqueue_workspaces([valid["id"], not_ready["id"]])
        self.assertEqual(len(self.database.list_runs()), before)
        self.assertEqual(self.database.get_workspace(valid["id"])["status"], "ready")

    def test_run_checkpoint_and_proxy_are_encrypted_and_proxy_is_immutable(self):
        workspace, _, _ = self.create_workspace("encrypted-run")
        run = self.database.enqueue_workspace(workspace["id"])
        checkpoint_secret = "checkpoint-canary-712"
        proxy = "http://user:proxy-canary-931@proxy.example:9000"

        self.database.set_run_checkpoint(
            run["id"], {"session": checkpoint_secret, "completed": ["invite"]}, current_step="invite"
        )
        self.database.set_run_proxy(run["id"], proxy)
        self.database.set_run_proxy(run["id"], proxy)

        self.assertEqual(self.database.get_run_checkpoint(run["id"])["session"], checkpoint_secret)
        self.assertEqual(self.database.get_run_proxy(run["id"]), proxy)
        self.assertEqual(self.database.get_run(run["id"])["current_step"], "invite")
        self.assert_secret_absent_from_database_files(checkpoint_secret)
        self.assert_secret_absent_from_database_files(proxy)
        with self.assertRaises(StateConflictError):
            self.database.set_run_proxy(run["id"], "http://different.example:9000")

    def test_account_proxy_is_encrypted_normalized_and_clearable(self):
        account = self.create_account("independent-proxy")
        proxy = "s5://mother-a:proxy-secret@proxy-a.example:1080"

        configured = self.database.set_account_proxy(account["id"], proxy)

        self.assertTrue(configured["proxy_configured"])
        self.assertEqual(
            self.database.get_account_proxy(account["id"]),
            "socks5://mother-a:proxy-secret@proxy-a.example:1080",
        )
        self.assert_secret_absent_from_database_files("proxy-secret")
        with self.assertRaises(ValidationError):
            self.database.set_account_proxy(account["id"], "ftp://proxy.example:21")

        cleared = self.database.clear_account_proxy(account["id"])
        self.assertFalse(cleared["proxy_configured"])
        self.assertIsNone(self.database.get_account_proxy(account["id"]))

    def test_run_account_proxy_snapshot_is_encrypted_and_immutable(self):
        workspace, _, _ = self.create_workspace("proxy-snapshot")
        run = self.database.enqueue_workspace(workspace["id"])
        snapshot = {
            "version": 1,
            "current": {
                "proxy": "socks5://old:old-secret@old.example:1080",
                "source": "account",
            },
            "next": {
                "proxy": "socks5://global-{sid}:global-secret@global.example:1080",
                "source": "global",
            },
        }

        self.database.set_run_account_proxy_snapshot(run["id"], snapshot)
        self.database.set_run_account_proxy_snapshot(run["id"], snapshot)

        self.assertEqual(
            self.database.get_run_account_proxy_snapshot(run["id"]), snapshot
        )
        self.assertTrue(
            self.database.get_run(run["id"])["account_proxy_snapshot_configured"]
        )
        self.assert_secret_absent_from_database_files("old-secret")
        self.assert_secret_absent_from_database_files("global-secret")
        changed = json.loads(json.dumps(snapshot))
        changed["current"]["proxy"] = "socks5://changed.example:1080"
        with self.assertRaises(StateConflictError):
            self.database.set_run_account_proxy_snapshot(run["id"], changed)

    def test_queue_pause_fifo_claim_and_single_running(self):
        first, _, _ = self.create_workspace("fifo-first")
        second, _, _ = self.create_workspace("fifo-second")
        runs = self.database.enqueue_workspaces([first["id"], second["id"]])

        self.database.set_queue_paused(True)
        self.assertTrue(self.database.is_queue_paused())
        self.assertIsNone(self.database.claim_next_queue_item())
        self.database.set_queue_paused(False)
        claimed = self.database.claim_next_queue_item()

        self.assertEqual(claimed["run_id"], runs[0]["id"])
        self.assertEqual(claimed["state"], "running")
        self.assertIsNone(self.database.claim_next_queue_item())
        self.assertEqual(self.database.get_workspace(first["id"])["status"], "running")

    def test_concurrent_claims_cannot_create_two_running_items(self):
        workspaces = [self.create_workspace(f"race-{index}")[0] for index in range(2)]
        self.database.enqueue_workspaces([workspace["id"] for workspace in workspaces])
        barrier = threading.Barrier(3)
        results = []
        errors = []

        def claim():
            try:
                barrier.wait()
                results.append(self.database.claim_next_queue_item())
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(sum(item["state"] == "running" for item in self.database.list_queue()), 1)

    def test_queue_reorder_is_transactional(self):
        workspaces = [self.create_workspace(f"order-{index}")[0] for index in range(3)]
        runs = self.database.enqueue_workspaces([workspace["id"] for workspace in workspaces])
        original = self.database.list_queue()
        reversed_ids = [item["id"] for item in reversed(original)]

        reordered = self.database.reorder_queue(reversed_ids)

        self.assertEqual([item["id"] for item in reordered], reversed_ids)
        with self.assertRaises(StateConflictError):
            self.database.reorder_queue(reversed_ids[:-1])
        self.assertEqual([item["id"] for item in self.database.list_queue()], reversed_ids)
        self.assertEqual({item["run_id"] for item in reordered}, {run["id"] for run in runs})

    def test_pending_stop_cancels_and_active_failure_releases_next_item(self):
        first, _, _ = self.create_workspace("stop-first")
        second, _, _ = self.create_workspace("stop-second")
        runs = self.database.enqueue_workspaces([first["id"], second["id"]])
        claimed = self.database.claim_next_queue_item()

        self.assertEqual(self.database.request_stop(claimed["run_id"]), "stopping")
        failed = self.database.fail_run(claimed["run_id"], "safe failure")
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(self.database.claim_next_queue_item()["run_id"], runs[1]["id"])

        third, _, _ = self.create_workspace("stop-pending")
        pending = self.database.enqueue_workspace(third["id"])
        self.assertEqual(self.database.request_stop(pending["id"]), "cancelled")
        self.assertEqual(self.database.get_run(pending["id"])["state"], "cancelled")
        self.assertEqual(self.database.get_workspace(third["id"])["status"], "ready")

    def test_recover_interrupted_run_preserves_identity_and_checkpoint(self):
        workspace, _, _ = self.create_workspace("recover")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.set_run_checkpoint(run["id"], {"step": "login"})
        self.database.claim_next_queue_item()
        self.database.request_stop(run["id"])

        recovered = self.database.recover_interrupted_runs()

        self.assertEqual(recovered, [run["id"]])
        self.assertEqual(self.database.get_run(run["id"])["state"], "queued")
        self.assertEqual(self.database.get_run_checkpoint(run["id"]), {"step": "login"})
        self.assertEqual(self.database.list_queue()[0]["state"], "pending")

    def test_retry_reuses_failed_run_only_while_bindings_match(self):
        workspace, _, _ = self.create_workspace("retry")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.set_run_checkpoint(run["id"], {"completed": ["login"]})
        self.database.claim_next_queue_item()
        self.database.fail_run(run["id"], "redacted")

        retried = self.database.retry_run(run["id"])

        self.assertEqual(retried["id"], run["id"])
        self.assertEqual(retried["state"], "queued")
        self.assertEqual(self.database.get_run_checkpoint(run["id"]), {"completed": ["login"]})
        self.database.claim_next_queue_item()
        self.database.fail_run(run["id"], "redacted again")
        replacement = self.create_account("retry-replacement")
        latest = self.database.get_workspace(workspace["id"])
        self.database.update_workspace_bindings(
            workspace["id"],
            current_account_id=replacement["id"],
            next_account_id=latest["next_account_id"],
            expected_version=latest["version"],
        )
        with self.assertRaises(StateConflictError):
            self.database.retry_run(run["id"])

    def test_success_rotation_is_atomic_and_idempotent(self):
        workspace, current, next_account = self.create_workspace("success")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.claim_next_queue_item()

        succeeded = self.database.complete_run_and_rotate(run["id"], {"file": "result.json"})
        first_rotation = self.database.get_workspace(workspace["id"])
        repeated = self.database.complete_run_and_rotate(run["id"], {"ignored": True})

        self.assertEqual(succeeded["state"], "succeeded")
        self.assertEqual(repeated["id"], run["id"])
        self.assertEqual(first_rotation["current_account_id"], next_account["id"])
        self.assertIsNone(first_rotation["next_account_id"])
        self.assertEqual(first_rotation["rotation_count"], 1)
        self.assertEqual(self.database.get_workspace(workspace["id"])["rotation_count"], 1)
        self.assertEqual(self.database.get_account(current["id"])["status"], "exited_pending")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "bound_current")
        self.assertEqual(self.database.list_queue(), [])
        self.assertEqual(
            self.database.transition_account_status(current["id"], "available")["status"],
            "available",
        )

    def test_success_rotation_rolls_back_every_mutation_on_failure(self):
        self.database = FailingRotationDatabase(self.path, secret_store=TestSecretStore())
        workspace, current, next_account = self.create_workspace("rollback")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.claim_next_queue_item()
        self.database.fail_before_commit = True

        with self.assertRaisesRegex(RuntimeError, "injected rotation failure"):
            self.database.complete_run_and_rotate(run["id"])

        unchanged = self.database.get_workspace(workspace["id"])
        self.assertEqual(self.database.get_run(run["id"])["state"], "running")
        self.assertEqual(unchanged["current_account_id"], current["id"])
        self.assertEqual(unchanged["next_account_id"], next_account["id"])
        self.assertEqual(unchanged["rotation_count"], 0)
        self.assertEqual(self.database.get_account(current["id"])["status"], "bound_current")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "bound_next")

    def test_run_events_are_ordered_and_support_replay(self):
        workspace, _, _ = self.create_workspace("events")
        run = self.database.enqueue_workspace(workspace["id"])
        first = self.database.append_run_event(
            run["id"], step="login", level="info", message="started"
        )
        second = self.database.append_run_event(
            run["id"], step="login", level="debug", message="routine", routine=True
        )

        replay = self.database.list_run_events(run_id=run["id"], after_seq=first["seq"])

        self.assertEqual([event["seq"] for event in replay], [second["seq"]])
        self.assertTrue(replay[0]["routine"])

    def test_legacy_import_is_idempotent_and_encrypts_all_sensitive_state(self):
        model = self.legacy_model(with_state=True)

        first = self.database.apply_legacy_import(model)
        second = self.database.apply_legacy_import(model)

        self.assertEqual(first, second)
        self.assertEqual(first["counts"]["accounts"], 3)
        self.assertEqual(first["counts"]["workspaces"], 1)
        self.assertEqual(first["counts"]["runs"], 1)
        self.assertEqual(first["counts"]["queue_items"], 1)
        self.assertEqual(len(self.database.list_accounts()), 3)
        accounts = {account["email"]: account for account in self.database.list_accounts()}
        self.assertIn("main@example.com", accounts)
        self.assertNotIn("other@example.com", accounts)
        self.assertIn("main+3@example.com", accounts)
        self.assertIn("main+4@example.com", accounts)
        old_credentials = self.database.get_account_credentials(
            accounts["main+3@example.com"]["id"]
        )
        self.assertEqual(old_credentials["account_password"], "account-secret-old")
        self.assertEqual(old_credentials["refresh_token"], "refresh-secret-main")
        workspace = self.database.list_workspaces()[0]
        run = self.database.list_runs()[0]
        self.assertEqual(workspace["status"], "failed")
        self.assertEqual(run["state"], "failed")
        checkpoint = self.database.get_run_checkpoint(run["id"])
        self.assertIn("old_login", checkpoint)
        self.assertNotIn("steps", checkpoint)
        self.assertEqual(run["current_step"], "old_login")
        self.assertEqual(self.database.list_queue(include_terminal=True)[0]["state"], "failed")
        self.assertEqual(self.database.get_text_setting("pat_ttl"), "3600")
        self.assertEqual(self.database.get_secret_setting("proxy"), model.config.proxy.encode())
        self.assertEqual(
            self.database.get_secret_setting("management_api_key"), b"management-secret"
        )
        self.assertEqual(self.database.get_secret_setting("sub2api_password"), b"sub2-secret")
        self.assertEqual(self.database.get_secret_setting("sub2api_api_key"), b"sub2-api-key")
        self.assertEqual(
            self.database.get_secret_setting("sub2api_totp_secret"),
            b"sub2-totp-secret",
        )
        for secret in (
            "mailbox-secret-main",
            "client-secret-main",
            "refresh-secret-main",
            "account-secret-old",
            "account-secret-new",
            "proxy-secret",
            "management-secret",
            "sub2-secret",
            "sub2-api-key",
            "sub2-totp-secret",
            "state-secret",
        ):
            self.assert_secret_absent_from_database_files(secret)

    def test_prune_unreferenced_legacy_inventory_preserves_related_and_manual_accounts(self):
        model = self.legacy_model(with_state=False)
        self.database.apply_legacy_import(model)
        orphan = self.database.create_account(
            email="orphan@example.com",
            primary_email="orphan@example.com",
            credentials={
                "mailbox_password": "orphan-mail",
                "client_id": "orphan-client",
                "refresh_token": "orphan-refresh",
                "account_password": "",
            },
            source="legacy_txt",
        )
        manual = self.database.create_account(
            email="manual@example.com",
            primary_email="manual@example.com",
            credentials={
                "mailbox_password": "manual-mail",
                "client_id": "manual-client",
                "refresh_token": "manual-refresh",
                "account_password": "",
            },
            source="txt_import",
        )

        removed = self.database.prune_unreferenced_legacy_accounts()
        second = self.database.prune_unreferenced_legacy_accounts()

        remaining = {account["email"] for account in self.database.list_accounts()}
        self.assertEqual(removed, 1)
        self.assertEqual(second, 0)
        self.assertNotIn(orphan["email"], remaining)
        self.assertIn(manual["email"], remaining)
        self.assertIn("main@example.com", remaining)
        self.assertIn("main+3@example.com", remaining)
        self.assertIn("main+4@example.com", remaining)
        self.assertEqual(self.database.get_meta("legacy_account_scope_version"), "1")

    def test_legacy_import_disables_push_targets_without_required_secrets(self):
        model = self.legacy_model(with_state=False)
        config = replace(
            model.config,
            management=replace(model.config.management, api_key="", push=True),
            sub2api=replace(
                model.config.sub2api,
                password="",
                api_key="",
                totp_secret="",
                push=True,
            ),
        )

        self.database.apply_legacy_import(replace(model, config=config))

        self.assertEqual(self.database.get_text_setting("management_push"), "0")
        self.assertEqual(self.database.get_text_setting("sub2api_push"), "0")
        self.assertIsNone(self.database.get_secret_setting("management_api_key"))
        self.assertIsNone(self.database.get_secret_setting("sub2api_password"))
        self.assertIsNone(self.database.get_secret_setting("sub2api_api_key"))
        self.assertIsNone(self.database.get_secret_setting("sub2api_totp_secret"))

    def test_legacy_import_without_checkpoint_creates_ready_workspace(self):
        model = self.legacy_model(with_state=False)

        result = self.database.apply_legacy_import(model)

        self.assertEqual(result["counts"]["runs"], 0)
        self.assertEqual(result["counts"]["queue_items"], 0)
        self.assertEqual(self.database.list_workspaces()[0]["status"], "ready")

    def test_legacy_import_rolls_back_every_row_and_marker_on_failure(self):
        self.database = FailingImportDatabase(self.path, secret_store=TestSecretStore())
        self.database.fail_import = True
        model = self.legacy_model()

        with self.assertRaisesRegex(RuntimeError, "injected import failure"):
            self.database.apply_legacy_import(model)

        self.assertEqual(self.database.list_accounts(), [])
        self.assertEqual(self.database.list_workspaces(), [])
        self.assertEqual(self.database.list_runs(), [])
        self.assertEqual(self.database.list_queue(include_terminal=True), [])
        self.assertIsNone(self.database.get_meta("migration_id"))

    def test_legacy_import_rejects_nonfresh_or_different_migration(self):
        self.create_account("existing")
        with self.assertRaises(StateConflictError):
            self.database.apply_legacy_import(self.legacy_model())

        other_path = Path(self.temporary_directory.name) / "other.db"
        other = Database(other_path, secret_store=TestSecretStore())
        model = self.legacy_model()
        other.apply_legacy_import(model)
        different = LegacyImportModel(
            config=model.config,
            mailboxes=model.mailboxes,
            old_binding=model.old_binding,
            new_binding=model.new_binding,
            state=model.state,
            migration_id="f" * 64,
        )
        with self.assertRaises(ConflictError):
            other.apply_legacy_import(different)

    def test_snapshot_uses_live_wal_content_and_restore_replaces_database(self):
        model = self.legacy_model(with_state=False)
        self.database.apply_legacy_import(model)
        workspace = self.database.list_workspaces()[0]
        current_account = self.database.get_account(workspace["current_account_id"])
        self.database.set_account_proxy(
            current_account["id"],
            "socks5://backup-user:backup-proxy-secret@backup.proxy.invalid:1080",
        )
        run = self.database.enqueue_workspace(workspace["id"])
        proxy_snapshot = {
            "version": 1,
            "current": {
                "proxy": self.database.get_account_proxy(current_account["id"]),
                "source": "account",
            },
            "next": {"proxy": "", "source": "direct"},
        }
        self.database.set_run_account_proxy_snapshot(run["id"], proxy_snapshot)
        candidate = self.backup_candidate(self.database, model)
        self.assertTrue(candidate.sqlite_snapshot.startswith(b"SQLite format 3\x00"))

        target_path = Path(self.temporary_directory.name) / "restore" / "console.db"
        target = Database(target_path, secret_store=TestSecretStore())
        target.create_account(
            email="target-only@example.com",
            primary_email="target-only@example.com",
            credentials={"password": "target-only-secret"},
            source="test",
        )
        validation = target.validate_restore_candidate(candidate)
        with self.assertRaises(StateConflictError):
            target.restore_verified_backup(candidate, validation)
        target.set_queue_paused(True)

        result = target.restore_verified_backup(candidate, validation)

        self.assertEqual(result["status"], "restored")
        self.assertTrue(target.is_queue_paused())
        self.assertEqual(target.get_meta("migration_id"), model.migration_id)
        self.assertEqual(len(target.list_accounts()), 3)
        self.assertNotIn("target-only@example.com", {row["email"] for row in target.list_accounts()})
        self.assertEqual(result["row_counts"]["accounts"], 3)
        self.assertEqual(target.get_account_proxy(current_account["id"]), proxy_snapshot["current"]["proxy"])
        self.assertEqual(target.get_run_account_proxy_snapshot(run["id"]), proxy_snapshot)

    def test_restore_candidate_rejects_tampering_and_wrong_secret_purpose(self):
        model = self.legacy_model()
        self.database.apply_legacy_import(model)
        candidate = self.backup_candidate(self.database, model)
        truncated = VerifiedBackup(
            schema_version=candidate.schema_version,
            instance_id=candidate.instance_id,
            created_at=candidate.created_at,
            migration_id=candidate.migration_id,
            identity=candidate.identity,
            sources=(),
            sqlite_snapshot=b"X" + candidate.sqlite_snapshot[1:],
        )
        with self.assertRaises(RestoreValidationError):
            self.database.validate_restore_candidate(truncated)

        altered_path = Path(self.temporary_directory.name) / "wrong-purpose.db"
        altered_path.write_bytes(candidate.sqlite_snapshot)
        connection = sqlite3.connect(altered_path)
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            wrong_blob = self.database.secret_store.encrypt(
                b"management-secret", "setting:not-management-api-key"
            )
            connection.execute(
                "UPDATE settings SET value_blob = ? WHERE key = 'management_api_key'",
                (wrong_blob,),
            )
            connection.commit()
        finally:
            connection.close()
        wrong_purpose = VerifiedBackup(
            schema_version=candidate.schema_version,
            instance_id=candidate.instance_id,
            created_at=candidate.created_at,
            migration_id=candidate.migration_id,
            identity=candidate.identity,
            sources=(),
            sqlite_snapshot=altered_path.read_bytes(),
        )
        with self.assertRaises(RestoreValidationError):
            self.database.validate_restore_candidate(wrong_purpose)

    def test_v5_snapshot_restores_icloud_mailbox_alias_and_encrypted_secrets(self):
        model = self.legacy_model(with_state=False)
        self.database.apply_legacy_import(model)
        profile = self.database.create_icloud_mailbox(
            mailbox_id="icloud-backup-profile",
            name="Backup Apple parent",
            forwarding_email="forward-backup@example.com",
            secrets=self.icloud_secret("backup"),
            status="ready",
        )
        created = self.database.create_icloud_alias(
            profile["id"],
            email="hidden-backup@icloud.com",
            remote_metadata={
                "hme": "hidden-backup@icloud.com",
                "anonymousId": "remote-anonymous-secret-backup",
                "recipientMailId": "remote-recipient-secret-backup",
            },
            label="Team Workflow backup",
        )
        candidate = self.backup_candidate(self.database, model)

        for secret in (
            "icloud-cookie-secret-backup",
            "imap-password-secret-backup",
            "proxy-password-secret-backup",
            "remote-anonymous-secret-backup",
            "remote-recipient-secret-backup",
        ):
            self.assertNotIn(secret.encode(), candidate.sqlite_snapshot)

        target_path = Path(self.temporary_directory.name) / "icloud-restore" / "console.db"
        target = Database(target_path, secret_store=TestSecretStore())
        validation = target.validate_restore_candidate(candidate)
        target.set_queue_paused(True)
        result = target.restore_verified_backup(candidate, validation)

        restored_profile = target.get_icloud_mailbox(profile["id"])
        restored_alias = target.get_icloud_alias(created["alias"]["id"])
        restored_credentials = target.get_resolved_account_credentials(
            created["account"]["id"]
        )
        self.assertEqual(result["row_counts"]["icloud_mailboxes"], 1)
        self.assertEqual(result["row_counts"]["icloud_aliases"], 1)
        self.assertEqual(restored_profile["status"], "ready")
        self.assertEqual(restored_alias["email"], "hidden-backup@icloud.com")
        self.assertEqual(
            restored_credentials["imap_password"],
            "imap-password-secret-backup",
        )
        self.assertEqual(
            target.get_icloud_alias_remote(restored_alias["id"])["anonymousId"],
            "remote-anonymous-secret-backup",
        )

    def test_restore_rejects_candidate_changed_after_validation_and_running_queue(self):
        source_path = Path(self.temporary_directory.name) / "source.db"
        source = Database(source_path, secret_store=TestSecretStore())
        model = self.legacy_model(with_state=False)
        source.apply_legacy_import(model)
        candidate = self.backup_candidate(source, model)

        validation = self.database.validate_restore_candidate(candidate)
        changed = VerifiedBackup(
            schema_version=candidate.schema_version,
            instance_id=candidate.instance_id,
            created_at=candidate.created_at,
            migration_id=candidate.migration_id,
            identity=candidate.identity,
            sources=(),
            sqlite_snapshot=candidate.sqlite_snapshot + b"changed",
        )
        self.database.set_queue_paused(True)
        with self.assertRaises(RestoreValidationError):
            self.database.restore_verified_backup(changed, validation)

        workspace, _, _ = self.create_workspace("restore-running")
        self.database.enqueue_workspace(workspace["id"])
        self.database.set_queue_paused(False)
        self.database.claim_next_queue_item()
        self.database.set_queue_paused(True)
        with self.assertRaises(StateConflictError):
            self.database.restore_verified_backup(candidate, validation)

    def test_v1_schema_upgrades_in_order_and_rolls_back_as_one_transaction(self):
        legacy_path = Path(self.temporary_directory.name) / "v1" / "console.db"
        legacy_path.parent.mkdir(parents=True)
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            for statement in database_module._SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO app_meta(key, value) VALUES(?, ?)",
                (("schema_version", "1"), ("instance_id", "legacy-instance")),
            )
            connection.commit()
        finally:
            connection.close()

        FailingSchemaUpgradeDatabase.fail_upgrade = True
        try:
            with self.assertRaisesRegex(RuntimeError, "injected schema upgrade failure"):
                FailingSchemaUpgradeDatabase(
                    legacy_path, secret_store=TestSecretStore()
                )
        finally:
            FailingSchemaUpgradeDatabase.fail_upgrade = False

        connection = sqlite3.connect(legacy_path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM app_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "1",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='mailbox_inventory'"
                ).fetchone()
            )
        finally:
            connection.close()

        upgraded = Database(legacy_path, secret_store=TestSecretStore())
        self.assertEqual(
            upgraded.diagnostics()["schema_version"], database_module.SCHEMA_VERSION
        )
        self.assertEqual(upgraded.get_meta("instance_id"), "legacy-instance")
        upgraded.initialize()
        self.assertEqual(
            upgraded.diagnostics()["schema_version"], database_module.SCHEMA_VERSION
        )

    def test_inventory_import_search_and_credentials_are_encrypted(self):
        records = [
            self.inventory_record(f"user{index:02d}@example.com", index)
            for index in range(25)
        ]
        records.append({"primary_email": "broken", "client_id": "x"})

        imported = self.database.import_mailbox_inventory(records)
        repeated = self.database.import_mailbox_inventory(
            [self.inventory_record("USER00@EXAMPLE.COM", 999)]
        )
        results = self.database.search_mailbox_inventory(
            query="user", status="available", limit=999
        )

        self.assertEqual(
            imported,
            {"total": 26, "imported": 25, "existing": 0, "invalid": 1},
        )
        self.assertEqual(repeated["existing"], 1)
        self.assertEqual(len(results), 20)
        self.assertNotIn("credential_blob", results[0])
        self.assertNotIn("refresh_token", results[0])
        first = self.database.get_mailbox_inventory(results[0]["id"])
        credentials = self.database.get_mailbox_inventory_credentials(first["id"])
        self.assertEqual(credentials["refresh_token"], "refresh-user00")
        self.assertEqual(
            self.database.get_mailbox_inventory_summary(),
            {"total": 25, "available": 25, "disabled": 0, "exhausted": 0},
        )
        with self.assertRaises(ValidationError):
            self.database.search_mailbox_inventory(status="unknown")
        for secret in ("mailbox-user00", "client-user00", "refresh-user00"):
            self.assert_secret_absent_from_database_files(secret)

    def test_alias_allocator_is_sequential_and_switches_inventory_after_plus_five(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("first@example.com", 1),
                self.inventory_record("second@example.com", 2),
            ]
        )
        inventories = self.database.search_mailbox_inventory(limit=20)
        first = next(row for row in inventories if row["primary_email"] == "first@example.com")

        allocated = [
            self.database.allocate_mailbox_alias(first["id"])["email"]
            for _ in range(5)
        ]
        switched = self.database.allocate_mailbox_alias()

        self.assertEqual(
            allocated,
            [f"first+{number}@example.com" for number in range(1, 6)],
        )
        self.assertEqual(switched["email"], "second+1@example.com")
        exhausted = self.database.get_mailbox_inventory(first["id"])
        self.assertEqual(exhausted["status"], "exhausted")
        self.assertEqual(exhausted["next_alias_number"], 6)
        with self.assertRaises(ConflictError):
            self.database.allocate_mailbox_alias(first["id"])

    def test_concurrent_alias_allocation_never_duplicates_or_moves_cursor_backwards(self):
        self.database.import_mailbox_inventory(
            [self.inventory_record("concurrent@example.com")]
        )
        inventory = self.database.search_mailbox_inventory(query="concurrent")[0]
        other = Database(self.path, secret_store=TestSecretStore())
        barrier = threading.Barrier(2)
        results = []
        failures = []

        def allocate(database):
            try:
                barrier.wait(timeout=2)
                results.append(database.allocate_mailbox_alias(inventory["id"])["email"])
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(target=allocate, args=(database,))
            for database in (self.database, other)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)

        self.assertEqual(failures, [])
        self.assertEqual(set(results), {"concurrent+1@example.com", "concurrent+2@example.com"})
        self.assertEqual(
            self.database.get_mailbox_inventory(inventory["id"])["next_alias_number"],
            3,
        )

    def test_disabled_inventory_is_skipped_and_constraints_reject_plus_six(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("disabled@example.com", 0),
                self.inventory_record("active@example.com", 1),
            ]
        )
        inventory = self.database.search_mailbox_inventory(query="disabled")[0]
        self.database.set_mailbox_inventory_status(
            inventory["id"],
            "disabled",
            failure_code="mailbox_credentials_invalid",
            failure_message="safe message",
        )
        self.assertEqual(
            self.database.allocate_mailbox_alias()["email"],
            "active+1@example.com",
        )
        with self.assertRaises(ConflictError):
            with self.database._write_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO mailbox_alias_allocations(
                        inventory_id, alias_number, account_id, state, created_at, updated_at
                    ) VALUES(?, 6, NULL, 'allocated', 'now', 'now')
                    """,
                    (inventory["id"],),
                )

    def test_workspace_inventory_selection_allocates_only_after_version_check(self):
        current = self.create_account("inventory-current")
        self.database.import_mailbox_inventory(
            [self.inventory_record("workspace-stock@example.com")]
        )
        inventory = self.database.search_mailbox_inventory(query="workspace-stock")[0]
        workspace = self.database.create_workspace(
            name="Inventory space",
            workspace_uid="inventory-space-uid",
            current_account_id=current["id"],
            next_inventory_id=inventory["id"],
        )
        next_account = self.database.get_account(workspace["next_account_id"])
        self.assertEqual(next_account["email"], "workspace-stock+1@example.com")
        before = len(self.database.list_accounts())

        with self.assertRaises(StaleVersionError):
            self.database.update_workspace_bindings(
                workspace["id"],
                current_account_id=current["id"],
                next_account_id=None,
                next_inventory_id=inventory["id"],
                expected_version=workspace["version"] - 1,
            )
        self.assertEqual(len(self.database.list_accounts()), before)

    def test_success_rotation_promotes_and_allocates_next_alias_atomically(self):
        self.database.import_mailbox_inventory(
            [self.inventory_record("rotate@example.com")]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(5)]
        workspace = self.database.create_workspace(
            name="Rotate",
            workspace_uid="rotate-uid",
            current_account_id=aliases[2]["id"],
            next_account_id=aliases[3]["id"],
        )
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.claim_next_queue_item()

        self.database.complete_run_and_rotate(run["id"])
        rotated = self.database.get_workspace(workspace["id"])

        self.assertEqual(
            self.database.get_account(rotated["current_account_id"])["email"],
            "rotate+4@example.com",
        )
        self.assertEqual(
            self.database.get_account(rotated["next_account_id"])["email"],
            "rotate+5@example.com",
        )
        self.assertEqual(rotated["status"], "ready")
        self.assertEqual(self.database.get_account(aliases[2]["id"])["status"], "exited_pending")
        count = len(self.database.list_accounts())
        self.database.complete_run_and_rotate(run["id"])
        self.assertEqual(len(self.database.list_accounts()), count)

    def test_manual_workspace_advance_promotes_plus_five_and_switches_primary(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("first-primary@example.com", 0),
                self.inventory_record("second-primary@example.com", 1),
            ]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(5)]
        workspace = self.database.create_workspace(
            name="Manual rotation",
            workspace_uid="manual-rotation-uid",
            current_account_id=aliases[3]["id"],
            next_account_id=aliases[4]["id"],
        )

        result = self.database.advance_workspace_accounts(
            workspace["id"], expected_version=workspace["version"]
        )
        advanced = result["workspace"]
        replacement = result["replacement"]

        self.assertEqual(
            self.database.get_account(advanced["current_account_id"])["email"],
            "first-primary+5@example.com",
        )
        self.assertEqual(replacement["email"], "second-primary+1@example.com")
        self.assertEqual(advanced["next_account_id"], replacement["id"])
        self.assertEqual(advanced["rotation_count"], 1)
        self.assertEqual(advanced["version"], 2)
        self.assertEqual(advanced["status"], "ready")
        self.assertEqual(
            self.database.get_account(aliases[3]["id"])["status"],
            "exited_pending",
        )
        allocation = next(
            row
            for row in self.database.list_mailbox_alias_allocations()
            if row["account_id"] == aliases[3]["id"]
        )
        self.assertEqual(allocation["state"], "retired")

        with self.assertRaises(StaleVersionError):
            self.database.advance_workspace_accounts(
                workspace["id"], expected_version=workspace["version"]
            )
        self.assertEqual(len(self.database.list_accounts()), 6)

    def test_manual_and_failed_run_replacement_share_atomic_rotation_rules(self):
        self.database.import_mailbox_inventory(
            [self.inventory_record("replace@example.com")]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(2)]
        workspace = self.database.create_workspace(
            name="Replace",
            workspace_uid="replace-uid",
            current_account_id=aliases[0]["id"],
            next_account_id=aliases[1]["id"],
        )

        manual = self.database.replace_workspace_account(
            workspace["id"],
            role="next",
            failure_code="alias_disabled",
            expected_version=workspace["version"],
        )
        self.assertEqual(
            self.database.get_account(manual["workspace"]["next_account_id"])["email"],
            "replace+3@example.com",
        )
        self.assertEqual(self.database.get_account(aliases[1]["id"])["status"], "disabled")

        active_workspace = manual["workspace"]
        subsequent_workspace, _, _ = self.create_workspace("after-identity-failure")
        runs = self.database.enqueue_workspaces(
            [active_workspace["id"], subsequent_workspace["id"]]
        )
        run = runs[0]
        queued_workspace = self.database.get_workspace(active_workspace["id"])
        with self.assertRaises(WorkspaceActiveError):
            self.database.replace_workspace_account(
                active_workspace["id"],
                role="next",
                failure_code="alias_disabled",
                expected_version=queued_workspace["version"],
            )
        self.database.claim_next_queue_item()
        automated = self.database.fail_run_and_replace_account(
            run["id"],
            role="current",
            failure_code="mailbox_credentials_invalid",
            redacted_error="mailbox credentials rejected",
        )

        self.assertEqual(automated["run"]["state"], "failed")
        self.assertEqual(automated["workspace"]["status"], "needs_account")
        self.assertEqual(
            automated["workspace"]["current_account_id"],
            active_workspace["current_account_id"],
        )
        self.assertIsNone(automated["workspace"]["next_account_id"])
        self.assertIsNone(automated["replacement"])
        self.assertEqual(
            self.database.claim_next_queue_item()["run_id"], runs[1]["id"]
        )
        inventory = self.database.search_mailbox_inventory(query="replace")[0]
        self.assertEqual(inventory["status"], "disabled")

    def test_backfill_inventory_repairs_legacy_rotation_once(self):
        records = [
            self.inventory_record("main@example.com", 0),
            self.inventory_record("other@example.com", 1),
        ]
        primary = self.database.create_account(
            email="main@example.com",
            primary_email="main@example.com",
            credentials={"refresh_token": "legacy-primary"},
            source="legacy_txt",
        )
        self.database.transition_account_status(primary["id"], "disabled")
        manual = self.database.create_account(
            email="manual-disabled@example.com",
            primary_email="manual-disabled@example.com",
            credentials={"refresh_token": "manual"},
            source="txt_import",
        )
        self.database.transition_account_status(manual["id"], "disabled")
        aliases = {}
        for number in (3, 4, 5):
            aliases[number] = self.database.create_account(
                email=f"main+{number}@example.com",
                primary_email="main@example.com",
                credentials={"refresh_token": f"legacy-{number}"},
                source="legacy_txt",
            )
        workspace = self.database.create_workspace(
            name="Legacy",
            workspace_uid="legacy-backfill-uid",
            current_account_id=aliases[3]["id"],
            next_account_id=aliases[4]["id"],
        )

        first = self.database.backfill_mailbox_inventory(
            records,
            migration_id="a" * 64,
            expected_count=2,
            legacy_old_email="main+3@example.com",
            legacy_new_email="main+4@example.com",
        )
        second = self.database.backfill_mailbox_inventory(
            records,
            migration_id="a" * 64,
            expected_count=2,
            legacy_old_email="main+3@example.com",
            legacy_new_email="main+4@example.com",
        )

        repaired = self.database.get_workspace(workspace["id"])
        self.assertEqual(first["repair_status"], "repaired")
        self.assertEqual(second["repair_status"], "already_completed")
        self.assertEqual(first["marker"], "1")
        self.assertEqual(repaired["current_account_id"], aliases[4]["id"])
        self.assertEqual(repaired["next_account_id"], aliases[5]["id"])
        self.assertEqual(repaired["rotation_count"], 1)
        self.assertEqual(repaired["version"], 2)
        self.assertEqual(self.database.get_account(aliases[3]["id"])["status"], "exited_pending")
        self.assertNotIn(primary["id"], {row["id"] for row in self.database.list_accounts()})
        self.assertIn(manual["id"], {row["id"] for row in self.database.list_accounts()})
        inventory = self.database.search_mailbox_inventory(query="main")[0]
        self.assertEqual(inventory["next_alias_number"], 6)
        self.assertEqual(inventory["status"], "exhausted")

    def test_backfill_handles_full_inventory_scale_without_creating_accounts(self):
        records = [
            self.inventory_record(f"bulk{index:05d}@example.com", index)
            for index in range(7_211)
        ]

        result = self.database.backfill_mailbox_inventory(
            records,
            migration_id="c" * 64,
            expected_count=7_211,
        )

        self.assertEqual(result["counts"]["inventory_total"], 7_211)
        self.assertEqual(result["counts"]["imported"], 7_211)
        self.assertEqual(self.database.list_accounts(), [])
        self.assertEqual(self.database.get_mailbox_inventory_summary()["total"], 7_211)
        self.assertEqual(len(self.database.search_mailbox_inventory(query="bulk", limit=100)), 20)
        self.assert_secret_absent_from_database_files("refresh-bulk07210")

    def test_v1_snapshot_validates_and_restores_with_v2_upgrade(self):
        source_path = Path(self.temporary_directory.name) / "snapshot-v1.db"
        connection = sqlite3.connect(source_path)
        try:
            connection.execute(
                "CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            for statement in database_module._SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO app_meta(key, value) VALUES(?, ?)",
                (
                    ("schema_version", "1"),
                    ("instance_id", "snapshot-v1-instance"),
                    ("migration_id", "b" * 64),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        candidate = VerifiedBackup(
            schema_version=1,
            instance_id="snapshot-v1-instance",
            created_at="2026-07-13T00:00:00Z",
            migration_id="b" * 64,
            identity={
                "workspace_id": "legacy",
                "old_email": "old@example.com",
                "new_email": "new@example.com",
            },
            sources=(),
            sqlite_snapshot=source_path.read_bytes(),
        )

        validation = self.database.validate_restore_candidate(candidate)
        self.database.set_queue_paused(True)
        restored = self.database.restore_verified_backup(candidate, validation)

        self.assertEqual(validation.schema_version, 1)
        self.assertEqual(restored["schema_version"], database_module.SCHEMA_VERSION)
        self.assertEqual(self.database.get_meta("instance_id"), "snapshot-v1-instance")
        self.assertEqual(
            self.database.diagnostics()["schema_version"],
            database_module.SCHEMA_VERSION,
        )


if __name__ == "__main__":
    unittest.main()
