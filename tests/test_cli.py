from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from team_protocol.cli import build_parser, main


class CliCutoverTests(unittest.TestCase):
    def _commands(self) -> dict[str, argparse.ArgumentParser]:
        parser = build_parser()
        action = next(
            item
            for item in parser._actions
            if isinstance(item, argparse._SubParsersAction)
        )
        return dict(action.choices)

    def test_legacy_runtime_commands_and_parameters_are_absent(self) -> None:
        parser = build_parser()
        commands = self._commands()

        self.assertNotIn("workflow", commands)
        self.assertNotIn("login-otp", commands)
        self.assertNotIn("tk-gui", commands)
        self.assertTrue(
            {
                "analyze",
                "convert",
                "push",
                "push-sub2api",
                "invite",
                "leave",
                "create-token",
                "refresh-session",
                "web",
                "gui",
            }.issubset(commands)
        )

        help_text = "\n".join(
            [parser.format_help(), *(command.format_help() for command in commands.values())]
        )
        self.assertNotIn("--config", help_text)
        self.assertNotIn("--mail-account-file", help_text)
        self.assertNotIn("tk-gui", help_text)

    def test_web_routes_only_server_options(self) -> None:
        with patch("team_protocol.web_console.serve_web_console", return_value=17) as serve:
            result = main(["web", "--port", "9012", "--no-browser"])

        self.assertEqual(result, 17)
        serve.assert_called_once_with(port=9012, open_browser=False)

    def test_gui_is_web_compatibility_alias(self) -> None:
        with patch("team_protocol.web_console.serve_web_console", return_value=23) as serve:
            result = main(["gui"])

        self.assertEqual(result, 23)
        serve.assert_called_once_with(port=8765, open_browser=True)

    def test_push_sub2api_uses_encrypted_settings_and_production_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "account.sub2api.json"
            path.write_text(
                json.dumps(
                    {
                        "exported_at": "2026-07-21T00:00:00.000Z",
                        "proxies": [],
                        "accounts": [
                            {
                                "name": "user@example.com",
                                "platform": "openai",
                                "type": "oauth",
                                "concurrency": 10,
                                "priority": 1,
                                "credentials": {
                                    "access_token": "at-test",
                                    "email": "user@example.com",
                                    "chatgpt_account_id": "workspace-1",
                                },
                                "extra": {"email": "user@example.com"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            database = MagicMock()
            database.get_text_setting.side_effect = lambda key, default="": {
                "sub2api_base_url": "https://sub2api.example",
                "sub2api_email": "",
            }.get(key, default)
            database.get_secret_setting.side_effect = lambda key: {
                "sub2api_api_key": b"admin-key",
            }.get(key)
            client = MagicMock()
            client.__enter__.return_value = client
            client.push_production_account.return_value = SimpleNamespace(
                action="would-update",
                account_name="user@example.com",
                verified=False,
                concurrency=9999,
                load_factor=9999,
                group_count=4,
            )

            with (
                patch("team_protocol.cli.SecretStore"),
                patch("team_protocol.cli.Database", return_value=database),
                patch("team_protocol.cli.Sub2APIClient", return_value=client) as client_class,
            ):
                result = main(
                    [
                        "push-sub2api",
                        "--file",
                        str(path),
                        "--dry-run",
                    ]
                )

        self.assertEqual(result, 0)
        client_class.assert_called_once_with(
            "https://sub2api.example",
            "",
            "",
            timeout=30.0,
            api_key="admin-key",
        )
        client.push_production_account.assert_called_once()
        self.assertTrue(client.push_production_account.call_args.kwargs["dry_run"])

    def test_configure_sub2api_alerts_encrypts_stdin_imap_config(self) -> None:
        database = MagicMock()
        secret = json.dumps(
            {
                "host": "imap.example.com",
                "port": 993,
                "username": "monitor@example.com",
                "password": "app-password",
                "folder": "INBOX",
                "recipient": "monitor@example.com",
            }
        ).encode("utf-8")

        with (
            patch("team_protocol.cli.SecretStore"),
            patch("team_protocol.cli.Database", return_value=database),
            patch("team_protocol.cli.sys.stdin", SimpleNamespace(buffer=io.BytesIO(secret))),
        ):
            result = main(
                [
                    "configure-sub2api-alerts",
                    "--imap-json-stdin",
                    "--sender",
                    "support@yunbay.xyz",
                ]
            )

        self.assertEqual(0, result)
        database.initialize.assert_called_once_with()
        encrypted = database.set_secret_setting.call_args
        self.assertEqual("sub2api_alert_imap", encrypted.args[0])
        self.assertEqual("app-password", json.loads(encrypted.args[1])["password"])
        self.assertEqual(
            [
                ("sub2api_alert_sender", "support@yunbay.xyz"),
                ("sub2api_alert_enabled", "1"),
            ],
            [call.args for call in database.set_text_setting.call_args_list],
        )

    def test_configure_sub2api_alerts_rejects_invalid_stdin_config(self) -> None:
        database = MagicMock()

        with (
            patch("team_protocol.cli.SecretStore"),
            patch("team_protocol.cli.Database", return_value=database),
            patch(
                "team_protocol.cli.sys.stdin",
                SimpleNamespace(buffer=io.BytesIO(b'{"host":"imap.example.com"}')),
            ),
        ):
            result = main(
                [
                    "configure-sub2api-alerts",
                    "--imap-json-stdin",
                    "--sender",
                    "support@yunbay.xyz",
                ]
            )

        self.assertEqual(1, result)
        database.set_secret_setting.assert_not_called()
        database.set_text_setting.assert_not_called()


if __name__ == "__main__":
    unittest.main()
