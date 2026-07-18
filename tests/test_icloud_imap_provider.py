from __future__ import annotations

import email.utils
import imaplib
import json
import threading
import time
import unittest
from unittest import mock

import socks

from team_protocol.registrar_runtime.appleemail_provider import (
    MailboxCredentialsInvalidError,
)
from team_protocol.registrar_runtime.icloud_imap_provider import (
    ICloudImapProvider,
    ImapMailboxConfig,
    ImapOtpReader,
    _ProxyIMAP4SSL,
    _proxy_spec,
)
from team_protocol.registrar import MailboxCredentials


class FakeImap:
    def __init__(self, messages=None, *, login_error=False):
        self.messages = dict(messages or {})
        self.login_error = login_error
        self.logged_out = False

    def login(self, _username, _password):
        if self.login_error:
            raise imaplib.IMAP4.error("authentication failed with secret detail")
        return "OK", []

    def select(self, _folder, readonly=False):
        return ("OK", [b"1"]) if readonly else ("NO", [])

    def uid(self, command, *args):
        if command == "search":
            return "OK", [" ".join(self.messages).encode("ascii")]
        if command == "fetch":
            uid = str(args[0])
            raw = self.messages.get(uid)
            return ("OK", [(b"header", raw)]) if raw is not None else ("NO", [])
        raise AssertionError(command)

    def logout(self):
        self.logged_out = True


def raw_message(
    *,
    recipient,
    code,
    timestamp=None,
    html=False,
    recipient_header="Delivered-To",
    include_date=True,
):
    date_header = (
        f"Date: {email.utils.formatdate(timestamp or time.time(), usegmt=True)}\r\n"
        if include_date
        else ""
    )
    content_type = "text/html; charset=utf-8" if html else "text/plain; charset=utf-8"
    body = f"<p>Your verification code is <b>{code}</b></p>" if html else f"Your verification code is {code}"
    return (
        f"From: OpenAI <noreply@openai.com>\r\n"
        f"To: forwarding@example.com\r\n"
        f"{recipient_header}: {recipient}\r\n"
        f"Subject: Verify your email\r\n"
        f"{date_header}"
        f"Content-Type: {content_type}\r\n\r\n"
        f"{body}\r\n"
    ).encode("utf-8")


def credential(**overrides):
    value = {
        "provider": "icloud_hme_imap",
        "registration_email": "target@icloud.com",
        "forwarding_email": "forwarding@example.com",
        "imap_host": "imap.example.com",
        "imap_port": 993,
        "imap_username": "forwarding@example.com",
        "imap_password": "imap-secret",
        "imap_folder": "INBOX",
        "mailbox_proxy": "socks5h://parent:proxy-secret@proxy.invalid:1080",
    }
    value.update(overrides)
    return json.dumps(value)


class ICloudImapProviderTests(unittest.TestCase):
    def test_provider_supplies_one_precreated_hme_mailbox_to_registration(self):
        mailbox = MailboxCredentials(
            primary_email="forwarding@example.com",
            registration_email="target@icloud.com",
            client_id="",
            refresh_token="",
            provider="icloud_hme_imap",
            forwarding_email="forwarding@example.com",
            imap_host="imap.example.com",
            imap_username="forwarding@example.com",
            imap_password="imap-secret",
        )
        provider = ICloudImapProvider(accounts=[mailbox])

        email_address, auth_credential = provider.create_mailbox()

        self.assertEqual(email_address, "target@icloud.com")
        self.assertEqual(json.loads(auth_credential)["provider"], "icloud_hme_imap")
        self.assertEqual(provider.create_mailbox(), ("", ""))

    def test_reader_matches_exact_alias_and_ignores_other_alias(self):
        connection = FakeImap(
            {
                "10": raw_message(recipient="other@icloud.com", code="111111"),
                "11": raw_message(recipient="target@icloud.com", code="222222"),
            }
        )
        config = ImapMailboxConfig.from_auth_credential(
            credential(mailbox_proxy=""), "target@icloud.com"
        )
        reader = ImapOtpReader(
            config, connection_factory=lambda _config, _timeout: connection
        )

        result = reader.find_code(
            "target@icloud.com",
            sent_at_ts=time.time() - 5,
            excluded_uids=set(),
            excluded_codes=set(),
            timeout=5,
        )

        self.assertEqual(result, ("222222", "11"))
        self.assertTrue(connection.logged_out)

    def test_reader_accepts_supported_forwarding_headers(self):
        for index, header in enumerate(
            (
                "To",
                "Delivered-To",
                "X-Original-To",
                "Envelope-To",
                "Resent-To",
                "X-Envelope-To",
            ),
            start=1,
        ):
            with self.subTest(header=header):
                connection = FakeImap(
                    {
                        str(index): raw_message(
                            recipient="target@icloud.com",
                            code=f"{index:06d}",
                            recipient_header=header,
                        )
                    }
                )
                config = ImapMailboxConfig.from_auth_credential(
                    credential(mailbox_proxy=""), "target@icloud.com"
                )

                result = ImapOtpReader(
                    config,
                    connection_factory=lambda _config, _timeout: connection,
                ).find_code(
                    "target@icloud.com",
                    sent_at_ts=time.time() - 5,
                    excluded_uids=set(),
                    excluded_codes=set(),
                    timeout=5,
                )

                self.assertEqual(result, (f"{index:06d}", str(index)))

    def test_reader_filters_old_mail_and_extracts_html_code(self):
        now = time.time()
        connection = FakeImap(
            {
                "20": raw_message(
                    recipient="target@icloud.com", code="333333", timestamp=now - 300
                ),
                "21": raw_message(
                    recipient="target@icloud.com", code="444444", timestamp=now, html=True
                ),
            }
        )
        config = ImapMailboxConfig.from_auth_credential(
            credential(mailbox_proxy=""), "target@icloud.com"
        )
        result = ImapOtpReader(
            config, connection_factory=lambda _config, _timeout: connection
        ).find_code(
            "target@icloud.com",
            sent_at_ts=now - 5,
            excluded_uids=set(),
            excluded_codes=set(),
            timeout=5,
        )

        self.assertEqual(result, ("444444", "21"))

    def test_reader_rejects_message_without_date_when_send_time_is_known(self):
        connection = FakeImap(
            {
                "30": raw_message(
                    recipient="target@icloud.com",
                    code="303030",
                    include_date=False,
                )
            }
        )
        config = ImapMailboxConfig.from_auth_credential(
            credential(mailbox_proxy=""), "target@icloud.com"
        )

        result = ImapOtpReader(
            config, connection_factory=lambda _config, _timeout: connection
        ).find_code(
            "target@icloud.com",
            sent_at_ts=time.time() - 5,
            excluded_uids=set(),
            excluded_codes=set(),
            timeout=5,
        )

        self.assertIsNone(result)

    def test_reader_rejects_an_explicitly_excluded_duplicate_code(self):
        connection = FakeImap(
            {
                "40": raw_message(
                    recipient="target@icloud.com",
                    code="404040",
                )
            }
        )
        config = ImapMailboxConfig.from_auth_credential(
            credential(mailbox_proxy=""), "target@icloud.com"
        )

        result = ImapOtpReader(
            config, connection_factory=lambda _config, _timeout: connection
        ).find_code(
            "target@icloud.com",
            sent_at_ts=time.time() - 5,
            excluded_uids=set(),
            excluded_codes={"404040"},
            timeout=5,
        )

        self.assertIsNone(result)

    def test_provider_prefers_parent_proxy_and_checkpoints_consumed_uid(self):
        configs = []
        states = []

        class Reader:
            def __init__(self, config):
                configs.append(config)

            def find_code(self, *_args, excluded_uids, **_kwargs):
                return (
                    ("666666", "56")
                    if "55" in excluded_uids
                    else ("555555", "55")
                )

        provider = ICloudImapProvider(
            reader_factory=Reader,
            state_callback=states.append,
            poll_interval=0.05,
        )

        first = provider.wait_for_otp(
            credential(),
            "target@icloud.com",
            proxy="socks5h://child:secret@other.invalid:1080",
            timeout=1,
        )
        second = provider.wait_for_otp(
            credential(), "target@icloud.com", timeout=1
        )
        stop = threading.Event()
        stop.set()
        stopped = provider.wait_for_otp(
            credential(), "target@icloud.com", stop_event=stop, timeout=1
        )

        self.assertEqual(first, "555555")
        self.assertEqual(second, "666666")
        self.assertEqual(stopped, "")
        self.assertEqual(
            configs[0].proxy,
            "socks5h://parent:proxy-secret@proxy.invalid:1080",
        )
        self.assertEqual(
            states[-1]["seen_uids"]["target@icloud.com"], ["55", "56"]
        )
        self.assertNotIn("imap-secret", json.dumps(states))

    def test_explicit_empty_mailbox_proxy_does_not_inherit_workflow_proxy(self):
        config = ImapMailboxConfig.from_auth_credential(
            credential(mailbox_proxy=""),
            "target@icloud.com",
            fallback_proxy="socks5h://workflow:secret@proxy.invalid:1080",
        )

        self.assertEqual(config.proxy, "")

    def test_provider_empty_polling_stops_at_the_requested_timeout(self):
        class Reader:
            def __init__(self, _config):
                pass

            def find_code(self, *_args, **_kwargs):
                return None

        provider = ICloudImapProvider(reader_factory=Reader, poll_interval=0.05)
        started = time.monotonic()

        result = provider.wait_for_otp(
            credential(mailbox_proxy=""),
            "target@icloud.com",
            timeout=1,
        )

        elapsed = time.monotonic() - started
        self.assertEqual(result, "")
        self.assertGreaterEqual(elapsed, 0.8)
        self.assertLess(elapsed, 2.0)

    def test_imap_auth_rejection_maps_to_structured_credentials_failure(self):
        connection = FakeImap(login_error=True)
        config = ImapMailboxConfig.from_auth_credential(
            credential(mailbox_proxy=""), "target@icloud.com"
        )
        reader = ImapOtpReader(
            config, connection_factory=lambda _config, _timeout: connection
        )

        with self.assertRaises(MailboxCredentialsInvalidError) as caught:
            reader.find_code(
                "target@icloud.com",
                sent_at_ts=None,
                excluded_uids=set(),
                excluded_codes=set(),
                timeout=5,
            )
        self.assertNotIn("secret detail", str(caught.exception))

    def test_proxy_spec_preserves_authenticated_socks5_and_remote_dns(self):
        spec = _proxy_spec(
            "socks5h://user%2Bsid:password%40value@proxy.example:1080"
        )

        self.assertEqual(spec[0], socks.SOCKS5)
        self.assertEqual(spec[1:4], ("proxy.example", 1080, True))
        self.assertEqual(spec[4:], ("user+sid", "password@value"))

    def test_proxy_socket_uses_credentials_without_global_socket_patch(self):
        calls = []

        class FakeSocket:
            def set_proxy(self, *args, **kwargs):
                calls.append((args, kwargs))

            def settimeout(self, timeout):
                calls.append(("timeout", timeout))

            def connect(self, address):
                calls.append(("connect", address))

            def close(self):
                calls.append(("close",))

        class FakeContext:
            def wrap_socket(self, sock, server_hostname):
                calls.append(("tls", server_hostname))
                return sock

        connection = object.__new__(_ProxyIMAP4SSL)
        connection.proxy_url = "socks5h://parent:password@proxy.invalid:1080"
        connection.host = "imap.example.com"
        connection.port = 993
        connection.ssl_context = FakeContext()
        with mock.patch("socks.socksocket", return_value=FakeSocket()):
            connection._create_socket(7)

        proxy_call = calls[0][1]
        self.assertEqual(proxy_call["username"], "parent")
        self.assertEqual(proxy_call["password"], "password")
        self.assertEqual((proxy_call["addr"], proxy_call["port"]), ("proxy.invalid", 1080))
        self.assertIn(("connect", ("imap.example.com", 993)), calls)


if __name__ == "__main__":
    unittest.main()
