import unittest

from team_protocol.workspace_lookup import (
    WorkspaceLookupError,
    WorkspaceLookupService,
)


OWNER = "owner@icloud.com"
CHILD = "child@icloud.com"


class FakeRegistrar:
    instances = []
    login_email = CHILD

    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.login_calls = []
        self.__class__.instances.append(self)

    @staticmethod
    def resolve_proxy_geo(proxy):
        return {"resolved": True, "country_code": "JP", "proxy": proxy}

    @staticmethod
    def resolve_session_profile(*, geo_hint):
        return {"geo_hint": geo_hint}

    def login(self, **kwargs):
        self.login_calls.append(kwargs)
        return {
            "user": {"email": self.login_email},
            "account": {"id": "personal"},
            "session_token": "login-session-secret",
            "workspaces": [
                {"id": "personal"},
                {"id": "team-one"},
                {"id": "team-two"},
            ],
        }


class FakeChatGPT:
    def __init__(self, members, *, proxy, session_profile):
        self.members = members
        self.proxy = proxy
        self.session_profile = session_profile
        self.calls = []
        self.closed = False

    def refresh_session(self, session_token, *, account_id=None):
        self.calls.append(("refresh", session_token, account_id))
        selected = account_id or "personal"
        return {
            "user": {"email": CHILD},
            "account": {"id": selected},
            "accessToken": f"access-{selected}-secret",
            "sessionToken": f"session-{selected}-secret",
        }

    def get_members(self, access_token, account_id):
        self.calls.append(("members", access_token, account_id))
        return self.members[account_id]

    def close(self):
        self.closed = True


class FakeFetcher:
    def __init__(self):
        self.calls = []

    def fetch(self, source_url, bootstrap_proxy):
        self.calls.append((source_url, bootstrap_proxy))
        return object()


class FakeRelay:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        self.effective_proxy = f"socks5h://127.0.0.1:{kwargs['listener_port']}"
        self.__class__.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True
        return True


def mailbox():
    return {"forwarding_email": "forwarding@icloud.com"}


def mailbox_secret():
    return {
        "proxy": "socks5h://mail-proxy.invalid:1080",
        "imap": {
            "host": "imap.example.com",
            "port": 993,
            "username": "forwarding@icloud.com",
            "password": "imap-secret",
            "folder": "INBOX",
        },
    }


def member_payload(*emails, total=None):
    items = [{"id": f"user-{index}", "email": email} for index, email in enumerate(emails)]
    return {"items": items, "total": len(items) if total is None else total}


class WorkspaceLookupTests(unittest.TestCase):
    def setUp(self):
        FakeRegistrar.instances = []
        FakeRegistrar.login_email = CHILD
        FakeRelay.instances = []

    def service(self, members):
        fetcher = FakeFetcher()
        clients = []

        def client_factory(**kwargs):
            client = FakeChatGPT(members, **kwargs)
            clients.append(client)
            return client

        return (
            WorkspaceLookupService(
                registrar_factory=FakeRegistrar,
                chatgpt_client_factory=client_factory,
                relay_factory=FakeRelay,
                proxy_fetcher=fetcher,
            ),
            fetcher,
            clients,
        )

    def lookup(self, service):
        return service.lookup(
            mailbox=mailbox(),
            mailbox_secret=mailbox_secret(),
            owner_email=OWNER,
            child_email=CHILD,
            proxy_mode="clash_chain",
            source_url="socks5://proxy-source.invalid:1080",
            bootstrap_proxy="http://127.0.0.1:7897",
        )

    def test_unique_two_member_team_is_returned_and_relay_is_stopped(self):
        service, fetcher, clients = self.service(
            {
                "personal": member_payload(CHILD),
                "team-one": member_payload(OWNER, CHILD),
                "team-two": member_payload("other@example.com", CHILD),
            }
        )

        result = self.lookup(service)

        self.assertEqual(
            result,
            {"workspace_uid": "team-one", "member_count": 2, "verified": True},
        )
        self.assertEqual(len(fetcher.calls), 1)
        self.assertEqual(len(FakeRelay.instances), 1)
        self.assertTrue(FakeRelay.instances[0].started)
        self.assertTrue(FakeRelay.instances[0].stopped)
        self.assertTrue(clients[0].closed)
        login_call = FakeRegistrar.instances[0].login_calls[0]
        self.assertIsNone(login_call["workspace_id"])
        self.assertEqual(login_call["email"], CHILD)
        self.assertEqual(login_call["mailbox"].provider, "icloud_hme_imap")

    def test_matching_team_with_three_members_is_rejected(self):
        service, _fetcher, clients = self.service(
            {
                "personal": member_payload(CHILD),
                "team-one": member_payload(OWNER, CHILD, "third@example.com"),
                "team-two": member_payload("other@example.com", CHILD),
            }
        )

        with self.assertRaisesRegex(WorkspaceLookupError, "恰好两人"):
            self.lookup(service)

        self.assertTrue(clients[0].closed)
        self.assertTrue(FakeRelay.instances[0].stopped)

    def test_incomplete_member_page_is_rejected(self):
        service, _fetcher, _clients = self.service(
            {
                "personal": member_payload(CHILD),
                "team-one": member_payload(OWNER, CHILD, total=3),
                "team-two": member_payload("other@example.com", CHILD),
            }
        )

        with self.assertRaisesRegex(WorkspaceLookupError, "恰好两人"):
            self.lookup(service)

    def test_multiple_matching_teams_are_rejected(self):
        service, _fetcher, _clients = self.service(
            {
                "personal": member_payload(CHILD),
                "team-one": member_payload(OWNER, CHILD),
                "team-two": member_payload(OWNER, CHILD),
            }
        )

        with self.assertRaisesRegex(WorkspaceLookupError, "唯一"):
            self.lookup(service)

    def test_no_matching_team_is_rejected(self):
        service, _fetcher, _clients = self.service(
            {
                "personal": member_payload(CHILD),
                "team-one": member_payload(OWNER, "other@example.com"),
                "team-two": member_payload("another@example.com", CHILD),
            }
        )

        with self.assertRaisesRegex(WorkspaceLookupError, "唯一"):
            self.lookup(service)

    def test_login_identity_mismatch_is_rejected_before_member_reads(self):
        FakeRegistrar.login_email = "wrong-child@icloud.com"
        service, _fetcher, clients = self.service(
            {
                "personal": member_payload(CHILD),
                "team-one": member_payload(OWNER, CHILD),
                "team-two": member_payload("other@example.com", CHILD),
            }
        )

        with self.assertRaisesRegex(WorkspaceLookupError, "身份不一致"):
            self.lookup(service)

        self.assertEqual(clients, [])
        self.assertTrue(FakeRelay.instances[0].stopped)


if __name__ == "__main__":
    unittest.main()
