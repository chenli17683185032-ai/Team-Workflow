import json
import socket
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from team_protocol.proxy_chain import (
    ClashConfigManager,
    LokiProxyEndpoint,
    LokiProxyFetcher,
    MihomoApiClient,
    OwnerChainConfig,
    ProxyChainManager,
    ProxySourceError,
    build_clash_config,
    parse_lokiproxy_response,
    provider_document,
    validate_generator_url,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        if isinstance(self.payload, BaseException):
            raise self.payload
        return self.payload


class FakeMihomoApi:
    def __init__(self):
        self.payloads = []

    def put_config(self, payload):
        self.payloads.append(payload)

    def version(self):
        return "v-test"


class FakeClashManager:
    def __init__(self, nodes):
        self.nodes = set(nodes)
        self.applied = []

    def available_nodes(self):
        return set(self.nodes)

    def apply(self, chains):
        self.applied.append(list(chains))
        return {"applied": True, "chain_count": len(chains), "version": "v-test"}


class ProxyChainTests(unittest.TestCase):
    def test_unix_api_client_decodes_chunked_json_responses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mihomo.sock"
            ready = threading.Event()

            def serve():
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(path))
                listener.listen(1)
                ready.set()
                connection, _ = listener.accept()
                try:
                    connection.recv(4096)
                    body = b'{"proxies":{"owner":"ok"}}'
                    chunks = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Connection: close\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n"
                        + chunks
                    )
                finally:
                    connection.close()
                    listener.close()

            thread = threading.Thread(target=serve)
            thread.start()
            self.assertTrue(ready.wait(2))
            status, payload = MihomoApiClient(
                unix_socket=path, timeout=2
            )._unix_request("GET", "/proxies", b"")
            thread.join(2)

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"proxies": {"owner": "ok"}})

    def test_generator_url_is_distinct_from_a_proxy_url(self):
        source = "https://gen.lokiproxy.com/gen?region=JP&token=source-secret"
        normalized = validate_generator_url(source)

        self.assertEqual(normalized, source)
        for invalid in (
            "socks5://proxy.example:1080",
            "https://example.com/gen?token=secret",
            "https://gen.lokiproxy.com/other?token=secret",
            "https://user:pass@gen.lokiproxy.com/gen",
            "https://gen.lokiproxy.com/gen#fragment",
        ):
            with self.assertRaises(ValueError):
                validate_generator_url(invalid)

    def test_lokiproxy_json_parser_validates_endpoint_and_ttl(self):
        endpoint = parse_lokiproxy_response(
            {
                "data": [
                    {
                        "ip": "203.0.113.18",
                        "port": "1080",
                        "protocol": "socks5h",
                        "username": "source-user",
                        "password": "source-password",
                        "ttl": 90,
                    }
                ]
            }
        )

        self.assertEqual(endpoint.host, "203.0.113.18")
        self.assertEqual(endpoint.port, 1080)
        self.assertEqual(endpoint.scheme, "socks5")
        self.assertEqual(endpoint.username, "source-user")
        self.assertEqual(endpoint.password, "source-password")
        self.assertEqual(endpoint.ttl_seconds, 90)
        for invalid in (
            {},
            {"data": []},
            {"data": [{"ip": "https://bad.example", "port": 1080}]},
            {"data": [{"ip": "203.0.113.1", "port": 70_000}]},
        ):
            with self.assertRaises(ValueError):
                parse_lokiproxy_response(invalid)

    def test_fetcher_uses_only_the_selected_bootstrap_listener(self):
        calls = []

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return FakeResponse({"data": [{"ip": "203.0.113.20", "port": 1080}]})

        source = "https://gen.lokiproxy.com/gen?token=source-secret"
        endpoint = LokiProxyFetcher(requester=request).fetch(
            source, "http://127.0.0.1:18781"
        )

        self.assertEqual(endpoint.port, 1080)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2]["proxies"], {
            "http": "http://127.0.0.1:18781",
            "https": "http://127.0.0.1:18781",
        })

    def test_fetcher_errors_never_include_source_url_or_response_content(self):
        source = "https://gen.lokiproxy.com/gen?token=source-secret"
        fetcher = LokiProxyFetcher(
            requester=lambda *_args, **_kwargs: FakeResponse(
                {"error": "provider-response-secret"}, status_code=403
            )
        )

        with self.assertRaises(ProxySourceError) as caught:
            fetcher.fetch(source, "http://127.0.0.1:18781")

        message = str(caught.exception)
        self.assertNotIn("source-secret", message)
        self.assertNotIn("provider-response-secret", message)

    def test_provider_document_contains_only_the_generated_endpoint(self):
        document = provider_document(
            "owner-a",
            LokiProxyEndpoint(
                "203.0.113.22",
                1080,
                username="dynamic-user",
                password="dynamic-password",
            ),
            dialer_proxy="US 33 AI",
        )
        payload = json.loads(document)
        node = payload["proxies"][0]

        self.assertEqual(node["dialer-proxy"], "US 33 AI")
        self.assertEqual(node["server"], "203.0.113.22")
        self.assertNotIn("source_url", payload)

    def test_one_clash_config_builds_two_isolated_owner_chains(self):
        base = {
            "mixed-port": 7897,
            "proxies": [
                {"name": "US 33 AI", "type": "trojan", "server": "us.invalid", "port": 443},
                {"name": "JP 22 GMO", "type": "trojan", "server": "jp.invalid", "port": 443},
            ],
            "proxy-groups": [{"name": "Proxy", "type": "select", "proxies": ["US 33 AI"]}],
            "listeners": [{"name": "user listener", "type": "mixed", "port": 19000}],
            "rules": ["MATCH,Proxy"],
        }
        chains = [
            OwnerChainConfig(
                "owner-a",
                "https://gen.lokiproxy.com/gen?token=source-a",
                "US 33 AI",
                18781,
                18881,
                "socks5://127.0.0.1:18881",
            ),
            OwnerChainConfig(
                "owner-b",
                "https://gen.lokiproxy.com/gen?token=source-b",
                "JP 22 GMO",
                18782,
                18882,
                "socks5://127.0.0.1:18882",
            ),
        ]

        merged = build_clash_config(
            base,
            chains,
            provider_base_url="http://127.0.0.1:8765",
            provider_token="local-provider-token",
        )
        serialized = yaml.safe_dump(merged, allow_unicode=True)
        generated_listeners = [
            item for item in merged["listeners"] if str(item["name"]).startswith("TeamWorkflow::")
        ]
        providers = list(merged["proxy-providers"].values())

        self.assertEqual(merged["mixed-port"], 7897)
        self.assertEqual(merged["rules"], ["MATCH,Proxy"])
        self.assertEqual(merged["listeners"][0]["name"], "user listener")
        self.assertEqual(len(generated_listeners), 4)
        self.assertEqual(
            {item["proxy"] for item in generated_listeners if item["port"] < 18800},
            {"US 33 AI", "JP 22 GMO"},
        )
        self.assertEqual(
            {item["override"]["dialer-proxy"] for item in providers},
            {"US 33 AI", "JP 22 GMO"},
        )
        self.assertNotIn("source-a", serialized)
        self.assertNotIn("source-b", serialized)
        self.assertNotIn("gen.lokiproxy.com", serialized)

    def test_clash_manager_validates_writes_and_applies_a_private_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "clash-verge.yaml"
            source.write_text(
                yaml.safe_dump(
                    {
                        "proxies": [
                            {
                                "name": "US 33 AI",
                                "type": "socks5",
                                "server": "127.0.0.1",
                                "port": 19999,
                            }
                        ],
                        "proxy-groups": [],
                        "rules": ["MATCH,DIRECT"],
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            api = FakeMihomoApi()
            manager = ClashConfigManager(
                app_dir=root / "app",
                provider_base_url="http://127.0.0.1:8765",
                provider_token="provider-token",
                source_path=source,
                api=api,
                binary=root / "missing-mihomo",
            )
            chain = OwnerChainConfig(
                "owner-a",
                "https://gen.lokiproxy.com/gen?token=source-secret",
                "US 33 AI",
                18781,
                18881,
                "socks5://127.0.0.1:18881",
            )

            result = manager.apply([chain])

            self.assertTrue(result["applied"])
            self.assertEqual(result["version"], "v-test")
            self.assertEqual(len(api.payloads), 1)
            self.assertEqual(manager.generated_path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(b"source-secret", api.payloads[0])

    def test_refresh_lock_deduplicates_one_owner_without_serializing_another(self):
        configs = {
            "owner-a": OwnerChainConfig(
                "owner-a",
                "https://gen.lokiproxy.com/gen?token=a",
                "US 33 AI",
                18781,
                18881,
                "socks5://127.0.0.1:18881",
            ).as_secret_dict(),
            "owner-b": OwnerChainConfig(
                "owner-b",
                "https://gen.lokiproxy.com/gen?token=b",
                "JP 22 GMO",
                18782,
                18882,
                "socks5://127.0.0.1:18882",
            ).as_secret_dict(),
        }

        class CountingFetcher:
            def __init__(self):
                self.calls = []
                self.active = 0
                self.max_active = 0
                self.lock = threading.Lock()

            def fetch(self, source_url, bootstrap_proxy):
                with self.lock:
                    self.calls.append((source_url, bootstrap_proxy))
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                time.sleep(0.05)
                with self.lock:
                    self.active -= 1
                return LokiProxyEndpoint("203.0.113.30", 1080)

        fetcher = CountingFetcher()
        clash = FakeClashManager({"US 33 AI", "JP 22 GMO"})
        with tempfile.TemporaryDirectory() as directory:
            manager = ProxyChainManager(
                app_dir=directory,
                console_port=8765,
                list_configs=lambda: list(configs.values()),
                get_config=lambda owner_id: configs[owner_id],
                fetcher=fetcher,
                clash=clash,
                provider_token="provider-token",
                cache_ttl=30,
            )
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(manager.refresh, "owner-a"),
                    executor.submit(manager.refresh, "owner-a"),
                    executor.submit(manager.refresh, "owner-b"),
                ]
                for future in futures:
                    future.result()

        self.assertEqual(len([call for call in fetcher.calls if "token=a" in call[0]]), 1)
        self.assertEqual(len([call for call in fetcher.calls if "token=b" in call[0]]), 1)
        self.assertGreaterEqual(fetcher.max_active, 2)
        self.assertIn((configs["owner-a"]["source_url"], "http://127.0.0.1:18781"), fetcher.calls)
        self.assertIn((configs["owner-b"]["source_url"], "http://127.0.0.1:18782"), fetcher.calls)


if __name__ == "__main__":
    unittest.main()
