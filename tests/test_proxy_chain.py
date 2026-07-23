import json
import select
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from team_protocol.proxy_chain import (
    CHAIN_PROXY_MODE,
    ChainedProxyRelay,
    LokiProxyEndpoint,
    LokiProxyFetcher,
    OwnerChainConfig,
    ProxyChainManager,
    ProxyConfigurationError,
    ProxySourceDepletedError,
    ProxySourceError,
    ProxySourceNotWhitelistedError,
    parse_lokiproxy_response,
    parse_proxy_source_response,
    validate_generator_url,
    validate_proxy_source,
)


LINKUP_GENERATOR_URL = (
    "http://global.rpapi.linkup.onl:8089/gen?zone=custom&ptype=1&region=PH&"
    "asn=ASN17639&count=1&proto=http&stype=txt&sessType=sticky&"
    "split=\\r\\n&sessTime=5&sessAuto=1"
)


def _read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def _read_until(sock, marker, limit=65536):
    data = bytearray()
    while marker not in data:
        if len(data) >= limit:
            raise ValueError("header too large")
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def _pump(left, right):
    try:
        while True:
            readable, _, _ = select.select([left, right], [], [], 2.0)
            if not readable:
                continue
            for source in readable:
                destination = right if source is left else left
                data = source.recv(65536)
                if not data:
                    return
                destination.sendall(data)
    except OSError:
        return


def _parse_authority(value):
    text = str(value)
    if text.startswith("["):
        closing = text.index("]")
        return text[1:closing], int(text[closing + 2 :])
    host, port = text.rsplit(":", 1)
    return host, int(port)


def _read_socks_address(sock, atyp):
    if atyp == 1:
        host = socket.inet_ntoa(_read_exact(sock, 4))
    elif atyp == 3:
        host = _read_exact(sock, _read_exact(sock, 1)[0]).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _read_exact(sock, 16))
    else:
        raise ValueError("invalid address type")
    return host, int.from_bytes(_read_exact(sock, 2), "big")


class _ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _RunningServer:
    def __init__(self, handler, **attributes):
        self.server = _ThreadingServer(("127.0.0.1", 0), handler)
        for name, value in attributes.items():
            setattr(self.server, name, value)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return int(self.server.server_address[1])

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        del exc_type, exc, traceback
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class _LokiSocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            greeting = _read_exact(self.request, 2)
            methods = _read_exact(self.request, greeting[1])
            username = str(getattr(self.server, "username", ""))
            password = str(getattr(self.server, "password", ""))
            if username or password:
                if 2 not in methods:
                    self.request.sendall(b"\x05\xff")
                    return
                self.request.sendall(b"\x05\x02")
                version = _read_exact(self.request, 1)
                user = _read_exact(self.request, _read_exact(self.request, 1)[0]).decode()
                secret = _read_exact(self.request, _read_exact(self.request, 1)[0]).decode()
                if version != b"\x01" or user != username or secret != password:
                    self.request.sendall(b"\x01\x01")
                    return
                self.request.sendall(b"\x01\x00")
            else:
                if 0 not in methods:
                    self.request.sendall(b"\x05\xff")
                    return
                self.request.sendall(b"\x05\x00")
            request = _read_exact(self.request, 4)
            if request[:3] != b"\x05\x01\x00":
                return
            host, port = _read_socks_address(self.request, request[3])
            with self.server.records_lock:
                self.server.records.append((host, port))
            upstream = socket.create_connection((host, port), timeout=2)
            self.request.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            _pump(self.request, upstream)
        except (EOFError, OSError, ValueError):
            return
        finally:
            if upstream is not None:
                upstream.close()


class _ClashConnectHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            request = _read_until(self.request, b"\r\n\r\n")
            first_line = request.split(b"\r\n", 1)[0].decode("ascii")
            method, authority, _ = first_line.split(" ", 2)
            if method != "CONNECT":
                return
            host, port = _parse_authority(authority)
            with self.server.records_lock:
                self.server.records.append((host, port))
            upstream = socket.create_connection((host, port), timeout=2)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _pump(self.request, upstream)
        except (EOFError, OSError, ValueError):
            return
        finally:
            if upstream is not None:
                upstream.close()


class _FakeResponse:
    def __init__(self, payload, status_code=200, *, plain=False):
        self.payload = payload
        self.status_code = status_code
        if plain:
            self.content = str(payload).encode("utf-8")

    def json(self):
        if isinstance(self.payload, BaseException):
            raise self.payload
        return self.payload


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _request_through_socks(relay_port, target_port, payload):
    with socket.create_connection(("127.0.0.1", relay_port), timeout=3) as client:
        client.sendall(b"\x05\x01\x00")
        if _read_exact(client, 2) != b"\x05\x00":
            raise AssertionError("relay rejected SOCKS5 greeting")
        client.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + int(target_port).to_bytes(2, "big")
        )
        response = _read_exact(client, 4)
        if response[1] != 0:
            raise AssertionError(f"relay returned SOCKS5 error {response[1]}")
        _read_socks_address(client, response[3])
        client.sendall(payload)
        return _read_exact(client, len(payload))


class ProxyChainTests(unittest.TestCase):
    def test_generator_url_is_distinct_from_a_proxy_url(self):
        source = "https://gen.lokiproxy.com/gen?region=JP&token=source-secret"
        self.assertEqual(validate_generator_url(source), source)
        for invalid in (
            "socks5://proxy.example:1080",
            "https://example.com/gen?token=secret",
            "https://gen.lokiproxy.com/other?token=secret",
            "https://user:pass@gen.lokiproxy.com/gen",
            "https://gen.lokiproxy.com/gen#fragment",
        ):
            with self.assertRaises(ValueError):
                validate_generator_url(invalid)

    def test_linkup_generator_url_preserves_literal_line_separator(self):
        self.assertEqual(
            validate_generator_url(LINKUP_GENERATOR_URL),
            LINKUP_GENERATOR_URL,
        )
        self.assertEqual(
            validate_proxy_source(LINKUP_GENERATOR_URL),
            LINKUP_GENERATOR_URL,
        )
        for invalid in (
            LINKUP_GENERATOR_URL.replace(
                "global.rpapi.linkup.onl",
                "global.rpapi.linkup.onl.evil.example",
            ),
            LINKUP_GENERATOR_URL.replace("/gen?", "/other?"),
            LINKUP_GENERATOR_URL.replace(
                "http://",
                "http://user:pass@",
                1,
            ),
            LINKUP_GENERATOR_URL + "#fragment",
            LINKUP_GENERATOR_URL.replace("region=PH", "region=P\r\nH"),
        ):
            with self.subTest(invalid=invalid.rsplit("/", 1)[-1][:24]):
                with self.assertRaises(ValueError):
                    validate_proxy_source(invalid)

    def test_linkup_generator_uses_query_protocol_for_json_response(self):
        calls = []

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return _FakeResponse(
                {
                    "code": 200,
                    "success": "success",
                    "msg": "success",
                    "request_ip": "",
                    "data": [{"ip": "203.0.113.28", "port": 10000}],
                }
            )

        endpoint = LokiProxyFetcher(requester=request).fetch(
            LINKUP_GENERATOR_URL,
            "http://127.0.0.1:7897",
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0:2], ("GET", LINKUP_GENERATOR_URL))
        self.assertEqual(
            calls[0][2]["proxies"],
            {
                "http": "http://127.0.0.1:7897",
                "https": "http://127.0.0.1:7897",
            },
        )
        self.assertEqual(
            (
                endpoint.host,
                endpoint.port,
                endpoint.scheme,
                endpoint.username,
                endpoint.password,
            ),
            (
                "203.0.113.28",
                10000,
                "http",
                "",
                "",
            ),
        )
        explicit = parse_proxy_source_response(
            {
                "data": [
                    {
                        "ip": "203.0.113.29",
                        "port": 1080,
                        "protocol": "socks5",
                    }
                ]
            },
            default_scheme="http",
        )
        self.assertEqual(explicit.scheme, "socks5")
        for invalid_source in (
            LINKUP_GENERATOR_URL.replace("proto=http", "proto=ftp"),
            LINKUP_GENERATOR_URL.replace(
                "proto=http",
                "proto=http&proto=socks5",
            ),
        ):
            with self.subTest(invalid_source=invalid_source.rsplit("proto=", 1)[-1]):
                with self.assertRaises(ProxySourceError):
                    LokiProxyFetcher(
                        requester=lambda *_args, **_kwargs: self.fail(
                            "invalid generator protocol must fail before network access"
                        )
                    ).fetch(
                        invalid_source,
                        "http://127.0.0.1:7897",
                    )

    def test_fixed_authenticated_proxy_sources_bypass_generator_request(self):
        fetcher = LokiProxyFetcher(
            requester=lambda *_args, **_kwargs: self.fail(
                "fixed proxy source must not call the generator"
            )
        )

        for source, expected_scheme in (
            ("socks5://fixed-user:fixed-pass@proxy.example:3010", "socks5"),
            ("http://fixed-user:fixed-pass@proxy.example:3010", "http"),
            ("http://proxy.example:3010", "http"),
        ):
            with self.subTest(source=source):
                endpoint = fetcher.fetch(source, "http://127.0.0.1:7897")

                self.assertEqual(validate_proxy_source(source), source)
                self.assertEqual(
                    (
                        endpoint.host,
                        endpoint.port,
                        endpoint.scheme,
                        endpoint.username,
                        endpoint.password,
                    ),
                    (
                        "proxy.example",
                        3010,
                        expected_scheme,
                        "" if source == "http://proxy.example:3010" else "fixed-user",
                        "" if source == "http://proxy.example:3010" else "fixed-pass",
                    ),
                )

    def test_curl_proxy_commands_are_normalized_without_the_probe_target(self):
        cases = (
            (
                'curl -L -x global.rp.linkup.onl:10000 '
                '-U "USER-example-zone-custom:proxy-pass" ipinfo.io',
                "socks5://USER-example-zone-custom:proxy-pass@global.rp.linkup.onl:10000",
            ),
            (
                'curl -L -x proxy.example:3010 -U "region-PH:proxy-pass" ipinfo.io',
                "http://region-PH:proxy-pass@proxy.example:3010",
            ),
            (
                'curl -L -x global.rp.linkup.onl.example:3010 '
                '-U "region-PH:proxy-pass" ipinfo.io',
                "http://region-PH:proxy-pass@global.rp.linkup.onl.example:3010",
            ),
            (
                'curl --location -x proxy.example:3010 -U "region-JP:proxy-pass" mayips.com',
                "http://region-JP:proxy-pass@proxy.example:3010",
            ),
            (
                "curl --socks5 proxy.example:3010 "
                "-U 'region-JP:p@ss word' https://mayips.com",
                "socks5://region-JP:p%40ss%20word@proxy.example:3010",
            ),
            (
                "curl --proxy=proxy.example:3010 "
                "--proxy-user=region-JP:proxy-pass mayips.com",
                "http://region-JP:proxy-pass@proxy.example:3010",
            ),
        )

        for command, expected in cases:
            with self.subTest(command=command.split()[1]):
                self.assertEqual(validate_proxy_source(command), expected)

    def test_saved_linkup_http_source_is_normalized_to_socks5(self):
        source = (
            "http://USER-example-zone-custom:proxy-pass@"
            "global.rp.linkup.onl:10000"
        )
        near_match = "http://user:pass@global.rp.linkup.onl.example:10000"

        self.assertEqual(
            validate_proxy_source(source),
            source.replace("http://", "socks5://", 1),
        )
        self.assertEqual(validate_proxy_source(near_match), near_match)

    def test_curl_proxy_commands_reject_ambiguous_or_incomplete_input(self):
        invalid = (
            "curl mayips.com",
            "curl -x proxy.example:3010",
            "curl -x proxy.example:3010 -U region-JP mayips.com",
            "curl -x proxy.example:3010 --socks5 proxy.example:3011 mayips.com",
            "curl -x user:pass@proxy.example:3010 -U other:pass mayips.com",
            "curl --silent -x proxy.example:3010 mayips.com",
            "curl -x proxy.example:70000 mayips.com",
            "curl -x 'proxy.example:3010 mayips.com",
        )

        for command in invalid:
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    validate_proxy_source(command)

    def test_lokiproxy_parser_accepts_json_and_plain_text(self):
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
        plain = parse_lokiproxy_response("203.0.113.19:1081\n")
        url = parse_lokiproxy_response(
            "socks5://dynamic-user:dynamic-pass@203.0.113.20:1082"
        )

        self.assertEqual(endpoint.host, "203.0.113.18")
        self.assertEqual(endpoint.ttl_seconds, 90)
        self.assertEqual((plain.host, plain.port), ("203.0.113.19", 1081))
        self.assertEqual((url.username, url.password), ("dynamic-user", "dynamic-pass"))
        for invalid in ({}, {"data": []}, "not-an-endpoint", "203.0.113.1:70000"):
            with self.assertRaises(ValueError):
                parse_lokiproxy_response(invalid)

    def test_fetcher_uses_the_shared_clash_for_json_and_text_sources(self):
        calls = []
        responses = iter(
            [
                _FakeResponse({"data": [{"ip": "203.0.113.20", "port": 1080}]}),
                _FakeResponse("203.0.113.21:1081", plain=True),
            ]
        )

        def request(method, url, **kwargs):
            calls.append((method, url, kwargs))
            return next(responses)

        fetcher = LokiProxyFetcher(requester=request)
        source_a = "https://gen.lokiproxy.com/gen?token=source-a"
        source_b = "https://gen.lokiproxy.com/gen?token=source-b"
        clash = "http://127.0.0.1:7897"

        self.assertEqual(fetcher.fetch(source_a, clash).port, 1080)
        self.assertEqual(fetcher.fetch(source_b, clash).port, 1081)
        self.assertEqual(len(calls), 2)
        for _, _, kwargs in calls:
            self.assertEqual(kwargs["proxies"], {"http": clash, "https": clash})

    def test_fetcher_errors_never_include_source_or_response_content(self):
        source = "https://gen.lokiproxy.com/gen?token=source-secret"
        fetcher = LokiProxyFetcher(
            requester=lambda *_args, **_kwargs: _FakeResponse(
                "provider-response-secret", status_code=403, plain=True
            )
        )
        with self.assertRaises(ProxySourceError) as caught:
            fetcher.fetch(source, "http://127.0.0.1:7897")
        self.assertNotIn("source-secret", str(caught.exception))
        self.assertNotIn("provider-response-secret", str(caught.exception))

    def test_fetcher_classifies_whitelist_and_depleted_sources(self):
        source = "https://gen.lokiproxy.com/gen?token=source-secret"
        cases = (
            (
                '{"message":"Proxies are available after whitelisting IP"}',
                ProxySourceNotWhitelistedError,
            ),
            (
                '{"message":"rrp_ip total surplus 0 < count 1; surplus insufficient"}',
                ProxySourceDepletedError,
            ),
        )
        for payload, expected in cases:
            fetcher = LokiProxyFetcher(
                requester=lambda *_args, payload=payload, **_kwargs: _FakeResponse(
                    payload, status_code=400, plain=True
                )
            )
            with self.assertRaises(expected) as caught:
                fetcher.fetch(source, "http://127.0.0.1:7897")
            self.assertNotIn("source-secret", str(caught.exception))
            self.assertNotIn("rrp_ip", str(caught.exception))

    def test_old_per_node_config_migrates_to_the_shared_clash_url(self):
        config = OwnerChainConfig.from_mapping(
            {
                "version": 1,
                "mode": "lokiproxy_generator",
                "owner_id": "owner-a",
                "source_url": "https://gen.lokiproxy.com/gen?token=secret",
                "bootstrap_name": "US 33 AI",
                "bootstrap_port": 18781,
                "listener_port": 18881,
                "effective_proxy": "socks5://127.0.0.1:18881",
            }
        )
        stored = config.as_secret_dict()

        self.assertEqual(config.bootstrap_proxy, "http://127.0.0.1:7897")
        self.assertEqual(stored["version"], 3)
        self.assertEqual(stored["mode"], CHAIN_PROXY_MODE)
        self.assertNotIn("bootstrap_name", stored)
        self.assertNotIn("bootstrap_port", stored)

    def test_two_relays_traverse_one_clash_then_their_own_loki(self):
        records_lock = threading.Lock()
        with (
            _RunningServer(_EchoHandler) as target,
            _RunningServer(
                _LokiSocksHandler,
                records=[],
                records_lock=records_lock,
                username="user-a",
                password="pass-a",
            ) as loki_a,
            _RunningServer(
                _LokiSocksHandler,
                records=[],
                records_lock=records_lock,
                username="user-b",
                password="pass-b",
            ) as loki_b,
            _RunningServer(
                _ClashConnectHandler,
                records=[],
                records_lock=records_lock,
            ) as clash,
        ):
            shared = f"http://127.0.0.1:{clash.port}"
            relay_a = ChainedProxyRelay(
                owner_id="owner-a",
                bootstrap_proxy=shared,
                listener_port=_free_port(),
                endpoint_supplier=lambda: LokiProxyEndpoint(
                    "127.0.0.1", loki_a.port, username="user-a", password="pass-a"
                ),
            )
            relay_b = ChainedProxyRelay(
                owner_id="owner-b",
                bootstrap_proxy=shared,
                listener_port=_free_port(),
                endpoint_supplier=lambda: LokiProxyEndpoint(
                    "127.0.0.1", loki_b.port, username="user-b", password="pass-b"
                ),
            )
            try:
                relay_a.start()
                relay_b.start()
                self.assertEqual(
                    _request_through_socks(relay_a.listener_port, target.port, b"chain-a"),
                    b"chain-a",
                )
                self.assertEqual(
                    _request_through_socks(relay_b.listener_port, target.port, b"chain-b"),
                    b"chain-b",
                )
            finally:
                relay_a.stop()
                relay_b.stop()

            self.assertCountEqual(
                clash.server.records,
                [("127.0.0.1", loki_a.port), ("127.0.0.1", loki_b.port)],
            )
            self.assertEqual(loki_a.server.records, [("127.0.0.1", target.port)])
            self.assertEqual(loki_b.server.records, [("127.0.0.1", target.port)])

    def test_manager_keeps_two_sources_isolated_and_never_calls_clash_control(self):
        configs = {}

        class Fetcher:
            def __init__(self):
                self.calls = []

            def fetch(self, source_url, bootstrap_proxy):
                self.calls.append((source_url, bootstrap_proxy))
                port = 1081 if "source-a" in source_url else 1082
                return LokiProxyEndpoint("203.0.113.30", port)

        class ForbiddenClashControl:
            def __getattribute__(self, name):
                if name.startswith("_"):
                    return object.__getattribute__(self, name)
                raise AssertionError("Mihomo control API must not be used")

        fetcher = Fetcher()
        shared = "http://127.0.0.1:7897"
        with tempfile.TemporaryDirectory() as directory:
            manager = ProxyChainManager(
                app_dir=directory,
                list_configs=lambda: list(configs.values()),
                get_config=lambda owner_id: configs[owner_id],
                fetcher=fetcher,
                clash=ForbiddenClashControl(),
                bootstrap_proxy=shared,
            )
            chain_a = manager.prepare(
                "owner-a",
                "https://gen.lokiproxy.com/gen?token=source-a",
                shared,
            )
            configs["owner-a"] = chain_a.as_secret_dict()
            chain_b = manager.prepare(
                "owner-b",
                "https://gen.lokiproxy.com/gen?token=source-b",
                shared,
            )
            configs["owner-b"] = chain_b.as_secret_dict()
            try:
                applied = manager.apply()
                endpoint_a = manager.refresh("owner-a", force=True)
                endpoint_b = manager.refresh("owner-b", force=True)
                status_a = manager.status("owner-a")
                status_b = manager.status("owner-b")
            finally:
                self.assertTrue(manager.shutdown())

        self.assertEqual(applied["chain_count"], 2)
        self.assertNotEqual(chain_a.listener_port, chain_b.listener_port)
        self.assertEqual((endpoint_a.port, endpoint_b.port), (1081, 1082))
        self.assertEqual({call[1] for call in fetcher.calls}, {shared})
        self.assertTrue(status_a["relay_running"])
        self.assertTrue(status_b["relay_running"])
        serialized = json.dumps({"a": status_a, "b": status_b})
        self.assertNotIn("source-a", serialized)
        self.assertNotIn("source-b", serialized)

    def test_manager_rejects_different_clash_fronts_for_a_and_b(self):
        manager = ProxyChainManager(
            app_dir=tempfile.gettempdir(),
            list_configs=lambda: [],
            get_config=lambda _owner_id: {},
            bootstrap_proxy="http://127.0.0.1:7897",
        )
        with self.assertRaises(ProxyConfigurationError):
            manager.prepare(
                "owner-a",
                "https://gen.lokiproxy.com/gen?token=source-a",
                "http://127.0.0.1:7898",
            )

    def test_refresh_lock_deduplicates_one_owner_without_serializing_another(self):
        shared = "http://127.0.0.1:7897"
        configs = {
            owner_id: OwnerChainConfig(
                owner_id=owner_id,
                source_url=f"https://gen.lokiproxy.com/gen?token={token}",
                bootstrap_proxy=shared,
                listener_port=listener_port,
                effective_proxy=f"socks5://127.0.0.1:{listener_port}",
            ).as_secret_dict()
            for owner_id, token, listener_port in (
                ("owner-a", "a", 18881),
                ("owner-b", "b", 18882),
            )
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
        with tempfile.TemporaryDirectory() as directory:
            manager = ProxyChainManager(
                app_dir=directory,
                list_configs=lambda: list(configs.values()),
                get_config=lambda owner_id: configs[owner_id],
                fetcher=fetcher,
                bootstrap_proxy=shared,
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
        self.assertEqual({call[1] for call in fetcher.calls}, {shared})


if __name__ == "__main__":
    unittest.main()
