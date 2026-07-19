from __future__ import annotations

import unittest
from unittest.mock import patch

from team_protocol.registrar_runtime import sentinel_browser


class _FakePage:
    def __init__(self, *, fail_first_navigation: bool = False) -> None:
        self.fail_first_navigation = fail_first_navigation
        self.calls: list[tuple[str, dict]] = []

    def goto(self, url: str, **kwargs):
        self.calls.append(("goto", {"url": url, **kwargs}))
        if self.fail_first_navigation and len(self.calls) == 1:
            raise RuntimeError("document did not reach the requested load state")

    def wait_for_timeout(self, timeout: int) -> None:
        self.calls.append(("warmup", {"timeout": timeout}))

    def wait_for_function(self, expression: str, **kwargs) -> None:
        self.calls.append(("sdk", {"expression": expression, **kwargs}))


class SentinelBrowserTimingTests(unittest.TestCase):
    def test_remaining_timeout_is_capped_and_never_negative(self):
        with patch.object(sentinel_browser.time, "monotonic", return_value=4.25):
            self.assertEqual(
                sentinel_browser._remaining_timeout_ms(10.0),
                5750,
            )
            self.assertEqual(
                sentinel_browser._remaining_timeout_ms(10.0, cap_ms=3000),
                3000,
            )

        with patch.object(sentinel_browser.time, "monotonic", return_value=11.0):
            self.assertEqual(sentinel_browser._remaining_timeout_ms(10.0), 0)

    def test_navigation_fallback_consumes_only_the_remaining_deadline(self):
        page = _FakePage(fail_first_navigation=True)

        with patch.object(
            sentinel_browser.time,
            "monotonic",
            side_effect=[0.0, 4.0, 5.0, 6.0],
        ):
            sentinel_browser._prepare_sentinel_page(page, "https://example.test", 10.0)

        self.assertEqual(page.calls[0][1]["timeout"], 10_000)
        self.assertEqual(page.calls[1][0], "goto")
        self.assertEqual(page.calls[1][1]["wait_until"], "commit")
        self.assertEqual(page.calls[1][1]["timeout"], 6_000)
        self.assertEqual(page.calls[2], ("warmup", {"timeout": 1_000}))
        self.assertEqual(page.calls[3][1]["timeout"], 4_000)

    def test_expired_deadline_does_not_start_a_second_navigation(self):
        page = _FakePage(fail_first_navigation=True)

        with patch.object(
            sentinel_browser.time,
            "monotonic",
            side_effect=[0.0, 10.0],
        ):
            with self.assertRaises(sentinel_browser._SentinelCaptureDeadlineExceeded):
                sentinel_browser._prepare_sentinel_page(
                    page,
                    "https://example.test",
                    10.0,
                )

        self.assertEqual(len(page.calls), 1)

    def test_ready_page_keeps_sdk_wait_inside_the_same_budget(self):
        page = _FakePage()

        with patch.object(
            sentinel_browser.time,
            "monotonic",
            side_effect=[0.0, 1.0, 2.0],
        ):
            sentinel_browser._prepare_sentinel_page(page, "https://example.test", 100.0)

        self.assertEqual(page.calls[0][1]["timeout"], 100_000)
        self.assertEqual(page.calls[1], ("warmup", {"timeout": 1_000}))
        self.assertEqual(page.calls[2][1]["timeout"], 30_000)


if __name__ == "__main__":
    unittest.main()
