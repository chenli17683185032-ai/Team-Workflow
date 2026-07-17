import base64
import os
import subprocess
import unittest
from unittest import mock

from team_protocol import secret_store
from team_protocol.secret_store import SecretStore, SecretStoreError


class _FailingBackend:
    def __init__(self, leaked_value: bytes):
        self.leaked_value = leaked_value

    def protect(self, _plaintext: bytes, _entropy: bytes) -> bytes:
        raise OSError(f"native failure for {self.leaked_value!r}")

    def unprotect(self, _ciphertext: bytes, _entropy: bytes) -> bytes:
        raise OSError(f"native failure for {self.leaked_value!r}")


@unittest.skipUnless(os.name == "nt", "Windows DPAPI is required")
class WindowsSecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = SecretStore()

    def test_roundtrip(self):
        plaintext = b"roundtrip-secret-4fbffcb0e250"
        ciphertext = self.store.encrypt(plaintext, "account.credentials")

        self.assertEqual(
            self.store.decrypt(ciphertext, "account.credentials"),
            plaintext,
        )
        self.assertNotEqual(ciphertext, plaintext)

    def test_roundtrip_empty_and_binary_payloads(self):
        payloads = (
            b"",
            bytes(range(256)),
            b"\x00\xff\x80binary\x00payload",
        )
        for payload in payloads:
            with self.subTest(payload_size=len(payload)):
                ciphertext = self.store.encrypt(payload, "checkpoint")
                self.assertEqual(
                    self.store.decrypt(ciphertext, "checkpoint"),
                    payload,
                )

    def test_purpose_mismatch_is_rejected(self):
        ciphertext = self.store.encrypt(b"purpose-bound", "account.credentials")

        with self.assertRaisesRegex(
            SecretStoreError,
            r"^Secret decryption failed\.$",
        ):
            self.store.decrypt(ciphertext, "checkpoint")

    def test_tampered_ciphertext_is_rejected(self):
        ciphertext = bytearray(self.store.encrypt(b"tamper-canary", "proxy"))
        ciphertext[-1] ^= 0x01

        with self.assertRaisesRegex(
            SecretStoreError,
            r"^Secret decryption failed\.$",
        ):
            self.store.decrypt(bytes(ciphertext), "proxy")

    def test_unsupported_envelope_version_is_rejected_before_dpapi(self):
        ciphertext = bytearray(self.store.encrypt(b"version-canary", "settings"))
        ciphertext[len(secret_store._MAGIC)] = secret_store._VERSION + 1

        with mock.patch.object(
            self.store._backend,
            "unprotect",
            wraps=self.store._backend.unprotect,
        ) as unprotect:
            with self.assertRaisesRegex(
                SecretStoreError,
                r"^Secret decryption failed\.$",
            ):
                self.store.decrypt(bytes(ciphertext), "settings")

        unprotect.assert_not_called()

    def test_ciphertext_does_not_contain_plaintext(self):
        plaintext = b"plaintext-scan-canary-724337fa3bf3483bb94596dfa752b8c4"
        ciphertext = self.store.encrypt(plaintext, "backup")

        self.assertNotIn(plaintext, ciphertext)


class SecretStoreFailureTests(unittest.TestCase):
    def test_mocked_native_failures_are_stable_and_do_not_leak_input(self):
        canary = b"failure-canary-824cb171"
        store = SecretStore(_backend=_FailingBackend(canary))

        with self.assertRaises(SecretStoreError) as encrypt_error:
            store.encrypt(canary, "account.credentials")
        with self.assertRaises(SecretStoreError) as decrypt_error:
            store.decrypt(
                secret_store._HEADER.pack(
                    secret_store._MAGIC,
                    secret_store._VERSION,
                )
                + b"ciphertext",
                "account.credentials",
            )

        self.assertEqual(str(encrypt_error.exception), "Secret encryption failed.")
        self.assertEqual(str(decrypt_error.exception), "Secret decryption failed.")
        self.assertNotIn(canary.decode("ascii"), str(encrypt_error.exception))
        self.assertNotIn(canary.decode("ascii"), str(decrypt_error.exception))


class MacOSSecretStoreTests(unittest.TestCase):
    def setUp(self):
        backend = secret_store._MacOSKeychain(_master_key=b"m" * 32)
        self.store = SecretStore(_backend=backend)

    def test_roundtrip_empty_binary_and_purpose_binding(self):
        for payload in (b"", bytes(range(256)), b"\x00\xffbinary\x00"):
            with self.subTest(payload_size=len(payload)):
                ciphertext = self.store.encrypt(payload, "account.credentials")
                self.assertEqual(
                    self.store.decrypt(ciphertext, "account.credentials"), payload
                )
                if payload:
                    self.assertNotIn(payload, ciphertext)

        ciphertext = self.store.encrypt(b"purpose-canary", "account.credentials")
        with self.assertRaisesRegex(SecretStoreError, r"^Secret decryption failed\.$"):
            self.store.decrypt(ciphertext, "checkpoint")

    def test_tampering_is_rejected(self):
        ciphertext = bytearray(self.store.encrypt(b"tamper-canary", "proxy"))
        ciphertext[-1] ^= 1

        with self.assertRaisesRegex(SecretStoreError, r"^Secret decryption failed\.$"):
            self.store.decrypt(bytes(ciphertext), "proxy")

    def test_keychain_existing_key_is_reused(self):
        encoded = base64.b64encode(b"k" * 32).decode("ascii")
        completed = subprocess.CompletedProcess([], 0, stdout=encoded + "\n", stderr="")
        with mock.patch.object(secret_store.subprocess, "run", return_value=completed) as run:
            key = secret_store._load_or_create_macos_master_key()

        self.assertEqual(key, b"k" * 32)
        self.assertEqual(run.call_count, 1)

    def test_keychain_first_use_writes_secret_via_stdin_and_reads_it_back(self):
        created_key = b"n" * 32
        encoded = base64.b64encode(created_key).decode("ascii")
        missing = subprocess.CompletedProcess([], 44, stdout="", stderr="not found")
        written = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        loaded = subprocess.CompletedProcess([], 0, stdout=encoded + "\n", stderr="")
        with (
            mock.patch.object(secret_store.os, "urandom", return_value=created_key),
            mock.patch.object(
                secret_store.subprocess,
                "run",
                side_effect=[missing, written, loaded],
            ) as run,
        ):
            key = secret_store._load_or_create_macos_master_key()

        self.assertEqual(key, created_key)
        write_call = run.call_args_list[1]
        self.assertEqual(write_call.args[0], ["/usr/bin/security", "-i"])
        self.assertIn(encoded, write_call.kwargs["input"])
        self.assertNotIn(encoded, " ".join(write_call.args[0]))

    def test_keychain_failures_are_stable_and_hide_native_output(self):
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="failure with keychain-canary"
        )
        with mock.patch.object(secret_store.subprocess, "run", return_value=completed):
            with self.assertRaises(SecretStoreError) as caught:
                secret_store._read_macos_master_key()

        self.assertEqual(str(caught.exception), "macOS Keychain is unavailable.")
        self.assertNotIn("keychain-canary", str(caught.exception))

    def test_default_backend_selects_macos_keychain(self):
        backend = object()
        with (
            mock.patch.object(secret_store.sys, "platform", "darwin"),
            mock.patch.object(secret_store, "_MacOSKeychain", return_value=backend),
        ):
            store = SecretStore()

        self.assertIs(store._backend, backend)


if __name__ == "__main__":
    unittest.main()
