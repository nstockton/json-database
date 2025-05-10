# Copyright (c) 2025 Nick Stockton
# -----------------------------------------------------------------------------
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# -----------------------------------------------------------------------------
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# -----------------------------------------------------------------------------
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Future Modules:
from __future__ import annotations

# Built-in Modules:
from unittest import TestCase

# JSON Database Modules:
from json_database.encryption import (
	CorruptedDataError,
	InvalidHashError,
	WrongPasswordError,
	decode_base64,
	decrypt,
	encode_base64,
	encrypt,
	get_checksum,
)


class TestEncryption(TestCase):
	def test_get_checksum(self) -> None:
		text: str = "hello"
		text_bytes: bytes = bytes(text, "utf-8")
		checksum: str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
		checksum_bytes: bytes = bytes(checksum, "utf-8")
		self.assertEqual(get_checksum("sha256", text), checksum)
		self.assertEqual(get_checksum("sha256", text_bytes), checksum_bytes)

	def test_base64_encode_and_decode(self) -> None:
		decoded: str = "Hello world!"
		decoded_bytes: bytes = bytes(decoded, "utf-8")
		encoded: str = "SGVsbG8gd29ybGQh"
		encoded_bytes: bytes = bytes(encoded, "utf-8")
		self.assertEqual(decode_base64(encoded), decoded)
		self.assertEqual(decode_base64(encoded_bytes), decoded_bytes)
		self.assertEqual(encode_base64(decoded), encoded)
		self.assertEqual(encode_base64(decoded_bytes), encoded_bytes)

	def test_encryption_decryption(self) -> None:
		password: str = "test_password"  # NOQA: S105
		unencrypted: bytes = b"Some data in plain text."
		# Test encrypt.
		hash, encrypted_data = encrypt(password, unencrypted)  # NOQA: A001
		self.assertTrue(hash.startswith("$argon2"))
		self.assertNotEqual(encrypted_data, unencrypted)
		# Test decrypt with valid password, hash, and data.
		self.assertEqual(decrypt(password, hash, encrypted_data), (unencrypted, False))
		# Test decrypt with invalid password.
		with self.assertRaises(WrongPasswordError):
			self.assertEqual(decrypt("invalid_password", hash, encrypted_data), (unencrypted, False))
		# Test decrypt with invalid hash.
		with self.assertRaises(InvalidHashError):
			self.assertEqual(decrypt(password, "invalid_hash", encrypted_data), (unencrypted, False))
		# Test decrypt with invalid encrypted data.
		with self.assertRaises(CorruptedDataError):
			self.assertEqual(decrypt(password, hash, b"invalid_encrypted_data"), (unencrypted, False))
