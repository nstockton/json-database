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

"""Encryption."""

# Future Modules:
from __future__ import annotations

# Built-in Modules:
import base64
import hashlib
from typing import Union

# Third-party Modules:
import argon2
from cryptography.fernet import Fernet, InvalidToken
from knickknacks.typedef import BytesOrStrType


class EncryptionError(Exception):
	"""Base class for decryption module errors."""


class DecryptorError(EncryptionError):
	"""Base class for decryption errors."""


class EncryptorError(EncryptionError):
	"""Base class for decryption errors."""


class InvalidHashError(DecryptorError):
	"""Raised when a hash is invalid or corrupted."""


class WrongPasswordError(DecryptorError):
	"""Raised when a password does not match a hash."""


class CorruptedDataError(DecryptorError):
	"""Raised when data to be decrypted is malformed or lacks a valid signature."""


def decode_base64(text: BytesOrStrType) -> BytesOrStrType:
	"""
	Decodes base64 text.

	Args:
		text: The base64 encoded text.

	Returns:
		The base64 decoded text.
	"""
	if isinstance(text, str):
		data = base64.urlsafe_b64decode(bytes(text, "utf-8"))
		return str(data, "utf-8")
	return base64.urlsafe_b64decode(text)


def encode_base64(text: BytesOrStrType) -> BytesOrStrType:
	"""
	Encodes text in base64.

	Args:
		text: The text to encode in base64.

	Returns:
		The base64 encoded text.
	"""
	if isinstance(text, str):
		data = base64.urlsafe_b64encode(bytes(text, "utf-8"))
		return str(data, "utf-8")
	return base64.urlsafe_b64encode(text)


def get_checksum(algorithm: str, data: BytesOrStrType) -> BytesOrStrType:
	"""
	Generates a checksum.

	Args:
		algorithm: The hashing algorithm to use.
		data: The data to hash.

	Returns:
		The checksum.
	"""
	if isinstance(data, str):
		return hashlib.new(algorithm, bytes(data, "utf-8")).hexdigest()
	return bytes(hashlib.new(algorithm, data).hexdigest(), "utf-8")


def hash_password(password: Union[bytes, str]) -> str:
	"""
	Creates a hash of a password.

	Args:
		password: A password in plain text.

	Returns:
		A password hash.
	"""
	hasher: argon2.PasswordHasher = argon2.PasswordHasher()
	return hasher.hash(password)


def verify_password(password: Union[bytes, str], password_hash: str) -> bool:
	"""
	Verifies a password against a hash.

	Args:
		password: A password in plain text.
		password_hash: A password hash.

	Returns:
		True if the password needs rehashing, False otherwise.

	Raises:
		WrongPasswordError: The data cannot be decrypted with password.
		InvalidHashError: Invalid password hash.
	"""
	hasher = argon2.PasswordHasher()
	try:
		hasher.verify(password_hash, password)
	except argon2.exceptions.VerifyMismatchError:
		raise WrongPasswordError("Password does not match password hash.") from None
	except argon2.exceptions.InvalidHash:
		raise InvalidHashError("Invalid password hash.") from None
	return hasher.check_needs_rehash(password_hash)


def generate_fernet_key(password: str, password_hash: str) -> bytes:
	"""
	Generates a Fernet key (required when instantiating the Fernet class).

	Args:
		password: A password in plain text.
		password_hash: The Argon2 hash of the password.

	Returns:
		The generated Fernet key.
	"""
	parameters: argon2.Parameters = argon2.extract_parameters(password_hash)
	salt: str = password_hash.split("$")[-2]
	raw_hash: bytes = argon2.low_level.hash_secret_raw(
		secret=bytes(password, "utf_16_le"),
		salt=bytes(salt, "utf_16_le"),
		time_cost=parameters.time_cost,
		memory_cost=parameters.memory_cost,
		parallelism=parameters.parallelism,
		hash_len=parameters.hash_len,
		type=parameters.type,
		version=parameters.version,
	)
	return base64.urlsafe_b64encode(raw_hash)


def decrypt(password: str, password_hash: str, data: bytes) -> tuple[bytes, bool]:
	"""
	Decrypts data using a password.

	Args:
		password: A password in plain text.
		password_hash: The Argon2 hash associated with the encrypted data.
		data: The encrypted data to be decrypted.

	Returns:
		A tuple containing the decrypted data, and a boolean representing if the password needs rehashing.

	Raises:
		CorruptedDataError: Invalid data.
	"""
	needs_rehash: bool = verify_password(password, password_hash)
	key: bytes = generate_fernet_key(password, password_hash)
	fernet = Fernet(key)
	try:
		decrypted_data: bytes = fernet.decrypt(data)
	except InvalidToken:
		raise CorruptedDataError("Data to be decrypted is invalid.") from None
	return decrypted_data, needs_rehash


def encrypt(password: str, data: bytes) -> tuple[str, bytes]:
	"""
	Encrypts data using a password.

	Args:
		password: A password in plain text.
		data: The unencrypted data to be encrypted.

	Returns:
		A tuple containing an Argon2 hash and the associated encrypted data.
	"""
	password_hash: str = hash_password(password)
	key: bytes = generate_fernet_key(password, password_hash)
	fernet = Fernet(key)
	encrypted_data: bytes = fernet.encrypt(data)
	return password_hash, encrypted_data
