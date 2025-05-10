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

"""Database related functions."""

# Future Modules:
from __future__ import annotations

# Built-in Modules:
import logging
import secrets
import threading
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from dataclasses import asdict, is_dataclass
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar, Optional, TypeVar, Union, cast
from uuid import UUID

# Third-party Modules:
import fastjsonschema
import orjson
from knickknacks.typedef import AnyMappingType, TypeAlias, override
from knickknacks.uuid7 import UUID7

# Local Modules:
from .encryption import decrypt, encrypt, get_checksum


if TYPE_CHECKING:  # pragma: no cover
	from _typeshed import DataclassInstance


ValidatorType: TypeAlias = Callable[[AnyMappingType], None]
_KeyType = TypeVar("_KeyType")  # Used by Database and FrozenDatabase.
_ValueType = TypeVar("_ValueType")  # Used by Database and FrozenDatabase.


logger: logging.Logger = logging.getLogger(__name__)


class DatabaseError(Exception):
	"""All database related errors inherit from this class."""


class ChecksumsDoNotMatchError(DatabaseError):
	"""Raised when a file checksum doesn't match with the expected checksum."""


class FileIOError(DatabaseError):
	"""Raised when there is a problem accessing a file for input or output."""


class JSONDecodeError(DatabaseError):
	"""Raised when there is a problem decoding from JSON."""


class JSONEncodeError(DatabaseError):
	"""Raised when there is a problem encoding to JSON."""


class JSONValidationError(DatabaseError):
	"""Raised when there is a problem validating JSON."""


class LoaderNotImplementedError(DatabaseError):
	"""Raised if a loader for the schema version was not implemented."""

	def __init__(self, version: int) -> None:
		"""
		Defines the constructor.

		Args:
			version: The schema version.
		"""
		super().__init__(f"Loader for schema version {version} not implemented.")


class DatabaseNotFoundError(FileIOError):
	"""Raised when the database file is not found."""

	def __init__(self, filename: str) -> None:
		"""
		Defines the constructor.

		Args:
			filename: The name of the database file.
		"""
		super().__init__(f"Database file '{filename}' not found.")


class SchemaNotFoundError(FileIOError):
	"""Raised when the schema file for a given version is not found."""

	def __init__(self, version: int) -> None:
		"""
		Defines the constructor.

		Args:
			version: The invalid version.
		"""
		super().__init__(f"No schema file for version {version} found.")


class ReadError(FileIOError):
	"""Raised when there is a problem reading from a file."""


class WriteError(FileIOError):
	"""Raised when there is a problem writing to a file."""


@cache
def _get_database_path(name: str, *, extension: str, directory: Path) -> Path:
	"""
	Retrieves the database path.

	Args:
		name: The database name.
		extension: The file extension.
		directory: The directory where the database is located.

	Returns:
		The database path.
	"""
	return directory / f"{name}{extension}"


@cache
def _get_validator(database_path: Path, version: int) -> ValidatorType:
	"""
	Retrieves the database validator.

	Args:
		database_path: The database file path associated with the schema.
		version: The schema version.

	Returns:
		The validator.

	Raises:
		SchemaNotFoundError: No schema file found matching version.
		ReadError: There was a problem reading from the file.
		JSONDecodeError: There was a problem decoding json from the file.
	"""
	# Change "database.extension" to "database_v1.extension.schema".
	schema_path = database_path.with_stem(
		f"{database_path.stem}_v{version}{database_path.suffix}"
	).with_suffix(".schema")
	if not schema_path.is_file():
		raise SchemaNotFoundError(version)
	try:
		data: bytes = schema_path.read_bytes()
	except OSError as e:
		raise ReadError from e
	try:
		schema: dict[str, Any] = orjson.loads(data)
	except orjson.JSONDecodeError as e:
		raise JSONDecodeError from e
	validator: ValidatorType = fastjsonschema.compile(schema)
	return validator


def _validate_database(database: AnyMappingType, database_path: Path) -> None:
	"""
	Validates a database against a schema.

	Args:
		database: The database to validate.
		database_path: The path to the database file (used for determining schema path).

	Raises:
		JSONValidationError: Error validating the database.
	"""
	validator = _get_validator(database_path, database.get("schema_version", 0))
	try:
		validator(database)
	except fastjsonschema.JsonSchemaException as e:
		raise JSONValidationError from e


def _read_database(database_path: Path, *, password: Optional[str] = None) -> bytes:
	"""
	Reads data from a database file.

	Args:
		database_path: The path to the database file.
		password: If supplied, data will be decrypted with this password.

	Returns:
		The file data.

	Raises:
		DatabaseNotFoundError: The database file was not found.
		ReadError: There was a problem reading from the file.
		ChecksumsDoNotMatchError: Corrupted database file detected during decryption.
	"""
	if not database_path.is_file():
		raise DatabaseNotFoundError(str(database_path))
	try:
		with database_path.open("rb") as f:
			if password is None:
				return f.read()
			checksum: bytes = f.readline().strip()
			pw_hash: bytes = f.readline().strip()
			encrypted_data: bytes = f.read()
	except OSError as e:
		raise ReadError from e
	if not secrets.compare_digest(get_checksum("sha256", pw_hash + b"\n" + encrypted_data), checksum):
		raise ChecksumsDoNotMatchError(f"Corrupted database file: '{database_path!s}'.")
	data, needs_rehash = decrypt(password, str(pw_hash, "utf-8"), encrypted_data)
	if needs_rehash:
		# Default values for the password hasher have been updated since the database was last saved.
		# Encrypt the database with the new values and save it to disk.
		_write_database(database_path, data, password=password)
	return data


def _write_database(database_path: Path, data: bytes, *, password: Optional[str] = None) -> None:
	"""
	Writes data to a database file.

	Args:
		database_path: The path to the database file.
		data: The data to be encrypted.
		password: If supplied, data will be encrypted with this password.

	Raises:
		WriteError: There was a problem writing to the file.
	"""
	try:
		with database_path.open("wb") as f:
			if password is None:
				f.write(data)
				return
			pw_hash, encrypted_data = encrypt(password, data)
			body: bytes = bytes(pw_hash, "utf-8") + b"\n" + encrypted_data
			f.write(get_checksum("sha256", body))
			f.write(b"\n")
			f.write(body)
	except OSError as e:
		raise WriteError from e


def convert_unsupported_types(obj: AnyMappingType) -> dict[Any, Any]:
	"""
	Converts any dataclasses found in a dict-like object to dicts.

	This is necessary since although orjson can
	serialize dataclasses natively, fastjsonschema will choke on them.

	Args:
		obj: The dict-like object to convert.

	Returns:
		A new dict with all dataclass objects converted to dicts.
	"""
	stack: list[tuple[Any, list[Any]]] = [(obj, [])]
	result: dict[Any, Any] = {}
	while stack:
		current, parent_key = stack.pop()
		if is_dataclass(current):
			if TYPE_CHECKING:  # pragma: no cover
				current = cast(DataclassInstance, current)
			for current_key, current_value in asdict(current).items():
				stack.append((current_value, [*parent_key, current_key]))
		elif isinstance(current, (UUID, UUID7)):
			current = current.hex
		elif isinstance(current, Mapping):
			key: Union[UUID7, UUID, str]
			for key, value in current.items():
				k = key.hex if isinstance(key, (UUID, UUID7)) else key
				stack.append((value, [*parent_key, k]))
		else:
			d = result
			for key in parent_key[:-1]:
				d = d.setdefault(key, {})
			d[parent_key[-1]] = current
	return result


def _orjson_default(obj: Any) -> Any:
	"""
	Defines special behavior for orjson serialization.

	Args:
		obj: The unknown object.

	Returns:
		A serializable object.

	Raises:
		TypeError: Unsupported object.
	"""
	if isinstance(obj, tuple) and hasattr(obj, "_asdict"):
		# NamedTuple.
		return list(obj)
	if isinstance(obj, (UUID, UUID7)):
		return obj.hex
	raise TypeError


def load_database(
	name: str, *, directory: Path, password: Optional[str] = None, skip_validation: bool = False
) -> tuple[dict[Any, Any], int]:
	"""
	Loads a database from disc.

	Args:
		name: The name of the database.
		directory: The directory where the database is located.
		password: If supplied, decrypt the database with password.
		skip_validation: True if database validation should be skipped, False otherwise.

	Returns:
		A tuple containing The database and the database schema version.

	Raises:
		JSONDecodeError: There was a problem decoding json from the file.
	"""
	database_path = _get_database_path(
		name, extension=".json" if password is None else ".encrypted", directory=directory
	)
	data = _read_database(database_path, password=password)
	try:
		outer_database: dict[str, Any] = orjson.loads(data)
	except orjson.JSONDecodeError as e:
		raise JSONDecodeError from e
	if not skip_validation:
		_validate_database(outer_database, database_path)
	version: int = outer_database.pop("schema_version")
	database: dict[Any, Any] = outer_database["database"]
	return database, version


def dump_database(  # NOQA: PLR0913
	name: str,
	database: AnyMappingType,
	*,
	directory: Path,
	version: int,
	password: Optional[str] = None,
	convert_unsupported: bool = True,
) -> None:
	"""
	Saves a database to disk.

	Args:
		name: The name of the database, from which file name is determined.
		database: The database to be saved.
		directory: The directory where the database is located.
		version: The schema version.
		password: If supplied, encrypt the database with password.
		convert_unsupported: True if unsupported types should be converted, False otherwise.

	Raises:
		JSONEncodeError: There was a problem encoding json to the file.
	"""
	database_path = _get_database_path(
		name, extension=".json" if password is None else ".encrypted", directory=directory
	)
	if convert_unsupported:
		database = convert_unsupported_types(database)
	outer_database = {"database": database, "schema_version": version}
	_validate_database(outer_database, database_path)
	orjson_options: int = (
		orjson.OPT_APPEND_NEWLINE  # Append a line feed to the output.
		| orjson.OPT_INDENT_2  # Pretty-print output with an indent of two spaces.
		| orjson.OPT_SORT_KEYS  # Serialize dict keys in sorted order.
		| orjson.OPT_STRICT_INTEGER  # Enforce 53-bit limit on integers.
	)
	try:
		data: bytes = orjson.dumps(outer_database, option=orjson_options, default=_orjson_default)
	except orjson.JSONEncodeError as e:
		raise JSONEncodeError from e
	_write_database(database_path, data, password=password)


class FrozenDatabase(Mapping[_KeyType, _ValueType]):
	"""
	A generic Mapping type which can load data from disk.

	Users must subclass this class and provide their own loader based on the schema version.
	"""

	_locks: ClassVar[dict[Path, threading.RLock]] = {}
	"""Per-file based locks."""

	@override
	def __init__(
		self, *, name: str, latest_version: int, directory: Optional[Union[Path, str]] = None
	) -> None:
		"""
		Defines the constructor for the object.

		Args:
			name: The name of the database.
			latest_version: The latest version of the database schema.
			directory: The directory where the database is stored.
		"""
		super().__init__()
		self._name: str = name
		self._directory: Path
		if directory is None:
			self._directory = Path.cwd()
		elif isinstance(directory, str):
			self._directory = Path(directory)
		else:
			self._directory = directory
		self._latest_version: int = latest_version
		self._lock = self._locks.setdefault(self._directory / name, threading.RLock())
		self._database: dict[_KeyType, _ValueType] = {}
		self._database_proxy: MappingProxyType[_KeyType, _ValueType] = MappingProxyType(self._database)

	@property
	def name(self) -> str:
		"""The name of the database."""
		return self._name

	@property
	def directory(self) -> Path:
		"""The directory where the database is located."""
		return self._directory

	def load(self, *, password: Optional[str] = None, skip_validation: bool = False) -> None:
		"""
		Loads the secrets database from disc.

		Note:
			Subclasses must implement `load_vX` methods for each supported schema version.

		Args:
			password: If supplied, the database will be decrypted with this password.
			skip_validation: True if database validation should be skipped, False otherwise.

		Raises:
			LoaderNotImplementedError: A loader for the schema version is not implemented.
		"""
		with self._lock:
			try:
				database, version = load_database(
					self.name, directory=self.directory, password=password, skip_validation=skip_validation
				)
			except DatabaseNotFoundError as e:
				logger.warning(str(e))
				return
			loader = getattr(self, f"load_v{version}", None)
			if loader is None:
				raise LoaderNotImplementedError(version)
			self._database.clear()
			loader(database)

	@override
	def __getitem__(self, key: _KeyType) -> _ValueType:
		with self._lock:
			return self._database_proxy[key]

	@override
	def __iter__(self) -> Iterator[_KeyType]:
		with self._lock:
			return iter(self._database_proxy)

	@override
	def __len__(self) -> int:
		with self._lock:
			return len(self._database_proxy)


class Database(FrozenDatabase[_KeyType, _ValueType], MutableMapping[_KeyType, _ValueType]):
	"""A generic MutableMapping type which can save data to disk."""

	def save(self, *, password: Optional[str] = None, convert_unsupported: bool = True) -> None:
		"""
		Saves the database to disc.

		Args:
			password: If supplied, the database will be encrypted with this password.
			convert_unsupported: True if unsupported types should be converted, False otherwise.
		"""
		with self._lock:
			dump_database(
				self._name,
				self._database,
				directory=self.directory,
				version=self._latest_version,
				password=password,
				convert_unsupported=convert_unsupported,
			)

	@override
	def __setitem__(self, key: _KeyType, value: _ValueType) -> None:
		with self._lock:
			self._database[key] = value

	@override
	def __delitem__(self, key: _KeyType) -> None:
		with self._lock:
			del self._database[key]
