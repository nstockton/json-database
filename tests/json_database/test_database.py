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
from pathlib import Path
from typing import Any, NamedTuple
from unittest import TestCase
from unittest.mock import Mock, _CallList, call, patch
from uuid import uuid4

# Third-party Modules:
import orjson

# JSON Database Modules:
from json_database.database import (
	_get_database_path,
	_get_validator,
	_orjson_default,
	_read_database,
	_validate_database,
	_write_database,
	Database,
	FrozenDatabase,
	JSONDecodeError,
	JSONEncodeError,
	convert_unsupported_types,
	dump_database,
	load_database,
)


TEST_SCHEMA: bytes = b"""
{
  "id": "test_v1.encrypted.schema",
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "Test V1",
  "description": "A test schema.",
  "type": "object",
  "properties": {
    "database": {
      "type": "object",
      "patternProperties": {
        "^[0-9a-f]{32}$": {
          "type": "object",
          "properties": {
            "username": {
              "type": "string",
              "minLength": 3,
              "maxLength": 254,
              "pattern": "^[a-z][a-z0-9]+$"
            }
          },
          "required": [
            "username"
          ],
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },
    "schema_version": {
      "type": "integer",
      "enum": [1]
    }
  },
  "required": [
    "database",
    "schema_version"
  ],
  "additionalProperties": false
}
""".strip()


class TestDatabase(TestCase):
	def setUp(self) -> None:
		self.orjson_options: int = (
			orjson.OPT_APPEND_NEWLINE  # Append a line feed to the output.
			| orjson.OPT_INDENT_2  # Pretty-print output with an indent of two spaces.
			| orjson.OPT_SORT_KEYS  # Serialize dict keys in sorted order.
			| orjson.OPT_STRICT_INTEGER  # Enforce 53-bit limit on integers.
		)
		self.database_dict: dict[str, Any] = {"database": {"username": "testname"}, "schema_version": 1}
		self.database_bytes: bytes = orjson.dumps(self.database_dict, option=self.orjson_options)

	def tearDown(self) -> None:
		del self.database_dict

	def test_orjson_default(self) -> None:
		named_tuple = NamedTuple("named_tuple", [])
		self.assertEqual(_orjson_default(named_tuple()), [])
		uuid = uuid4()
		self.assertEqual(_orjson_default(uuid), uuid.hex)
		with self.assertRaises(TypeError):
			_orjson_default(None)

	@patch("json_database.database._validate_database")
	@patch("json_database.database._read_database")
	def test_load_database(self, mock_read_database: Mock, mock_validate_database: Mock) -> None:
		name = "__junk__"
		directory = Path.cwd()
		password = None
		skip_validation = False
		database_path = _get_database_path(name, extension=".json", directory=directory)
		mock_read_database.return_value = self.database_bytes
		loaded_dict = load_database(name, directory=directory, password=password, skip_validation=skip_validation)
		self.assertEqual(loaded_dict, (self.database_dict["database"], self.database_dict["schema_version"]))
		mock_read_database.assert_called_once_with(database_path, password=password)
		# Validate would have actually received the full database dict, however the call to load_database popped the schema off the dict.
		mock_validate_database.assert_called_once_with({"database": self.database_dict["database"]}, database_path)
		mock_read_database.reset_mock()
		mock_validate_database.reset_mock()
		# Test corrupted data:
		mock_read_database.return_value = b"**JUNK**"
		with self.assertRaises(JSONDecodeError):
			load_database(name, directory=directory, password=password, skip_validation=skip_validation)
		mock_read_database.assert_called_once_with(database_path, password=password)
		mock_validate_database.assert_not_called()

	@patch("json_database.database.orjson.dumps")
	@patch("json_database.database.convert_unsupported_types")
	@patch("json_database.database._validate_database")
	@patch("json_database.database._write_database")
	def test_dump_database(self, mock_write_database: Mock, mock_validate_database: Mock, mock_convert_unsupported_types: Mock, mock_dumps: Mock) -> None:
		name = "__junk__"
		directory = Path.cwd()
		password = None
		skip_validation = False
		database_path = _get_database_path(name, extension=".json", directory=directory)
		mock_convert_unsupported_types.return_value = self.database_dict["database"]
		mock_dumps.side_effect = lambda *args, **kwargs: self.database_bytes
		dump_database(name, self.database_dict["database"], directory=directory, version=self.database_dict["schema_version"], password=password)
		mock_convert_unsupported_types.assert_called_once_with(self.database_dict["database"])
		mock_validate_database.assert_called_once_with(self.database_dict, database_path)
		mock_dumps.assert_called_once_with(self.database_dict, option=self.orjson_options, default=_orjson_default)
		mock_write_database.assert_called_once_with(database_path, self.database_bytes, password=password)
		mock_convert_unsupported_types.reset_mock()
		mock_validate_database.reset_mock()
		mock_dumps.reset_mock()
		mock_write_database.reset_mock()
		# Test problem encoding.
		mock_dumps.side_effect = lambda *args, **kwargs: (_ for _ in ()).throw(orjson.JSONEncodeError("some error"))
		with self.assertRaises(JSONEncodeError):
			dump_database(name, self.database_dict["database"], directory=directory, version=self.database_dict["schema_version"], password=password)
		mock_convert_unsupported_types.assert_called_once_with(self.database_dict["database"])
		mock_validate_database.assert_called_once_with(self.database_dict, database_path)
		mock_dumps.assert_called_once_with(self.database_dict, option=self.orjson_options, default=_orjson_default)
		mock_write_database.assert_not_called()
