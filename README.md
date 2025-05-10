# JSON Database

A dict-like object which can serialize to disk using JSON.
The database can be optionally password protected using the [Fernet][] recipe
from the Cryptography package for Python, with [Argon2][] as the key derivation function.

## License And Credits

JSON Database was created by [Nick Stockton,][My GitHub] and is licensed under the terms of the [MIT License.][MIT]

## Running From Source

Install the [Python][] interpreter and make sure it's in your path before running this package.

Execute the following commands from the root directory of this repository to install the module dependencies.
```
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade --require-hashes --requirement requirements-uv.txt
uv sync --frozen
pre-commit install -t pre-commit
pre-commit install -t pre-push
```


[Fernet]: https://cryptography.io/en/latest/fernet (Fernet Main Page)
[Argon2]: https://en.wikipedia.org/wiki/Argon2 (Argon2 Wikipedia Page)
[MIT]: /LICENSE.txt (MIT License)
[My GitHub]: https://github.com/nstockton (My Profile On GitHub)
[Python]: https://python.org (Python Main Page)
