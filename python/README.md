# pyfaup: Fast URL Parser for Python (Rust-Powered)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/Made%20with-Rust-orange)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Made%20for-Python-blue)](https://www.python.org/)

`pyfaup` is a high-performance URL parsing library for Python, built in Rust using PyO3. It provides a modern, type-safe, and efficient way to parse URLs, with backward compatibility for the legacy [Faup](https://github.com/stricaud/faup) C project's API.

## Features

- **Fast and Efficient**: Powered by Rust for maximum performance.
- **Modern API**: Direct access to URL components via the `Url` class.
- **Backward Compatibility**: `FaupCompat` class mimics the original Faup Python API.
- **Comprehensive Parsing**: Supports schemes, credentials, hosts, ports, paths, queries, and fragments.
- **Error Handling**: Clear and informative error messages.

## Installation

### Prerequisites

- Python 3.8+
- Rust toolchain (for building from source)

### Install from PyPI

```bash
pip install pyfaup-rs
```

### Install from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/ail-project/faup-rs.git
   cd faup-rs
   ```
2. Install using `maturin`:
   ```bash
   pip install maturin
   maturin develop
   ```

## Usage

### Using the `Url` Class

The `Url` class provides direct access to all URL components:

```python
from pyfaup import Url

url = Url("https://user:pass@sub.example.com:8080/path?query=value#fragment")
print(url.scheme)   # "https"
print(url.username) # "user"
print(url.host)     # "sub.example.com"
print(url.port)     # 8080
```

### Using the `FaupCompat` Class

The `FaupCompat` class provides a compatibility layer for the original FAUP API:

```python
from pyfaup import FaupCompat as Faup

faup = Faup()
faup.decode("https://user:pass@sub.example.com:8080/path?query=value#fragment")
result = faup.get()
print(result["credentials"])  # "user:pass"
print(result["domain"])       # "example.com"
print(result["scheme"])       # "https"
```

## API Reference

### `Url` Class

- **Attributes**:
  - `scheme`: URL scheme (e.g., "http", "https").
  - `username`: Username from credentials.
  - `password`: Password from credentials.
  - `host`: Host part of the URL.
  - `subdomain`: Subdomain part of the hostname.
  - `domain`: Domain part of the hostname.
  - `suffix`: Top-level domain (TLD).
  - `port`: Port number.
  - `path`: Path component.
  - `query`: Query string.
  - `fragment`: Fragment identifier.

- **Methods**:
  - `new(url: str) -> Url`: Parses a URL string and returns a `Url` object.

### `FaupCompat` Class

- **Methods**:
  - `new() -> FaupCompat`: Creates a new `FaupCompat` instance.
  - `decode(url: str) -> None`: Decodes a URL string.
  - `get() -> dict`: Returns a dictionary with all URL components.

## Compatibility Notes

- The `FaupCompat` class is provided for backward compatibility and may be slower than the `Url` class due to additional Python object creation.
- The `Url` class is recommended for new projects.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the **GPLv3 License**.