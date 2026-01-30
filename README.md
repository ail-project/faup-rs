<!-- cargo-rdme start -->

# faup-rs: Fast URL Parser for Rust

[![Crates.io Version](https://img.shields.io/crates/v/faup-rs?style=for-the-badge&color=orange)](https://crates.io/crates/faup-rs)
[![docs.rs](https://img.shields.io/docsrs/faup-rs?style=for-the-badge&logo=docs.rs&color=blue)](https://docs.rs/faup-rs)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/ail-project/faup-rs/rust.yml?style=for-the-badge)

A high-performance, zero-allocation URL parser for Rust that handles:
- Hostnames (with subdomains, custom TLDs, and IDNs)
- IPv4/IPv6 addresses
- User credentials (username/password)
- Ports, paths, queries, and fragments
- UTF-8 and URL-encoded characters

## Features

✅ **Zero-allocation parsing**: Borrows input strings where possible

✅ **Public Suffix List (PSL)**: Correctly identifies domain suffixes

✅ **Custom TLDs**: Extendable via the `CUSTOM_TLDS` constant

✅ **Comprehensive error handling**: Clear, actionable error types

✅ **UTF-8 support**: Full Unicode handling for all URL components

## Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
faup-rs = "0.1"
```

## Usage

### Basic Parsing
```rust
use faup_rs::Url;

let url = Url::parse("https://user:pass@sub.example.com:8080/path?query=value#fragment").unwrap();
assert_eq!(url.scheme(), "https");
assert_eq!(url.host().to_string(), "sub.example.com");
assert_eq!(url.port(), Some(8080));
assert_eq!(url.path(), Some("/path"));
assert_eq!(url.query(), Some("query=value"));
assert_eq!(url.fragment(), Some("fragment"));
```

### Hostname Components
```rust
use faup_rs::{Url, Host};

let url = Url::parse("https://sub.example.co.uk").unwrap();
if let Host::Hostname(hostname) = url.host() {
    assert_eq!(hostname.full_name(), "sub.example.co.uk");
    assert_eq!(hostname.suffix(), Some("co.uk"));
    assert_eq!(hostname.domain(), Some("example.co.uk"));
    assert_eq!(hostname.subdomain(), Some("sub"));
}
```

### IP Addresses
```rust
use faup_rs::Url;

let url = Url::parse("http://[::1]").unwrap();
assert!(matches!(url.host(), faup_rs::Host::Ip(ip) if ip.is_loopback()));
```

### User Info (UTF-8 Support)
```rust
use faup_rs::Url;

let url = Url::parse("https://用户:密码@example.com").unwrap();
let user_info = url.userinfo().unwrap();
assert_eq!(user_info.username(), "用户");
assert_eq!(user_info.password(), Some("密码"));
```

### Custom TLDs
```rust
use faup_rs::Url;

let url = Url::parse("http://example.b32.i2p").unwrap();
assert_eq!(url.suffix(), Some("b32.i2p"));
```

## Examples

### Real-World URLs
```rust
use faup_rs::Url;

let urls = [
    "https://www.example.co.uk",
    "http://sub.domain.example.com/path/to/page",
    "https://例子.测试",
    "http://toaster.dyrøy.no",
    "http://full.custom-tld.test.b32.i2p",
];
for url_str in urls {
    let url = Url::parse(url_str).unwrap();
    println!("Parsed: {}", url);
}
```

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3).

## Acknowledgement

Thanks to Sebastien Tricaud for [the original work on faup](https://github.com/stricaud/faup).

<!-- cargo-rdme end -->

# Funding

Faup-rs is co-funded by [CIRCL](https://www.circl.lu/) and by the European Union under [FETTA](https://www.circl.lu/pub/press/20240131/) (Federated European Team for Threat Analysis) project.

![EU logo](assets/eu-funded-en.svg)