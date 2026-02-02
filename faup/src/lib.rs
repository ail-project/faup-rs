#![deny(missing_docs)]
//! # faup-rs: Fast URL Parser for Rust
//!
//! [![Crates.io Version](https://img.shields.io/crates/v/faup-rs?style=for-the-badge&color=orange)](https://crates.io/crates/faup-rs)
//! [![docs.rs](https://img.shields.io/docsrs/faup-rs?style=for-the-badge&logo=docs.rs&color=blue)](https://docs.rs/faup-rs)
//! ![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/ail-project/faup-rs/rust.yml?style=for-the-badge)
//!
//! A high-performance, zero-allocation URL parser for Rust that handles:
//! - Hostnames (with subdomains, custom TLDs, and IDNs)
//! - IPv4/IPv6 addresses
//! - User credentials (username/password)
//! - Ports, paths, queries, and fragments
//! - UTF-8 and URL-encoded characters
//!
//! ## Features
//!
//! ✅ **Zero-allocation parsing**: Borrows input strings where possible
//!
//! ✅ **Public Suffix List (PSL)**: Correctly identifies domain suffixes
//!
//! ✅ **Custom TLDs**: Extendable via the `CUSTOM_TLDS` constant
//!
//! ✅ **Comprehensive error handling**: Clear, actionable error types
//!
//! ✅ **UTF-8 support**: Full Unicode handling for all URL components
//!
//! ## Installation
//!
//! Add to your `Cargo.toml`:
//! ```toml
//! [dependencies]
//! faup-rs = "0.1"
//!```
//!
//! ## Usage
//!
//! ### Basic Parsing
//! ```
//! use faup_rs::Url;
//!
//! let url = Url::parse("https://user:pass@sub.example.com:8080/path?query=value#fragment").unwrap();
//! assert_eq!(url.scheme(), "https");
//! assert_eq!(url.host().to_string(), "sub.example.com");
//! assert_eq!(url.port(), Some(8080));
//! assert_eq!(url.path(), Some("/path"));
//! assert_eq!(url.query(), Some("query=value"));
//! assert_eq!(url.fragment(), Some("fragment"));
//!```
//!
//! ### Hostname Components
//! ```
//! use faup_rs::{Url, Host};
//!
//! let url = Url::parse("https://sub.example.co.uk").unwrap();
//! if let Host::Hostname(hostname) = url.host() {
//!     assert_eq!(hostname.full_name(), "sub.example.co.uk");
//!     assert_eq!(hostname.suffix_str(), Some("co.uk"));
//!     assert_eq!(hostname.domain(), Some("example.co.uk"));
//!     assert_eq!(hostname.subdomain(), Some("sub"));
//! }
//!```
//!
//! ### IP Addresses
//! ```
//! use faup_rs::Url;
//!
//! let url = Url::parse("http://[::1]").unwrap();
//! assert!(matches!(url.host(), faup_rs::Host::Ip(ip) if ip.is_loopback()));
//!```
//!
//! ### User Info (UTF-8 Support)
//! ```
//! use faup_rs::Url;
//!
//! let url = Url::parse("https://用户:密码@example.com").unwrap();
//! let user_info = url.userinfo().unwrap();
//! assert_eq!(user_info.username(), "用户");
//! assert_eq!(user_info.password(), Some("密码"));
//!```
//!
//! ### Custom TLDs
//! ```
//! use faup_rs::Url;
//!
//! let url = Url::parse("http://example.b32.i2p").unwrap();
//! assert_eq!(url.suffix_str(), Some("b32.i2p"));
//!```
//!
//! ## Examples
//!
//! ### Real-World URLs
//! ```
//! use faup_rs::Url;
//!
//! let urls = [
//!     "https://www.example.co.uk",
//!     "http://sub.domain.example.com/path/to/page",
//!     "https://例子.测试",
//!     "http://toaster.dyrøy.no",
//!     "http://full.custom-tld.test.b32.i2p",
//! ];
//! for url_str in urls {
//!     let url = Url::parse(url_str).unwrap();
//!     println!("Parsed: {}", url);
//! }
//!```
//!
//! ## License
//!
//! This project is licensed under the GNU General Public License v3.0 (GPLv3)..
//!
//! ## Acknowledgement
//!
//! Thanks to Sebastien Tricaud for [the original work on faup](https://github.com/stricaud/faup).
//!
use std::{
    borrow::Cow,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use pest::{Parser, iterators::Pair};
use thiserror::Error;

mod parser;

use parser::*;

static CUSTOM_TLDS: &[&str] = &["b32.i2p"];

/// URL parsing errors that can occur during URL analysis.
///
/// This enum represents all possible errors that can occur when parsing URLs
/// using the faup-rs library. Each variant corresponds to a specific type
/// of parsing failure, from invalid port numbers to malformed IP addresses.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid port number encountered during URL parsing.
    ///
    /// This error occurs when a port number cannot be parsed as a valid u16 value.
    /// Port numbers must be between 0 and 65535.
    #[error("invalid port")]
    InvalidPort,

    /// Invalid IPv4 address encountered during URL parsing.
    ///
    /// This error occurs when a string that should be an IPv4 address
    /// cannot be parsed according to IPv4 address standards.
    #[error("invalid ipv4 address")]
    InvalidIPv4,

    /// Invalid IPv6 address encountered during URL parsing.
    ///
    /// This error occurs when a string that should be an IPv6 address
    /// cannot be parsed according to IPv6 address standards.
    #[error("invalid ipv6 address")]
    InvalidIPv6,

    /// Invalid host encountered during URL parsing.
    ///
    /// This error occurs when a host string cannot be parsed as either
    /// a valid hostname or a valid IP address (IPv4 or IPv6).
    #[error("invalid host")]
    InvalidHost,

    /// Generic error for other parsing issues.
    ///
    /// This error is used for various parsing problems that don't fit
    /// the more specific error categories.
    #[error("{0}")]
    Other(String),

    /// Parsing error from the underlying pest parser.
    ///
    /// This error occurs when the URL string doesn't conform to
    /// the expected grammar structure.
    #[error("parser error: {0}")]
    Parse(#[from] Box<pest::error::Error<Rule>>),
}

impl Error {
    fn other<S: AsRef<str>>(s: S) -> Self {
        Error::Other(s.as_ref().to_string())
    }
}

/// Classification of a suffix (Top-Level Domain) based on its origin and validity.
///
/// This enum categorizes suffixes according to their source and compliance status.
/// The classification helps determine whether a suffix is officially recognized
/// by ICANN, privately managed, or unknown.
///
/// # Variants
///
/// - `Icann`: Suffixes that are officially recognized by ICANN and listed in the
///   Mozilla Public Suffix List (PSL). These are standard top-level domains like
///   `.com`, `.org`, `.net`, etc.
///
/// - `Private`: Suffixes that are privately managed but still listed in the Mozilla PSL.
///   These include some specific domains used by organizations.
///
/// - `Unknown`: Suffixes that are not found in the Mozilla Public Suffix List.
///   These are typically custom or non-standard suffixes used in private networks
///   or testing environments (e.g., `.local`, `.test`, `.example`).
///
/// # Examples
///
/// ```
/// use faup_rs::{Url, SuffixType};
///
/// // ICANN-recognized suffix
/// let url = Url::parse("https://example.com").unwrap();
/// assert!(matches!(url.suffix().unwrap().ty(), SuffixType::Icann));
///
/// // Private suffix (if in PSL)
/// let url = Url::parse("https://example.transfer-webapp.af-south-1.on.aws").unwrap();
/// assert!(matches!(url.suffix().unwrap().ty(), SuffixType::Private));
///
/// // Unknown suffix (in PSL)
/// let url = Url::parse("https://example.custom").unwrap();
/// assert!(matches!(url.suffix().unwrap().ty(), SuffixType::Unknown));
/// ```
#[derive(Debug, Clone, Copy)]
pub enum SuffixType {
    /// ICANN-recognized top-level domain from the Mozilla Public Suffix List.
    ///
    /// These are standard, globally recognized domain suffixes like `.com`, `.org`, `.net`.
    Icann,

    /// Privately managed suffix from the Mozilla Public Suffix List.
    ///
    /// These include special-purpose domains like organization-specific
    /// suffixes that are officially listed in PSL but not ICANN-managed.
    Private,

    /// Custom or non-standard suffix not found in the Mozilla Public Suffix List.
    ///
    /// These are typically used in private networks, testing environments, or custom setups.
    /// Examples include `.local`, `.test`, `.example`, or any custom TLDs.
    Unknown,
}

impl SuffixType {
    #[inline]
    fn from_psl_suffix(ps: psl::Suffix<'_>) -> Self {
        ps.typ()
            .map(|t| match t {
                psl::Type::Icann => Self::Icann,
                psl::Type::Private => Self::Private,
            })
            .unwrap_or(Self::Unknown)
    }

    /// Returns `true` if the suffix is known from official sources.
    ///
    /// A suffix is considered "known" if it is either:
    /// - Listed in the Mozilla Public Suffix List (PSL) as ICANN-recognized (`Icann`)
    /// - Listed in the Mozilla Public Suffix List as privately managed (`Private`)
    ///
    /// Returns `false` for custom or unknown suffixes that are not found in the PSL
    /// and are not in the library's `CUSTOM_TLDS` list.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{SuffixType, Url};
    ///
    /// // Known suffixes (from PSL)
    /// let url = Url::parse("https://example.com").unwrap();
    /// assert!(url.suffix().unwrap().ty().is_known()); // .com is in PSL
    ///
    /// // Unknown suffixes (not in PSL)
    /// let url = Url::parse("https://example.custom").unwrap();
    /// assert!(!url.suffix().unwrap().ty().is_known()); // .custom is not in PSL
    /// ```
    pub fn is_known(&self) -> bool {
        match self {
            SuffixType::Icann => true,
            SuffixType::Private => true,
            SuffixType::Unknown => false,
        }
    }
}

/// Internal representation of suffix data with type information.
///
/// `SuffixData` is an internal struct that stores a suffix (Top-Level Domain) string
/// along with its classification type.
///
/// This struct is used internally by the [`Suffix`] enum to represent both PSL-based
/// suffixes and custom suffixes with consistent data structure and methods.
///
/// # Type Parameters
///
/// - `'s`: Lifetime parameter indicating the lifetime of the borrowed string data
#[derive(Debug)]
pub struct SuffixData<'s> {
    s: Cow<'s, str>,
    ty: SuffixType,
}

impl<'s> SuffixData<'s> {
    fn new(suf: &'s str, ty: SuffixType) -> Self {
        SuffixData {
            s: Cow::Borrowed(suf),
            ty,
        }
    }

    /// Returns the suffix as a string slice.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.s.as_ref()
    }

    fn into_owned<'owned>(self) -> SuffixData<'owned> {
        SuffixData {
            s: Cow::Owned(self.s.into_owned()),
            ty: self.ty,
        }
    }
}

/// Represents a suffix (Top-Level Domain) with its source classification.
///
/// The `Suffix` enum categorizes domain suffixes based on their origin:
/// either from the Mozilla Public Suffix List (PSL) or as custom/unknown suffixes.
///
/// # Variants
///
/// - `Psl`: A suffix found in the Mozilla Public Suffix List. These are officially
///   recognized domain suffixes that follow ICANN standards or are privately managed
///   but listed in the PSL.
///
/// - `Custom`: A suffix defined in this library but not in PSL
///
/// # Type Parameters
///
/// - `'s`: Lifetime parameter for the borrowed string data
///
/// # Examples
///
/// ```
/// use faup_rs::{Url, Suffix};
///
/// // PSL suffix (.com is in the Mozilla Public Suffix List)
/// let url = Url::parse("https://example.com").unwrap();
/// assert!(matches!(url.suffix(), Some(Suffix::Psl(_))));
///
/// // Custom suffix (.b32.i2p is not in PSL but hardcoded in this crate)
/// let url = Url::parse("https://example.b32.i2p").unwrap();
/// assert!(matches!(url.suffix(), Some(Suffix::Custom(_))));
/// ```
#[derive(Debug)]
pub enum Suffix<'s> {
    /// A custom suffix not found in the Mozilla Public Suffix List but defined in this crate.
    Custom(SuffixData<'s>),

    /// A suffix from the Mozilla Public Suffix List.
    ///
    /// These suffixes are officially recognized and follow established domain naming
    /// standards. They can be either ICANN-managed or privately managed but listed
    /// in the PSL.
    Psl(SuffixData<'s>),
}

impl Suffix<'_> {
    fn into_owned<'owned>(self) -> Suffix<'owned> {
        match self {
            Suffix::Custom(s) => Suffix::Custom(s.into_owned()),
            Suffix::Psl(s) => Suffix::Psl(s.into_owned()),
        }
    }

    /// Returns the suffix as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Some(suffix) = url.suffix() {
    ///     assert_eq!(suffix.as_str(), "com");
    /// }
    /// ```
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        match self {
            Suffix::Custom(s) => s.as_str(),
            Suffix::Psl(s) => s.as_str(),
        }
    }

    /// Returns the suffix type classification.
    ///
    /// This method provides a reference to the [`SuffixType`] enum that classifies
    /// the suffix as either ICANN-recognized, privately managed, or unknown.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, SuffixType};
    ///
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Some(suffix) = url.suffix() {
    ///     match suffix.ty() {
    ///         SuffixType::Icann => println!("ICANN-recognized suffix"),
    ///         SuffixType::Private => println!("Privately managed suffix"),
    ///         SuffixType::Unknown => println!("Unknown suffix"),
    ///     }
    /// }
    /// ```
    pub fn ty(&self) -> &SuffixType {
        match self {
            Suffix::Custom(s) => &s.ty,
            Suffix::Psl(s) => &s.ty,
        }
    }

    /// Returns `true` if the suffix is known from official sources.
    ///
    /// A suffix is considered "known" if it is listed in the Mozilla Public
    /// Suffix List or if it is in the list of hardcoded suffix of this crate.
    /// Returns `false` for custom or unknown suffixes.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// // Known suffix (.com is in PSL)
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Some(suffix) = url.suffix() {
    ///     assert!(suffix.is_known());
    /// }
    ///
    /// // Unknown suffix (.custom is typically not in PSL)
    /// let url = Url::parse("https://example.custom").unwrap();
    /// if let Some(suffix) = url.suffix() {
    ///     assert!(!suffix.is_known());
    /// }
    /// ```
    pub fn is_known(&self) -> bool {
        self.ty().is_known()
    }
}

#[inline(always)]
fn suffix<'h>(hostname: &'h str) -> Option<Suffix<'h>> {
    for tld in CUSTOM_TLDS {
        if hostname.ends_with(tld) {
            return Some(Suffix::Custom(SuffixData::new(tld, SuffixType::Private)));
        }
    }
    let suf_str = psl::suffix_str(hostname)?;
    let suf = psl::suffix(hostname.as_bytes())?;
    Some(Suffix::Psl(SuffixData::new(
        suf_str,
        SuffixType::from_psl_suffix(suf),
    )))
}

/// Represents a parsed hostname with its components (subdomain, domain, and suffix).
///
/// The `Hostname` struct provides access to the different parts of a domain name,
/// including support for internationalized domain names (IDNs), custom top-level domains (TLDs),
/// and subdomains. It uses the Public Suffix List (via the `psl` crate) to properly identify
/// domain suffixes, with additional support for custom TLDs.
///
/// # Examples
///
/// ```
/// use faup_rs::{Url, Host};
///
/// // Parse a simple domain
/// let url = Url::parse("https://example.com").unwrap();
/// if let Host::Hostname(hostname) = url.host() {
///     assert_eq!(hostname.full_name(), "example.com");
///     assert_eq!(hostname.suffix_str(), Some("com"));
///     assert_eq!(hostname.domain(), Some("example.com"));
///     assert_eq!(hostname.subdomain(), None);
/// }
///
/// // Parse a domain with subdomains
/// let url = Url::parse("https://sub.example.co.uk").unwrap();
/// if let Host::Hostname(hostname) = url.host() {
///     assert_eq!(hostname.full_name(), "sub.example.co.uk");
///     assert_eq!(hostname.suffix_str(), Some("co.uk"));
///     assert_eq!(hostname.domain(), Some("example.co.uk"));
///     assert_eq!(hostname.subdomain(), Some("sub"));
/// }
///
/// // Parse a domain with UTF-8 characters
/// let url = Url::parse("https://例子.测试").unwrap();
/// if let Host::Hostname(hostname) = url.host() {
///     assert_eq!(hostname.full_name(), "例子.测试");
///     assert_eq!(hostname.suffix_str(), Some("测试"));
///     assert_eq!(hostname.domain(), Some("例子.测试"));
///     assert_eq!(hostname.subdomain(), None);
/// }
///
/// // Parse a domain with custom TLD
/// let url = Url::parse("http://example.b32.i2p").unwrap();
/// if let Host::Hostname(hostname) = url.host() {
///     assert_eq!(hostname.suffix_str(), Some("b32.i2p"));
/// }
/// ```
#[derive(Debug)]
pub struct Hostname<'url> {
    hostname: Cow<'url, str>,
    subdomain: Option<Cow<'url, str>>,
    domain: Option<Cow<'url, str>>,
    suffix: Option<Suffix<'url>>,
}

impl<'url> Hostname<'url> {
    fn into_owned<'owned>(self) -> Hostname<'owned> {
        Hostname {
            hostname: Cow::Owned(self.hostname.into_owned()),
            subdomain: self.subdomain.map(|s| Cow::Owned(s.into_owned())),
            domain: self.domain.map(|d| Cow::Owned(d.into_owned())),
            suffix: self.suffix.map(|s| s.into_owned()),
        }
    }

    fn from_str(hostname: &'url str) -> Self {
        let suffix = suffix(hostname);

        let domain = if let Some(suffix) = suffix.as_ref() {
            let i = hostname.rfind(suffix.as_str()).unwrap();
            let dom_start = hostname[..i]
                .trim_end_matches('.')
                .rfind('.')
                .map(|i| i + 1)
                .unwrap_or_default();
            Some(Cow::Borrowed(&hostname[dom_start..]))
        } else {
            None
        };

        let subdomain = if let Some(domain) = domain.as_ref() {
            // cannot panic domain must be in hostname
            let i = hostname.find(domain.as_ref()).unwrap().saturating_sub(1); // we get index after dot so we need to jump over it in order to process string backward
            let subdomain = &hostname[..i];
            if subdomain.is_empty() {
                None
            } else {
                Some(Cow::Borrowed(subdomain))
            }
        } else {
            None
        };

        Hostname {
            hostname: Cow::Borrowed(hostname),
            subdomain,
            domain,
            suffix,
        }
    }

    /// Returns the complete hostname as a string.
    ///
    /// # Returns
    ///
    /// * `&str` - The full hostname.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, Host};
    ///
    /// let url = Url::parse("https://sub.example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.full_name(), "sub.example.com");
    /// }
    /// ```
    #[inline(always)]
    pub fn full_name(&self) -> &str {
        &self.hostname
    }

    /// Returns the suffix (top-level domain) of the hostname, if recognized.
    ///
    /// The suffix is determined using the Public Suffix List, with additional support
    /// for custom TLDs defined in the `CUSTOM_TLDS` constant.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The suffix (TLD), or `None` if not recognized.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, Host};
    ///
    /// // Standard TLD
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.suffix_str(), Some("com"));
    /// }
    ///
    /// // Multi-level TLD
    /// let url = Url::parse("https://example.co.uk").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.suffix_str(), Some("co.uk"));
    /// }
    ///
    /// // Custom TLD
    /// let url = Url::parse("http://example.b32.i2p").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.suffix_str(), Some("b32.i2p"));
    /// }
    /// ```
    #[inline(always)]
    pub fn suffix_str(&self) -> Option<&str> {
        self.suffix.as_ref().map(|p| p.as_str())
    }

    /// Returns the suffix (TLD) part of the hostname as a [`Suffix`] enum, if recognized.
    ///
    /// The suffix represents the top-level domain (TLD) and can be either a standard
    /// Public Suffix List (PSL) entry or a custom suffix.
    ///
    /// # Returns
    ///
    /// * `Option<&Suffix>` - The suffix as a `Suffix` enum variant, or `None` if not recognized.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, Host, Suffix};
    ///
    /// // Standard TLD
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     if let Some(Suffix::Psl(suf)) = hostname.suffix() {
    ///         assert_eq!(suf.as_str(), "com");
    ///     }
    /// }
    /// ```
    #[inline(always)]
    pub fn suffix(&self) -> Option<&Suffix<'_>> {
        self.suffix.as_ref()
    }

    /// Returns the domain part of the hostname, if recognized.
    ///
    /// The domain is the registrable part of the hostname, excluding any subdomains
    /// and including the suffix.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The domain, or `None` if not recognized.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, Host};
    ///
    /// // Simple domain
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.domain(), Some("example.com"));
    /// }
    ///
    /// // Domain with multi-level TLD
    /// let url = Url::parse("https://example.co.uk").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.domain(), Some("example.co.uk"));
    /// }
    /// ```
    #[inline(always)]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_ref().map(|p| p.as_ref())
    }

    /// Returns the subdomain part of the hostname, if present.
    ///
    /// The subdomain is everything before the domain. For example, in "sub.example.com",
    /// "sub" is the subdomain.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The subdomain, or `None` if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, Host};
    ///
    /// // Single-level subdomain
    /// let url = Url::parse("https://sub.example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.subdomain(), Some("sub"));
    /// }
    ///
    /// // Multi-level subdomain
    /// let url = Url::parse("https://a.b.example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.subdomain(), Some("a.b"));
    /// }
    ///
    /// // No subdomain
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Host::Hostname(hostname) = url.host() {
    ///     assert_eq!(hostname.subdomain(), None);
    /// }
    /// ```
    #[inline(always)]
    pub fn subdomain(&self) -> Option<&str> {
        self.subdomain.as_ref().map(|p| p.as_ref())
    }
}

/// Represents the host component of a URL, which can be either a hostname or an IP address.
#[derive(Debug)]
pub enum Host<'url> {
    /// A hostname (domain name).
    Hostname(Hostname<'url>),
    /// An IP address (either IPv4 or IPv6).
    Ip(IpAddr),
}

impl fmt::Display for Host<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Hostname(hostname) => write!(f, "{}", hostname.full_name()),
            Host::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

impl<'host> Host<'host> {
    fn into_owned<'owned>(self) -> Host<'owned> {
        match self {
            Host::Hostname(h) => Host::Hostname(h.into_owned()),
            Host::Ip(ip) => Host::Ip(ip),
        }
    }

    #[inline(always)]
    fn from_pair(host_pair: Pair<'host, Rule>) -> Result<Self, Error> {
        match host_pair.as_rule() {
            Rule::hostname => {
                if let Ok(ipv4) =
                    UrlParser::parse(Rule::ipv4, host_pair.as_str()).map(|p| p.as_str())
                {
                    Ok(Ipv4Addr::from_str(ipv4)
                        .map(IpAddr::from)
                        .map(Host::Ip)
                        .map_err(|_| Error::InvalidIPv4)?)
                } else {
                    Ok(Host::Hostname(Hostname::from_str(host_pair.as_str())))
                }
            }

            Rule::ipv6 => Ok(Ipv6Addr::from_str(
                host_pair.as_str().trim_matches(|c| c == '[' || c == ']'),
            )
            .map(IpAddr::from)
            .map(Host::Ip)
            .map_err(|_| Error::InvalidIPv6)?),
            _ => Err(Error::other(format!(
                "unexpected parsing rule: {:?}",
                host_pair.as_rule()
            ))),
        }
    }

    /// Parses a string into a `Host` enum.
    ///
    /// This function expects the input string to be a URL host, which can be either
    /// an IPv4 address, an IPv6 address, or a hostname.
    ///
    /// # Arguments
    ///
    /// * `host` - A string slice that holds the host to parse (e.g., `"example.com"`, `"127.0.0.1"`, `"::1"`).
    ///
    /// # Returns
    ///
    /// * `Result<Host, Error>` - A [`Host`] enum if parsing is successful, or an [`enum@Error`] if parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Host;
    ///
    /// // Parse an IPv4 address
    /// let host = Host::parse("127.0.0.1").unwrap();
    /// assert!(matches!(host, Host::Ip(std::net::IpAddr::V4(_))));
    ///
    /// // Parse an IPv6 address
    /// let host = Host::parse("::1").unwrap();
    /// assert!(matches!(host, Host::Ip(std::net::IpAddr::V6(_))));
    ///
    /// // Parse a hostname
    /// let host = Host::parse("example.com").unwrap();
    /// assert!(matches!(host, Host::Hostname(_)));
    ///
    /// // Parse a hostname with a subdomain
    /// let host = Host::parse("sub.example.com").unwrap();
    /// assert!(matches!(host, Host::Hostname(_)));
    ///
    /// // Parse a hostname with a custom TLD
    /// let host = Host::parse("example.b32.i2p").unwrap();
    /// assert!(matches!(host, Host::Hostname(_)));
    ///
    /// // Attempt to parse an invalid host
    /// let result = Host::parse("invalid..host");
    /// assert!(matches!(result, Err(faup_rs::Error::InvalidHost)));
    /// ```
    #[inline]
    pub fn parse(host: &'host str) -> Result<Self, Error> {
        Self::from_pair(
            UrlParser::parse(Rule::checked_host, host)
                .map_err(|_| Error::InvalidHost)?
                .next()
                // this should not panic as parser guarantee some pair exist
                .expect("expecting host pair"),
        )
    }

    /// Returns the hostname component if this is a `Host::Hostname` variant.
    ///
    /// # Returns
    ///
    /// * `Option<&Hostname>` - The hostname, or `None` if this is an IP address.
    pub fn as_hostname(&self) -> Option<&Hostname<'_>> {
        match self {
            Host::Hostname(h) => Some(h),
            _ => None,
        }
    }
}

/// Represents user information (username and password) in a URL.
///
/// This struct stores the credentials that may be present in a URL's authority component.
/// It supports both ASCII and UTF-8 characters in usernames and passwords.
///
/// # Examples
///
/// ```
/// use faup_rs::{Url, UserInfo};
///
/// // Parse a URL with user info
/// let url = Url::parse("https://user:pass@example.com").unwrap();
/// let user_info = url.userinfo().unwrap();
///
/// // Access username and password
/// assert_eq!(user_info.username(), "user");
/// assert_eq!(user_info.password(), Some("pass"));
///
/// // Parse a URL with only username
/// let url = Url::parse("https://user@example.com").unwrap();
/// let user_info = url.userinfo().unwrap();
/// assert_eq!(user_info.username(), "user");
/// assert_eq!(user_info.password(), None);
///
/// // Parse a URL with UTF-8 user info
/// let url = Url::parse("https://用户:密码@example.com").unwrap();
/// let user_info = url.userinfo().unwrap();
/// assert_eq!(user_info.username(), "用户");
/// assert_eq!(user_info.password(), Some("密码"));
/// ```
#[derive(Debug)]
pub struct UserInfo<'url> {
    username: Cow<'url, str>,
    password: Option<Cow<'url, str>>,
}

impl<'url> UserInfo<'url> {
    #[inline]
    fn into_owned<'owned>(self) -> UserInfo<'owned> {
        UserInfo {
            username: Cow::Owned(self.username.into_owned()),
            password: self.password.map(|p| Cow::Owned(p.into_owned())),
        }
    }

    #[inline(always)]
    fn from_pair(pair: Pair<'url, Rule>) -> Self {
        let mut username = None;
        let mut password = None;
        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::username => username = Some(Cow::Borrowed(p.as_str())),
                Rule::password => password = Some(Cow::Borrowed(p.as_str())),
                _ => {}
            }
        }
        Self {
            username: username.expect("username is guaranteed by parser"),
            password,
        }
    }
}

impl UserInfo<'_> {
    /// Returns the username component of the user information.
    ///
    /// # Returns
    ///
    /// * `&str` - The username.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://user@example.com").unwrap();
    /// assert_eq!(url.userinfo().unwrap().username(), "user");
    ///
    /// // UTF-8 username
    /// let url = Url::parse("https://用户@example.com").unwrap();
    /// assert_eq!(url.userinfo().unwrap().username(), "用户");
    /// ```
    #[inline(always)]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password component of the user information, if present.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The password, or `None` if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// // With password
    /// let url = Url::parse("https://user:pass@example.com").unwrap();
    /// assert_eq!(url.userinfo().unwrap().password(), Some("pass"));
    ///
    /// // Without password
    /// let url = Url::parse("https://user@example.com").unwrap();
    /// assert_eq!(url.userinfo().unwrap().password(), None);
    ///
    /// // UTF-8 password
    /// let url = Url::parse("https://user:密码@example.com").unwrap();
    /// assert_eq!(url.userinfo().unwrap().password(), Some("密码"));
    /// ```
    #[inline(always)]
    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|p| p.as_ref())
    }
}

/// A parsed URL with support for hostnames, IPv4/IPv6 addresses, userinfo, ports, paths, queries, and fragments.
///
/// This struct represents a URL parsed from a string, with all components accessible individually.
/// It supports both ASCII and UTF-8 characters in all components, and properly handles subdomains,
/// custom TLDs, and internationalized domain names (IDNs).
///
/// # Examples
///
/// ```
/// use faup_rs::Url;
///
/// // Parse a simple URL
/// let url = Url::parse("https://example.com").unwrap();
/// assert_eq!(url.scheme(), "https");
/// assert_eq!(url.host().as_hostname().unwrap().full_name(), "example.com");
///
/// // Parse a URL with all components
/// let url = Url::parse("https://user:pass@sub.example.com:8080/path?query=value#fragment").unwrap();
/// assert_eq!(url.scheme(), "https");
/// assert_eq!(url.userinfo().unwrap().username(), "user");
/// assert_eq!(url.port(), Some(8080));
/// assert_eq!(url.path(), Some("/path"));
/// assert_eq!(url.query(), Some("query=value"));
/// assert_eq!(url.fragment(), Some("fragment"));
/// ```
#[derive(Debug)]
pub struct Url<'url> {
    orig: Cow<'url, str>,
    scheme: Cow<'url, str>,
    userinfo: Option<UserInfo<'url>>,
    host: Host<'url>,
    port: Option<u16>,
    path: Option<Cow<'url, str>>,
    query: Option<Cow<'url, str>>,
    fragment: Option<Cow<'url, str>>,
}

impl fmt::Display for Url<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<'url> Url<'url> {
    fn from_pair(pair: Pair<'url, Rule>) -> Result<Self, Error> {
        let orig = Cow::Borrowed(pair.as_str());
        let mut scheme = None;
        let mut userinfo = None;
        let mut host = None;
        let mut port = None;
        let mut path = None;
        let mut query = None;
        let mut fragment = None;

        for p in pair.into_inner() {
            match p.as_rule() {
                Rule::scheme => {
                    scheme = Some(Cow::Borrowed(p.as_str()));
                }
                Rule::userinfo => userinfo = Some(UserInfo::from_pair(p)),
                Rule::host => {
                    // cannot panic guarantee by parser
                    let host_pair = p.into_inner().next().unwrap();
                    host = Some(Host::from_pair(host_pair)?)
                }
                Rule::port => {
                    port = Some(u16::from_str(p.as_str()).map_err(|_| Error::InvalidPort)?)
                }
                Rule::path => {
                    path = Some(Cow::Borrowed(p.as_str()));
                }

                Rule::query => {
                    query = Some(Cow::Borrowed(&p.as_str()[1..]));
                }

                Rule::fragment => {
                    fragment = Some(Cow::Borrowed(&p.as_str()[1..]));
                }
                _ => {}
            }
        }

        Ok(Url {
            orig,
            scheme: scheme.unwrap(),
            userinfo,
            host: host.unwrap(),
            port,
            path,
            query,
            fragment,
        })
    }

    /// Creates a new `Url` by parsing a string slice.
    ///
    /// # Arguments
    ///
    /// * `s` - A string slice containing the URL to parse.
    ///
    /// # Returns
    ///
    /// * `Result<Url, Error>` - A parsed `Url` if successful, or an `Error` if parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com").unwrap();
    /// assert_eq!(url.scheme(), "https");
    /// assert_eq!(url.domain(), Some("example.com"));
    /// assert_eq!(url.suffix_str(), Some("com"));
    /// ```
    pub fn parse(s: &'url str) -> Result<Self, Error> {
        let mut pairs = UrlParser::parse(Rule::url, s).map_err(Box::new)?;
        Self::from_pair(pairs.next().unwrap())
    }

    /// Returns the original URL string.
    ///
    /// # Returns
    ///
    /// * `&str` - The original URL string.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com").unwrap();
    /// assert_eq!(url.as_str(), "https://example.com");
    /// ```
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.orig
    }

    /// Returns the scheme of the URL.
    ///
    /// # Returns
    ///
    /// * `&str` - The URL scheme (e.g., "http", "https").
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com").unwrap();
    /// assert_eq!(url.scheme(), "https");
    /// ```
    #[inline(always)]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the user information component of the URL, if present.
    ///
    /// # Returns
    ///
    /// * `Option<&UserInfo>` - The user information, or `None` if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://user:pass@example.com").unwrap();
    /// assert_eq!(url.userinfo().unwrap().username(), "user");
    /// assert_eq!(url.userinfo().unwrap().password(), Some("pass"));
    /// ```
    #[inline(always)]
    pub fn userinfo(&self) -> Option<&UserInfo<'_>> {
        self.userinfo.as_ref()
    }

    /// Returns the host component of the URL.
    ///
    /// # Returns
    ///
    /// * `&Host` - The host, which can be either a hostname or an IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://sub2.sub1.example.com").unwrap();
    /// let hostname = url.host().as_hostname().unwrap();
    /// assert_eq!(hostname.full_name(), "sub2.sub1.example.com");
    /// assert_eq!(hostname.domain(), Some("example.com"));
    /// assert_eq!(hostname.suffix_str(), Some("com"));
    /// assert_eq!(hostname.subdomain(), Some("sub2.sub1"));
    /// ```
    #[inline(always)]
    pub fn host(&self) -> &Host<'_> {
        &self.host
    }

    /// Returns the domain part of the hostname, if present.
    ///
    /// This is a convenience method that directly accesses the domain component
    /// of the hostname, if the host is a hostname (not an IP address).
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The domain part of the hostname, or `None` if:
    ///   - The host is an IP address
    ///   - The hostname doesn't have a recognized domain
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// // With a domain name
    /// let url = Url::parse("https://sub.example.com").unwrap();
    /// assert_eq!(url.domain(), Some("example.com"));
    ///
    /// // With an IP address
    /// let url = Url::parse("https://127.0.0.1").unwrap();
    /// assert_eq!(url.domain(), None);
    /// ```
    #[inline(always)]
    pub fn domain(&self) -> Option<&str> {
        self.host.as_hostname().and_then(|h| h.domain())
    }

    /// Returns the subdomain part of the hostname, if present.
    ///
    /// This is a convenience method that directly accesses the subdomain component
    /// of the hostname, if the host is a hostname (not an IP address).
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The subdomain part of the hostname, or `None` if:
    ///   - The host is an IP address
    ///   - The hostname doesn't have a subdomain
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// // With a subdomain
    /// let url = Url::parse("https://sub.example.com").unwrap();
    /// assert_eq!(url.subdomain(), Some("sub"));
    ///
    /// // Without a subdomain
    /// let url = Url::parse("https://example.com").unwrap();
    /// assert_eq!(url.subdomain(), None);
    ///
    /// // With an IP address
    /// let url = Url::parse("https://127.0.0.1").unwrap();
    /// assert_eq!(url.subdomain(), None);
    /// ```
    #[inline(always)]
    pub fn subdomain(&self) -> Option<&str> {
        self.host.as_hostname().and_then(|h| h.subdomain())
    }

    /// Returns the suffix (top-level domain) of the hostname, if present.
    ///
    /// This is a convenience method that directly accesses the suffix component
    /// of the hostname, if the host is a hostname (not an IP address).
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The suffix (TLD) of the hostname, or `None` if:
    ///   - The host is an IP address
    ///   - The hostname doesn't have a recognized suffix
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// // With a standard TLD
    /// let url = Url::parse("https://example.com").unwrap();
    /// assert_eq!(url.suffix_str(), Some("com"));
    ///
    /// // With a custom TLD
    /// let url = Url::parse("http://example.b32.i2p").unwrap();
    /// assert_eq!(url.suffix_str(), Some("b32.i2p"));
    ///
    /// // With an IP address
    /// let url = Url::parse("https://127.0.0.1").unwrap();
    /// assert_eq!(url.suffix_str(), None);
    /// ```
    #[inline(always)]
    pub fn suffix_str(&self) -> Option<&str> {
        self.host.as_hostname().and_then(|h| h.suffix_str())
    }

    /// Returns the suffix (TLD) part of the URL's hostname as a `Suffix` enum, if recognized.
    ///
    /// The suffix represents the top-level domain (TLD) and can be either a standard
    /// Public Suffix List (PSL) entry or a custom suffix. Returns `None` if the host
    /// is an IP address or if no suffix is recognized.
    ///
    /// # Returns
    ///
    /// * `Option<&Suffix>` - The suffix as a `Suffix` enum variant, or `None` if not recognized
    ///   or if the host is an IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::{Url, Suffix};
    ///
    /// // With a standard TLD
    /// let url = Url::parse("https://example.com").unwrap();
    /// if let Some(Suffix::Psl(suf)) = url.suffix() {
    ///     assert_eq!(suf.as_str(), "com");
    /// }
    ///
    /// // With a multi-level TLD
    /// let url = Url::parse("https://example.co.uk").unwrap();
    /// if let Some(Suffix::Psl(suf)) = url.suffix() {
    ///     assert_eq!(suf.as_str(), "co.uk");
    /// }
    ///
    /// // With a custom TLD
    /// let url = Url::parse("http://example.b32.i2p").unwrap();
    /// if let Some(Suffix::Custom(suf)) = url.suffix() {
    ///     assert_eq!(suf.as_str(), "b32.i2p");
    /// }
    ///
    /// // With an IP address (returns None)
    /// let url = Url::parse("https://127.0.0.1").unwrap();
    /// assert!(url.suffix().is_none());
    /// ```
    #[inline(always)]
    pub fn suffix(&self) -> Option<&Suffix<'_>> {
        self.host.as_hostname().and_then(|h| h.suffix())
    }

    /// Returns the port number of the URL, if present.
    ///
    /// # Returns
    ///
    /// * `Option<u16>` - The port number, or `None` if not specified.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com:8080").unwrap();
    /// assert_eq!(url.port(), Some(8080));
    /// ```
    #[inline(always)]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the path component of the URL, if present.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The path, or `None` if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com/path").unwrap();
    /// assert_eq!(url.path(), Some("/path"));
    /// ```
    #[inline(always)]
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(|p| p.as_ref())
    }

    /// Returns the query component of the URL, if present.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The query string, or `None` if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com?query=value").unwrap();
    /// assert_eq!(url.query(), Some("query=value"));
    /// ```
    #[inline(always)]
    pub fn query(&self) -> Option<&str> {
        self.query.as_ref().map(|p| p.as_ref())
    }

    /// Returns the fragment component of the URL, if present.
    ///
    /// # Returns
    ///
    /// * `Option<&str>` - The fragment, or `None` if not present.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com#fragment").unwrap();
    /// assert_eq!(url.fragment(), Some("fragment"));
    /// ```
    #[inline(always)]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_ref().map(|p| p.as_ref())
    }

    /// Converts this borrowed `Url` into an owned `Url`.
    ///
    /// This is useful when you need to store the `Url` for longer than the lifetime of the input string.
    ///
    /// # Performance
    ///
    /// When using this method strings will be cloned.
    ///
    /// # Returns
    ///
    /// * `Url<'owned>` - An owned version of the URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use faup_rs::Url;
    ///
    /// let url = Url::parse("https://example.com").unwrap();
    /// let owned_url = url.into_owned();
    /// ```
    pub fn into_owned<'owned>(self) -> Url<'owned> {
        Url {
            orig: Cow::Owned(self.orig.into_owned()),
            scheme: Cow::Owned(self.scheme.into_owned()),
            userinfo: self.userinfo.map(|u| u.into_owned()),
            host: self.host.into_owned(),
            port: self.port,
            path: self.path.map(|p| Cow::Owned(p.into_owned())),
            query: self.query.map(|q| Cow::Owned(q.into_owned())),
            fragment: self.fragment.map(|f| Cow::Owned(f.into_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Test basic URL parsing with various real-world examples
    #[test]
    fn test_real_world_examples() {
        let test_urls = [
            "https://www.example.co.uk",
            "http://sub.domain.example.com/path/to/page",
            "ftp://files.example.org/downloads/archive.zip",
            "https://www.example.com/search?q=rust+programming&page=1",
            "http://api.example.net/data?user=123&sort=desc",
            "https://docs.example.com/guide#installation",
            "http://example.com/page#section-1",
            "https://example.com/path%20with%20spaces",
            "http://localhost:3000/api/v1",
            "http://toaster.dyrøy.no",
            "http://full.custom-tld.test.b32.i2p",
            "https://alex:adore-la-quiche@avec-des-œufs.be#et-des-lardons",
            "https://%40lex:adore:la:quiche@%61vec-des-œufs.be/../../..some/directory/traversal/../#et-des-lardons",
            "https://44.129.205.92.host.secureserver.net",
        ];

        for url in test_urls {
            println!("Testing: {url}");
            let _ = Url::parse(url)
                .inspect_err(|e| println!("Error parsing '{url}': {e}"))
                .unwrap();
        }
    }

    /// Test minimal URL components
    #[test]
    fn test_minimal_url() {
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host().to_string(), "example.com");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), None);
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
        assert!(url.userinfo().is_none());

        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "example.com");
        assert_eq!(hn.suffix_str(), Some("com"));
        assert_eq!(hn.domain(), Some("example.com"));
        assert_eq!(hn.subdomain(), None);
    }

    /// Test URLs with user information
    #[test]
    fn test_user_info() {
        // With both username and password
        let url = Url::parse("https://user:pass@example.com").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host().to_string(), "example.com");
        let userinfo = url.userinfo().unwrap();
        assert_eq!(userinfo.username(), "user");
        assert_eq!(userinfo.password(), Some("pass"));

        // With only username
        let url = Url::parse("ftp://user@example.com").unwrap();
        assert_eq!(url.scheme(), "ftp");
        let userinfo = url.userinfo().unwrap();
        assert_eq!(userinfo.username(), "user");
        assert_eq!(userinfo.password(), None);

        // With UTF-8 user info
        let url = Url::parse("https://用户:密码@example.com").unwrap();
        let userinfo = url.userinfo().unwrap();
        assert_eq!(userinfo.username(), "用户");
        assert_eq!(userinfo.password(), Some("密码"));
    }

    /// Test URLs with ports
    #[test]
    fn test_ports() {
        // With standard port
        let url = Url::parse("http://example.com:80").unwrap();
        assert_eq!(url.port(), Some(80));

        // With custom port
        let url = Url::parse("http://example.com:8080").unwrap();
        assert_eq!(url.port(), Some(8080));

        // Invalid port
        let err = Url::parse("http://example.com:99999").unwrap_err();
        assert!(matches!(err, Error::InvalidPort));
    }

    /// Test URLs with paths
    #[test]
    fn test_paths() {
        // Simple path
        let url = Url::parse("https://example.com/path/to/resource").unwrap();
        assert_eq!(url.path(), Some("/path/to/resource"));

        // Complex path
        let url = Url::parse("http://example.com/a/b/c.html").unwrap();
        assert_eq!(url.path(), Some("/a/b/c.html"));

        // UTF-8 path
        let url = Url::parse("https://example.com/路径/资源").unwrap();
        assert_eq!(url.path(), Some("/路径/资源"));

        // No path
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.path(), None);
    }

    /// Test URLs with queries
    #[test]
    fn test_queries() {
        // Simple query
        let url = Url::parse("https://example.com?key=value").unwrap();
        assert_eq!(url.query(), Some("key=value"));

        // UTF-8 query
        let url = Url::parse("https://example.com?查询=值").unwrap();
        assert_eq!(url.query(), Some("查询=值"));

        // No query
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.query(), None);
    }

    /// Test URLs with fragments
    #[test]
    fn test_fragments() {
        // Simple fragment
        let url = Url::parse("https://example.com#section1").unwrap();
        assert_eq!(url.fragment(), Some("section1"));

        // UTF-8 fragment
        let url = Url::parse("https://example.com#片段").unwrap();
        assert_eq!(url.fragment(), Some("片段"));

        // No fragment
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.fragment(), None);
    }

    /// Test URLs with all components
    #[test]
    fn test_all_components() {
        let url = Url::parse(
            "https://user:pass@sub.example.com:8080/path/to/resource?key=value#section1",
        )
        .unwrap();

        assert_eq!(url.scheme(), "https");
        let userinfo = url.userinfo().unwrap();
        assert_eq!(userinfo.username(), "user");
        assert_eq!(userinfo.password(), Some("pass"));
        assert_eq!(url.host().to_string(), "sub.example.com");
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), Some("/path/to/resource"));
        assert_eq!(url.query(), Some("key=value"));
        assert_eq!(url.fragment(), Some("section1"));
    }

    /// Test hostname parsing
    #[test]
    fn test_hostnames() {
        // Basic hostname
        let url = Url::parse("https://example.com").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "example.com");
        assert_eq!(hn.suffix_str(), Some("com"));
        assert_eq!(hn.domain(), Some("example.com"));
        assert_eq!(hn.subdomain(), None);

        // Single-level subdomain
        let url = Url::parse("https://sub.example.com").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "sub.example.com");
        assert_eq!(hn.suffix_str(), Some("com"));
        assert_eq!(hn.domain(), Some("example.com"));
        assert_eq!(hn.subdomain(), Some("sub"));

        // Multi-level subdomain
        let url = Url::parse("https://a.b.example.com").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "a.b.example.com");
        assert_eq!(hn.suffix_str(), Some("com"));
        assert_eq!(hn.domain(), Some("example.com"));
        assert_eq!(hn.subdomain(), Some("a.b"));

        // Complex subdomain with all components
        let url = Url::parse(
            "https://user:pass@sub1.sub2.example.com:8080/path/to/resource?key=value#section1",
        )
        .unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "sub1.sub2.example.com");
        assert_eq!(hn.suffix_str(), Some("com"));
        assert_eq!(hn.domain(), Some("example.com"));
        assert_eq!(hn.subdomain(), Some("sub1.sub2"));

        // Custom TLD
        let url = Url::parse("http://example.b32.i2p").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "example.b32.i2p");
        assert_eq!(hn.suffix_str(), Some("b32.i2p"));
        assert_eq!(hn.domain(), Some("example.b32.i2p"));
        assert_eq!(hn.subdomain(), None);
        assert!(hn.suffix.as_ref().unwrap().is_known());

        // UTF-8 hostname
        let url = Url::parse("https://例子.测试").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "例子.测试");
        assert_eq!(hn.suffix_str(), Some("测试"));
        assert_eq!(hn.domain(), Some("例子.测试"));
        assert_eq!(hn.subdomain(), None);

        // UTF-8 subdomain
        let url = Url::parse("https://子域.例子.测试").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.full_name(), "子域.例子.测试");
        assert_eq!(hn.suffix_str(), Some("测试"));
        assert_eq!(hn.domain(), Some("例子.测试"));
        assert_eq!(hn.subdomain(), Some("子域"));
    }

    /// Test IP address hosts
    #[test]
    fn test_ip_hosts() {
        // IPv4
        let url = Url::parse("http://127.0.0.1").unwrap();
        match url.host() {
            Host::Ip(IpAddr::V4(ip)) => assert_eq!(ip, &Ipv4Addr::new(127, 0, 0, 1)),
            _ => panic!("Expected IPv4 address"),
        }

        // IPv6
        let url = Url::parse("http://[::1]").unwrap();
        match url.host() {
            Host::Ip(IpAddr::V6(ip)) => assert_eq!(ip, &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            _ => panic!("Expected IPv6 address"),
        }

        // Invalid IPv4
        let err = Url::parse("http://999.999.999.999").unwrap_err();
        assert!(matches!(err, Error::InvalidIPv4));

        // Invalid IPv6
        let err = Url::parse("http://[::::]").unwrap_err();
        assert!(matches!(err, Error::InvalidIPv6));
    }

    /// Test edge cases
    #[test]
    fn test_edge_cases() {
        // Empty path
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(url.path(), Some("/"));

        // Empty query
        let url = Url::parse("https://example.com?").unwrap();
        assert_eq!(url.query(), Some(""));

        // Empty fragment
        let url = Url::parse("https://example.com#").unwrap();
        assert_eq!(url.fragment(), Some(""));

        // No subdomain
        let url = Url::parse("https://example.com").unwrap();
        let hn = url.host().as_hostname().unwrap();
        assert_eq!(hn.subdomain(), None);
    }

    /// Test URLs with special characters
    #[test]
    fn test_special_characters() {
        // URL-encoded characters
        let url =
            Url::parse("https://%40lex:adore:la:quiche@%61vec-des-œufs.be#et-des-lardons").unwrap();
        assert_eq!(url.host().to_string(), "%61vec-des-œufs.be");
        let userinfo = url.userinfo().unwrap();
        assert_eq!(userinfo.username(), "%40lex");
        assert_eq!(userinfo.password(), Some("adore:la:quiche"));
        assert_eq!(url.fragment(), Some("et-des-lardons"));

        // Path traversal
        let url = Url::parse("https://example.com/../../..some/directory/traversal/../").unwrap();
        assert_eq!(url.path(), Some("/../../..some/directory/traversal/../"));
    }

    #[test]
    fn test_host_from_str() {
        // Valid IPv4
        let host = Host::parse("127.0.0.1").unwrap();
        assert!(matches!(host, Host::Ip(std::net::IpAddr::V4(_))));

        // Valid IPv6
        let host = Host::parse("::1").unwrap();
        assert!(matches!(host, Host::Ip(std::net::IpAddr::V6(_))));

        let host = Host::parse("[::1]");
        assert!(matches!(host, Err(Error::InvalidHost)));

        // Invalid IPv6
        let result = Host::parse("::::");
        assert!(matches!(result, Err(Error::InvalidIPv6)));

        // Valid hostname
        let host = Host::parse("example.com").unwrap();
        assert!(matches!(host, Host::Hostname(_)));

        // Hostname with subdomain
        let host = Host::parse("sub.example.com").unwrap();
        assert!(matches!(host, Host::Hostname(_)));

        // Hostname with custom TLD
        let host = Host::parse("example.b32.i2p").unwrap();
        assert!(matches!(host, Host::Hostname(_)));

        // Invalid hostname (placeholder logic)
        let result = Host::parse("example..com");
        assert!(matches!(result, Err(Error::InvalidHost)));
    }

    /// Test Hostname::suffix() method with various known and unknown suffixes
    #[test]
    fn test_hostname_suffix_detection() {
        // Known PSL suffixes - should be recognized and known
        let h = Hostname::from_str("example.com");
        assert!(h.suffix().unwrap().is_known());

        // Custom suffixes - should be known
        let h = Hostname::from_str("example.b32.i2p");
        assert!(h.suffix().unwrap().is_known());

        // Private custom TLD - should not be known
        let h = Hostname::from_str("test.custom-tld");
        assert!(!h.suffix().unwrap().is_known());

        // Edge case
        let h = Hostname::from_str("SSH-2.0-OpenSSH_9.2p1");
        assert!(!h.suffix().unwrap().is_known());
    }

    #[test]
    fn tests_query_bug() {
        // tests from issue: https://github.com/ail-project/faup-rs/issues/12
        let u = Url::parse("https://www.gstatic.com/mysidia/c081791544e5ee0d5e650a98f7336d84.js?tag=addon/mysidia_one_click_handler_one_afma").unwrap();
        assert_eq!(
            u.query(),
            Some("tag=addon/mysidia_one_click_handler_one_afma")
        );

        let u = Url::parse("https://ib.adnxs.com/getuid?https%3A%2F%2Flive.primis.tech%2Flive%2FliveCS.php%3Fsource%3Dexternal%26advId%3D105%26advUuid%3D%24UID%26gdpr%3D1%26gdpr_consent%3DCQe140AQe140AAKA8AENCQFsAP_gAEPgACiQL8tR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURUCgKIgFryDMaEyU4TNKJ6BkiFMZI2tYCFxvm4tjWQCY4vr99lc1mB-t7dr82dzyy6hHn3a5_2S1UJCdIYetDfv8ZBKT-9IEd_x8v4v4_EbpE2-eS1n_pGvp4jd-YnM_dBmxt-Tyff7Pn__rl_e7X_vc_n3zv94XH77v_-__f_-7___2b_-__gvuACYaFRBGWRAgECgYQQIAFBWEAFAgCAABIGiAgBMGBDkDABdYTIAQAoABggBAACDAAEAAAkACEQAQAEAgBAgECgADAAgCAgAYGAAMAFiIBAACA6BimBBAIFgAkZlUGmBKAAkEBLZUIJQMCCuEIRZ4BBAiJgoAAAQACgAAAHgsBCSQErEggC4gmgAAIAAAogRIEUhZgCCoM0WgrAk4DI0wDB8wTJKdBkATBCRkGRCb8Jh4pCiBBDkBsUswB08QUAIAAAAA.IAAA.YAAAAAAAAAAA").inspect_err(|e| print!("{e}")).unwrap();
        assert_eq!(
            u.query(),
            Some(
                "https%3A%2F%2Flive.primis.tech%2Flive%2FliveCS.php%3Fsource%3Dexternal%26advId%3D105%26advUuid%3D%24UID%26gdpr%3D1%26gdpr_consent%3DCQe140AQe140AAKA8AENCQFsAP_gAEPgACiQL8tR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURUCgKIgFryDMaEyU4TNKJ6BkiFMZI2tYCFxvm4tjWQCY4vr99lc1mB-t7dr82dzyy6hHn3a5_2S1UJCdIYetDfv8ZBKT-9IEd_x8v4v4_EbpE2-eS1n_pGvp4jd-YnM_dBmxt-Tyff7Pn__rl_e7X_vc_n3zv94XH77v_-__f_-7___2b_-__gvuACYaFRBGWRAgECgYQQIAFBWEAFAgCAABIGiAgBMGBDkDABdYTIAQAoABggBAACDAAEAAAkACEQAQAEAgBAgECgADAAgCAgAYGAAMAFiIBAACA6BimBBAIFgAkZlUGmBKAAkEBLZUIJQMCCuEIRZ4BBAiJgoAAAQACgAAAHgsBCSQErEggC4gmgAAIAAAogRIEUhZgCCoM0WgrAk4DI0wDB8wTJKdBkATBCRkGRCb8Jh4pCiBBDkBsUswB08QUAIAAAAA.IAAA.YAAAAAAAAAAA"
            )
        );

        let u = Url::parse(
            "https://sync.a-mo.net/cjoin/1?cb=https%3A%2F%2Fprebid.a-mo.net%2Fcchain%2F4%2F24901%3Fgpp%3D%26gdpr_consent%3DCQe140AQe140AAKA8AENCQFsAP_gAEPgACiQL8tR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURUCgKIgFryDMaEyU4TNKJ6BkiFMZI2tYCFxvm4tjWQCY4vr99lc1mB-t7dr82dzyy6hHn3a5_2S1UJCdIYetDfv8ZBKT-9IEd_x8v4v4_EbpE2-eS1n_pGvp4jd-YnM_dBmxt-Tyff7Pn__rl_e7X_vc_n3zv94XH77v_-__f_-7___2b_-__gvuACYaFRBGWRAgECgYQQIAFBWEAFAgCAABIGiAgBMGBDkDABdYTIAQAoABggBAACDAAEAAAkACEQAQAEAgBAgECgADAAgCAgAYGAAMAFiIBAACA6BimBBAIFgAkZlUGmBKAAkEBLZUIJQMCCuEIRZ4BBAiJgoAAAQACgAAAHgsBCSQErEggC4gmgAAIAAAogRIEUhZgCCoM0WgrAk4DI0wDB8wTJKdBkATBCRkGRCb8Jh4pCiBBDkBsUswB08QUAIAAAAA.IAAA.YAAAAAAAAAAA%26gdpr%3D1%26gpp_sid%3D%26us_privacy%3D%26A%3D037c5ad0-ef80-48d1-bf62-ad8c8fad73ed%26bidder%3Damx_com%26cbx%3DaHR0cHM6Ly9saXZlLnByaW1pcy50ZWNoL2xpdmUvbGl2ZUNTLnBocD9zb3VyY2U9ZXh0ZXJuYWwmYWR2SWQ9MTU2L3NldHVpZD91aWQ9%26uid%3D037c5ad0-ef80-48d1-bf62-ad8c8fad73ed&uid=037c5ad0-ef80-48d1-bf62-ad8c8fad73ed&?us_privacy=1---&gdpr_consent=CQe140AQe140AAKA8AENCQFsAP_gAEPgACiQL8tR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURUCgKIgFryDMaEyU4TNKJ6BkiFMZI2tYCFxvm4tjWQCY4vr99lc1mB-t7dr82dzyy6hHn3a5_2S1UJCdIYetDfv8ZBKT-9IEd_x8v4v4_EbpE2-eS1n_pGvp4jd-YnM_dBmxt-Tyff7Pn__rl_e7X_vc_n3zv94XH77v_-__f_-7___2b_-__gvuACYaFRBGWRAgECgYQQIAFBWEAFAgCAABIGiAgBMGBDkDABdYTIAQAoABggBAACDAAEAAAkACEQAQAEAgBAgECgADAAgCAgAYGAAMAFiIBAACA6BimBBAIFgAkZlUGmBKAAkEBLZUIJQMCCuEIRZ4BBAiJgoAAAQACgAAAHgsBCSQErEggC4gmgAAIAAAogRIEUhZgCCoM0WgrAk4DI0wDB8wTJKdBkATBCRkGRCb8Jh4pCiBBDkBsUswB08QUAIAAAAA.IAAA.YAAAAAAAAAAA&gdpr=1",
        ).unwrap();
        assert_eq!(
            u.query(),
            Some(
                "cb=https%3A%2F%2Fprebid.a-mo.net%2Fcchain%2F4%2F24901%3Fgpp%3D%26gdpr_consent%3DCQe140AQe140AAKA8AENCQFsAP_gAEPgACiQL8tR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURUCgKIgFryDMaEyU4TNKJ6BkiFMZI2tYCFxvm4tjWQCY4vr99lc1mB-t7dr82dzyy6hHn3a5_2S1UJCdIYetDfv8ZBKT-9IEd_x8v4v4_EbpE2-eS1n_pGvp4jd-YnM_dBmxt-Tyff7Pn__rl_e7X_vc_n3zv94XH77v_-__f_-7___2b_-__gvuACYaFRBGWRAgECgYQQIAFBWEAFAgCAABIGiAgBMGBDkDABdYTIAQAoABggBAACDAAEAAAkACEQAQAEAgBAgECgADAAgCAgAYGAAMAFiIBAACA6BimBBAIFgAkZlUGmBKAAkEBLZUIJQMCCuEIRZ4BBAiJgoAAAQACgAAAHgsBCSQErEggC4gmgAAIAAAogRIEUhZgCCoM0WgrAk4DI0wDB8wTJKdBkATBCRkGRCb8Jh4pCiBBDkBsUswB08QUAIAAAAA.IAAA.YAAAAAAAAAAA%26gdpr%3D1%26gpp_sid%3D%26us_privacy%3D%26A%3D037c5ad0-ef80-48d1-bf62-ad8c8fad73ed%26bidder%3Damx_com%26cbx%3DaHR0cHM6Ly9saXZlLnByaW1pcy50ZWNoL2xpdmUvbGl2ZUNTLnBocD9zb3VyY2U9ZXh0ZXJuYWwmYWR2SWQ9MTU2L3NldHVpZD91aWQ9%26uid%3D037c5ad0-ef80-48d1-bf62-ad8c8fad73ed&uid=037c5ad0-ef80-48d1-bf62-ad8c8fad73ed&?us_privacy=1---&gdpr_consent=CQe140AQe140AAKA8AENCQFsAP_gAEPgACiQL8tR_G__bWlr-bb3aftkeYxP9_hr7sQxBgbJk24FzLvW7JwXx2E5NAzatqIKmRIAu3TBIQNlHJDURUCgKIgFryDMaEyU4TNKJ6BkiFMZI2tYCFxvm4tjWQCY4vr99lc1mB-t7dr82dzyy6hHn3a5_2S1UJCdIYetDfv8ZBKT-9IEd_x8v4v4_EbpE2-eS1n_pGvp4jd-YnM_dBmxt-Tyff7Pn__rl_e7X_vc_n3zv94XH77v_-__f_-7___2b_-__gvuACYaFRBGWRAgECgYQQIAFBWEAFAgCAABIGiAgBMGBDkDABdYTIAQAoABggBAACDAAEAAAkACEQAQAEAgBAgECgADAAgCAgAYGAAMAFiIBAACA6BimBBAIFgAkZlUGmBKAAkEBLZUIJQMCCuEIRZ4BBAiJgoAAAQACgAAAHgsBCSQErEggC4gmgAAIAAAogRIEUhZgCCoM0WgrAk4DI0wDB8wTJKdBkATBCRkGRCb8Jh4pCiBBDkBsUswB08QUAIAAAAA.IAAA.YAAAAAAAAAAA&gdpr=1"
            )
        );
    }
}
