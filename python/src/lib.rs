use pyo3::{exceptions::PyValueError, prelude::*, types::PyDict};

struct Error(faup_rs::Error);

impl From<faup_rs::Error> for Error {
    fn from(value: faup_rs::Error) -> Self {
        Self(value)
    }
}

impl From<Error> for PyErr {
    fn from(value: Error) -> Self {
        PyValueError::new_err(value.0.to_string())
    }
}

/// A parsed URL representation for Python.
///
/// This class provides access to all components of a parsed URL, including scheme,
/// credentials, host, port, path, query, and fragment. It's a direct mapping of
/// the faup_rs::Url struct to Python.
///
/// Attributes:
///     scheme (str): The URL scheme (e.g., "http", "https").
///     username (Optional[str]): The username from the URL credentials, if present.
///     password (Optional[str]): The password from the URL credentials, if present.
///     host (str): The host part of the URL (hostname or IP address).
///     subdomain (Optional[str]): The subdomain part of the hostname, if present.
///     domain (Optional[str]): The domain part of the hostname, if recognized.
///     suffix (Optional[str]): The suffix (TLD) of the hostname, if recognized.
///     port (Optional[int]): The port number, if specified.
///     path (Optional[str]): The path component of the URL, if present.
///     query (Optional[str]): The query string, if present.
///     fragment (Optional[str]): The fragment identifier, if present.
///
/// Example:
///     >>> from pyfaup import Url
///     >>> url = Url("https://user:pass@sub.example.com:8080/path?query=value#fragment")
///     >>> print(url.scheme)  # "https"
///     >>> print(url.username)  # "user"
///     >>> print(url.host)  # "sub.example.com"
///     >>> print(url.port)  # 8080
#[pyclass]
pub struct Url {
    #[pyo3(get)]
    pub scheme: String,
    #[pyo3(get)]
    pub username: Option<String>,
    #[pyo3(get)]
    pub password: Option<String>,
    #[pyo3(get)]
    pub host: String,
    #[pyo3(get)]
    pub subdomain: Option<String>,
    #[pyo3(get)]
    pub domain: Option<String>,
    #[pyo3(get)]
    pub suffix: Option<String>,
    #[pyo3(get)]
    pub port: Option<u16>,
    #[pyo3(get)]
    pub path: Option<String>,
    #[pyo3(get)]
    pub query: Option<String>,
    #[pyo3(get)]
    pub fragment: Option<String>,
}

impl From<faup_rs::Url<'_>> for Url {
    fn from(value: faup_rs::Url<'_>) -> Self {
        let mut subdomain = None;
        let mut domain = None;
        let mut suffix = None;

        let (username, password) = match value.userinfo() {
            Some(u) => (
                Some(u.username().to_string()),
                u.password().map(|p| p.to_string()),
            ),
            None => (None, None),
        };

        let host = match value.host() {
            faup_rs::Host::Hostname(hostname) => {
                subdomain = hostname.subdomain().map(|s| s.into());
                domain = hostname.domain().map(|d| d.into());
                suffix = hostname.suffix().map(|s| s.into());
                hostname.full_name().into()
            }
            faup_rs::Host::Ip(ip) => ip.to_string(),
        };

        Self {
            scheme: value.scheme().into(),
            username,
            password,
            host,
            subdomain,
            domain,
            suffix,
            port: value.port(),
            path: value.path().map(|p| p.into()),
            query: value.query().map(|q| q.into()),
            fragment: value.fragment().map(|f| f.into()),
        }
    }
}

impl Url {
    fn credentials(&self) -> Option<String> {
        let un = self.username.as_ref()?;
        if let Some(pw) = self.password.as_ref() {
            Some(format!("{un}:{pw}"))
        } else {
            Some(un.clone())
        }
    }
}

#[pymethods]
impl Url {
    /// Creates a new Url instance by parsing a URL string.
    ///
    /// Args:
    ///     url (str): The URL string to parse.
    ///
    /// Returns:
    ///     Url: A new Url instance.
    ///
    /// Raises:
    ///     ValueError: If the URL string is invalid.
    ///
    /// Example:
    ///     >>> from pyfaup import Url
    ///     >>> url = Url("https://example.com")
    ///     >>> print(url.scheme)  # "https"
    #[new]
    fn new(url: &str) -> PyResult<Self> {
        faup_rs::Url::parse(url)
            .map(|u| u.into())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

/// A compatibility class that mimics the FAUP (Fast URL Parser) Python API.
///
/// This class provides a decode() method and a get() method that returns a dictionary
/// with URL components, similar to the original FAUP Python library.
///
/// WARNING: using this API may be slower than than using Url object
/// because it involves creating more Python objects.
///
/// Example:
///     >>> from pyfaup import FaupCompat as Faup
///     >>> faup = Faup()
///     >>> faup.decode("https://user:pass@sub.example.com:8080/path?query=value#fragment")
///     >>> result = faup.get()
///     >>> print(result["scheme"])  # "https"
///     >>> print(result["credentials"])  # "user:pass"
#[pyclass]
pub struct FaupCompat {
    url: Option<Url>,
}

#[pymethods]
impl FaupCompat {
    /// Creates a new FaupCompat instance.
    ///
    /// Returns:
    ///     FaupCompat: A new FaupCompat instance.
    #[new]
    fn new() -> Self {
        Self { url: None }
    }

    /// Decodes a URL string and stores its components.
    ///
    /// Args:
    ///     url (str): The URL string to parse.
    ///
    /// Raises:
    ///     ValueError: If the URL string is invalid.
    ///
    /// Example:
    ///     >>> from pyfaup import FaupCompat
    ///     >>> faup = FaupCompat()
    ///     >>> faup.decode("https://example.com")
    fn decode(&mut self, url: &str) -> PyResult<()> {
        self.url = Some(Url::new(url)?);
        Ok(())
    }

    /// Returns a dictionary with all URL components.
    ///
    /// The dictionary contains the following keys:
    /// - credentials: The credentials part (username:password or just username)
    /// - domain: The domain part of the hostname
    /// - subdomain: The subdomain part of the hostname
    /// - fragment: The fragment identifier
    /// - host: The host part (hostname or IP address)
    /// - resource_path: The path component
    /// - tld: The top-level domain (suffix)
    /// - query_string: The query string
    /// - scheme: The URL scheme
    /// - port: The port number
    ///
    /// Returns:
    ///     dict: A dictionary with all URL components.
    ///
    /// Example:
    ///     >>> from pyfaup import FaupCompat as Faup
    ///     >>> faup = Faup()
    ///     >>> faup.decode("https://user:pass@sub.example.com:8080/path?query=value#fragment")
    ///     >>> result = faup.get()
    ///     >>> print(result["credentials"])  # "user:pass"
    ///     >>> print(result["domain"])  # "example.com"
    fn get<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let m = PyDict::new(py);
        let url = self.url.as_ref();

        let credentials = url.and_then(|u| u.credentials());

        m.set_item("credentials", credentials)?;
        m.set_item("domain", url.and_then(|u| u.domain.clone()))?;
        m.set_item("subdomain", url.and_then(|u| u.subdomain.clone()))?;
        m.set_item("fragment", url.and_then(|u| u.fragment.clone()))?;
        m.set_item("host", url.map(|u| u.host.clone()))?;
        m.set_item("resource_path", url.and_then(|u| u.path.clone()))?;
        m.set_item("tld", url.and_then(|u| u.suffix.clone()))?;
        m.set_item("query_string", url.and_then(|u| u.query.clone()))?;
        m.set_item("scheme", url.map(|u| u.scheme.clone()))?;
        m.set_item("port", url.map(|u| u.port))?;

        Ok(m)
    }
}

/// A Python module implemented in Rust for URL parsing.
///
/// This module provides two classes:
/// - Url: A direct representation of a parsed URL
/// - FaupCompat: A compatibility class that mimics the FAUP Python API
///
/// Example:
///     >>> from pyfaup import Url, FaupCompat as Faup
///     >>> # Using Url class
///     >>> url = Url("https://example.com")
///     >>> print(url.scheme)  # "https"
///     >>>
///     >>> # Using FaupCompat class
///     >>> faup = Faup()
///     >>> faup.decode("https://example.com")
///     >>> result = faup.get()
///     >>> print(result["scheme"])  # "https"
#[pymodule]
fn pyfaup(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Url>()?;
    m.add_class::<FaupCompat>()?;

    Ok(())
}
