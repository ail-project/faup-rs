from typing import Optional

class Hostname:
    hostname: str
    subdomain: Optional[str]
    domain: Optional[str]
    suffix: Optional[str]

    def __init__(self, hn: str) -> None:
        ...

    def __str__(self) -> str:
        ...

class Host:
    def __init__(self, s: str) -> None:
        ...

    def try_into_hostname(self) -> Hostname:
        ...

    def try_into_ip(self) -> str:
        ...

    def is_hostname(self) -> bool:
        ...

    def is_ipv4(self) -> bool:
        ...

    def is_ipv6(self) -> bool:
        ...

    def is_ip_addr(self) -> bool:
        ...

    def __str__(self) -> str:
        ...

class FaupCompat:

    url: bytes

    def __init__(self, url: str | None=None) -> None:
        ...

    def decode(self, url: str) -> None:
        ...

    def get_credential(self) -> str | None:
        ...

    def get_domain(self) -> str | None:
        ...

    def get_subdomain(self) -> str | None:
        ...

    def get_fragment(self) -> str | None:
        ...

    def get_host(self) -> str | None:
        ...

    def get_resource_path(self) -> str | None:
        ...

    def get_tld(self) -> str | None:
        ...

    def get_query_string(self) -> str | None:
        ...

    def get_scheme(self) -> str | None:
        ...

    def get_domain_without_tld(self) -> str | None:
        ...

    def get_port(self) -> int | None:
        ...

class Url:
    orig: str
    scheme: str
    username: Optional[str]
    password: Optional[str]
    host: str
    subdomain: Optional[str]
    domain: Optional[str]
    suffix: Optional[str]
    port: Optional[int]
    path: Optional[str]
    query: Optional[str]
    fragment: Optional[str]

    def __init__(self, url: str) -> None:
        ...

    def __str__(self) -> str:
        ...