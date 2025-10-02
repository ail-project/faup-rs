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
    username: str | None
    password: str | None
    host: str
    subdomain: str | None
    domain: str | None
    suffix: str | None
    port: int | None
    path: str | None
    query: str | None
    fragment: str | None

    def __init__(self, url: str | None = None) -> None:
        ...
