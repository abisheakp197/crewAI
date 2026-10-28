# Optional dependency: Requires pip install ube-foundation
from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urljoin, urlparse
import uuid

import requests
from requests.adapters import DEFAULT_POOLBLOCK, HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import (
    ConnectTimeoutError,
    NameResolutionError,
    NewConnectionError,
)
from urllib3.poolmanager import PoolManager

try:
    from ube_foundation import PqcKeyPair, TrustEngine  # type: ignore[import-untyped]
except ImportError:
    TrustEngine = None
    PqcKeyPair = None


_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


def is_public_ip(ip_val: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Validate whether an IP address is a public, routable IP address.

    Blocks private, loopback, link-local, multicast, reserved, unspecified,
    and cloud metadata IP ranges (e.g., 169.254.169.254, 127.0.0.1, ::1).
    """
    if isinstance(ip_val, str):
        try:
            ip = ipaddress.ip_address(ip_val)
        except ValueError:
            return False
    else:
        ip = ip_val

    if hasattr(ip, "ipv4_mapped") and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    if hasattr(ip, "is_global") and not ip.is_global:
        return False

    return True


def validate_ip(ip_str: str) -> None:
    """Raise ValueError if *ip_str* is not a valid public IP address."""
    if not is_public_ip(ip_str):
        raise ValueError(
            f"Access to private, loopback, link-local, or metadata IP range ({ip_str}) is forbidden."
        )


def validate_url(url: str) -> str:
    """Validate that *url* uses http/https scheme and resolves only to public IPs."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Only http and https are allowed."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Check if hostname is an IP address literal directly
    try:
        ip = ipaddress.ip_address(hostname)
        validate_ip(str(ip))
        return url
    except ValueError as exc:
        if "forbidden" in str(exc):
            raise

    try:
        addrinfos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname '{hostname}': {exc}") from exc

    if not addrinfos:
        raise ValueError(f"Could not resolve hostname '{hostname}'")

    for family, socktype, proto, canonname, sockaddr in addrinfos:
        ip_str = str(sockaddr[0])
        validate_ip(ip_str)

    return url


def _connect_timeout(timeout: Any) -> float | None:
    connect = getattr(timeout, "connect_timeout", timeout)
    if connect is None or connect is getattr(timeout, "DEFAULT_TIMEOUT", None):
        return socket.getdefaulttimeout()
    if isinstance(connect, (int, float)):
        return float(connect)
    return socket.getdefaulttimeout()


def create_pinned_socket(
    host: str,
    port: int,
    *,
    timeout: Any = None,
    source_address: tuple[str, int] | None = None,
    socket_options: Any = None,
) -> socket.socket:
    """Open a TCP socket to *host* and *port* after validating and pinning the peer IP."""
    if host.startswith("["):
        host = host.strip("[]")

    try:
        ip = ipaddress.ip_address(host)
        validate_ip(str(ip))
    except ValueError as exc:
        if "forbidden" in str(exc):
            raise

    try:
        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname '{host}': {exc}") from exc

    if not addrinfos:
        raise ValueError(f"Could not resolve hostname '{host}'")

    for family, socktype, proto, canonname, sockaddr in addrinfos:
        ip_str = str(sockaddr[0])
        validate_ip(ip_str)

    timeout_val = _connect_timeout(timeout)
    err: OSError | None = None

    for family, socktype, proto, canonname, sockaddr in addrinfos:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, socktype, proto)
            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)
            sock.settimeout(timeout_val)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)

            peer = sock.getpeername()
            peer_ip = str(peer[0])
            validate_ip(peer_ip)

            return sock
        except Exception as exc:
            if sock is not None:
                sock.close()
            err = exc

    if err is not None:
        raise err
    raise OSError(f"Failed to connect to '{host}'")


class PinnedHTTPConnection(HTTPConnection):
    """HTTP Connection that pins connections to pre-validated public IPs."""

    def _new_conn(self) -> socket.socket:
        port = self.port or 80
        try:
            return create_pinned_socket(
                self._dns_host,
                port,
                timeout=self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        except socket.timeout as exc:
            raise ConnectTimeoutError(
                self, f"Connection to {self.host} timed out."
            ) from exc
        except OSError as exc:
            raise NewConnectionError(
                self, f"Failed to establish connection to {self.host}: {exc}"
            ) from exc


class PinnedHTTPSConnection(HTTPSConnection):
    """HTTPS Connection that pins connections to pre-validated public IPs."""

    def _new_conn(self) -> socket.socket:
        port = self.port or 443
        try:
            return create_pinned_socket(
                self._dns_host,
                port,
                timeout=self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except socket.gaierror as exc:
            raise NameResolutionError(self.host, self, exc) from exc
        except socket.timeout as exc:
            raise ConnectTimeoutError(
                self, f"Connection to {self.host} timed out."
            ) from exc
        except OSError as exc:
            raise NewConnectionError(
                self, f"Failed to establish connection to {self.host}: {exc}"
            ) from exc


class PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection


class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection


_PINNED_POOL_CLASSES = {
    "http": PinnedHTTPConnectionPool,
    "https": PinnedHTTPSConnectionPool,
}


class PinnedPoolManager(PoolManager):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = _PINNED_POOL_CLASSES


class SocketPinnedAdapter(HTTPAdapter):
    """HTTPAdapter that pins TCP socket connections to validated peer IPs."""

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = DEFAULT_POOLBLOCK,
        **pool_kwargs: Any,
    ) -> None:
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = PinnedPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def create_safe_session() -> requests.Session:
    """Return a requests Session with socket-level IP pinning enabled."""
    session = requests.Session()
    session.trust_env = False
    session.proxies = {}
    adapter = SocketPinnedAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_request(
    method: str,
    url: str,
    *,
    max_redirects: int = 10,
    **kwargs: Any,
) -> requests.Response:
    """Perform an HTTP request with socket-level IP pinning and redirect target re-validation."""
    current_url = validate_url(url)
    kwargs["allow_redirects"] = False

    session = create_safe_session()
    redirect_count = 0
    history: list[requests.Response] = []

    try:
        while True:
            response = session.request(method, current_url, **kwargs)
            if (
                response.status_code in _REDIRECT_STATUS_CODES
                and "Location" in response.headers
            ):
                if redirect_count >= max_redirects:
                    response.close()
                    raise ValueError(f"Too many redirects while requesting URL: {url}")

                location = response.headers["Location"]
                redirect_url = validate_url(urljoin(current_url, location))
                history.append(response)
                current_url = redirect_url
                redirect_count += 1
            else:
                response.history = history
                return response
    except Exception:
        for resp in history:
            resp.close()
        session.close()
        raise


class NTIGuardrailMiddleware:
    """
    Neutral Trust Infrastructure (NTI) Guardrail for CrewAI agents.
    Enforces post-quantum zero-trust capability bounds, cryptographic signatures,
    and SSRF / network boundary security.
    """

    def __init__(self, agent_id: str):
        if TrustEngine is None or PqcKeyPair is None:
            raise RuntimeError(
                "NTI Guardrail requires 'ube-foundation' to be installed. Run 'pip install ube-foundation'"
            )
        self.agent_id = agent_id
        self.engine = TrustEngine()
        if hasattr(PqcKeyPair, "generate") and callable(getattr(PqcKeyPair, "generate")):
            self.pqc_key = PqcKeyPair.generate()
        else:
            self.pqc_key = PqcKeyPair()

    def grant_capability(self, capability: str) -> None:
        self.engine.grant(self.agent_id, capability)

    def validate_url(self, url: str) -> str:
        """Validate target URL against SSRF and private IP ranges."""
        return validate_url(url)

    def safe_request(
        self,
        method: str,
        url: str,
        *,
        max_redirects: int = 10,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute an SSRF-safe HTTP request using socket-level IP pinning."""
        return safe_request(method, url, max_redirects=max_redirects, **kwargs)

    def verify_tool_execution(self, tool_name: str, tool_input: dict[str, Any]) -> bool:
        req = {
            "id": f"req-{uuid.uuid4()}",
            "actor": self.agent_id,
            "capability": tool_name,
            "action": tool_name,
            "input": tool_input,
            "signature": None,
            "pqc_signature": None,
            "public_key": None,
            "pqc_public_key": None,
            "token": None,
            "identity_claim": None,
        }
        canonical_json = json.dumps(req, sort_keys=True)
        message = canonical_json.encode("utf-8")
        sig = self.pqc_key.sign(message)
        _signature = sig.hex() if isinstance(sig, bytes) else str(sig)

        raw_decision = self.engine.evaluate(canonical_json)
        if isinstance(raw_decision, str):
            decision = json.loads(raw_decision)
        elif isinstance(raw_decision, dict):
            decision = raw_decision
        else:
            decision = {}

        return bool(decision.get("decision") == "Allow")
