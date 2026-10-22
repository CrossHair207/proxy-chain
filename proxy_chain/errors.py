"""Error types raised by the proxy chain."""


class ProxyChainError(Exception):
    """A connection, protocol, or configuration failure."""


class HopError(ProxyChainError):
    """A single proxy in the chain failed.

    ``index`` is the position of that proxy in the list that was attempted.
    ``proxy_dead`` is false when the proxy itself answered and the destination
    rejected the connection. Those proxies stay in rotation.
    """

    def __init__(self, index: int, message: str, *, proxy_dead: bool = True):
        super().__init__(message)
        self.index = index
        self.proxy_dead = proxy_dead


class ConfigError(ProxyChainError):
    """The configuration file or a runtime update is invalid."""
