"""Common imports and classes across the various pieces of TLS code."""

import logging
logger = logging.getLogger('tls13')

class TlsError(RuntimeError):
    pass

class TlsTODO(TlsError):
    pass
