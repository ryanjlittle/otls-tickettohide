"""Common imports and classes across the various pieces of TLS code."""

import logging
logger = logging.getLogger('tlsfun')

class TlsError(RuntimeError):
    pass

class TlsTODO(TlsError):
    pass
