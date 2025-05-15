"""Common imports and classes across the various pieces of TLS code."""

from typing import Any
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

import logging
logger = logging.getLogger('tlsfun')

class TlsError(RuntimeError):
    pass

class TlsTODO(TlsError):
    pass
