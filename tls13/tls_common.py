"""Common imports and classes across the various pieces of TLS code."""

from typing import Any, override, Protocol, Self, runtime_checkable
from collections.abc import Iterable, Mapping, Callable
from abc import ABC, abstractmethod, abstractproperty
from functools import cached_property
from dataclasses import dataclass, field
from config import *

import logging
logger = logging.getLogger('tlsfun')
logging.basicConfig(format='[%(threadName)s] %(message)s')

if DEBUG:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.WARNING)

class TlsError(RuntimeError):
    pass

class TlsTODO(TlsError):
    pass
