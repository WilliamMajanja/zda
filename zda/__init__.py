"""ZDA: Zero-Dep Anything."""

from . import registry as _registry
from .formats import FORMATS

_registry.REGISTRY = FORMATS

from .registry import identify, inspect_file, list_formats

__version__ = "0.1.0"
__all__ = ["identify", "inspect_file", "list_formats", "FORMATS", "__version__"]
