"""Format inspector registry: import Side-effects add formats to REGISTRY."""

from .elf import ElfFormat
from .pe import PeFormat
from .macho import MachOFormat
from .zipfam import ZipFormat
from .pdf import PdfFormat
from .sqlite import SqliteFormat
from .gguf import GgufFormat
from .safetensors import SafetensorsFormat
from .wasm import WasmFormat
from .jvm import JvmFormat
from .evm import EvmFormat
from .beam import BeamFormat
from .godot import GodotPckFormat
from .images import PngFormat, JpegFormat, GifFormat, WebPFormat
from .pyinst import PyInstallerFormat
from .asar import AsarFormat

_EXTRA = (
    PngFormat, JpegFormat, GifFormat, WebPFormat, PdfFormat,
    GgufFormat, SafetensorsFormat, WasmFormat, EvmFormat, BeamFormat,
    GodotPckFormat, SqliteFormat, ZipFormat, JvmFormat, PyInstallerFormat, AsarFormat,
)

FORMATS = (
    ElfFormat, PeFormat, MachOFormat, ZipFormat, PdfFormat,
    SqliteFormat, GgufFormat, SafetensorsFormat, WasmFormat, JvmFormat,
    EvmFormat, BeamFormat, GodotPckFormat, PngFormat, JpegFormat,
    GifFormat, WebPFormat, PyInstallerFormat, AsarFormat,
)

__all__ = ["FORMATS", "REGISTRY", "_EXTRA"]
