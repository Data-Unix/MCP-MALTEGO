"""Capa de aceleración nativa (maltego_core_rs) con degradación elegante a Python puro.

El binario se compila con `uv run python scripts/build_native.py`, que incrusta el sello de las fuentes Rust.
Se usa el fallback Python (mismos resultados bit a bit, solo más lento) si el binario no existe, no carga, o está
OBSOLETO respecto a las fuentes de `rust/`. `MALTEGO_MCP_DISABLE_NATIVE=1` fuerza el fallback.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from maltego_mcp._native_build import RUST_DIR, source_fingerprint

logger = logging.getLogger(__name__)


def native_is_current(native_hash: str, rust_dir: Path = RUST_DIR) -> bool:
    """Con fuentes presentes (checkout de desarrollo) el sello del binario debe coincidir con el de las fuentes;
    sin fuentes (paquete instalado) se confía en el binario distribuido."""
    if not (rust_dir / "Cargo.toml").is_file():
        return True
    return bool(native_hash) and native_hash == source_fingerprint(rust_dir)


_native_module: Any = None
HAS_NATIVE: bool = False

try:
    from maltego_mcp import _accel_native as _candidate
except Exception as _exc:  # ImportError, binario para otra plataforma o ABI incompatible
    logger.debug("maltego_core_rs no disponible (%s); se usa el fallback Python.", _exc.__class__.__name__)
else:
    if native_is_current(str(getattr(_candidate, "__src_hash__", ""))):
        _native_module = _candidate
        HAS_NATIVE = True
    else:
        logger.warning(
            "maltego_core_rs está obsoleto respecto a rust/: se usa el fallback Python. "
            "Recompila con `uv run python scripts/build_native.py`."
        )


def is_native_disabled() -> bool:
    """Indica si el usuario ha deshabilitado la aceleración nativa por entorno."""
    return os.environ.get("MALTEGO_MCP_DISABLE_NATIVE", "").strip().lower() in ("1", "true", "yes")


def force_layout(
    nodes: list[str],
    edges: list[tuple[int, int]],
    initial_pos: list[tuple[float, float]],
    iterations: int = 150,
) -> list[tuple[float, float]]:
    """Layout Fruchterman-Reingold nativo (libera el GIL). Lanza RuntimeError si no hay binario utilizable."""
    if not HAS_NATIVE or is_native_disabled() or _native_module is None:
        raise RuntimeError("Aceleración nativa no disponible")
    result: list[tuple[float, float]] = _native_module.force_layout(nodes, edges, initial_pos, iterations)
    return result
