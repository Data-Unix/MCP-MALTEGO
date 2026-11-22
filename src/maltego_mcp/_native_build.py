"""Sello de las fuentes Rust de maltego_core_rs (sin importar el módulo nativo).

Lo usan `scripts/build_native.py` (para incrustarlo en el binario al compilar) y `_accel.py` (para descartar un
binario que no corresponde a las fuentes actuales). Está en un módulo aparte porque en Windows un `.pyd` cargado no
se puede sobrescribir: el script de compilación no debe importar el binario que va a reemplazar.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

RUST_DIR = Path(__file__).resolve().parents[2] / "rust"


def source_fingerprint(rust_dir: Path = RUST_DIR) -> str:
    """SHA-256 de Cargo.toml, Cargo.lock, build.rs y src/**/*.rs con finales de línea normalizados (CRLF == LF)."""
    digest = hashlib.sha256()
    files = [rust_dir / "Cargo.toml", rust_dir / "Cargo.lock", rust_dir / "build.rs"]
    files += sorted((rust_dir / "src").rglob("*.rs"))
    for path in files:
        if not path.is_file():
            continue
        digest.update(path.relative_to(rust_dir).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()
