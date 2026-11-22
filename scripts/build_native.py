"""Compila maltego_core_rs (rust/) y deja el módulo nativo en src/maltego_mcp/ con el sello de sus fuentes.

Uso:   uv run python scripts/build_native.py [--debug]
Requiere Rust (rustup). Solo compila en local: no publica nada.

El sello (SHA-256 de las fuentes) se incrusta en el binario; `maltego_mcp._accel` lo compara con las fuentes y, si
el binario está obsoleto, usa el fallback Python. Funciona en Windows (.pyd), Linux y macOS (.abi3.so).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "rust"
PKG = ROOT / "src" / "maltego_mcp"


def _cargo() -> str:
    found = shutil.which("cargo")
    if found:
        return found
    fallback = Path.home() / ".cargo" / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")
    if fallback.is_file():
        return str(fallback)
    sys.exit("No se encontró cargo. Instala Rust con rustup (https://rustup.rs) y vuelve a ejecutar.")


def _artifact(profile: str) -> Path:
    out = RUST / "target" / profile
    if sys.platform == "win32":
        return out / "_accel_native.dll"
    if sys.platform == "darwin":
        return out / "lib_accel_native.dylib"
    return out / "lib_accel_native.so"


def _destination() -> Path:
    return PKG / ("_accel_native.pyd" if sys.platform == "win32" else "_accel_native.abi3.so")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--debug", action="store_true", help="compilación sin optimizar (más rápida de compilar)")
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT / "src"))
    from maltego_mcp._native_build import source_fingerprint  # no importa el binario (Windows lo bloquearía)

    fingerprint = source_fingerprint(RUST)
    env = {**os.environ, "MALTEGO_CORE_SRC_HASH": fingerprint, "PYO3_PYTHON": sys.executable}
    if sys.platform == "darwin":  # extensión de Python: los símbolos de libpython se resuelven al cargar
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C link-arg=-undefined -C link-arg=dynamic_lookup").strip()
    profile = "debug" if args.debug else "release"
    cmd = [_cargo(), "build", "--locked"] + ([] if args.debug else ["--release"])
    subprocess.run(cmd, cwd=RUST, env=env, check=True)

    src, dst = _artifact(profile), _destination()
    tmp = dst.with_name(dst.name + ".tmp")
    shutil.copy2(src, tmp)
    try:
        os.replace(tmp, dst)
    except PermissionError:
        tmp.unlink(missing_ok=True)
        sys.exit(f"No se pudo reemplazar {dst.name}: ciérralo en los procesos que usen el MCP y repite.")
    print(f"OK: {dst.relative_to(ROOT).as_posix()} (sello {fingerprint[:12]}, perfil {profile})")


if __name__ == "__main__":
    main()
