"""Paridad EXACTA (bit a bit) entre el layout nativo maltego_core_rs y el fallback Python, y degradación elegante.

Los tests que necesitan el binario se omiten si no está compilado (CI sin Rust, otro equipo, otro IDE); los de
fallback se ejecutan siempre. Compilar: `uv run python scripts/build_native.py`.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from maltego_mcp import _accel
from maltego_mcp._native_build import source_fingerprint
from maltego_mcp.graph.memory import MemoryGraphStore
from maltego_mcp.maltego import mtgx
from maltego_mcp.maltego.mtgx import MAX_FORCE_NODES, _force, _force_py
from maltego_mcp.service import OsintService
from maltego_mcp.transforms.catalog import TransformCatalog

needs_native = pytest.mark.skipif(
    not _accel.HAS_NATIVE, reason="maltego_core_rs no compilado o obsoleto (uv run python scripts/build_native.py)"
)

SMALL = {
    "alpha": {"beta", "gamma"},
    "beta": {"alpha", "gamma", "delta"},
    "gamma": {"alpha", "beta"},
    "delta": {"beta", "epsilon"},
    "epsilon": {"delta"},
}


def _graph(num_nodes: int, degree: int = 4) -> dict[str, set[str]]:
    """Grafo determinista conexo (anillo con saltos) para paridad y rendimiento."""
    nodes = [f"node_{i:04d}" for i in range(num_nodes)]
    adj: dict[str, set[str]] = {n: set() for n in nodes}
    for i in range(num_nodes):
        for d in range(1, degree + 1):
            j = (i + d) % num_nodes
            adj[nodes[i]].add(nodes[j])
            adj[nodes[j]].add(nodes[i])
    return adj


# ------------------------------------------------------------------------------------------- con binario nativo
@needs_native
def test_binario_nativo_cargado_y_al_dia() -> None:
    assert _accel.HAS_NATIVE
    assert _accel._native_module.__src_hash__ == source_fingerprint()


@needs_native
@pytest.mark.parametrize(
    ("adj", "iterations"),
    [({"a": set()}, 10), (SMALL, 20), (SMALL, 150), (_graph(80), 150), (_graph(255), 60), (_graph(256), 60)],
    ids=["1-nodo", "5-nodos-20it", "5-nodos-150it", "80-nodos", "255-secuencial", "256-paralelo"],
)
def test_paridad_exacta_bit_a_bit(adj: dict[str, set[str]], iterations: int) -> None:
    """Igualdad EXACTA (sin tolerancias) en los dos caminos del núcleo Rust: por pares y paralelo por nodo."""
    assert _force(adj, iterations) == _force_py(adj, iterations)


@needs_native
def test_aceleracion_nativa_en_grafo_mediano() -> None:
    adj = _graph(300)
    t0 = time.perf_counter()
    p_nat = _force(adj, 150)
    t_nat = time.perf_counter() - t0
    t0 = time.perf_counter()
    p_py = _force_py(adj, 150)
    t_py = time.perf_counter() - t0
    assert p_nat == p_py
    speedup = t_py / max(t_nat, 1e-9)
    assert speedup > 10.0, f"Speedup insuficiente: {speedup:.1f}x (nat={t_nat * 1000:.1f}ms, py={t_py * 1000:.1f}ms)"


# ------------------------------------------------------------------------------------------- siempre (sin binario)
def test_grafos_triviales() -> None:
    assert _force({}, iterations=10) == {} == _force_py({}, iterations=10)


def test_sin_binario_usa_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_accel, "HAS_NATIVE", False)
    adj = _graph(30)
    assert _force(adj, 30) == _force_py(adj, 30)


def test_disable_native_fuerza_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MALTEGO_MCP_DISABLE_NATIVE", "1")
    assert _accel.is_native_disabled() is True
    with pytest.raises(RuntimeError):
        _accel.force_layout(["a"], [], [(0.0, 0.0)], 1)
    adj = {"a": {"b"}, "b": {"a"}}
    assert _force(adj, iterations=50) == _force_py(adj, iterations=50)


def test_grafo_mayor_que_max_force_nodes_usa_jerarquico() -> None:
    n = MAX_FORCE_NODES + 10
    large_graph = {f"n_{i}": {f"n_{(i + 1) % n}"} for i in range(n)}
    assert len(_force(large_graph)) == n


def test_sello_detecta_binario_obsoleto(tmp_path: Path) -> None:
    rust = tmp_path / "rust"
    (rust / "src").mkdir(parents=True)
    (rust / "Cargo.toml").write_bytes(b"[package]\nname = 'x'\n")
    (rust / "src" / "lib.rs").write_bytes(b"fn a() {}\n")
    fp = source_fingerprint(rust)
    assert _accel.native_is_current(fp, rust)
    assert not _accel.native_is_current("", rust)  # binario sin sello (p. ej. compilado a mano)
    (rust / "src" / "lib.rs").write_bytes(b"fn a() { let _ = 1; }\n")
    assert not _accel.native_is_current(fp, rust)  # fuentes cambiadas -> binario obsoleto
    lf = source_fingerprint(rust)
    (rust / "src" / "lib.rs").write_bytes(b"fn a() { let _ = 1; }\r\n")
    assert source_fingerprint(rust) == lf  # CRLF (checkout en Windows) y LF dan el mismo sello
    assert _accel.native_is_current("cualquiera", tmp_path / "sin-fuentes")  # paquete instalado: se confía


async def test_exportacion_mtgx_fuera_del_event_loop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """El layout + XML + ZIP del .mtgx no deben bloquear el event loop (minutos con grafos grandes en Python)."""
    hilos: list[str] = []
    original = mtgx.write_mtgx

    def espia(*args, **kwargs):  # type: ignore[no-untyped-def]
        hilos.append(threading.current_thread().name)
        return original(*args, **kwargs)

    monkeypatch.setattr("maltego_mcp.service.write_mtgx", espia)
    svc = OsintService(MemoryGraphStore(tmp_path / "g.json"), TransformCatalog(), tmp_path / "exports")
    await svc.create_case("c1", "export")
    for value in ("example.com", "example.org", "example.net"):
        await svc.upsert_entity("c1", "maltego.Domain", value, 0.5, "manual", [])
    path, n_entities, _ = await svc.export_case("c1", "mtgx", layout="force")
    assert path.is_file() and n_entities == 3
    assert hilos and hilos[0] != threading.current_thread().name
