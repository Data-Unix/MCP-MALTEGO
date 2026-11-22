"""Pruebas periciales exhaustivas para los informes de investigación (Markdown y HTML) y .mtgx."""

from __future__ import annotations

import re

import pytest

from maltego_mcp.domain.records import CaseRecord, EdgeRecord, EntityRecord, StepRecord
from maltego_mcp.maltego.mtgx import read_mtgx, write_mtgx
from maltego_mcp.report import ReportData, to_html, to_markdown

EMOJI_PATTERN = re.compile(
    "["
    "\U0001f600-\U0001f64f"  # emoticones
    "\U0001f300-\U0001f5ff"  # simbolos y pictogramas
    "\U0001f680-\U0001f6ff"  # transporte y mapa
    "\U0001f1e0-\U0001f1ff"  # banderas
    "\U00002702-\U000027b0"
    "\U000024c2-\U0001f251"
    "\U0001f900-\U0001f9ff"  # suplementario
    "\U0001fa70-\U0001faff"
    "\U00002600-\U000026ff"  # miscelaneos
    "]+",
    flags=re.UNICODE,
)


ReferenceData = tuple[list[EntityRecord], list[EdgeRecord], list[StepRecord]]


def _synthetic_reference_data() -> ReferenceData:
    """Caso BPO sintético y autocontenido que ejercita todas las secciones del informe pericial.

    Incluye un proveedor con servicio, sede georreferenciada, cliente concurrente (matriz de concurrencia) y una
    evidencia por URL (neutralización de enlaces), de modo que los tests no dependan de ningún archivo local.
    """
    ents = [
        EntityRecord(
            "e1", "c1", "Company", "maltego.Company", "TelcoGlobal Corp", 1.0, ["test"], {"role": "target_client"}
        ),
        EntityRecord("e2", "c1", "Phrase", "maltego.Phrase", "[DICTAMEN] Sin exclusividad contractual", 1.0, ["test"]),
        EntityRecord(
            "e3",
            "c1",
            "Company",
            "maltego.Company",
            "Operadora Andina BPO",
            0.9,
            ["test"],
            {"geo.country": "Perú", "bpo.role": "provider", "ruc": "20100000001"},
        ),
        EntityRecord("e4", "c1", "Company", "maltego.Company", "Banco Ejemplo", 0.8, ["test"]),
        EntityRecord(
            "e5",
            "c1",
            "URL",
            "maltego.URL",
            "https://registro.example.org/operadora-andina",
            0.9,
            ["test"],
            {"url": "https://registro.example.org/operadora-andina"},
        ),
        EntityRecord("e6", "c1", "Phrase", "maltego.Phrase", "Servicio :: Atención al cliente", 0.9, ["test"]),
        EntityRecord("e7", "c1", "Location", "maltego.Location", "Sede Lima Centro", 0.9, ["test"]),
        EntityRecord("e8", "c1", "GPS", "maltego.GPS", "-12.0464,-77.0428", 0.9, ["test"]),
    ]
    edges = [
        EdgeRecord("l1", "c1", "provides_bpo_service_to", "e3", "e1"),
        EdgeRecord("l2", "c1", "subject_to_verdict", "e3", "e2"),
        EdgeRecord("l3", "c1", "services_concurrent_client", "e3", "e4"),
        EdgeRecord("l4", "c1", "verified_via_url", "e3", "e5"),
        EdgeRecord("l5", "c1", "delivers_service", "e3", "e6"),
        EdgeRecord("l6", "c1", "operates_facility", "e3", "e7"),
        EdgeRecord("l7", "c1", "georeferenced_at", "e7", "e8"),
    ]
    return ents, edges, [StepRecord(1, "c1", "2026-03-30T10:00:00Z", "transform", "recon")]


@pytest.fixture
def reference_data() -> ReferenceData:
    """Datos sintéticos de referencia para validación hermética."""
    return _synthetic_reference_data()


def test_informe_pericial_completo_estructura_y_cero_emojis(reference_data: ReferenceData) -> None:
    ents, edges, steps = reference_data
    case = CaseRecord(
        case_id="BPO-SYNTHETIC-AUDIT-01",
        description="Mapeo Pericial Sintético de Proveedores BPO Multijurisdicción",
    )
    data = ReportData(
        case=case,
        entities=ents,
        edges=edges,
        steps=steps,
        scores={},
        actions=[],
        generated="2026-03-30 18:00:00 UTC",
    )

    md = to_markdown(data)
    html_doc = to_html(data)

    # 1. Regla obligatoria: ZERO EMOJIS
    assert not EMOJI_PATTERN.search(md), "El informe Markdown contiene emojis prohibidos."
    assert not EMOJI_PATTERN.search(html_doc), "El informe HTML contiene emojis prohibidos."

    # 2. Verificacion de portada y metadatos
    assert "TLP:AMBER+STRICT" in md and "TLP:AMBER+STRICT" in html_doc
    assert "BPO-SYNTHETIC-AUDIT-01" in md and "BPO-SYNTHETIC-AUDIT-01" in html_doc
    assert "TelcoGlobal Corp" in md and "TelcoGlobal Corp" in html_doc

    # 3. Verificacion de § 01 Resumen Ejecutivo & BLUF & Dictamen
    assert "§ 01. Resumen Ejecutivo" in md
    assert "[DICTAMEN PERICIAL // VEREDICTO EJECUTIVO]" in md
    assert "§ 01 // RESUMEN EJECUTIVO & BLUF" in html_doc
    assert "DICTAMEN PERICIAL EMITIDO" in html_doc

    # 4. Verificacion de § 02/03 Matrices de Evidencias Consolidadas (6 columnas)
    assert "Matrices de Evidencias Consolidadas" in md
    assert "Registro / ID" in md and "Sedes Físicas & GPS" in md
    assert "matrix-table" in html_doc
    assert "col-entity" in html_doc and "col-conf" in html_doc

    # 5. Verificacion de § 04 Concurrencia
    assert "Matriz de Concurrencia" in md
    assert "heatmap-table" in html_doc

    # 6. Verificacion de § 05 Arquitectura Topologica del Grafo y SVG
    assert "Tier -1" in md and "Tier 8" in md
    assert "<svg" in html_doc and "</svg>" in html_doc
    assert "viewBox=" in html_doc
    assert "arrow-verdict" in html_doc and "arrow-bpo" in html_doc
    assert "legend-grid" in html_doc

    # 7. Verificacion de § 06 Trazabilidad y Sello SHA-256
    assert "SELLO CRIPTOGRAFICO SHA-256:" in html_doc
    assert "Sello Criptográfico SHA-256:" in md


def test_mtgx_ida_y_vuelta_completo_con_notas_y_geometria(reference_data: ReferenceData) -> None:
    ents, edges, steps = reference_data
    sidecar = {"case_id": "test_case", "steps": [s.to_dict() for s in steps]}

    mtgx_bytes = write_mtgx(ents, edges, "hierarchical", sidecar)
    imported = read_mtgx(mtgx_bytes)

    assert len(imported.entities) == len(ents)
    assert len(imported.links) == len(edges)
    assert all(e.notes for e in imported.entities), "El 100% de las entidades deben tener Notes poblado."
    assert all(e.position is not None for e in imported.entities), "El 100% de las entidades deben tener posicion."
    assert len(imported.sidecar.get("steps", [])) == len(steps)


def test_html_report_no_contiene_enlaces_vivos_ni_prefetch(reference_data: ReferenceData) -> None:
    """Verifica que el informe HTML no incluye enlaces clicables a objetivos ni recursos remotos."""
    ents, edges, steps = reference_data
    # Inyectar una entidad con URL para verificar neutralizacion
    ents.append(
        EntityRecord(
            "e_url",
            "c1",
            "URL",
            "maltego.URL",
            "https://target-victim.org/evidence/leak",
            1.0,
            ["transform:test"],
            {"url": "https://target-victim.org/evidence/leak"},
        )
    )
    case = CaseRecord("c1", "Caso Seguridad", "2026-01-01T00:00:00Z")
    data = ReportData(
        case=case,
        entities=ents,
        edges=edges,
        steps=steps,
        scores={},
        actions=[],
        generated="2026-03-30 18:00:00 UTC",
    )
    html_doc = to_html(data)

    # 1. Metadatos anti-rastreo y anti-prefetch obligatorios
    assert '<meta name="referrer" content="no-referrer">' in html_doc
    assert '<meta http-equiv="x-dns-prefetch-control" content="off">' in html_doc

    # 2. Sin href="http..." ni src="http..."
    assert 'href="http' not in html_doc
    assert "href='http" not in html_doc
    assert 'src="http' not in html_doc
    assert "src='http" not in html_doc

    # 3. Presencia de forma neutralizada (defanged)
    assert "hxxps[://]" in html_doc


def test_report_markdown_escapa_inyeccion_html() -> None:
    """Verifica que el informe Markdown escape tags HTML maliciosos en valores de entidades y notas (S6/B13)."""
    e_malicious = EntityRecord(
        "e_xss",
        "c_sec",
        "<img src=x onerror=alert(1)>",
        "maltego.Phrase",
        "<img src=x onerror=alert(1)>",
        1.0,
        ["source:test"],
        {},
    )
    case = CaseRecord("c_sec", "Caso con <script>alert('xss')</script>", "2026-01-01T00:00:00Z")
    data = ReportData(
        case=case,
        entities=[e_malicious],
        edges=[],
        steps=[],
        scores={},
        actions=[],
        generated="2026-03-30 18:00:00 UTC",
    )
    md = to_markdown(data)
    assert "<img src=x onerror=alert(1)>" not in md
    assert "&lt;img src=x onerror=alert(1)&gt;" in md
    assert "<script>" not in md
    assert "&lt;script&gt;" in md
