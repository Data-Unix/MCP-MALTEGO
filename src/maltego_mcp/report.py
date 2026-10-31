"""Informes ejecutivos de un caso (Markdown y HTML autocontenido)."""

from __future__ import annotations

import html
from dataclasses import dataclass, field

from maltego_mcp.analysis import Action, EntityScore
from maltego_mcp.domain.records import CaseRecord, EdgeRecord, EntityRecord, StepRecord


@dataclass(slots=True)
class ReportData:
    case: CaseRecord
    entities: list[EntityRecord]
    edges: list[EdgeRecord]
    steps: list[StepRecord]
    scores: dict[str, EntityScore]
    actions: list[Action] = field(default_factory=list)
    generated: str = ""

    def quality(self) -> dict[str, float | int]:
        n = len(self.entities) or 1
        linked = {e.out_id for e in self.edges} | {e.in_id for e in self.edges}
        transform_steps = [s for s in self.steps if s.kind == "transform"]
        return {
            "entidades": len(self.entities),
            "relaciones": len(self.edges),
            "confianza_media": round(sum(e.confidence for e in self.entities) / n, 2),
            "corroboradas_pct": round(100 * sum(len(set(e.sources)) > 1 for e in self.entities) / n, 1),
            "aisladas": sum(e.id not in linked for e in self.entities),
            "pasos": len(self.steps),
            "errores_pct": round(100 * sum(bool(s.error) for s in transform_steps) / (len(transform_steps) or 1), 1),
        }

    def by_type(self) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for e in self.entities:
            counts[e.maltego_type] = counts.get(e.maltego_type, 0) + 1
        return sorted(counts.items(), key=lambda x: (-x[1], x[0]))

    def top(self, n: int = 15) -> list[EntityScore]:
        return sorted(self.scores.values(), key=lambda s: (-s.priority, s.entity.value))[:n]


def _md(v: object) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def to_markdown(d: ReportData) -> str:
    q = d.quality()
    by_id = {e.id: e for e in d.entities}
    lines = [
        f"# Informe del caso `{d.case.case_id}`",
        f"_{_md(d.case.description) or 'Sin descripción'}_ · generado {d.generated}",
        "",
        "> Los valores proceden de fuentes OSINT y deben verificarse antes de actuar sobre ellos.",
        "",
        "## Resumen",
        f"- Entidades: **{q['entidades']}** · Relaciones: **{q['relaciones']}** · Pasos registrados: {q['pasos']}",
        f"- Calidad: confianza media {q['confianza_media']}, {q['corroboradas_pct']} % corroboradas por varias "
        f"fuentes, {q['aisladas']} aisladas, {q['errores_pct']} % de transforms con error",
        "",
        "## Entidades por tipo",
        "| Tipo | Nº |",
        "|---|---|",
        *[f"| {t} | {n} |" for t, n in d.by_type()],
        "",
        "## Entidades prioritarias",
        "| Prioridad | Tipo | Valor | Conexiones | Fuentes |",
        "|---|---|---|---|---|",
        *[
            f"| {s.priority:.2f} | {s.entity.maltego_type} | {_md(s.entity.value)} | {s.degree} | "
            f"{_md(', '.join(s.entity.sources[-3:]))} |"
            for s in d.top()
        ],
        "",
        "## Relaciones clave",
    ]
    key_ids = {s.entity.id for s in d.top(10)}
    rels = [e for e in d.edges if e.out_id in key_ids or e.in_id in key_ids][:40]
    lines += [
        f"- {_md(by_id[e.out_id].value)} —{e.label}→ {_md(by_id[e.in_id].value)}"
        for e in rels
        if e.out_id in by_id and e.in_id in by_id
    ] or ["- (sin relaciones)"]
    lines += ["", "## Cronología de la investigación"]
    lines += [
        f"{s.seq}. {s.timestamp} · {s.kind} **{_md(s.action)}**"
        + (f" sobre {_md(s.input_value)}" if s.input_value else "")
        + f" → {s.new_entities} nuevas"
        + (f" · ⚠ {_md(s.error)}" if s.error else "")
        + (f" · motivo: {_md(s.reason)}" if s.reason else "")
        for s in d.steps[-60:]
    ] or ["(sin pasos)"]
    if d.actions:
        lines += ["", "## Siguientes pasos recomendados"]
        lines += [
            f"{i}. **{a.transform}** sobre {_md(a.entity.value)} ({a.entity.maltego_type}) — {_md(a.reason)}"
            for i, a in enumerate(d.actions, 1)
        ]
    return "\n".join(lines) + "\n"


def to_html(d: ReportData) -> str:
    """HTML autocontenido (sin scripts ni recursos externos); todo el texto escapado."""
    e = html.escape
    q = d.quality()
    by_id = {x.id: x for x in d.entities}
    rows_top = "".join(
        f"<tr><td>{s.priority:.2f}</td><td>{e(s.entity.maltego_type)}</td><td>{e(s.entity.value)}</td>"
        f"<td>{s.degree}</td><td>{e(', '.join(s.entity.sources[-3:]))}</td></tr>"
        for s in d.top()
    )
    rows_type = "".join(f"<tr><td>{e(t)}</td><td>{n}</td></tr>" for t, n in d.by_type())
    key_ids = {s.entity.id for s in d.top(10)}
    rels = "".join(
        f"<li>{e(by_id[x.out_id].value)} <small>—{e(x.label)}→</small> {e(by_id[x.in_id].value)}</li>"
        for x in d.edges
        if (x.out_id in key_ids or x.in_id in key_ids) and x.out_id in by_id and x.in_id in by_id
    )
    steps = "".join(
        f"<li>{e(s.timestamp)} · {e(s.kind)} <b>{e(s.action)}</b> {e(s.input_value)} → {s.new_entities} nuevas"
        f"{' · ⚠ ' + e(s.error) if s.error else ''}</li>"
        for s in d.steps[-60:]
    )
    actions = "".join(f"<li><b>{e(a.transform)}</b> sobre {e(a.entity.value)} — {e(a.reason)}</li>" for a in d.actions)
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Informe {e(d.case.case_id)}</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1d1d1f}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.3rem .5rem;text-align:left}}
th{{background:#f2f2f2}}.kpi{{display:flex;gap:1rem;flex-wrap:wrap}}.kpi div{{background:#f6f8fa;padding:.6rem 1rem;
border-radius:6px}}.note{{color:#8a6d3b;background:#fcf8e3;padding:.5rem 1rem;border-radius:6px}}</style></head>
<body><h1>Informe del caso <code>{e(d.case.case_id)}</code></h1><p><i>{e(d.case.description or "Sin descripción")}</i>
 · generado {e(d.generated)}</p>
<p class="note">Los valores proceden de fuentes OSINT y deben verificarse antes de actuar sobre ellos.</p>
<div class="kpi"><div>Entidades<br><b>{q["entidades"]}</b></div><div>Relaciones<br><b>{q["relaciones"]}</b></div>
<div>Confianza media<br><b>{q["confianza_media"]}</b></div><div>Corroboradas<br><b>{q["corroboradas_pct"]} %</b></div>
<div>Aisladas<br><b>{q["aisladas"]}</b></div><div>Transforms con error<br><b>{q["errores_pct"]} %</b></div></div>
<h2>Entidades por tipo</h2><table><tr><th>Tipo</th><th>Nº</th></tr>{rows_type}</table>
<h2>Entidades prioritarias</h2><table><tr><th>Prioridad</th><th>Tipo</th><th>Valor</th><th>Conexiones</th>
<th>Fuentes</th></tr>{rows_top}</table>
<h2>Relaciones clave</h2><ul>{rels or "<li>(sin relaciones)</li>"}</ul>
<h2>Cronología</h2><ol>{steps or "<li>(sin pasos)</li>"}</ol>
<h2>Siguientes pasos recomendados</h2><ol>{actions or "<li>(ninguno)</li>"}</ol>
</body></html>
"""
