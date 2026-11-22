"""Tests exhaustivos para endpoints de Reconocimiento Pasivo, Perímetro Intocable y Machines en Web App."""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from maltego_mcp.config import Settings
from maltego_mcp.server import build_service, create_server
from maltego_mcp.web_app import attach_dashboard_routes


def _create_test_app(tmp_path: Path):
    settings = Settings(data_file=tmp_path / "graph.json", home=tmp_path)
    server = create_server(settings)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    svc = getattr(server, "_service", None) or build_service(settings)
    attach_dashboard_routes(app, svc, settings)
    return app, svc


def test_recon_endpoints_and_perimeter_contagion(tmp_path: Path) -> None:
    app, svc = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "caso-prueba-recon"

    # 1. Crear caso
    r_create = client.post("/api/cases", json={"case_id": cid, "description": "Caso Test Recon"})
    assert r_create.status_code == 200

    # 2. Obtener reconocimiento inicial (default Fase 0 framing)
    r_recon = client.get(f"/api/cases/{cid}/recon")
    assert r_recon.status_code == 200
    recon_data = r_recon.json()["recon"]
    assert recon_data["active_phase"] in ("Fase 0", "P0")
    assert "Ley 5/2014" in recon_data["p0_framing"]["legal_basis"]

    # 3. Actualizar framing Fase 0 (incluyendo calibración cognitiva anti-anclaje)
    recon_data["p0_framing"]["question"] = "¿Qué infraestructura pasiva tiene target.corp?"
    recon_data["p0_framing"]["pre_mortem"] = (
        "Si en 3 meses concluimos erróneamente, pudo ser un hosting compartido no detectado."
    )
    recon_data["p0_framing"]["reference_class"] = "PYME Tecnológica Nacional"
    recon_data["p0_framing"]["assumptions"] = [
        {
            "text": "La infraestructura principal radica en la UE",
            "refutation": "Hallar servidores autoritativos o ASNs en EEUU/Asia",
            "status": "activo",
        }
    ]
    r_put = client.put(f"/api/cases/{cid}/recon", json=recon_data)
    assert r_put.status_code == 200
    saved_framing = r_put.json()["recon"]["p0_framing"]
    assert saved_framing["question"] == "¿Qué infraestructura pasiva tiene target.corp?"
    assert "hosting compartido" in saved_framing["pre_mortem"]
    assert saved_framing["reference_class"] == "PYME Tecnológica Nacional"
    assert len(saved_framing["assumptions"]) == 1
    assert saved_framing["assumptions"][0]["status"] == "activo"
    assert "ASNs en EEUU" in saved_framing["assumptions"][0]["refutation"]

    # 4. Añadir semilla -> Verificar contagio al Perímetro y grafo + atributos anti-sesgo y homónimos
    r_seed = client.post(
        f"/api/cases/{cid}/recon/seeds",
        json={
            "type": "Domain",
            "value": "target.corp",
            "origin": "Fase 0",
            "hop": 0,
            "diagnosticidad": "alta",
            "cluster": "CL-01",
            "origen_tipo": "fuente_primaria",
            "buscado_no_encontrado": False,
            "identificador_1": "Dominio oficial target.corp",
            "identificador_2": "Cert SSL Org: TARGET CORP S.L.",
            "admiralty_contenido": "2",
            "admiralty_fuente": "B",
            "consultas_confirmacion": 3,
            "consultas_refutacion": 1,
        },
    )
    assert r_seed.status_code == 200
    seeds_list = r_seed.json()["seeds"]
    assert len(seeds_list) == 1
    seed_id = seeds_list[0]["id"]
    assert seeds_list[0]["status"].lower() == "nueva"
    assert seeds_list[0]["diagnosticidad"] == "alta"
    assert seeds_list[0]["cluster"] == "CL-01"
    assert seeds_list[0]["origen_tipo"] == "fuente_primaria"
    assert seeds_list[0]["buscado_no_encontrado"] is False
    assert seeds_list[0]["homonimo_verificado"] is True
    assert seeds_list[0]["admiralty_code"] == "B2"
    assert seeds_list[0]["consultas_confirmacion"] == 3
    assert seeds_list[0]["consultas_refutacion"] == 1

    # 4b. Actualizar estado y homónimos de la semilla (PATCH)
    r_patch = client.patch(
        f"/api/cases/{cid}/recon/seeds/{seed_id}",
        json={
            "status": "INVESTIGANDO",
            "consultas_refutacion": 2,
            "diagnosticidad": "alta",
        },
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["seeds"][0]["status"].lower() == "investigando"
    assert r_patch.json()["seeds"][0]["consultas_refutacion"] == 2
    assert r_patch.json()["seeds"][0]["homonimo_verificado"] is True

    # 4c. Añadir segunda semilla como evidencia negativa (buscado_no_encontrado) y borrarla (DELETE)
    r_seed2 = client.post(
        f"/api/cases/{cid}/recon/seeds",
        json={
            "type": "IPv4Address",
            "value": "198.51.100.99",
            "origin": "Fase 2",
            "hop": 1,
            "buscado_no_encontrado": True,
            "diagnosticidad": "no_discrimina",
        },
    )
    assert r_seed2.status_code == 200
    assert len(r_seed2.json()["seeds"]) == 2
    seed2 = next(s for s in r_seed2.json()["seeds"] if s["value"] == "198.51.100.99")
    assert seed2["buscado_no_encontrado"] is True
    seed2_id = seed2["id"]

    r_del = client.delete(f"/api/cases/{cid}/recon/seeds/{seed2_id}")
    assert r_del.status_code == 200
    assert len(r_del.json()["seeds"]) == 1
    assert r_del.json()["seeds"][0]["id"] == seed_id

    # 5. Comprobar que target.corp ahora está en el perímetro intocable
    r_perim = client.get(f"/api/cases/{cid}/perimeter")
    assert r_perim.status_code == 200
    p_data = r_perim.json()
    assert "target.corp" in p_data["domains"] or "target.corp" in p_data["custom_assets"]
    assert p_data["total"] >= 1

    # 6. Añadir activo manual al perímetro
    r_perim_add = client.post(f"/api/cases/{cid}/perimeter", json={"asset": "198.51.100.25"})
    assert r_perim_add.status_code == 200
    assert "198.51.100.25" in r_perim_add.json()["ips"]

    # 7. Generar pivotes laterales M3
    r_pivots = client.get(f"/api/cases/{cid}/recon/pivots")
    assert r_pivots.status_code == 200
    pivots = r_pivots.json()["pivots"]
    assert len(pivots) >= 1
    assert any("crt.sh" in p["action"] or "Wayback" in p["action"] for p in pivots)

    # 8. Generar dorks seguros
    r_dorks = client.get(f"/api/cases/{cid}/recon/dorks?domain=target.corp")
    assert r_dorks.status_code == 200
    dorks = r_dorks.json()["dorks"]
    assert len(dorks) >= 5
    assert any("github.com" in d["dork"] for d in dorks)
    assert any(d["category"].startswith("Fase ") for d in dorks)

    # 9. Añadir hipótesis rival ACH - Validación de campo refutación obligatorio
    r_bad_hyp = client.post(
        f"/api/cases/{cid}/recon/hypotheses",
        json={"statement": "Hipótesis sin refutación", "what_would_refute_it": ""},
    )
    assert r_bad_hyp.status_code == 400
    assert "refutaría" in r_bad_hyp.json()["error"]

    r_ok_hyp = client.post(
        f"/api/cases/{cid}/recon/hypotheses",
        json={
            "statement": "El objetivo opera infraestructura delegada en Cloudflare",
            "what_would_refute_it": "Observar NS autoritativo en ASN propio",
            "probability": "PROBABLE",
            "confidence": "MEDIA",
        },
    )
    assert r_ok_hyp.status_code == 200
    assert len(r_ok_hyp.json()["hypotheses"]) == 1

    # 10. Listar Machines pasivas disponibles
    r_mach = client.get(f"/api/cases/{cid}/machines")
    assert r_mach.status_code == 200
    machines = r_mach.json()["machines"]
    passive_mach_names = [m["name"] for m in machines if m["is_passive"]]
    assert "PassiveDomainRecon" in passive_mach_names

    # 11. Egress Audit Log
    r_audit = client.get("/api/egress/audit")
    assert r_audit.status_code == 200
    audit_data = r_audit.json()
    assert "chain_valid" in audit_data

    # 12. Insertar entidad en el grafo y verificar propiedades en /api/cases/{id}/graph
    ent = svc.build_entity(cid, "maltego.Domain", "target.corp", 0.95, "manual")
    import asyncio

    asyncio.run(svc.store.upsert_entity(ent))

    r_graph = client.get(f"/api/cases/{cid}/graph")
    assert r_graph.status_code == 200
    nodes = r_graph.json()["nodes"]
    assert len(nodes) >= 1
    node = nodes[0]
    assert "is_canary" in node
    assert "vigencia" in node
    assert "vigencia_score" in node
    assert "vigencia_rationale" in node


def test_fase2_and_fase3_endpoints_and_cognitive_reframing(tmp_path: Path) -> None:
    app, _ = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "caso-fase2-fase3"

    # Crear caso
    r_create = client.post("/api/cases", json={"case_id": cid, "description": "Caso Fase 2 y 3"})
    assert r_create.status_code == 200

    # 1. Fase 2: Registrar activo técnico con calibración de tasa base
    r_infra = client.post(
        f"/api/cases/{cid}/recon/infra",
        json={
            "host": "api.target.corp",
            "ip": "198.51.100.42",
            "provider": "AS13335 Cloudflare",
            "tasa_base": "cdn_alta",
            "vigencia": "activo",
            "ct_cert": "Certificado Let's Encrypt E1",
        },
    )
    assert r_infra.status_code == 200
    infra_item = r_infra.json()["item"]
    assert infra_item["host"] == "api.target.corp"
    assert infra_item["tasa_base"] == "cdn_alta"
    infra_id = infra_item["id"]

    # 2. Fase 2: Declarar laguna de cobertura
    r_gap = client.post(
        f"/api/cases/{cid}/recon/gaps",
        json={
            "phase": "Fase 2",
            "description": "WAF Cloudflare oculta IP de origen y backend real",
        },
    )
    assert r_gap.status_code == 200
    assert len(r_gap.json()["recon"]["coverage_gaps"]) == 1
    assert any("WAF Cloudflare" in g for g in r_gap.json()["recon"]["p0_framing"]["named_gaps"])

    # 3. Reencuadre Cognitivo Transversal (Heuer Cap. 10)
    r_reframing = client.post(
        f"/api/cases/{cid}/recon/reframing",
        json={"phase": "Fase 2"},
    )
    assert r_reframing.status_code == 200
    assert len(r_reframing.json()["recon"]["reframing_log"]) == 1
    assert r_reframing.json()["recon"]["reframing_log"][0]["phase"] == "Fase 2"

    # 4. Fase 3: Registrar snapshot histórico con auditoría de canarios y admiralty
    r_arch = client.post(
        f"/api/cases/{cid}/recon/archive",
        json={
            "url": "https://target.corp/legal/terms.html",
            "repository": "wayback",
            "timestamp_capture": "2023-10-15 11:30",
            "http_status": "200",
            "mime_type": "text/html",
            "possible_canary": True,
            "admiralty": "B2",
        },
    )
    assert r_arch.status_code == 200
    arch_item = r_arch.json()["item"]
    assert arch_item["possible_canary"] is True
    assert arch_item["admiralty"] == "B2"
    arch_id = arch_item["id"]

    # 5. Comprobar que get_case_recon devuelve infra, archives, gaps y reframing
    r_recon = client.get(f"/api/cases/{cid}/recon")
    assert r_recon.status_code == 200
    recon = r_recon.json()["recon"]
    assert len(recon["fase2_infra"]) == 1
    assert len(recon["fase3_archives"]) == 1
    assert len(recon["coverage_gaps"]) == 1
    assert len(recon["reframing_log"]) == 1

    # 6. Eliminar registros
    r_del_infra = client.delete(f"/api/cases/{cid}/recon/infra/{infra_id}")
    assert r_del_infra.status_code == 200
    assert len(r_del_infra.json()["recon"]["fase2_infra"]) == 0

    r_del_arch = client.delete(f"/api/cases/{cid}/recon/archive/{arch_id}")
    assert r_del_arch.status_code == 200
    assert len(r_del_arch.json()["recon"]["fase3_archives"]) == 0


def test_fase4_and_fase5_symmetric_dorks_and_phacking_control(tmp_path: Path) -> None:
    app, _ = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "caso-dorks-simetricos"

    # 1. Crear caso y añadir semilla de dominio
    r_create = client.post("/api/cases", json={"case_id": cid, "description": "Caso Dorks Simétricos"})
    assert r_create.status_code == 200

    r_seed = client.post(
        f"/api/cases/{cid}/recon/seeds",
        json={"type": "Domain", "value": "acme-solutions.corp", "origin": "Fase 0", "hop": 0},
    )
    assert r_seed.status_code == 200

    # 2. Obtener tríos de dorks simétricos
    r_dorks = client.get(f"/api/cases/{cid}/recon/symmetric-dorks?domain=acme-solutions.corp")
    assert r_dorks.status_code == 200
    trios = r_dorks.json()["trios"]
    assert len(trios) >= 3

    for trio in trios:
        assert "seed" in trio
        assert "positive" in trio and "dork" in trio["positive"]
        assert "negative" in trio and "dork" in trio["negative"]
        assert "neutral" in trio and "dork" in trio["neutral"]
        assert trio["negative"]["type"] == "refutatorio"
        assert trio["positive"]["type"] == "confirmatorio"
        assert trio["neutral"]["type"] == "neutro"

    # 3. Registrar consultas y auditar ratio de refutación y p-hacking
    r_log1 = client.post(
        f"/api/cases/{cid}/recon/log-search",
        json={"search_type": "confirmatorio"},
    )
    assert r_log1.status_code == 200
    assert r_log1.json()["searches_count"] == 1
    assert r_log1.json()["refutations_count"] == 0
    assert r_log1.json()["refutation_rate"] == 0

    r_log2 = client.post(
        f"/api/cases/{cid}/recon/log-search",
        json={"search_type": "refutatorio"},
    )
    assert r_log2.status_code == 200
    assert r_log2.json()["searches_count"] == 2
    assert r_log2.json()["refutations_count"] == 1
    assert r_log2.json()["refutation_rate"] == 50


def test_fase6_breaches_honeytokens_and_graph_linking(tmp_path: Path) -> None:
    app, _ = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "caso-fase6-breaches"

    # 1. Crear caso
    r_create = client.post("/api/cases", json={"case_id": cid, "description": "Caso Fase 6 Filtraciones"})
    assert r_create.status_code == 200

    # 2. Registrar filtración histórica reciclada (§Heuer Cap. 11)
    r_b1 = client.post(
        f"/api/cases/{cid}/recon/breaches",
        json={
            "identity": "admin@target.corp",
            "breach_name": "LinkedIn 2016 Dump",
            "breach_date": "2016-05-18",
            "exposure_type": "third_party",
            "secret_sample": "5baa61e4c9b93f3f0682250b6cf8331b7ee68d80",
            "admiralty": "B2",
        },
    )
    assert r_b1.status_code == 200
    b1_item = r_b1.json()["item"]
    assert b1_item["identity"] == "admin@target.corp"
    assert b1_item["vigencia"] == "historica_reciclada"
    assert "2016" in b1_item["vigencia_rationale"]
    assert b1_item["is_honeytoken"] is False
    b1_id = b1_item["id"]

    # 3. Registrar credencial con marcador de Honeytoken / Canario (§Heuer Cap. 12)
    r_b2 = client.post(
        f"/api/cases/{cid}/recon/breaches",
        json={
            "identity": "sysadmin@target.corp",
            "breach_name": "Pastebin Leak",
            "breach_date": "2024-02-10",
            "exposure_type": "source_code",
            "secret_sample": "AKIAIOSFODNN7EXAMPLE_canary",
            "admiralty": "C3",
        },
    )
    assert r_b2.status_code == 200
    b2_item = r_b2.json()["item"]
    assert b2_item["is_honeytoken"] is True
    assert "ALERTA OPERATIVA" in b2_item["honeytoken_alert"]
    assert b2_item["vigencia"] == "activa_critica"
    b2_id = b2_item["id"]

    # 4. Vincular al grafo la brecha b1
    r_link = client.post(f"/api/cases/{cid}/recon/breaches/{b1_id}/link-graph")
    assert r_link.status_code == 200, f"Error vinculando brecha al grafo: {r_link.text}"
    assert r_link.json()["ok"] is True

    # Comprobar que en el grafo existe el nodo del correo y de la brecha
    r_graph = client.get(f"/api/cases/{cid}/graph")
    assert r_graph.status_code == 200
    gdata = r_graph.json()
    node_vals = [n["value"] for n in gdata["nodes"]]
    assert "admin@target.corp" in node_vals
    assert "Brecha: LinkedIn 2016 Dump" in node_vals

    # Comprobar arista 'exposed_in' en los links del grafo
    assert len(gdata["links"]) >= 1
    assert any(e.get("label") == "exposed_in" for e in gdata["links"])

    # 5. Confirmar 2º Punto de Reencuadre Cognitivo en Fase 6 (Heuer Cap. 10 y 11)
    r_ref = client.post(
        f"/api/cases/{cid}/recon/reframing",
        json={"phase": "Fase 6"},
    )
    assert r_ref.status_code == 200
    logs = r_ref.json()["recon"]["refframing_log" if "refframing_log" in r_ref.json()["recon"] else "reframing_log"]
    assert any(entry.get("phase") == "Fase 6" for entry in logs)

    # 6. Eliminar registro b2
    r_del = client.delete(f"/api/cases/{cid}/recon/breaches/{b2_id}")
    assert r_del.status_code == 200
    breaches_remaining = r_del.json()["recon"]["fase6_breaches"]
    assert len(breaches_remaining) == 1
    assert breaches_remaining[0]["id"] == b1_id


def test_fase7_humint_passive_and_attribution_decoupling(tmp_path: Path) -> None:
    app, _ = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "caso-fase7-humint"

    # 1. Crear caso
    r_create = client.post("/api/cases", json={"case_id": cid, "description": "Caso Fase 7 HUMINT Pasivo"})
    assert r_create.status_code == 200

    # 2. Registrar perfil personal de empleado (Heuer Cap. 10: Desacoplamiento de atribución)
    r_h1 = client.post(
        f"/api/cases/{cid}/recon/humint",
        json={
            "actor_name": "Carlos Méndez",
            "role": "technical_dev",
            "channel": "linkedin_passive",
            "opinion_scope": "personal",
            "tech_stack": "PostgreSQL 14, Django 4.2",
            "admiralty": "B2",
        },
    )
    assert r_h1.status_code == 200
    h1_item = r_h1.json()["item"]
    assert h1_item["actor_name"] == "Carlos Méndez"
    assert h1_item["diagnosticidad"] == "baja_personal"
    assert "DESACOPLAMIENTO HEUER" in h1_item["attribution_guard"]
    h1_id = h1_item["id"]

    # 3. Registrar perfil oficial corporativo (CEO / rol fiduciario)
    r_h2 = client.post(
        f"/api/cases/{cid}/recon/humint",
        json={
            "actor_name": "Elena Rivas (CEO)",
            "role": "c_level",
            "channel": "whois_contact",
            "opinion_scope": "corporate",
            "tech_stack": "",
            "admiralty": "A1",
        },
    )
    assert r_h2.status_code == 200
    h2_item = r_h2.json()["item"]
    assert h2_item["diagnosticidad"] == "alta_corporativa"
    assert "institucional oficial" in h2_item["attribution_guard"]
    h2_id = h2_item["id"]

    # 4. Vincular al grafo el perfil personal
    r_link = client.post(f"/api/cases/{cid}/recon/humint/{h1_id}/link-graph")
    assert r_link.status_code == 200, f"Error vinculando HUMINT al grafo: {r_link.text}"
    assert r_link.json()["ok"] is True

    # Comprobar que en el grafo existe el nodo de persona y de empresa
    r_graph = client.get(f"/api/cases/{cid}/graph")
    assert r_graph.status_code == 200
    gdata = r_graph.json()
    node_vals = [n["value"] for n in gdata["nodes"]]
    assert "Carlos Méndez" in node_vals

    # Comprobar arista 'employed_by'
    assert len(gdata["links"]) >= 1
    assert any(e.get("label") == "employed_by" for e in gdata["links"])

    # 5. Eliminar perfil h2
    r_del = client.delete(f"/api/cases/{cid}/recon/humint/{h2_id}")
    assert r_del.status_code == 200
    humint_remaining = r_del.json()["recon"]["fase7_humint"]
    assert len(humint_remaining) == 1
    assert humint_remaining[0]["id"] == h1_id


def test_fase8_ecosystem_and_guilt_by_association_mitigation(tmp_path: Path) -> None:
    """Valida la Fase 8: Ecosistema externo, proveedores y mitigación de culpa por asociación (Heuer 10-13)."""
    app, _ = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "test-recon-fase8-eco"
    r_create = client.post("/api/cases", json={"case_id": cid, "name": "Caso Recon Fase 8"})
    assert r_create.status_code == 200

    # 1. Fijar semilla y objetivo corporativo
    client.put(
        f"/api/cases/{cid}/recon",
        json={"active_phase": "Fase 8", "p0_framing": {"target": "Target Logistics Corp"}},
    )

    # 2. Registrar proveedor de pagos (Stripe) con alta tasa base
    r_e1 = client.post(
        f"/api/cases/{cid}/recon/ecosystem",
        json={
            "provider_name": "Stripe Payments Europe",
            "category": "payment_gateway",
            "dependency_level": "critica",
            "base_rate_commonality": "muy_alta",
            "shared_cluster_id": "Cluster-Fintech-1",
            "admiralty": "A1",
            "notes": "Pasarela oficial de cobro registrada en checkout.",
        },
    )
    assert r_e1.status_code == 200, f"Error al registrar ecosistema Fase 8: {r_e1.text}"
    e1_item = r_e1.json()["item"]
    assert e1_item["provider_name"] == "Stripe Payments Europe"
    assert e1_item["conduct_decoupled"] is True
    assert e1_item["dependency_level"] == "critica"
    assert e1_item["base_rate_commonality"] == "muy_alta"
    e1_id = e1_item["id"]

    # 3. Registrar proveedor logístico (DHL)
    r_e2 = client.post(
        f"/api/cases/{cid}/recon/ecosystem",
        json={
            "provider_name": "DHL Express Global",
            "category": "logistics_shipping",
            "dependency_level": "secundaria",
            "base_rate_commonality": "media",
            "shared_cluster_id": "Cluster-Logistica-1",
            "admiralty": "B2",
            "notes": "Operador de envíos internacionales.",
        },
    )
    assert r_e2.status_code == 200
    e2_item = r_e2.json()["item"]
    assert e2_item["conduct_decoupled"] is True
    e2_id = e2_item["id"]

    # 4. Vincular al grafo el proveedor de pagos (Stripe)
    r_link = client.post(f"/api/cases/{cid}/recon/ecosystem/{e1_id}/link-graph")
    assert r_link.status_code == 200, f"Error vinculando ecosistema al grafo: {r_link.text}"
    assert r_link.json()["ok"] is True

    # Comprobar que en el grafo existe el nodo del proveedor y la empresa objetivo
    r_graph = client.get(f"/api/cases/{cid}/graph")
    assert r_graph.status_code == 200
    gdata = r_graph.json()
    node_vals = [n["value"] for n in gdata["nodes"]]
    assert "Stripe Payments Europe" in node_vals
    assert "Target Logistics Corp" in node_vals

    # Comprobar arista 'uses_payment_gateway' con desacoplamiento de conducta
    assert len(gdata["links"]) >= 1
    edge = next(e for e in gdata["links"] if e.get("label") == "uses_payment_gateway")
    assert edge is not None

    # 5. Eliminar proveedor e2
    r_del = client.delete(f"/api/cases/{cid}/recon/ecosystem/{e2_id}")
    assert r_del.status_code == 200
    eco_remaining = r_del.json()["recon"]["fase8_ecosystem"]
    assert len(eco_remaining) == 1
    assert eco_remaining[0]["id"] == e1_id


def test_fase9_ach_hypotheses_key_evidence_and_icd203_report(tmp_path: Path) -> None:
    """Valida exhaustivamente la Fase 9: ACH, análisis de sensibilidad y generación de informe ICD 203."""
    app, _ = _create_test_app(tmp_path)
    client = TestClient(app)
    cid = "test-ach-icd203-case"

    # 1. Configurar encuadre P0 y semillas en el caso
    r_init = client.put(
        f"/api/cases/{cid}/recon",
        json={
            "active_phase": "Fase 9",
            "p0_framing": {
                "target": "acme-defense.org",
                "question": "¿Opera acme-defense infraestructura crítica encubierta?",
                "legal_basis": "Mandato pericial forense / Ley 5/2014",
                "humint_limits": "Ámbito profesional y fuentes públicas abiertas",
            },
        },
    )
    assert r_init.status_code == 200

    # Añadir semillas
    client.post(
        f"/api/cases/{cid}/recon/seeds",
        json={"value": "acme-defense.org", "type": "Domain", "origin": "Fase 0", "hop": 0},
    )
    client.post(
        f"/api/cases/{cid}/recon/seeds",
        json={"value": "198.51.100.25", "type": "IPv4Address", "origin": "Fase 2", "hop": 1},
    )

    # 2. Registrar dos hipótesis rivales en Fase 9
    r_h1 = client.post(
        f"/api/cases/{cid}/recon/hypotheses",
        json={
            "statement": "La infraestructura está alojada legítimamente en Cloudflare como proxy DDoS",
            "what_would_refute_it": "Detectar registros A directos sin proxificar a servidores no declarados",
            "probability": "PROBABLE",
            "confidence": "ALTA",
        },
    )
    assert r_h1.status_code == 200
    hyps = r_h1.json()["hypotheses"]
    assert len(hyps) == 1
    h1_id = hyps[0]["id"]

    r_h2 = client.post(
        f"/api/cases/{cid}/recon/hypotheses",
        json={
            "statement": "La entidad opera una red encubierta de comando y control",
            "what_would_refute_it": "Auditoría de ASN coincidente y contratos mercantiles públicos",
            "probability": "IMPROBABLE",
            "confidence": "MEDIA",
        },
    )
    assert r_h2.status_code == 200
    hyps2 = r_h2.json()["hypotheses"]
    assert len(hyps2) == 2
    h2_id = hyps2[1]["id"]

    # 3. Evaluar matriz ACH (§Heuer Cap. 8)
    # H1 tiene 0 inconsistencias (evaluaciones consistentes "C")
    r_ev1 = client.post(
        f"/api/cases/{cid}/recon/hypotheses/{h1_id}/evaluate",
        json={
            "evaluations": {"ev-cert": "C", "ev-dns": "C", "ev-whois": "C"},
            "probability": "MUY_PROBABLE",
            "confidence": "ALTA",
        },
    )
    assert r_ev1.status_code == 200
    assert r_ev1.json()["hypothesis"]["inconsistency_score"] == 0

    # H2 tiene 2 inconsistencias (evaluaciones inconsistentes "I")
    r_ev2 = client.post(
        f"/api/cases/{cid}/recon/hypotheses/{h2_id}/evaluate",
        json={
            "evaluations": {"ev-cert": "I", "ev-dns": "I", "ev-whois": "C"},
            "probability": "IMPROBABLE",
            "confidence": "BAJA",
        },
    )
    assert r_ev2.status_code == 200
    assert r_ev2.json()["hypothesis"]["inconsistency_score"] == 2

    # 4. Registrar análisis de Pieza Clave y Sensibilidad (§Heuer Caps. 10-13)
    r_key = client.post(
        f"/api/cases/{cid}/recon/key-evidence",
        json={
            "evidence_summary": "Certificado TLS emitido por Cloudflare con coincidencia SAN en registros CT",
            "source_cluster": "CL-02 Infraestructura y Certificados",
            "independent_clusters_count": 3,
            "sensitivity_impact": "alto",
            "vulnerability_to_deception": "bajo",
            "alternative_explanation": "Configuración estándar heredada de un proxy público",
        },
    )
    assert r_key.status_code == 200
    k_data = r_key.json()["key_evidence"]
    assert k_data["sensitivity_impact"] == "alto"
    assert k_data["independent_clusters_count"] == 3

    # 5. Generar informe estimativo formal ICD 203
    r_rep = client.get(f"/api/cases/{cid}/recon/icd203-report")
    assert r_rep.status_code == 200
    rep = r_rep.json()
    assert rep["ok"] is True
    assessment = rep["assessment"]

    # La hipótesis líder debe ser H1 (menor inconsistencia según regla de Heuer)
    assert assessment["leading_hypothesis"] == h1_id
    assert "Altamente Probable" in assessment["probability"]
    assert assessment["confidence"] == "Alta"
    assert assessment["key_evidence_impact"] == "ALTO"

    # Verificar presencia de secciones doctrinales en Markdown
    md = rep["report_markdown"]
    assert "# INFORME ESTIMATIVO DE INTELIGENCIA (ICD 203 / HEUER ACH)" in md
    assert "acme-defense.org" in md
    assert "## 3. ANÁLISIS DE HIPÓTESIS EN COMPETENCIA" in md
    assert "## 4. ANÁLISIS DE PIEZA CLAVE Y SENSIBILIDAD" in md
    assert "## 5. JUICIO ESTIMATIVO FINAL (ESTÁNDARES ICD 203)" in md
    assert "Hipótesis Alternativas Consideradas y Descartadas:" in md

    # Verificar versión HTML
    html = rep["report_html"]
    assert "<!DOCTYPE html>" in html
    assert "INFORME ESTIMATIVO DE INTELIGENCIA" in html
    assert "JUICIO ESTIMATIVO FINAL (ICD 203)" in html

    # 6. Eliminar hipótesis rival H2
    r_del_h = client.delete(f"/api/cases/{cid}/recon/hypotheses/{h2_id}")
    assert r_del_h.status_code == 200
    remaining_hyps = r_del_h.json()["recon"]["hypotheses"]
    assert len(remaining_hyps) == 1
    assert remaining_hyps[0]["id"] == h1_id
