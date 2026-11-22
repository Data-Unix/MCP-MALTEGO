"""Anillo 2 (Mullvad obligatorio): CLI con allowlist, relays propios, atestación doble, compuerta fail-closed,
guardián estricto PEP 578 y control del anillo desde el panel. Sin red ni daemon real: todo con dobles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.testclient import TestClient

from maltego_mcp.auth import CSRF_HEADER_NAME, hash_password_pbkdf2
from maltego_mcp.config import Settings
from maltego_mcp.egress import (
    AuditLog,
    EgressPolicy,
    GuardedTransport,
    check_egress_tunnel,
    connect_allowed,
    create_egress_client,
)
from maltego_mcp.errors import ConfigError, EgressKillSwitchError
from maltego_mcp.mullvad import (
    AMI_URL,
    RELAYS_URL,
    MullvadCli,
    MullvadError,
    MullvadGate,
    OwnedRelayRegistry,
    build_argv,
    is_mullvad_proxy_endpoint,
    parse_lockdown,
    parse_status,
    ring_snapshot,
    ring_state,
    set_gate_for_tests,
)

OWNED_EXIT = "se-sto-wg-001"
OWNED_ENTRY = "se-got-wg-001"
RENTED = "es-mad-wg-101"
REAL_IP = "203.0.113.77"


def _status(state: str, *, exit_host: str = "", entry_host: str = "", locked: bool | None = None) -> dict[str, Any]:
    """Salida con la forma real de `mullvad status -j`, incluida la IP real y la geolocalización (que deben caer)."""
    loc = {
        "latitude": 40.41,
        "longitude": -3.70,
        "ipv4": REAL_IP,
        "ipv6": None,
        "mullvad_exit_ip": state == "connected",
        "hostname": exit_host or None,
        "city": "Ciudad-Real-Del-Operador",
        "country": "Pais-Real",
        "entry_hostname": entry_host or None,
    }
    details: dict[str, Any] = {"location": loc}
    if locked is not None:
        details["locked_down"] = locked
    return {"state": state, "details": details}


class FakeCli(MullvadCli):
    def __init__(self, status: dict[str, Any], lockdown: bool = True, sig: str = "") -> None:
        super().__init__(path=Path("C:/no-existe/mullvad.exe"), verify_signature=False)
        self.status_doc = status
        self.lockdown = lockdown
        self.sig = sig
        self.calls: list[tuple[str, str, bool]] = []
        self.gate: MullvadGate | None = None
        self.on_action: dict[str, dict[str, Any]] = {}

    async def signature_code(self) -> str:
        return self.sig

    async def run(self, action: str, hostname: str = "") -> tuple[int, str]:
        build_argv(self.path, action, hostname)  # misma validación que el binario real
        self.calls.append((action, hostname, bool(self.gate and self.gate.closed)))
        if action == "status":
            return 0, json.dumps(self.status_doc)
        if action == "lockdown_get":
            return 0, f"Block traffic when the VPN is disconnected: {'on' if self.lockdown else 'off'}"
        if action in self.on_action:
            self.status_doc = self.on_action[action]
        return 0, ""


def _ami(exit_ip: bool = True, hostname: str | None = OWNED_EXIT) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == RELAYS_URL:
            return httpx.Response(503)  # refresco vivo de relays (por el túnel) caído: se mantiene la instantánea
        assert str(request.url) == AMI_URL
        body: dict[str, Any] = {"ip": "185.65.135.1", "mullvad_exit_ip": exit_ip, "blacklisted": {"blacklisted": False}}
        if hostname:
            body["mullvad_exit_ip_hostname"] = hostname
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


def _gate(cli: FakeCli, ami: httpx.MockTransport | None = None, remote: bool = True) -> MullvadGate:
    gate = MullvadGate(
        cli=cli, registry=OwnedRelayRegistry(), ttl_seconds=30, remote_check=remote, remote_transport=ami or _ami()
    )
    cli.gate = gate
    return gate


@pytest.fixture(autouse=True)
def _reset_gate() -> Any:
    yield
    set_gate_for_tests(None)


# ------------------------------------------------------------------------------------------------- CLI y parseo
def test_allowlist_de_subcomandos_y_hostnames() -> None:
    cli = Path("C:/Program Files/Mullvad VPN/resources/mullvad.exe")
    assert build_argv(cli, "status") == [str(cli), "status", "-j"]
    assert build_argv(cli, "relay_exit", OWNED_EXIT)[-4:] == ["relay", "set", "location", OWNED_EXIT]
    for forbidden in ("lockdown_set", "account", "split_tunnel", "ownership_any", "relay_custom", "dns", "api_access"):
        with pytest.raises(MullvadError):
            build_argv(cli, forbidden)
    for bad_host in ("se-got-wg-001 any", "se-got-wg-001;calc", "any", "../x", "SE-GOT-WG-001 ", ""):
        with pytest.raises(MullvadError):
            build_argv(cli, "relay_exit", bad_host)
    with pytest.raises(MullvadError):
        build_argv(cli, "connect", "se-got-wg-001")


def test_status_descarta_ip_real_y_geolocalizacion() -> None:
    st = parse_status(_status("disconnected", locked=False))
    flat = json.dumps(st.__repr__())
    assert REAL_IP not in flat and "Ciudad-Real" not in flat and "40.41" not in flat
    assert st.state == "disconnected" and st.locked_down is False and st.exit_hostname == ""
    st2 = parse_status(_status("connected", exit_host=OWNED_EXIT, entry_host=OWNED_ENTRY), lockdown=True)
    assert (st2.exit_hostname, st2.entry_hostname, st2.locked_down) == (OWNED_EXIT, OWNED_ENTRY, True)
    assert parse_lockdown("Block traffic when the VPN is disconnected: on") is True
    assert parse_lockdown("Block traffic when the VPN is disconnected: off") is False


def test_proxy_interno_de_mullvad() -> None:
    assert is_mullvad_proxy_endpoint("10.64.0.1", 1080)
    assert is_mullvad_proxy_endpoint("10.124.7.9", 1080)
    assert not is_mullvad_proxy_endpoint("10.124.7.9", 80)
    assert not is_mullvad_proxy_endpoint("127.0.0.1", 1080)
    assert not is_mullvad_proxy_endpoint("185.65.135.1", 1080)


# ------------------------------------------------------------------------------------------------- relays propios
def test_instantanea_de_relays_propios() -> None:
    reg = OwnedRelayRegistry()
    assert len(reg) >= 100 and reg.source == "snapshot"
    assert reg.is_owned(OWNED_EXIT) and reg.is_owned(OWNED_ENTRY)
    assert not reg.is_owned(RENTED) and not reg.is_owned("") and not reg.is_owned(None)


async def test_refresco_vivo_valida_y_rechaza_listas_anomalas(tmp_path: Path) -> None:
    cache = tmp_path / "relays.json"
    reg = OwnedRelayRegistry(cache)

    def rows(n: int) -> list[dict[str, Any]]:
        base = [
            {
                "hostname": f"se-sto-wg-{i:03d}",
                "owned": True,
                "active": True,
                "type": "wireguard",
                "country_code": "se",
                "country_name": "Sweden",
                "city_code": "sto",
                "city_name": "Stockholm",
            }
            for i in range(1, n + 1)
        ]
        base.append({"hostname": RENTED, "owned": False, "active": True, "type": "wireguard"})
        base.append({"hostname": "se-sto-wg-999", "owned": True, "active": False, "type": "wireguard"})
        base.append({"hostname": "x; rm -rf", "owned": True, "active": True, "type": "wireguard"})
        return base

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=rows(5)))) as c:
        assert await reg.refresh(c) is False  # demasiado pocos: se descarta
    assert reg.source == "snapshot"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=rows(30)))) as c:
        assert await reg.refresh(c) is True
    assert reg.source == "live" and len(reg) == 30
    assert not reg.is_owned(RENTED) and not reg.is_owned("se-sto-wg-999")
    assert OwnedRelayRegistry(cache).source == "cache"


# ------------------------------------------------------------------------------------------------- atestación
@pytest.mark.parametrize(
    ("status", "lockdown", "sig", "ami", "code", "state"),
    [
        (_status("disconnected", locked=True), True, "", None, "disconnected", "blocked"),
        (_status("disconnected", locked=False), False, "", None, "disconnected", "unlocked"),
        (_status("connected", exit_host=OWNED_EXIT), False, "", None, "lockdown_off", "unlocked"),
        (_status("connected", exit_host=RENTED), True, "", None, "rented_exit", "rented"),
        (_status("connected", exit_host=OWNED_EXIT, entry_host=RENTED), True, "", None, "rented_entry", "rented"),
        (_status("connecting", exit_host=OWNED_EXIT), True, "", None, "connecting", "connecting"),
        ({"state": "error", "details": {"cause": "AuthFailed: account expired"}}, True, "", None, "error", "account"),
        (_status("connected", exit_host=OWNED_EXIT), True, "cli_missing", None, "cli_missing", "daemon"),
        (_status("connected", exit_host=OWNED_EXIT), True, "cli_unsigned", None, "cli_unsigned", "daemon"),
        (_status("connected", exit_host=OWNED_EXIT), True, "", _ami(exit_ip=False), "remote_not_mullvad", "unverified"),
        (
            _status("connected", exit_host=OWNED_EXIT),
            True,
            "",
            _ami(hostname="se-sto-wg-002"),
            "remote_mismatch",
            "unverified",
        ),
        (_status("connected", exit_host=OWNED_EXIT, entry_host=OWNED_ENTRY), True, "", None, "ok", "protected"),
    ],
)
async def test_maquina_de_estados_de_la_atestacion(
    status: dict[str, Any], lockdown: bool, sig: str, ami: httpx.MockTransport | None, code: str, state: str
) -> None:
    gate = _gate(FakeCli(status, lockdown=lockdown, sig=sig), ami)
    att = await gate.attest()
    assert (att.code, ring_state(att)) == (code, state)
    assert att.ok is (code == "ok")
    snap = json.dumps(ring_snapshot(gate, att))
    assert REAL_IP not in snap and "Ciudad-Real" not in snap and "latitude" not in snap


async def test_compuerta_cerrada_por_el_operador_bloquea_aunque_el_daemon_este_bien() -> None:
    gate = _gate(FakeCli(_status("connected", exit_host=OWNED_EXIT), lockdown=True))
    assert (await gate.ensure()).exit_hostname == OWNED_EXIT
    gate.close("desconexión")
    with pytest.raises(EgressKillSwitchError):
        await gate.ensure()
    att = await gate.attest()
    assert att.gate_closed and not att.ok and ring_state(att) == "connecting"
    gate.open()
    assert (await gate.attest(force=True)).ok


# ------------------------------------------------------------------------------------------------- egreso
def _counting_transport() -> tuple[httpx.MockTransport, list[str]]:
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler), hits


async def test_compuerta_fail_closed_no_toca_la_red_y_audita(tmp_path: Path) -> None:
    transport, hits = _counting_transport()
    audit = AuditLog(tmp_path / "audit.log")
    gate = _gate(FakeCli(_status("disconnected", locked=True)))
    guarded = GuardedTransport(transport, EgressPolicy(), audit_log=audit, profile="mullvad", gate=gate)
    async with httpx.AsyncClient(transport=guarded) as client:
        with pytest.raises(EgressKillSwitchError):
            await client.get("https://crt.sh/?q=example.com")
    assert hits == []
    rec = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["decision"] == "blocked" and "MULLVAD_GATE" in rec["reason"]


async def test_auditoria_veraz_con_relay_atestado_y_loopback_sin_compuerta(tmp_path: Path) -> None:
    transport, hits = _counting_transport()
    audit = AuditLog(tmp_path / "audit.log")
    gate = _gate(FakeCli(_status("connected", exit_host=OWNED_EXIT), lockdown=True))
    guarded = GuardedTransport(transport, EgressPolicy(), audit_log=audit, profile="mullvad", gate=gate)
    async with httpx.AsyncClient(transport=guarded) as client:
        r = await client.get("https://crt.sh/?q=example.com")
        await r.aread()
        await r.aclose()
    rec = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["egress_profile"] == f"mullvad:{OWNED_EXIT}" and rec["decision"] == "allowed"

    # Loopback (TRX local) no sale de la máquina: no necesita atestación aunque Mullvad esté caído.
    down = _gate(FakeCli(_status("disconnected", locked=True)))
    guarded2 = GuardedTransport(
        transport, EgressPolicy(extra_allowed_hosts={"127.0.0.1"}), profile="mullvad", gate=down
    )
    async with httpx.AsyncClient(transport=guarded2) as client:
        assert (await client.get("http://127.0.0.1:9/x")).status_code == 200
    assert len(hits) == 2


async def test_factoria_con_mullvad_obligatorio_usa_la_compuerta_y_no_rebaja(tmp_path: Path) -> None:
    transport, hits = _counting_transport()
    set_gate_for_tests(_gate(FakeCli(_status("disconnected", locked=True))))
    s = Settings(home=tmp_path, egress="direct", require_mullvad=True, egress_per_provider="crtsh=direct")
    async with create_egress_client(settings=s, transport=transport, provider="crtsh") as client:
        with pytest.raises(EgressKillSwitchError):
            await client.get("https://crt.sh/?q=example.com")
    assert hits == []


async def test_t1_vpn_sin_proxy_bloquea_en_vez_de_salir_directo(tmp_path: Path) -> None:
    transport, hits = _counting_transport()
    s = Settings(home=tmp_path, egress="vpn", egress_proxy="", require_mullvad=False)
    async with create_egress_client(settings=s, transport=transport) as client:
        with pytest.raises(EgressKillSwitchError):
            await client.get("https://crt.sh/?q=example.com")
    assert hits == []


async def test_t2_check_tunnel_sin_proxy_no_da_falso_positivo() -> None:
    res = await check_egress_tunnel("vpn", proxy_url="")
    assert res["ok"] is False
    ok_client = httpx.AsyncClient(transport=_ami(exit_ip=False))
    res2 = await check_egress_tunnel("vpn", client=ok_client)
    assert res2["ok"] is False


def test_guardian_estricto_de_conexiones() -> None:
    assert connect_allowed(("127.0.0.1", 8000))
    assert connect_allowed(("::1", 8000, 0, 0))
    assert connect_allowed(("10.64.0.1", 1080))
    assert connect_allowed(("10.124.3.4", 1080))
    assert not connect_allowed(("10.124.3.4", 443))
    assert not connect_allowed(("185.65.135.1", 443))
    assert not connect_allowed(("8.8.8.8", 53))
    assert connect_allowed("/tmp/socket")  # AF_UNIX


# ------------------------------------------------------------------------------------------------- configuración
def test_config_mullvad_obligatorio_por_defecto(tmp_path: Path) -> None:
    s = Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path)})
    assert s.require_mullvad and s.egress == "mullvad" and s.mullvad_socks == "socks5h://10.64.0.1:1080"
    s2 = Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path), "MALTEGO_MCP_EGRESS": "vpn"})
    assert s2.egress == "mullvad"
    s3 = Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path), "MALTEGO_MCP_EGRESS": "tor"})
    assert s3.egress == "tor" and s3.require_mullvad
    with pytest.raises(ConfigError):
        Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path), "MALTEGO_MCP_EGRESS_PER_PROVIDER": "shodan=direct"})
    with pytest.raises(ConfigError):
        Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path), "MALTEGO_MCP_MULLVAD_SOCKS": "socks5h://1.2.3.4:1080"})
    with pytest.raises(ConfigError):
        Settings.from_env(
            {"MALTEGO_MCP_HOME": str(tmp_path), "MALTEGO_MCP_MULLVAD_SOCKS": "socks5h://u:p@10.64.0.1:1080"}
        )
    off = Settings.from_env({"MALTEGO_MCP_HOME": str(tmp_path), "MALTEGO_MCP_REQUIRE_MULLVAD": "0"})
    assert not off.require_mullvad and off.egress == "direct"


# ------------------------------------------------------------------------------------------------- panel
PASSWORD = "anillo-operador-2026"


def _app(tmp_path: Path, gate: MullvadGate, auth: bool = True, ring_control: bool | None = None) -> Any:
    from maltego_mcp.server import build_service, create_server
    from maltego_mcp.web_app import attach_dashboard_routes

    set_gate_for_tests(gate)
    settings = Settings(
        data_file=tmp_path / "graph.json",
        home=tmp_path,
        dashboard_auth=auth,
        dashboard_user="admin",
        dashboard_password_hash=hash_password_pbkdf2(PASSWORD, iterations=100_000),
    )
    server = create_server(settings)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    svc = getattr(server, "_service", None) or build_service(settings)
    attach_dashboard_routes(app, svc, settings, ring_control=ring_control)
    return app, svc


def _login(client: TestClient) -> dict[str, str]:
    r = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert r.status_code == 200
    return {CSRF_HEADER_NAME: r.json()["csrf_token"]}


def test_panel_estado_sin_ip_y_solo_lectura_sin_autenticacion(tmp_path: Path) -> None:
    cli = FakeCli(_status("disconnected", locked=False))
    app, _ = _app(tmp_path, _gate(cli), auth=False)
    client = TestClient(app)
    r = client.get("/api/egress/ring")
    assert r.status_code == 200
    body = r.json()
    assert body["ring"]["state"] == "unlocked" and body["control"]["enabled"] is False
    assert REAL_IP not in r.text and "Ciudad-Real" not in r.text and "latitude" not in r.text
    assert client.post("/api/egress/ring/connect").status_code == 403
    assert all(c[0] in ("status", "lockdown_get") for c in cli.calls)


def test_panel_conectar_desconectar_con_reautenticacion_y_auditoria(tmp_path: Path) -> None:
    cli = FakeCli(_status("disconnected", locked=True))
    cli.on_action = {
        "connect": _status("connected", exit_host=OWNED_EXIT, entry_host=OWNED_ENTRY),
        "disconnect": _status("disconnected", locked=True),
    }
    gate = _gate(cli)
    app, svc = _app(tmp_path, gate)
    client = TestClient(app)
    assert client.get("/api/egress/ring").status_code == 401  # sin sesión no hay estado
    hdr = _login(client)

    assert client.post("/api/egress/ring/connect").status_code == 403  # sin CSRF
    r = client.post("/api/egress/ring/connect", headers=hdr)
    assert r.status_code == 200 and r.json()["ring"]["state"] == "protected"

    r = client.post("/api/egress/ring/disconnect", headers=hdr, json={})
    assert r.status_code == 401 and r.json()["reauth_required"] is True
    r = client.post("/api/egress/ring/disconnect", headers=hdr, json={"password": "mala"})
    assert r.status_code == 401
    assert ("disconnect", "", True) not in cli.calls
    r = client.post("/api/egress/ring/disconnect", headers=hdr, json={"password": PASSWORD})
    assert r.status_code == 200 and r.json()["ring"]["state"] == "blocked"
    # D7: la compuerta del MCP estaba cerrada en el momento de desconectar
    assert ("disconnect", "", True) in cli.calls
    assert not gate.closed

    log = (svc.audit_log.log_path or tmp_path / "audit.log").read_text(encoding="utf-8")
    events = [json.loads(x) for x in log.splitlines() if '"vpn_control"' in x]
    assert [e["url_masked"].split("/")[2] for e in events] == ["connect", "disconnect"]
    assert all("operador=admin" in e["reason"] for e in events)


def test_panel_cambio_de_relay_valida_contra_la_lista_viva(tmp_path: Path) -> None:
    cli = FakeCli(_status("connected", exit_host=OWNED_EXIT, entry_host=OWNED_ENTRY), lockdown=True)
    cli.on_action = {"relay_exit": _status("connected", exit_host="se-sto-wg-002", entry_host=OWNED_ENTRY)}
    app, _ = _app(tmp_path, _gate(cli, _ami(hostname="se-sto-wg-002")))
    client = TestClient(app)
    hdr = _login(client)
    client.get("/api/egress/ring")
    for bad in (RENTED, "se-sto-wg-001; calc", "any", ""):
        r = client.post(
            "/api/egress/ring/relay", headers=hdr, json={"role": "exit", "hostname": bad, "password": PASSWORD}
        )
        assert r.status_code == 400, bad
    r = client.post(
        "/api/egress/ring/relay", headers=hdr, json={"role": "exit", "hostname": OWNED_ENTRY, "password": PASSWORD}
    )
    assert r.status_code == 400  # misma que la entrada
    r = client.post(
        "/api/egress/ring/relay", headers=hdr, json={"role": "exit", "hostname": "se-sto-wg-002", "password": PASSWORD}
    )
    assert r.status_code == 200, r.text
    assert ("relay_exit", "se-sto-wg-002", True) in cli.calls
    assert r.json()["ring"]["exit"]["hostname"] == "se-sto-wg-002"
    relays = client.get("/api/egress/ring/relays").json()["relays"]
    assert all(set(x) == {"hostname", "country_code", "country", "city_code", "city"} for x in relays)


def test_panel_fuera_de_loopback_es_solo_lectura(tmp_path: Path) -> None:
    cli = FakeCli(_status("connected", exit_host=OWNED_EXIT), lockdown=True)
    app, _ = _app(tmp_path, _gate(cli), ring_control=False)
    client = TestClient(app)
    hdr = _login(client)
    assert client.get("/api/egress/ring").json()["control"]["enabled"] is False
    r = client.post("/api/egress/ring/disconnect", headers=hdr, json={"password": PASSWORD})
    assert r.status_code == 403 and r.json()["readonly"] is True
    assert not any(c[0] == "disconnect" for c in cli.calls)


def test_no_existe_tool_mcp_para_controlar_la_vpn() -> None:
    from maltego_mcp.server import create_server

    tools_src = (Path(__file__).resolve().parents[1] / "src" / "maltego_mcp" / "tools.py").read_text(encoding="utf-8")
    assert "mullvad" not in tools_src.lower() and "egress/ring" not in tools_src
    assert create_server(Settings()) is not None


@pytest.mark.asyncio
async def test_canonicalizacion_hostname_socks5_remoto() -> None:
    reg = OwnedRelayRegistry()
    assert reg.is_owned("se-sto-wg-socks5-001")
    assert reg.get("se-sto-wg-socks5-001") is not None
    assert reg.get("se-sto-wg-socks5-001").hostname == "se-sto-wg-001"  # type: ignore[union-attr]

    cli = FakeCli(_status("connected", exit_host="se-sto-wg-001"), lockdown=True)
    gate = _gate(cli, ami=_ami(hostname="se-sto-wg-socks5-001"))
    att = await gate.attest(force=True)
    assert att.ok is True
    assert att.code == "ok"
    assert att.remote_ok is True
