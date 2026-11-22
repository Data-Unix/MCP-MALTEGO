"""Tests exhaustivos sin red para el punto único de salida y política de egress (F2)."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from types import SimpleNamespace

import httpcore
import httpx
import pytest

from maltego_mcp.config import Settings
from maltego_mcp.egress import (
    AuditLog,
    EgressPolicy,
    GuardedTransport,
    PinnedDNSBackend,
    Scope,
    create_egress_client,
    dns_lookup_allowed,
    get_following,
    inject_socks_auth,
    mask_url_secrets,
    register_egress_hosts,
    rotate_tor_circuit_newnym,
)
from maltego_mcp.errors import EgressBlockedError, EgressKillSwitchError, TransformError
from maltego_mcp.transforms.plugins import get_default_plugin_dirs


# 1. TEST ARQUITECTURAL: ÚNICO PUNTO DE SALIDA EN SRC
def test_unico_punto_de_salida_en_src() -> None:
    """Verifica estáticamente que no existan llamadas a httpx.AsyncClient o httpx.Client fuera de egress.py."""
    src_dir = Path(__file__).resolve().parents[1] / "src"
    violations: list[str] = []

    for py_path in sorted(src_dir.rglob("*.py")):
        if py_path.name == "egress.py":
            continue
        tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "httpx":
                    name = f"httpx.{func.attr}"
                if name in ("httpx.AsyncClient", "httpx.Client"):
                    violations.append(f"{py_path.name}:{node.lineno} -> {name}")

    assert not violations, "Se detectaron llamadas directas a clientes httpx fuera de egress.py:\n" + "\n".join(
        violations
    )


# 2. ALLOWLIST Y RECHAZO POR DEFECTO
def test_egress_policy_bloquea_hosts_no_autorizados() -> None:
    policy = EgressPolicy()
    ok, reason = policy.validate_request("GET", "https://unauthorized-domain.com/data")
    assert not ok
    assert "HOST_NOT_ALLOWED" in reason

    # Proveedor permitido
    ok_prov, reason_prov = policy.validate_request("GET", "https://api.certspotter.com/v1/issuances")
    assert ok_prov
    assert reason_prov == "ALLOWED"


def test_egress_policy_bloquea_esquemas_y_http_inseguro() -> None:
    policy = EgressPolicy()
    # HTTP hacia proveedor remoto bloqueado
    ok_http, reason_http = policy.validate_request("GET", "http://api.certspotter.com/v1/issuances")
    assert not ok_http
    assert "INSECURE_HTTP_BLOCKED" in reason_http

    # HTTP hacia loopback permitido
    ok_local, _ = policy.validate_request("GET", "http://127.0.0.1:8000/api/status")
    assert ok_local

    # Esquemas no soportados (ftp, file, etc.)
    ok_ftp, reason_ftp = policy.validate_request("GET", "ftp://api.certspotter.com/file")
    assert not ok_ftp
    assert "SCHEME_NOT_ALLOWED" in reason_ftp


def test_egress_policy_bloquea_ips_literales_externas() -> None:
    policy = EgressPolicy()
    ok, reason = policy.validate_request("GET", "https://93.184.216.34/resource")
    assert not ok
    assert "LITERAL_IP_BLOCKED" in reason


def test_egress_policy_bloquea_tlds_especiales() -> None:
    policy = EgressPolicy()
    for tld in ("onion", "local", "test", "internal", "example"):
        ok, reason = policy.validate_request("GET", f"https://target-service.{tld}/api")
        assert not ok
        assert "SPECIAL_TLD_BLOCKED" in reason


# 3. PERÍMETRO INTOCABLE (SCOPE)
def test_egress_policy_bloquea_perimetro_intocable() -> None:
    policy = EgressPolicy()
    scope = Scope(
        case_id="case_001",
        domains={"targetcorp.com"},
        ips={"198.51.100.25"},
    )

    # Dominio del objetivo
    ok_dom, reason_dom = policy.validate_request("GET", "https://targetcorp.com/api", scope=scope)
    assert not ok_dom
    assert "PERIMETER_UNTOUCHABLE" in reason_dom

    # Subdominio del objetivo
    ok_sub, reason_sub = policy.validate_request("GET", "https://vpn.targetcorp.com/login", scope=scope)
    assert not ok_sub
    assert "PERIMETER_UNTOUCHABLE" in reason_sub


# 4. LISTA NEGRA DE ENDPOINTS (§4.3)
def test_egress_policy_bloquea_endpoints_lista_negra() -> None:
    policy = EgressPolicy()

    # VirusTotal bloqueado entero
    ok_vt, r_vt = policy.validate_request("GET", "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1")
    assert not ok_vt
    assert "HOST_BLACKLISTED" in r_vt

    # Shodan scan en vivo
    ok_sh, r_sh = policy.validate_request("POST", "https://api.shodan.io/shodan/scan")
    assert not ok_sh
    assert "ENDPOINT_BLACKLISTED" in r_sh

    # Censys Rescan
    ok_cs, r_cs = policy.validate_request("POST", "https://search.censys.io/v2/hosts/rescan")
    assert not ok_cs
    assert "ENDPOINT_BLACKLISTED" in r_cs

    # urlscan scan
    ok_us, r_us = policy.validate_request("POST", "https://urlscan.io/api/v1/scan/")
    assert not ok_us
    assert "ENDPOINT_BLACKLISTED" in r_us

    # OTX submit
    ok_otx, r_otx = policy.validate_request("POST", "https://otx.alienvault.com/api/v1/indicators/submit")
    assert not ok_otx
    assert "ENDPOINT_BLACKLISTED" in r_otx

    # Hunter email-verifier
    ok_h, r_h = policy.validate_request("GET", "https://api.hunter.io/v2/email-verifier?email=a@b.com")
    assert not ok_h
    assert "ENDPOINT_BLACKLISTED" in r_h

    # HackerTarget: solo hostsearch y reverseiplookup permitidos
    ok_ht_good, _ = policy.validate_request("GET", "https://api.hackertarget.com/hostsearch/?q=example.com")
    assert ok_ht_good

    ok_ht_nmap, r_ht_nmap = policy.validate_request("GET", "https://api.hackertarget.com/nmap/?q=example.com")
    assert not ok_ht_nmap
    assert "HACKERTARGET_TOOL_BLOCKED" in r_ht_nmap


# 5. AUDIT LOG ENCADENADO
@pytest.mark.asyncio
async def test_audit_log_encadenado_criptograficamente(tmp_path: Path) -> None:
    log_file = tmp_path / "egress_audit.jsonl"
    audit = AuditLog(log_file)

    rec1 = await audit.record(
        case_id="case_a",
        decision="allowed",
        reason="ALLOWED",
        method="GET",
        url="https://crt.sh/?q=example.com",
        status_code=200,
        response_sha256="abc123hash",
        egress_profile="direct",
    )
    assert rec1["seq"] == 1
    assert rec1["prev_hash"] == "0" * 64
    assert len(rec1["record_hash"]) == 64

    rec2 = await audit.record(
        case_id="case_a",
        decision="blocked",
        reason="HOST_NOT_ALLOWED",
        method="GET",
        url="https://evil.com/api?api_key=SECRET_TOKEN_XYZ",
        status_code=None,
        response_sha256="",
        egress_profile="direct",
    )
    assert rec2["seq"] == 2
    assert rec2["prev_hash"] == rec1["record_hash"]
    assert "SECRET_TOKEN_XYZ" not in rec2["url_masked"]
    assert "api_key=***" in rec2["url_masked"]

    # Verificación de integridad
    ok, msg = AuditLog.verify_file(log_file)
    assert ok
    assert "2 registros verificados" in msg

    # Manipulación deliberada para comprobar detección de sabotaje
    raw_lines = log_file.read_text(encoding="utf-8").splitlines()
    tampered_entry = json.loads(raw_lines[0])
    tampered_entry["reason"] = "TAMPERED_REASON"
    raw_lines[0] = json.dumps(tampered_entry)
    log_file.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")

    tampered_ok, tampered_msg = AuditLog.verify_file(log_file)
    assert not tampered_ok
    assert "Firma inválida" in tampered_msg


# 6. ENMASCARAMIENTO DE SECRETOS EN AUDIT LOG
def test_mask_url_secrets() -> None:
    url = "https://api.hunter.io/v2/domain-search?domain=test.com&api_key=super_secret_12345&limit=10"
    masked = mask_url_secrets(url)
    assert "super_secret_12345" not in masked
    assert "api_key=***" in masked
    assert "domain=test.com" in masked
    assert "limit=10" in masked


# 7. GUARDED TRANSPORT Y KILL-SWITCH
@pytest.mark.asyncio
async def test_guarded_transport_bloquea_y_registra(tmp_path: Path) -> None:
    log_file = tmp_path / "audit_test.jsonl"
    mock_trans = httpx.MockTransport(lambda r: httpx.Response(200, text="OK"))
    audit = AuditLog(log_path=log_file)
    policy = EgressPolicy()
    guarded = GuardedTransport(mock_trans, policy, audit_log=audit, profile="direct")

    client = httpx.AsyncClient(transport=guarded)
    async with client:
        # Permitido
        resp = await client.get("https://crt.sh/?q=test.com")
        assert resp.status_code == 200
        assert resp.text == "OK"

        # Bloqueado
        with pytest.raises(EgressBlockedError) as exc_info:
            await client.get("https://forbidden-target.com/")
        assert "HOST_NOT_ALLOWED" in str(exc_info.value)

    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").strip().splitlines()]
    assert len(lines) == 2
    assert lines[0]["decision"] == "allowed"
    assert lines[0]["response_sha256"] == hashlib.sha256(b"OK").hexdigest()
    assert lines[1]["decision"] == "blocked"


@pytest.mark.asyncio
async def test_guarded_transport_kill_switch_en_tor() -> None:
    def failing_handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Proxy SOCKS caído", request=req)

    mock_trans = httpx.MockTransport(failing_handler)
    policy = EgressPolicy()
    guarded = GuardedTransport(mock_trans, policy, profile="tor")

    client = httpx.AsyncClient(transport=guarded)
    async with client:
        with pytest.raises(EgressKillSwitchError) as exc_info:
            await client.get("https://crt.sh/?q=test.com")
        assert "kill-switch activado" in str(exc_info.value)


# 8. GET FOLLOWING (REDIRECCIONES SEGURAS)
@pytest.mark.asyncio
async def test_get_following_valida_saltos_y_detecta_bucles() -> None:
    def redirect_router(req: httpx.Request) -> httpx.Response:
        if req.url == "https://crt.sh/step1":
            return httpx.Response(302, headers={"Location": "https://crt.sh/step2"})
        if req.url == "https://crt.sh/step2":
            return httpx.Response(200, text="DESTINO_SEGURO")
        if req.url == "https://crt.sh/loop1":
            return httpx.Response(302, headers={"Location": "https://crt.sh/loop2"})
        if req.url == "https://crt.sh/loop2":
            return httpx.Response(302, headers={"Location": "https://crt.sh/loop1"})
        if req.url == "https://crt.sh/evil_redirect":
            return httpx.Response(302, headers={"Location": "https://unauthorized-evil.com/leak"})
        return httpx.Response(404)

    client = create_egress_client(transport=httpx.MockTransport(redirect_router))
    async with client:
        # Salto seguro válido
        resp = await get_following(client, "https://crt.sh/step1")
        assert resp.status_code == 200
        assert resp.text == "DESTINO_SEGURO"

        # Bucle de redirección
        with pytest.raises(EgressBlockedError, match="Bucle de redirección"):
            await get_following(client, "https://crt.sh/loop1")

        # Redirección hacia host no autorizado
        with pytest.raises(EgressBlockedError, match="HOST_NOT_ALLOWED"):
            await get_following(client, "https://crt.sh/evil_redirect")


# 9. TOR SOCKS CREDENTIALS INJECTION (CIRCUIT ISOLATION)
def test_inject_socks_auth() -> None:
    base = "socks5h://127.0.0.1:9050"
    injected = inject_socks_auth(base, "provider_hackertarget", "pass123")
    assert injected == "socks5h://provider_hackertarget:pass123@127.0.0.1:9050"


# 10. ROTACIÓN DE CIRCUITO TOR VIA PUERTO DE CONTROL
def test_rotate_tor_circuit_newnym_simulado() -> None:
    # Levantar un servidor socket local simulando Tor Control Port (9051)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    def mock_tor_control():
        conn, _ = server_sock.accept()
        try:
            d1 = conn.recv(1024)
            if b"AUTHENTICATE" in d1:
                conn.sendall(b"250 OK\r\n")
            d2 = conn.recv(1024)
            if b"SIGNAL NEWNYM" in d2:
                conn.sendall(b"250 OK\r\n")
        finally:
            conn.close()
            server_sock.close()

    t = threading.Thread(target=mock_tor_control, daemon=True)
    t.start()

    ok, msg = rotate_tor_circuit_newnym("127.0.0.1", port, password="test")
    assert ok
    assert "Circuito Tor rotado con éxito" in msg


# 11. PLUGINS: CWD DESHABILITADO POR DEFECTO
def test_plugins_cwd_deshabilitado_por_defecto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MALTEGO_MCP_PLUGINS_CWD", raising=False)
    dirs = get_default_plugin_dirs()
    assert not any(d.resolve() == (Path.cwd() / "plugins").resolve() for d in dirs)

    # Con flag activo se incluye si existe
    fake_plugins = tmp_path / "plugins"
    fake_plugins.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MALTEGO_MCP_PLUGINS_CWD", "1")
    dirs_with_flag = get_default_plugin_dirs()
    assert any(d.resolve() == fake_plugins.resolve() for d in dirs_with_flag)


# 12. ANTI-REBINDING SIN TOCTOU, SIN FUGAS DNS Y GUARDIÁN PEP 578 (S1)
class _RecordingBackend(httpcore.AsyncNetworkBackend):
    """Backend interno falso: registra a qué IP se conectaría y no abre ningún socket (tests sin red)."""

    def __init__(self) -> None:
        self.connected: list[tuple[str, int]] = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # type: ignore[no-untyped-def]
        self.connected.append((host, port))
        raise httpcore.ConnectError("conexión simulada en test")

    async def sleep(self, seconds: float) -> None:
        return None


def _fake_dns(monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[list[str]]]) -> list[tuple[str, str]]:
    """Sustituye socket.getaddrinfo. ``answers``: por host, respuestas sucesivas (la última se repite).
    Devuelve la lista de llamadas (host, hilo)."""
    calls: list[tuple[str, str]] = []
    pending = {h: [list(r) for r in v] for h, v in answers.items()}

    def fake_getaddrinfo(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        h = host.decode() if isinstance(host, bytes) else str(host)
        calls.append((h, threading.current_thread().name))
        responses = pending.get(h)
        if not responses:
            raise socket.gaierror(-2, f"host desconocido en test: {h}")
        ips = responses.pop(0) if len(responses) > 1 else responses[0]
        p = port if isinstance(port, int) else 443
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p)) for ip in ips]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return calls


def test_politica_no_resuelve_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """La política es síncrona y no conoce el perfil: nunca debe resolver DNS (evita fugas bajo Tor/VPN)."""
    calls = _fake_dns(monkeypatch, {})
    ok, reason = EgressPolicy().validate_request("GET", "https://crt.sh/?q=example.com")
    assert ok and reason == "ALLOWED"
    assert calls == []


@pytest.mark.asyncio
async def test_perfil_tor_no_resuelve_destino_en_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regresión de la fuga DNS demostrada: con perfil tor el destino lo resuelve el proxy, nunca el sistema."""
    calls = _fake_dns(monkeypatch, {"crt.sh": [["93.184.216.34"]]})
    mock = httpx.MockTransport(lambda r: httpx.Response(200, text="OK"))
    async with create_egress_client(settings=Settings(egress="tor", data_file=None), transport=mock) as client:
        resp = await client.get("https://crt.sh/?q=example.com")
    assert resp.status_code == 200
    assert [c for c in calls if c[0] == "crt.sh"] == []


@pytest.mark.asyncio
async def test_perfil_tor_sin_pin_local() -> None:
    """Con proxy SOCKS el pool no lleva PinnedDNSBackend (la resolución es remota, en el proxy)."""
    pytest.importorskip("socksio")
    async with create_egress_client(settings=Settings(egress="tor", data_file=None)) as client:
        pool = client._transport._underlying._pool  # type: ignore[attr-defined]
        assert not isinstance(pool._network_backend, PinnedDNSBackend)


@pytest.mark.asyncio
async def test_pin_resuelve_una_vez_fuera_del_loop_y_conecta_a_esa_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sin TOCTOU: una única resolución (en el executor) y la conexión va a esa IP aunque el DNS cambie después."""
    calls = _fake_dns(monkeypatch, {"crt.sh": [["93.184.216.34"], ["127.0.0.1"]]})  # 2ª respuesta = rebinding
    inner = _RecordingBackend()
    with pytest.raises(httpcore.ConnectError):
        await PinnedDNSBackend(inner).connect_tcp("crt.sh", 443)
    assert [c[0] for c in calls] == ["crt.sh"]
    assert calls[0][1] != threading.current_thread().name  # no bloquea el hilo del event loop
    assert inner.connected == [("93.184.216.34", 443)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [["169.254.169.254"], ["10.0.0.7"], ["93.184.216.34", "192.168.1.5"], ["100.64.0.1"], ["::ffff:10.0.0.1"]],
)
async def test_rebinding_a_ip_no_publica_se_bloquea(monkeypatch: pytest.MonkeyPatch, answer: list[str]) -> None:
    _fake_dns(monkeypatch, {"crt.sh": [answer]})
    inner = _RecordingBackend()
    with pytest.raises(EgressBlockedError, match="REBIND_BLOCKED"):
        await PinnedDNSBackend(inner).connect_tcp("crt.sh", 443)
    assert inner.connected == []


@pytest.mark.asyncio
async def test_host_de_confianza_admite_ip_privada_y_literales(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _fake_dns(monkeypatch, {"trx.miempresa.local": [["10.0.0.5"]], "localhost": [["93.184.216.34"]]})
    inner = _RecordingBackend()
    backend = PinnedDNSBackend(inner, trusted_hosts={"TRX.MiEmpresa.local."})
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("trx.miempresa.local", 8443)  # servidor propio declarado: IP privada admitida
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("127.0.0.1", 8080)  # literal loopback: sin consulta DNS
    with pytest.raises(EgressBlockedError, match="REBIND_BLOCKED"):
        await backend.connect_tcp("10.9.9.9", 80)  # literal privado no declarado
    with pytest.raises(EgressBlockedError, match="REBIND_BLOCKED"):
        await backend.connect_tcp("localhost", 80)  # localhost debe resolver a loopback
    assert inner.connected == [("10.0.0.5", 8443), ("127.0.0.1", 8080)]
    assert [c[0] for c in calls] == ["trx.miempresa.local", "localhost"]


@pytest.mark.asyncio
async def test_cliente_directo_lleva_pin_y_bloquea_rebinding_de_extremo_a_extremo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _fake_dns(monkeypatch, {"crt.sh": [["10.1.2.3"]]})
    log_file = tmp_path / "audit.jsonl"
    async with create_egress_client(settings=Settings(data_file=None), audit_log=AuditLog(log_file)) as client:
        pool = client._transport._underlying._pool  # type: ignore[attr-defined]
        assert isinstance(pool._network_backend, PinnedDNSBackend)  # si httpx cambia su interna, avisa aquí
        with pytest.raises(EgressBlockedError, match="REBIND_BLOCKED"):
            await client.get("https://crt.sh/?q=example.com")
    assert [c[0] for c in calls] == ["crt.sh"]
    last = json.loads(log_file.read_text(encoding="utf-8").splitlines()[-1])
    assert last["decision"] == "blocked" and "REBIND_BLOCKED" in last["reason"]


def test_guardian_pep578_decision() -> None:
    assert dns_lookup_allowed("crt.sh") and dns_lookup_allowed(b"crt.sh")
    assert dns_lookup_allowed("169.254.169.254")  # literal: no genera consulta DNS
    assert dns_lookup_allowed("::1") and dns_lookup_allowed("localhost") and dns_lookup_allowed(None)
    assert not dns_lookup_allowed("cuenta-test-s1.gremlin.cosmos.azure.com")
    register_egress_hosts(["Cuenta-Test-S1.Gremlin.Cosmos.Azure.com."])
    assert dns_lookup_allowed("cuenta-test-s1.gremlin.cosmos.azure.com")


def test_guardian_pep578_solo_desde_main_y_bloquea_en_subproceso(tmp_path: Path) -> None:
    """El hook es global e irreversible: se prueba en un subproceso. create_server() no debe instalarlo."""
    code = textwrap.dedent(
        """
        import socket
        from maltego_mcp import egress
        from maltego_mcp.server import create_server
        create_server()
        print("R instalado_tras_create_server", egress.is_egress_audit_hook_installed())
        egress.install_egress_audit_hook()
        print("R instalado", egress.is_egress_audit_hook_installed())
        try:
            socket.getaddrinfo("no-registrado.example.invalid", 443)  # el hook aborta ANTES de consultar DNS
            print("R no_registrado PERMITIDO")
        except PermissionError:
            print("R no_registrado BLOQUEADO")
        socket.getaddrinfo("192.0.2.10", 443)  # literal: sin consulta DNS
        print("R literal PERMITIDO")
        """
    )
    env = {**os.environ, "MALTEGO_MCP_HOME": str(tmp_path)}
    env.pop("MALTEGO_MCP_DISABLE_PEP578", None)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=180)
    assert out.returncode == 0, out.stderr[-2000:]
    got = dict(line[2:].split(" ", 1) for line in out.stdout.splitlines() if line.startswith("R "))
    assert got == {
        "instalado_tras_create_server": "False",
        "instalado": "True",
        "no_registrado": "BLOQUEADO",
        "literal": "PERMITIDO",
    }


# 13. AUDITORÍA DEL CUERPO SIN PRECARGA (S11)
@pytest.mark.asyncio
async def test_s11_cuerpo_no_se_precarga_y_hash_parcial_vacio(tmp_path: Path) -> None:
    produced: list[int] = []

    async def body():  # type: ignore[no-untyped-def]
        for i in range(50):
            produced.append(i)
            yield b"x" * 65536

    mock = httpx.MockTransport(lambda r: httpx.Response(200, content=body()))
    log_file = tmp_path / "audit.jsonl"
    guarded = GuardedTransport(mock, EgressPolicy(), audit_log=AuditLog(log_file))
    async with httpx.AsyncClient(transport=guarded) as client, client.stream("GET", "https://crt.sh/") as resp:
        async for _chunk in resp.aiter_raw():
            break
    assert len(produced) < 50  # el transporte no leyó el cuerpo por su cuenta
    last = json.loads(log_file.read_text(encoding="utf-8").splitlines()[-1])
    assert last["decision"] == "allowed" and last["response_sha256"] == ""  # lectura parcial: sin hash


@pytest.mark.asyncio
async def test_s11_tope_5mb_del_cliente_trx_corta_sin_leer_todo(tmp_path: Path) -> None:
    from maltego_mcp.transforms.client import run_remote_transform

    produced: list[int] = []
    total = 120  # 120 x 64 KiB = 7,5 MiB

    async def body():  # type: ignore[no-untyped-def]
        for i in range(total):
            produced.append(i)
            yield b"<" * 65536

    mock = httpx.MockTransport(lambda r: httpx.Response(200, content=body()))
    guarded = GuardedTransport(mock, EgressPolicy(), audit_log=AuditLog(tmp_path / "audit.jsonl"))
    server = SimpleNamespace(name="trx-test", url="http://127.0.0.1:9/", timeout_s=5.0, headers=lambda env=None: {})
    spec = SimpleNamespace(settings={}, server=server, run_url="http://127.0.0.1:9/run/x", name="X", path="x")
    async with httpx.AsyncClient(transport=guarded) as client:
        with pytest.raises(TransformError, match="5 MB"):
            await run_remote_transform(spec, "maltego.Domain", "example.com", http=client)  # type: ignore[arg-type]
    assert len(produced) < total  # el tope corta sin haber leído los 7,5 MiB
