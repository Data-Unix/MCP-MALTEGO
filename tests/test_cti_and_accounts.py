"""Tests de sincronización viva con fastfire/deepdarkCTI, bóveda de cuentas/Sock Puppets y nuevos transforms."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from mcp import Client

from maltego_mcp.accounts import (
    ensure_accounts_template,
    generate_sockpuppet_persona,
    load_account_pool,
    save_persona_to_accounts_toml,
)
from maltego_mcp.cli import main as cli_main
from maltego_mcp.config import Settings
from maltego_mcp.cti_feeds import (
    apply_feed_snapshot,
    ensure_seed_cti_db,
    parse_deepdark_markdown,
    search_cti_feeds,
    sync_deepdark_cti,
)
from maltego_mcp.server import create_server
from maltego_mcp.transforms.builtin import BUILTIN_TRANSFORMS, BuiltinContext, new_http_client
from tests.test_builtin import KEYS, Router


def _t(name: str):  # type: ignore[no-untyped-def]
    return next(b for b in BUILTIN_TRANSFORMS if b.name == name)


def test_parse_deepdark_markdown_keeps_only_active_and_purges_offline(tmp_path: Path) -> None:
    """Verifica que solo se indexan filas ONLINE/VALID y que al pasar a OFFLINE se purgan automáticamente."""
    md_v1 = """
| Name | Status | Type | Description |
| --- | --- | --- | --- |
| [AlphaMarket](http://alphamarket2222222222222.onion) | ONLINE | Market | Active darknet market |
| [BetaForum](http://betaforum333333333333333.onion) | VALID | Forum | Active forum |
| [DeadSite](http://deadsite4444444444444444.onion) | OFFLINE | Market | Seized by LE |
| [ExpiredChan](https://t.me/expired_chan) | EXPIRED | Telegram | Old channel |
"""
    rows_v1 = parse_deepdark_markdown("markets.md", "market", md_v1)
    names_v1 = [r.name for r in rows_v1]
    assert "AlphaMarket" in names_v1
    assert "BetaForum" in names_v1
    assert "DeadSite" not in names_v1
    assert "ExpiredChan" not in names_v1

    db_path = ensure_seed_cti_db(tmp_path)
    inserted, _ = apply_feed_snapshot(db_path, "markets.md", "market", rows_v1)
    assert inserted == 2
    assert len(search_cti_feeds(tmp_path, "AlphaMarket")) == 1
    assert len(search_cti_feeds(tmp_path, "BetaForum")) == 1

    # Segunda sincronización: AlphaMarket pasa a OFFLINE y aparece GammaMarket como ONLINE
    md_v2 = """
| Name | Status | Type | Description |
| --- | --- | --- | --- |
| [AlphaMarket](http://alphamarket2222222222222.onion) | OFFLINE | Market | Down |
| [BetaForum](http://betaforum333333333333333.onion) | VALID | Forum | Active forum |
| [GammaMarket](http://gammamarket5555555555555.onion) | ONLINE | Market | New active market |
"""
    rows_v2 = parse_deepdark_markdown("markets.md", "market", md_v2)
    inserted_v2, purged_v2 = apply_feed_snapshot(db_path, "markets.md", "market", rows_v2)
    assert inserted_v2 == 2
    assert purged_v2 == 2
    assert search_cti_feeds(tmp_path, "AlphaMarket") == []
    assert len(search_cti_feeds(tmp_path, "GammaMarket")) == 1


async def test_sync_deepdark_cti_live_with_mock_http(tmp_path: Path) -> None:
    """Verifica la sincronización completa contra raw.githubusercontent.com/fastfire/deepdarkCTI."""
    router = Router()
    async with new_http_client(transport=httpx.MockTransport(router)) as http:
        res = await sync_deepdark_cti(tmp_path, http, force=True)
    assert res["updated"] is True
    assert res["active_rows"] >= 1
    hits = search_cti_feeds(tmp_path, "BreachForums")
    assert hits and hits[0].status == "ONLINE"
    assert search_cti_feeds(tmp_path, "OldDeadMarket") == []


def test_account_pool_rotation_cooldown_and_masking(tmp_path: Path) -> None:
    """Verifica carga de cuentas desde accounts.toml + env, rotación round-robin, cooldown 429 y enmascarado."""
    acc_file = ensure_accounts_template(tmp_path)
    acc_file.write_text(
        """
[[accounts]]
platform = "github"
username = "puppet_gh_1"
token = "ghp_secret1111111111"
enabled = true

[[accounts]]
platform = "github"
username = "puppet_gh_2"
token = "ghp_secret2222222222"
enabled = true

[[accounts]]
platform = "onion"
username = "dark_buyer_99"
site = "breachforums222222222222.onion"
cookie = "xf_user=secretcookie999"
enabled = true
""",
        encoding="utf-8",
    )
    pool = load_account_pool(tmp_path, {})
    a1 = pool.acquire("github")
    a2 = pool.acquire("github")
    assert a1 is not None and a2 is not None
    assert {a1.username, a2.username} == {"puppet_gh_1", "puppet_gh_2"}

    # Si marcamos a1 con HTTP 429, solo debe devolver la otra cuenta disponible
    pool.mark_rate_limited(a1, cooldown_seconds=600)
    a3 = pool.acquire("github")
    assert a3 is not None and a3.username == a2.username

    # Cabeceras para sitio .onion específico
    onion_acct = pool.acquire("onion", site="breachforums222222222222.onion")
    assert onion_acct is not None
    headers = pool.auth_headers(onion_acct)
    assert "xf_user=secretcookie999" in headers.get("Cookie", "")

    # Enmascarado seguro en summary()
    summary_str = json.dumps(pool.summary())
    assert "ghp_secret1111111111" not in summary_str
    assert "secretcookie999" not in summary_str


def test_sockpuppet_persona_generator_and_save(tmp_path: Path) -> None:
    """Verifica la generación determinista de kits operativos de Sock Puppet y guardado en accounts.toml."""
    p1 = generate_sockpuppet_persona(
        role="threat_intel_collector",
        region="EE",
        target_site="exploit.in",
        seed="op-001",
    )
    p2 = generate_sockpuppet_persona(
        role="threat_intel_collector",
        region="EE",
        target_site="exploit.in",
        seed="op-001",
    )
    assert p1.handle == p2.handle
    assert len(p1.totp_secret_base32) == 32
    assert p1.opsec_checklist
    saved_path = save_persona_to_accounts_toml(tmp_path, p1)
    assert saved_path.exists()
    assert p1.handle in saved_path.read_text(encoding="utf-8")


async def test_six_new_transforms_and_darkweb_footprint_machine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifica los 6 nuevos transforms integrados y la Machine DarkWebFootprint."""
    monkeypatch.setenv("MALTEGO_MCP_HOME", str(tmp_path))
    router = Router()
    env = {**KEYS, "MALTEGO_MCP_HOME": str(tmp_path)}
    ctx = BuiltinContext(new_http_client(transport=httpx.MockTransport(router)), env)

    # 1. HudsonRockStealerCheck
    hr = await _t("HudsonRockStealerCheck").handler(ctx, "maltego.Domain", "infected.org", {}, 10)
    assert any(e.link_label == "compromised_by_stealer" for e in hr.entities)
    assert any(e.value == "198.51.100.42" for e in hr.entities)

    # 2. DeepDarkCTISearch
    dd = await _t("DeepDarkCTISearch").handler(ctx, "maltego.Domain", "breachforums", {}, 20)
    vals = [e.value for e in dd.entities]
    assert any("BreachForums" in v for v in vals)
    assert any("lockbit3" in v for v in vals)
    assert any(v.endswith(".onion") for v in vals)

    # 3. OnionPassivePivot (extracción recursiva estilo TorCrawl)
    op = await _t("OnionPassivePivot").handler(ctx, "maltego.Website", "breachforums222222222222.onion", {}, 20)
    op_types = {e.entity_type for e in op.entities}
    assert "maltego.CryptocurrencyAddress" in op_types
    assert "maltego.EmailAddress" in op_types
    assert "maltego.Affiliation" in op_types
    assert any(e.value == "mirroronion5555555555555.onion" for e in op.entities)

    # 4. KeybaseAliasToProofs
    kb = await _t("KeybaseAliasToProofs").handler(ctx, "maltego.Alias", "kproof", {}, 20)
    assert any(e.value == "kproof.org" and e.entity_type == "maltego.Domain" for e in kb.entities)
    assert any(e.value == "kproof_gh" and e.entity_type == "humint.Alias" for e in kb.entities)
    assert any(e.entity_type == "maltego.CryptocurrencyAddress" for e in kb.entities)

    # 5. SocialAliasDeepRecon
    sa = await _t("SocialAliasDeepRecon").handler(ctx, "maltego.Alias", "jdoe", {}, 20)
    nets = {e.properties.get("affiliation.network") for e in sa.entities if e.entity_type == "maltego.Affiliation"}
    assert {"Reddit", "HackerNews", "Lobsters", "Bluesky"}.issubset(nets)
    assert any(e.value == "alice_sec" and e.link_label == "invited_by" for e in sa.entities)

    # 6. GitHubAliasToCommitEmails
    gh = await _t("GitHubAliasToCommitEmails").handler(ctx, "maltego.Alias", "jdoe", {}, 20)
    assert any(e.value == "jdoe.commits@example.com" and e.entity_type == "maltego.EmailAddress" for e in gh.entities)


async def test_mcp_tool_generate_persona_and_cli_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifica action='generate_persona' en osint_manage_entity y comandos CLI de maltegoctl."""
    monkeypatch.setenv("MALTEGO_MCP_HOME", str(tmp_path))
    settings = Settings(
        backend="memory",
        home=tmp_path,
        export_dir=tmp_path / "exports",
        import_dir=tmp_path / "imports",
    )
    async with Client(create_server(settings)) as client:
        res = await client.call_tool(
            "osint_manage_entity",
            {
                "case_id": "caso-puppet",
                "entity_id": "seed-01",
                "action": "generate_persona",
                "properties": ["role=security_researcher", "region=EU", "site=xss.is", "save=true"],
                "response_format": "json",
            },
        )
        payload = json.loads(res.content[0].text)
        assert payload["entity"]["maltego_type"] == "humint.Alias"
        assert payload["persona"]["role"] == "security_researcher"
        assert Path(payload["saved_accounts_toml"]).exists()

    assert cli_main(["accounts", "list"]) == 0
    assert cli_main(["accounts", "generate-persona", "--role", "journalist", "--save"]) == 0
