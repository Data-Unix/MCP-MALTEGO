"""Errores de red del cliente de transforms, independientes del sistema operativo."""

import httpx
import pytest

from maltego_mcp.errors import TransformError
from maltego_mcp.transforms.catalog import TransformServer, TransformSpec
from maltego_mcp.transforms.client import run_remote_transform

SPEC = TransformSpec("T", TransformServer("srv", "http://127.0.0.1:9", timeout_s=1), "t", ())


def _raising(exc: Exception) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("exc", "fragment"),
    [
        (httpx.ConnectError("refused"), "¿Está arrancado?"),
        (httpx.ConnectTimeout("connect timeout"), "¿Está arrancado?"),  # comportamiento típico de Windows
        (httpx.ReadTimeout("read timeout"), "tiempo máximo"),
        (httpx.RemoteProtocolError("bad"), "¿Está arrancado?"),
    ],
)
async def test_errores_de_red(exc: Exception, fragment: str) -> None:
    with pytest.raises(TransformError, match=fragment.replace("?", r"\?")):
        await run_remote_transform(SPEC, "maltego.Domain", "a.com", http=_raising(exc))


async def test_respuesta_http_inesperada() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(TransformError, match="HTTP 500"):
        await run_remote_transform(SPEC, "maltego.Domain", "a.com", http=client)
