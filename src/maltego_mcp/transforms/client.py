"""Cliente HTTP para servidores de transforms (maltego-trx, iTDS)."""

from __future__ import annotations

import logging

import httpx

from maltego_mcp.errors import TransformError
from maltego_mcp.transforms.catalog import TransformSpec
from maltego_mcp.transforms.protocol import TransformResponse, build_request, parse_response

logger = logging.getLogger(__name__)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


async def run_remote_transform(
    spec: TransformSpec,
    entity_type: str,
    value: str,
    properties: dict[str, str] | None = None,
    soft_limit: int = 12,
    http: httpx.AsyncClient | None = None,
) -> TransformResponse:
    body = build_request(entity_type, value, properties, spec.settings, soft_limit=soft_limit)
    headers = {"Content-Type": "application/xml", **spec.server.headers()}
    owns = http is None
    client = http or httpx.AsyncClient(timeout=spec.server.timeout_s, follow_redirects=False)
    try:
        async with client.stream("POST", spec.run_url, content=body, headers=headers) as resp:
            if resp.status_code == 404:
                raise TransformError(
                    f"El servidor '{spec.server.name}' no tiene el transform '{spec.path}'. "
                    "Revisa el path en el catálogo (maltego-trx usa el nombre en minúsculas, '_' -> '-')."
                )
            if resp.status_code in (401, 403):
                raise TransformError(f"El servidor '{spec.server.name}' rechazó la autenticación ({resp.status_code}).")
            if resp.status_code != 200:
                raise TransformError(f"El servidor '{spec.server.name}' respondió HTTP {resp.status_code}.")
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise TransformError("La respuesta del transform supera 5 MB; reduce soft_limit.")
                chunks.append(chunk)
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        # En Windows, conectar a un puerto cerrado tarda ~2 s en fallar y puede llegar como ConnectTimeout.
        raise TransformError(
            f"No se pudo contactar con el servidor de transforms '{spec.server.name}' ({spec.server.url}). "
            "¿Está arrancado?"
        ) from exc
    except httpx.TimeoutException as exc:
        raise TransformError(
            f"El transform '{spec.name}' superó el tiempo máximo ({spec.server.timeout_s:.0f}s). "
            "Prueba con un soft_limit menor o aumenta timeout_s en el catálogo."
        ) from exc
    except httpx.HTTPError as exc:
        logger.warning("Error HTTP con %s: %s", spec.server.name, exc.__class__.__name__)
        raise TransformError(
            f"No se pudo contactar con el servidor de transforms '{spec.server.name}'. ¿Está arrancado?"
        ) from exc
    finally:
        if owns:
            await client.aclose()
    return parse_response(b"".join(chunks))
