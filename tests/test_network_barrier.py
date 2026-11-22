"""Verificación de la barrera de aislamiento de red para tests."""

from __future__ import annotations

import socket

import pytest


def test_dns_bloqueado_para_hosts_externos() -> None:
    """Cualquier resolución DNS a hosts no permitidos (ej. example.com) debe ser bloqueada."""
    with pytest.raises(socket.gaierror, match="Resolución DNS externa bloqueada en tests"):
        socket.gethostbyname("example.com")

    with pytest.raises(socket.gaierror, match="Resolución DNS externa bloqueada en tests"):
        socket.gethostbyname_ex("example.com")

    with pytest.raises(socket.gaierror, match="Resolución DNS externa bloqueada en tests"):
        socket.getaddrinfo("example.com", 80)


def test_dns_ptr_bloqueado_para_hosts_externos() -> None:
    """La resolución DNS inversa (PTR) externa debe ser bloqueada en tests."""
    with pytest.raises(socket.herror, match="Resolución DNS inversa"):
        socket.gethostbyaddr("93.184.216.34")


def test_dns_permitido_para_localhost() -> None:
    """Localhost y loopback (127.0.0.1) deben resolverse para permitir los servidores de test."""
    assert socket.gethostbyname("127.0.0.1") == "127.0.0.1"
    info = socket.getaddrinfo("127.0.0.1", 80)
    assert len(info) > 0
