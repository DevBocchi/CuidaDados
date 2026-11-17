"""Autenticação mínima por Bearer token assinado, com expiração obrigatória.

Mesmo princípio do JWT do PDF [07]: payload sem segredo, assinatura HMAC-SHA256 e
`exp`. O segredo vem de APP_SECRET (.env). Sem ele, gera-se um segredo aleatório por
processo (tokens deixam de valer ao reiniciar), nunca um valor fixo no código.

Gerar um token de demonstração:  APP_SECRET=... python -m app.auth
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

_segredo_aleatorio: bytes | None = None


def _segredo() -> bytes:
    global _segredo_aleatorio
    valor = os.getenv("APP_SECRET")
    if valor:
        return valor.encode()
    if _segredo_aleatorio is None:
        _segredo_aleatorio = secrets.token_bytes(32)
    return _segredo_aleatorio


def _b64e(dados: bytes) -> str:
    return base64.urlsafe_b64encode(dados).rstrip(b"=").decode()


def _b64d(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def _assinar(parte: str) -> str:
    return _b64e(hmac.new(_segredo(), parte.encode(), hashlib.sha256).digest())


def emitir_token(usuario: str, ttl_segundos: int = 900) -> str:
    payload = _b64e(json.dumps({"sub": usuario, "exp": int(time.time()) + ttl_segundos}).encode())
    return f"{payload}.{_assinar(payload)}"


def validar_token(token: str) -> str | None:
    """Devolve o usuário se o token for válido e não expirado; senão None."""
    try:
        payload, assinatura = token.split(".")
        if not hmac.compare_digest(assinatura, _assinar(payload)):
            return None
        dados = json.loads(_b64d(payload))
        if int(dados["exp"]) <= time.time():
            return None
        return str(dados["sub"])
    except Exception:
        return None


if __name__ == "__main__":
    print(emitir_token("demo"))
