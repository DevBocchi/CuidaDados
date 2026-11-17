"""Dependência FastAPI que entrega o corpo da requisição já marcado (SOURCE)."""
from typing import Any

from fastapi import Request

from .sensitive import marcar


async def corpo_marcado(request: Request) -> Any:
    """Uso: `corpo: Any = Depends(corpo_marcado)`. Valores sensíveis chegam como Sensitive."""
    try:
        dados = await request.json()
    except Exception:
        return None
    return marcar(dados)
