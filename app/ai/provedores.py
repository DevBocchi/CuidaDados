"""Clientes HTTP dos LLMs (Parte 3): OpenAI e Gemini, via REST (sem SDK).

A chave vai SEMPRE em header, nunca na URL: o httpx registra a URL de cada requisição
em log, e uma chave na URL vazaria para o log. Mensagens de erro do httpx também não
são repassadas, só o motivo curto.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

import httpx

OPENAI_URL = "https://api.openai.com/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{modelo}:generateContent"


@dataclass(frozen=True)
class Config:
    provedor: str
    chave: str
    modelo: str
    timeout: float

    @property
    def pronta(self) -> bool:
        return self.provedor in ("openai", "gemini") and bool(self.chave) and bool(self.modelo)


def carregar_config() -> Config:
    """Lê do ambiente a cada chamada (permite trocar sem reiniciar e facilita testes)."""
    return Config(
        provedor=os.getenv("LLM_PROVIDER", "").strip().lower(),
        chave=os.getenv("LLM_API_KEY", "").strip(),
        modelo=os.getenv("LLM_MODEL", "").strip(),
        timeout=float(os.getenv("LLM_TIMEOUT", "8")),
    )


class ErroLLM(Exception):
    """Falha ao falar com o LLM. `motivo` é curto e seguro para log."""

    def __init__(self, motivo: str, detalhe: str = ""):
        super().__init__(motivo)
        self.motivo = motivo
        self.detalhe = detalhe  # só código HTTP e palavra-chave do erro; nunca texto livre


def _detalhe_http(resp: httpx.Response) -> str:
    """Ex.: 'HTTP 429 RESOURCE_EXHAUSTED'. Só aceita uma palavra-chave curta do erro,
    para o diagnóstico ajudar sem arriscar copiar a chave ou outro texto para o log."""
    detalhe = f"HTTP {resp.status_code}"
    try:
        erro = resp.json().get("error", {})
        for campo in ("status", "code"):
            valor = erro.get(campo)
            if isinstance(valor, str) and re.fullmatch(r"[A-Za-z_]{3,40}", valor):
                return f"{detalhe} {valor}"
    except (ValueError, AttributeError):
        pass
    return detalhe


async def gerar_texto(prompt: str, config: Config, cliente: httpx.AsyncClient | None = None) -> str:
    if cliente is not None:
        return await _chamar(prompt, config, cliente)
    async with httpx.AsyncClient(timeout=config.timeout) as novo:
        return await _chamar(prompt, config, novo)


async def _chamar(prompt: str, config: Config, cliente: httpx.AsyncClient) -> str:
    try:
        if config.provedor == "openai":
            resp = await cliente.post(
                OPENAI_URL,
                headers={"Authorization": f"Bearer {config.chave}"},
                json={
                    "model": config.modelo,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_completion_tokens": 300,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

        resp = await cliente.post(
            GEMINI_URL.format(modelo=config.modelo),
            headers={"x-goog-api-key": config.chave},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 300},
            },
        )
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    except httpx.TimeoutException:
        raise ErroLLM("timeout") from None
    except httpx.HTTPStatusError as erro:
        raise ErroLLM("erro_http", _detalhe_http(erro.response)) from None
    except httpx.HTTPError:
        raise ErroLLM("erro_http") from None
    except (KeyError, IndexError, TypeError, ValueError):
        raise ErroLLM("resposta_invalida") from None
