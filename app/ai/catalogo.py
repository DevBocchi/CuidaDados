"""Catálogo fixo de eventos de segurança e mensagens de reserva (Parte 3).

REGRA DE OURO: o LLM só recebe texto DESTE catálogo. Nada que veio do usuário (rota,
valores, caminhos, ids) entra no prompt. Isso impede que PII vá para a API externa
(seria o próprio vazamento que o módulo combate) e reduz prompt injection (PDF [02]).
"""
from __future__ import annotations

# Do mais grave para o menos grave.
ORDEM_AREAS = ("SENHA", "SAUDE", "CPF", "RG", "ESTRUTURA")

AREAS = {
    "SENHA": "sua senha",
    "SAUDE": "seus dados de saúde",
    "CPF": "seu CPF",
    "RG": "seu RG",
    "ESTRUTURA": "seus dados",
}

# descricao: falha técnica (entra no prompt) | acao: o que o sistema fez | reserva: texto
# de 2 frases usado quando o LLM não está disponível ou a resposta dele é rejeitada.
EVENTOS = {
    "RESPOSTA_BLOQUEADA": {
        "descricao": "Vazamento de dados pessoais bloqueado: o sistema ia enviar dados pessoais em uma resposta sem proteção",
        "acao": "bloqueou",
        "reserva": "O sistema ia mostrar {areas} em um lugar sem proteção, mas bloqueou a ação para proteger sua privacidade. Seus dados não foram expostos.",
    },
    "ENTRADA_REFLETIDA_BLOQUEADA": {
        "descricao": "Os dados digitados pelo usuário seriam repetidos numa mensagem de erro, e isso foi impedido",
        "acao": "bloqueou",
        "reserva": "Houve um erro ao enviar {areas}, e o sistema escondeu o que foi digitado da mensagem de erro. Assim, outras pessoas não conseguem ver essas informações.",
    },
    "LOG_SANITIZADO": {
        "descricao": "Dados pessoais iam ser gravados em texto claro no registro interno do sistema, e foram mascarados",
        "acao": "mascarou",
        "reserva": "O sistema ia guardar {areas} em um registro interno, mas escondeu essa informação antes. Seus dados ficaram protegidos.",
    },
    "ERRO_INTERNO": {
        "descricao": "Falha interna do sistema; os detalhes técnicos foram escondidos do usuário",
        "acao": "escondeu",
        "reserva": "O sistema teve um problema e escondeu os detalhes técnicos para sua segurança. Tente novamente mais tarde.",
    },
    "PII_EM_RESPOSTA_AUTENTICADA": {
        "descricao": "Dados pessoais foram entregues a um usuário que se identificou, e esse acesso ficou registrado",
        "acao": "registrou",
        "reserva": "O sistema entregou {areas} a uma pessoa que se identificou e registrou esse acesso. Isso é normal e fica guardado para conferência.",
    },
    "PII_RECEBIDA": {
        "descricao": "O sistema recebeu dados pessoais e os protegeu automaticamente",
        "acao": "protegeu",
        "reserva": "O sistema recebeu {areas} e já protegeu essas informações automaticamente. Você não precisa fazer nada.",
    },
}

DESCONHECIDO = {
    "descricao": "O sistema detectou uma situação incomum e agiu para proteger os dados",
    "acao": "protegeu",
    "reserva": "O sistema notou algo incomum e agiu para proteger {areas}. Se tiver dúvidas, procure o atendimento.",
}


def normalizar_evento(nome: str) -> str:
    """Só nomes conhecidos passam adiante; o resto vira DESCONHECIDO."""
    return nome if nome in EVENTOS else "DESCONHECIDO"


def dados_do_evento(nome: str) -> dict:
    return EVENTOS.get(nome, DESCONHECIDO)


def areas_do_evento(categorias) -> tuple[str, ...]:
    """Categorias conhecidas, da mais grave para a menos grave. Categorias estranhas somem."""
    conhecidas = [c for c in ORDEM_AREAS if c in set(categorias)]
    if len(conhecidas) > 1 and "ESTRUTURA" in conhecidas:
        conhecidas.remove("ESTRUTURA")  # "seus dados" é redundante ao lado de algo específico
    return tuple(conhecidas)


def humanizar(areas: tuple[str, ...]) -> str:
    nomes = [AREAS[a] for a in areas]
    if not nomes:
        return "seus dados"
    if len(nomes) == 1:
        return nomes[0]
    return ", ".join(nomes[:-1]) + " e " + nomes[-1]


def mensagem_reserva(nome: str, areas: tuple[str, ...]) -> str:
    return dados_do_evento(nome)["reserva"].format(areas=humanizar(areas))
