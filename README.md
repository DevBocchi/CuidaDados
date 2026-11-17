# CuidaDados — GS CitizenTech (Cybersecurity)

## Ficha da CitizenTech

| Campo | Conteúdo |
|---|---|
| Nome da CitizenTech | CuidaDados |
| Cidade e bairro | São Paulo (SP), bairro Belém |
| Cidadão beneficiado | Pessoa idosa (60+) que usa um assistente digital de saúde e benefícios e não é especialista em tecnologia |
| Problema, em uma frase | Idosos informam CPF, RG, senha e laudos em apps de saúde e benefícios, mas não entendem quando seus dados estão em risco. |
| Como funciona | O backend intercepta tudo que entra, identifica e protege dados pessoais (PII), impede que vazem por logs ou respostas sem login e traduz cada bloqueio, via IA, para uma mensagem simples e um farol de risco. |
| O que cada parte faz | Ver "Mapa da rubrica" abaixo. |
| Link do repositório | https://github.com/DevBocchi/CuidaDados |
| Indicador de impacto | **Risco Cidadão**: farol verde/amarelo/vermelho (0 a 100) calculado a partir dos eventos de segurança da última hora. |
| ODS conectados | ODS 3 (Saúde e bem-estar): protege dados de saúde. ODS 10 (Redução das desigualdades): linguagem simples para quem tem menos letramento digital. ODS 9 (Indústria, inovação e infraestrutura): segurança embutida na infraestrutura do serviço. |

**Integrantes:**

| Nome | RM |
|---|---|
| Rafael Bocchi | RM557603 |
| André Luiz Fernandes De Queiroz | RM554503 |
| Paulo Poças | RM556080 |
| Rafael Oliveira | RM554736 |
| Marcos Costas | RM555490 |

> Todos os dados deste projeto são **sintéticos**. Nenhum dado pessoal real foi usado.

## Como funciona (fluxo fonte → destino)

```
Requisição ──► PIIMiddleware ──► TaintMiddleware ──► rota ──► resposta
   (entrada)   Parte 1: acha PII    Parte 2: marca a PII      │
               e cria trace_id      como "contaminada"        ▼
                                                    SINKS (onde o dado pode vazar)
                                                    ├─ log      → mascarado
                                                    ├─ resposta → bloqueada se sem login (senha nunca sai)
                                                    └─ erro     → 422/500 sem eco do corpo, sem stack trace
                                         cada ação ──► auditoria (SQLite, sem valores)
                                                              │
                              Parte 4: Risco Cidadão ◄────────┘──► Parte 3: IA traduz o evento
                                       (/risco + /dashboard)        (o LLM só vê texto do catálogo)
```

## Como rodar

Requer Python 3.11 ou superior.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env
```

Edite o `.env`: defina `APP_SECRET` (texto longo e aleatório) e, para a demonstração, `MODO_DEMO=1`. O `.env` **não** é versionado.

```bash
python -m pytest -v                       # 83 testes (Partes 1 a 4)
python scripts/demo_taint.py              # evidência ANTES x DEPOIS (não precisa de servidor)
python scripts/demo_ia.py                 # prompt, mensagens e defesa contra saída maliciosa do LLM

uvicorn app.main:app --port 8000          # sobe o servidor
python -m app.auth                        # imprime um token de administrador (15 min)
# abra: http://127.0.0.1:8000/dashboard#token=COLE_O_TOKEN
python scripts/gerar_trafego.py normal    # em outro terminal: verde
python scripts/gerar_trafego.py amarelo   # 2 vazamentos de CPF bloqueados
python scripts/gerar_trafego.py vermelho  # + tentativas de vazar senha
```

Clique em "Atualizar agora" (ou aguarde 15 s) entre um cenário e outro.

**IA real (opcional):** preencha `LLM_PROVIDER` (`openai` ou `gemini`) e `LLM_API_KEY` no `.env`, rode `python scripts/listar_modelos.py` para ver os nomes de modelo que a sua chave aceita e copie um para `LLM_MODEL`. Depois, `python scripts/demo_ia.py` (seção 4) faz a chamada real. Sem isso o sistema usa mensagens de reserva e funciona igual.

## Mapa da rubrica

| Critério (pontos) | Onde está | Evidência |
|---|---|---|
| Parsing de PII (3,0) | `app/pii/` | `docs/evidencias/parte1_testes.txt` |
| Taint Analysis (3,0) | `app/taint/`, `app/audit/`, `app/auth.py` | `docs/evidencias/parte2_testes.txt`, `parte5_taint.txt` |
| IA para tradução (2,0) | `app/ai/` | `docs/evidencias/parte3_ia.txt`, `parte3_testes.txt` |
| Dashboard Risco Cidadão (2,0) | `app/risk/`, `dashboard/` | `docs/evidencias/parte4_dashboard_*.png` |

## Decisões técnicas

- **Linguagem:** Python com FastAPI. O módulo de segurança é um middleware, como o professor descreveu.
- **Parsing:** detecta por nome do campo (ex.: `documento`, `senha`, `laudo`) e por formato do valor (CPF, RG). O CPF sem pontuação só é aceito com dígitos verificadores válidos, para reduzir falso positivo. Falha para o lado seguro: na dúvida, mascara.
- **Taint Analysis:** `Sensitive` marca o dado na entrada (source); log, resposta e erro (sinks) são filtrados. Usuário não autenticado nunca recebe PII; autenticado recebe, com auditoria; **senha nunca sai**.
- **Auditoria:** SQLite + log JSON com `trace_id`, rota, tipo, categoria e gravidade. Nunca guarda o valor.
- **IA:** o LLM nunca recebe dados do usuário, só o tipo do evento, escolhido de uma lista fixa. A resposta dele é validada (sem HTML, link, PII; no máximo 2 frases) antes de ir à tela. A chave vai em header, não na URL.
- **Dashboard:** HTML puro, texto da API sempre via `textContent`, CSP restritiva, cor + texto + ícone (acessível).
- **Demo desligada por padrão:** rotas `/demo/*` só existem com `MODO_DEMO=1` (endpoint de teste esquecido em produção é risco do PDF [07]).

## Fórmula do Risco Cidadão

`Risco = min(100, soma dos pesos dos eventos da última hora)`. Pesos: alta 15, média 8, baixa 1; `PII_RECEBIDA` pesa 0 (é o funcionamento normal). Faixas: **0–9 verde**, **10–29 amarelo**, **30–100 vermelho**. Detalhes em `app/risk/formula.py`.

## Limitações conhecidas (honestidade técnica)

- **Sem controle de acesso por perfil (RBAC):** quem tem token válido é tratado igual. Um próximo passo seria limitar cada usuário aos próprios dados.
- **Detecção por chave ou formato:** uma senha solta, sem rótulo e fora de `Sensitive`, não é reconhecida num log de texto livre. Por isso o código sensível deve marcar o dado com `Sensitive`/`marcar`.
- **CPF como número JSON sem aspas** em campo sem nome sensível não é detectado.
- **Sem criptografia em repouso nem hash de senha:** o projeto não guarda usuários nem senhas (só eventos sem valores). Se passasse a guardar, o caminho seria bcrypt/AES (PDF [07]).
- **Painel com visão única:** não há separação entre administrador e demais perfis.
- **Tradução por IA em falha:** cada atualização do painel tenta o LLM de novo enquanto ele estiver indisponível (só sucessos são cacheados); o timeout padrão é de 8 s.

## Estrutura de pastas

```
├── app/
│   ├── main.py        # app FastAPI e rotas de demo
│   ├── pii/           # Parte 1: detectores, mascaramento, middleware
│   ├── taint/         # Parte 2: Sensitive, logs seguros, filtro de resposta, erros
│   ├── audit/         # Parte 2: auditoria em SQLite + JSON
│   ├── auth.py        # token assinado (HMAC) com expiração
│   ├── ai/            # Parte 3: catálogo, prompt, provedores, tradutor
│   └── risk/          # Parte 4: fórmula e rotas /risco e /dashboard
├── dashboard/         # Parte 4: painel (HTML, CSS, JS)
├── tests/             # 83 testes
├── scripts/           # demo_taint.py, demo_ia.py, gerar_trafego.py
└── docs/
    ├── prompts.md     # prompts usados com IA (regra da GS)
    └── evidencias/    # saídas de testes e prints para o PDF
```

## Origem das decisões (PDFs de Cyber)

- Sanitização, logs estruturados com trace id, `.env` e pseudoanonimização: PDF [07].
- Persona, restrições e prompt injection: PDF [02].
- Gravidade dos eventos (base para os pesos do Risco Cidadão): PDF [18].
