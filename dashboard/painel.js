"use strict";
// Regra de segurança deste arquivo: TODO texto vindo da API (inclusive o gerado pela IA)
// entra na página por textContent, nunca como HTML. Assim um texto malicioso aparece
// como texto puro e não executa nada (XSS). O token fica só na memória desta aba.
(function () {
  var token = "";
  var temporizador = null;
  var $ = function (id) { return document.getElementById(id); };

  var VISUAL = {
    verde: { classe: "nivel-verde", icone: "✔", resumo: "Tudo certo: nenhum problema relevante nesta janela de tempo." },
    amarelo: { classe: "nivel-amarelo", icone: "!", resumo: "Atenção: o sistema precisou agir para proteger dados. Vale revisar." },
    vermelho: { classe: "nivel-vermelho", icone: "✖", resumo: "Crítico: vários problemas de proteção de dados. Ação imediata da equipe." }
  };
  var EXEMPLOS = { baixa: "Dado pessoal entregue a usuário autenticado", media: "CPF ou RG em risco de exposição", alta: "Senha ou dado de saúde em risco de exposição" };

  function aviso(texto) { $("aviso").textContent = texto || ""; }

  function el(tag, classe, texto) {
    var e = document.createElement(tag);
    if (classe) e.className = classe;
    if (texto !== undefined) e.textContent = texto;
    return e;
  }

  function pintarFormula(f) {
    var corpo = $("tabela-pesos");
    corpo.textContent = "";
    ["alta", "media", "baixa"].forEach(function (g) {
      if (!(g in f.pesos)) return;
      var tr = document.createElement("tr");
      tr.appendChild(el("td", "", { alta: "Alta", media: "Média", baixa: "Baixa" }[g]));
      tr.appendChild(el("td", "", String(f.pesos[g])));
      tr.appendChild(el("td", "", EXEMPLOS[g]));
      corpo.appendChild(tr);
    });
    $("f-verde").textContent = f.faixas.verde;
    $("f-amarelo").textContent = f.faixas.amarelo;
    $("f-vermelho").textContent = f.faixas.vermelho;
  }

  function pintar(d) {
    var v = VISUAL[d.nivel] || { classe: "nivel-cinza", icone: "?", resumo: "" };
    $("indicador").className = "indicador " + v.classe;
    $("icone").textContent = v.icone;
    $("rotulo").textContent = d.rotulo;           // cor E texto E ícone: não depende só da cor
    $("pontos").textContent = String(d.pontuacao);
    $("janela").textContent = String(d.janela_minutos);
    $("resumo").textContent = v.resumo;
    var barra = document.querySelector(".barra");
    barra.setAttribute("aria-valuenow", String(d.pontuacao));
    $("preenchimento").style.width = Math.max(0, Math.min(100, d.pontuacao)) + "%";

    var lista = $("lista");
    lista.textContent = "";
    if (!d.explicacoes.length) {
      lista.appendChild(el("li", "vazio", "Nenhum evento de segurança na janela de tempo."));
    }
    d.explicacoes.forEach(function (x) {
      var li = el("li", x.pontos / x.ocorrencias >= 15 ? "alta" : (x.pontos / x.ocorrencias >= 8 ? "media" : "baixa"));
      li.appendChild(el("p", "", x.mensagem));            // texto do LLM: textContent
      var meta = el("p", "meta");
      meta.appendChild(el("span", "selo-ia " + (x.origem === "llm" ? "" : "selo-padrao"),
        x.origem === "llm" ? "Explicação gerada por IA" : "Mensagem padrão"));
      meta.appendChild(document.createTextNode(
        x.ocorrencias + (x.ocorrencias === 1 ? " ocorrência" : " ocorrências") + " · " + x.pontos + (x.pontos === 1 ? " ponto" : " pontos")));
      li.appendChild(meta);
      lista.appendChild(li);
    });
    pintarFormula(d.formula);
    $("atualizado").textContent = "Atualizado em " + new Date(d.atualizado_em).toLocaleString("pt-BR") +
      " · " + d.eventos_que_pontuam + " evento(s) pontuando" + (d.truncado ? " (lista truncada)" : "");
  }

  function atualizar() {
    token = $("token").value.trim() || token;
    if (!token) { aviso("Informe o token de acesso."); return; }
    fetch("/risco", { headers: { Authorization: "Bearer " + token }, cache: "no-store" })
      .then(function (r) {
        if (r.status === 401) { throw new Error("Token inválido ou expirado. Peça um novo ao administrador."); }
        if (!r.ok) { throw new Error("Não foi possível carregar o indicador (código " + r.status + ")."); }
        return r.json();
      })
      .then(function (d) { aviso(""); pintar(d); iniciarAutoAtualizar(); })
      .catch(function (e) { aviso(e.message || "Falha de conexão."); });
  }

  function iniciarAutoAtualizar() {
    if (temporizador) return;
    temporizador = setInterval(atualizar, 15000);
  }

  $("atualizar").addEventListener("click", atualizar);
  $("token").addEventListener("keydown", function (e) { if (e.key === "Enter") atualizar(); });

  // Atalho para a demonstração: /dashboard#token=...  (o fragmento não vai para o servidor
  // nem para logs; é apagado da barra de endereço logo em seguida).
  var m = /(?:^#|&)token=([^&]+)/.exec(location.hash);
  if (m) {
    $("token").value = decodeURIComponent(m[1]);
    history.replaceState(null, "", location.pathname + location.search);
    atualizar();
  }
})();
