// src/services/telegram.js
"use strict";
const db = require("../config/database");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const API       = `https://api.telegram.org/bot${BOT_TOKEN}`;

// ── Enviar mensagem simples ───────────────────────────────────────────────────
async function enviarMensagem(chatId, texto) {
  if (!BOT_TOKEN) return;
  try {
    await fetch(`${API}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: texto, parse_mode: "HTML" }),
    });
  } catch (e) {
    console.error("[Telegram] Falha ao enviar mensagem:", e.message);
  }
}

// ── Enviar mensagem com botões inline ─────────────────────────────────────────
async function enviarMensagemComBotoes(chatId, texto, botoes) {
  if (!BOT_TOKEN) return;
  try {
    await fetch(`${API}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id:      chatId,
        text:         texto,
        parse_mode:   "HTML",
        reply_markup: { inline_keyboard: [botoes] },
      }),
    });
  } catch (e) {
    console.error("[Telegram] Falha ao enviar mensagem com botões:", e.message);
  }
}

// ── Editar mensagem existente (após ação) ─────────────────────────────────────
async function editarMensagem(chatId, messageId, texto) {
  if (!BOT_TOKEN) return;
  try {
    await fetch(`${API}/editMessageText`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id:    chatId,
        message_id: messageId,
        text:       texto,
        parse_mode: "HTML",
      }),
    });
  } catch (e) {
    console.error("[Telegram] Falha ao editar mensagem:", e.message);
  }
}

// ── Responder callback query (remove o "loading" do botão) ────────────────────
async function responderCallback(callbackQueryId, texto) {
  if (!BOT_TOKEN) return;
  try {
    await fetch(`${API}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callback_query_id: callbackQueryId, text: texto }),
    });
  } catch (e) {}
}

// ── Montar texto da notificação ───────────────────────────────────────────────
function montarTexto(tipo, dados) {
  const emojis = {
    desligamento:          "🔴",
    plano_saude:           "💊",
    atualizacao_cadastral: "📋",
    ocorrencia:            "⚠️",
    autorizacao_desconto:  "💰",
    pagamento:             "💵",
  };
  const labels = {
    desligamento:          "Desligamento",
    plano_saude:           "Plano de Saúde",
    atualizacao_cadastral: "Atualização Cadastral",
    ocorrencia:            "Ocorrência Disciplinar",
    autorizacao_desconto:  "Autorização de Desconto",
    pagamento:             "Solicitação de Pagamento",
  };

  const fmtBRL = (v) => parseFloat(v||0).toLocaleString("pt-BR", { style:"currency", currency:"BRL" });

  const emoji = emojis[tipo] || "📌";
  const label = labels[tipo]  || tipo;

  return [
    `${emoji} <b>Nova solicitação — ${label}</b>`,
    ``,
    `👤 <b>Colaborador:</b> ${dados.colaborador_nome || "—"}`,
    dados.chapa        ? `🪪 <b>Matrícula:</b> ${dados.chapa}` : null,
    dados.funcao       ? `💼 <b>Função:</b> ${dados.funcao}` : null,
    dados.filial       ? `🏢 <b>Filial:</b> ${dados.filial}` : dados.centro_custo ? `🏢 <b>CC:</b> ${dados.centro_custo} — ${dados.desc_cc || ""}` : null,
    dados.solicitante  ? `👨‍💼 <b>Solicitante:</b> ${dados.solicitante}` : null,
    dados.tipo         ? `📌 <b>Tipo:</b> ${dados.tipo}` : null,
    dados.motivo       ? `📝 <b>Motivo:</b> ${dados.motivo}` : null,
    dados.observacao   ? `💬 <b>Obs:</b> ${dados.observacao}` : null,
    // Totais de rescisão (só para desligamento)
    dados.total_filial != null ? `\n💰 <b>Total gasto na filial (mês):</b> ${fmtBRL(dados.total_filial)}` : null,
    dados.total_geral  != null ? `💰 <b>Total geral (mês):</b> ${fmtBRL(dados.total_geral)}` : null,
    ``,
    `🕐 ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}`,
    ``,
    `🔗 <a href="https://benel-dpflow-5jas.vercel.app">Abrir DP Flow</a>`,
  ].filter(l => l !== null).join("\n");
}

// ── Buscar totais de rescisão da filial no mês atual ─────────────────────────
async function buscarTotaisRescisao(filial) {
  try {
    const mes = new Date().getMonth() + 1;
    const ano = new Date().getFullYear();

    const { rows: filialRows } = await db.query(`
      SELECT COALESCE(SUM(valor_total), 0) AS total
      FROM rescisao_valores
      WHERE competencia_mes=$1 AND competencia_ano=$2
        AND filial ILIKE $3
    `, [mes, ano, `%${(filial||"").replace(/^BENEL TRANSPORTES\s*[-–]\s*/i,"").trim()}%`]);

    const { rows: geralRows } = await db.query(`
      SELECT COALESCE(SUM(valor_total), 0) AS total
      FROM rescisao_valores
      WHERE competencia_mes=$1 AND competencia_ano=$2
    `, [mes, ano]);

    return {
      total_filial: parseFloat(filialRows[0]?.total || 0),
      total_geral:  parseFloat(geralRows[0]?.total  || 0),
    };
  } catch (e) {
    console.error("[Telegram] Erro ao buscar totais rescisão:", e.message);
    return { total_filial: null, total_geral: null };
  }
}

// ── Notificar todos dp/admin — com botões para desligamento ──────────────────
async function notificar(_, tipo, dados) {
  try {
    const { rows } = await db.query(`
      SELECT telegram_chat_id
      FROM usuarios
      WHERE perfil IN ('dp', 'admin')
        AND ativo = true
        AND telegram_chat_id IS NOT NULL
    `);
    if (!rows.length) return;

    // Para desligamento, busca totais de rescisão e envia com botões
    if (tipo === "desligamento" && dados.desligamento_id) {
      const totais = await buscarTotaisRescisao(dados.filial);
      const dadosCompletos = { ...dados, ...totais };
      const texto = montarTexto(tipo, dadosCompletos);
      const botoes = [
        { text: "✅ Aprovar",  callback_data: `aprovar_desl_${dados.desligamento_id}` },
        { text: "❌ Reprovar", callback_data: `reprovar_desl_${dados.desligamento_id}` },
      ];
      await Promise.all(rows.map(u => enviarMensagemComBotoes(u.telegram_chat_id, texto, botoes)));
    } else {
      const texto = montarTexto(tipo, dados);
      await Promise.all(rows.map(u => enviarMensagem(u.telegram_chat_id, texto)));
    }
  } catch (e) {
    console.error("[Telegram] Erro ao notificar DP:", e.message);
  }
}

// ── Vincular / Desvincular ────────────────────────────────────────────────────
async function vincularChatId(email, chatId) {
  await db.query(
    "UPDATE usuarios SET telegram_chat_id=$1, atualizado_em=NOW() WHERE LOWER(email)=LOWER($2)",
    [String(chatId), email.trim()]
  );
}

async function desvincularChatId(chatId) {
  await db.query(
    "UPDATE usuarios SET telegram_chat_id=NULL, atualizado_em=NOW() WHERE telegram_chat_id=$1",
    [String(chatId)]
  );
}

module.exports = {
  enviarMensagem, enviarMensagemComBotoes, editarMensagem,
  responderCallback, notificar, vincularChatId, desvincularChatId,
};
