// src/services/telegram.js
"use strict";
const db = require("../config/database");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const API       = `https://api.telegram.org/bot${BOT_TOKEN}`;

// ── Enviar mensagem ───────────────────────────────────────────────────────────
async function enviarMensagem(chatId, texto) {
  if (!BOT_TOKEN) return;
  try {
    await fetch(`${API}/sendMessage`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id:    chatId,
        text:       texto,
        parse_mode: "HTML",
      }),
    });
  } catch (e) {
    console.error("[Telegram] Falha ao enviar mensagem:", e.message);
  }
}

// ── Montar texto da notificação ───────────────────────────────────────────────
function montarTexto(tipo, dados) {
  const emojis = {
    desligamento:          "🔴",
    plano_saude:           "💊",
    atualizacao_cadastral: "📋",
    ocorrencia:            "⚠️",
  };
  const labels = {
    desligamento:          "Desligamento",
    plano_saude:           "Plano de Saúde",
    atualizacao_cadastral: "Atualização Cadastral",
    ocorrencia:            "Ocorrência Disciplinar",
  };

  const emoji = emojis[tipo] || "📌";
  const label = labels[tipo] || tipo;

  return [
    `${emoji} <b>Nova solicitação — ${label}</b>`,
    ``,
    `👤 <b>Colaborador:</b> ${dados.colaborador_nome || "—"}`,
    dados.chapa          ? `🪪 <b>Matrícula:</b> ${dados.chapa}` : null,
    dados.funcao         ? `💼 <b>Função:</b> ${dados.funcao}` : null,
    dados.centro_custo   ? `🏢 <b>CC:</b> ${dados.centro_custo} — ${dados.desc_cc || ""}` : null,
    dados.solicitante    ? `👨‍💼 <b>Solicitante:</b> ${dados.solicitante}` : null,
    dados.tipo           ? `📌 <b>Tipo:</b> ${dados.tipo}` : null,
    dados.motivo         ? `📝 <b>Motivo:</b> ${dados.motivo}` : null,
    dados.observacao     ? `💬 <b>Obs:</b> ${dados.observacao}` : null,
    ``,
    `🕐 ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}`,
    ``,
    `🔗 <a href="https://benel-dpflow-5jas.vercel.app">Abrir DP Flow</a>`,
  ].filter(l => l !== null).join("\n");
}

// ── Notificar todos do perfil dp e admin que vincularam o Telegram ────────────
async function notificar(_, tipo, dados) {
  // Ignora o usuarioId — notifica todos dp/admin vinculados
  try {
    const { rows } = await db.query(`
      SELECT telegram_chat_id
      FROM usuarios
      WHERE perfil IN ('dp', 'admin')
        AND ativo = true
        AND telegram_chat_id IS NOT NULL
    `);

    if (!rows.length) return;

    const texto = montarTexto(tipo, dados);
    await Promise.all(rows.map(u => enviarMensagem(u.telegram_chat_id, texto)));
  } catch (e) {
    console.error("[Telegram] Erro ao notificar DP:", e.message);
  }
}

// ── Vincular chat_id ao usuário ───────────────────────────────────────────────
async function vincularChatId(email, chatId) {
  await db.query(
    "UPDATE usuarios SET telegram_chat_id=$1, atualizado_em=NOW() WHERE LOWER(email)=LOWER($2)",
    [String(chatId), email.trim()]
  );
}

// ── Desvincular ───────────────────────────────────────────────────────────────
async function desvincularChatId(chatId) {
  await db.query(
    "UPDATE usuarios SET telegram_chat_id=NULL, atualizado_em=NOW() WHERE telegram_chat_id=$1",
    [String(chatId)]
  );
}

module.exports = { enviarMensagem, notificar, vincularChatId, desvincularChatId };
