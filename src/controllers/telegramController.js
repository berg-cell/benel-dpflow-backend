// src/controllers/telegramController.js
"use strict";
const tg = require("../services/telegram");
const db = require("../config/database");

exports.webhook = async (req, res) => {
  res.sendStatus(200);
  processarUpdate(req.body).catch(() => {});
};

async function queryComTimeout(sql, params, ms = 5000) {
  return Promise.race([
    db.query(sql, params),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("DB timeout")), ms)
    ),
  ]);
}

async function processarUpdate(update) {
  try {
    const msg = update?.message;
    if (!msg) return;

    const chatId = msg.chat?.id;
    const texto  = (msg.text || "").trim();

    if (texto === "/start" || texto.startsWith("/start ")) {
      // Não consulta banco — responde direto
      await tg.enviarMensagem(chatId,
        `👋 <b>Bem-vindo ao DP Flow Benel!</b>\n\n` +
        `Para receber notificações, envie:\n\n` +
        `<code>/vincular seu@email.com.br</code>`
      );
      return;
    }

    if (texto.startsWith("/vincular ")) {
      const email = texto.replace("/vincular ", "").trim().toLowerCase();
      if (!email.includes("@")) {
        await tg.enviarMensagem(chatId, "❌ E-mail inválido.\n<code>/vincular seu@email.com.br</code>");
        return;
      }
      const { rows } = await queryComTimeout(
        "SELECT id, nome FROM usuarios WHERE LOWER(email)=$1 AND ativo=true", [email]
      );
      if (!rows[0]) {
        await tg.enviarMensagem(chatId, `❌ E-mail não encontrado no DP Flow.`);
        return;
      }
      await queryComTimeout(
        "UPDATE usuarios SET telegram_chat_id=NULL WHERE telegram_chat_id=$1 AND id!=$2",
        [String(chatId), rows[0].id]
      );
      await queryComTimeout(
        "UPDATE usuarios SET telegram_chat_id=$1, atualizado_em=NOW() WHERE id=$2",
        [String(chatId), rows[0].id]
      );
      await tg.enviarMensagem(chatId,
        `✅ <b>Vinculado com sucesso!</b>\n\nOlá, <b>${rows[0].nome}</b>!\n` +
        `Você receberá notificações de novas solicitações.\n\n` +
        `<code>/sair</code> para desvincular.`
      );
      return;
    }

    if (texto === "/sair") {
      await queryComTimeout(
        "UPDATE usuarios SET telegram_chat_id=NULL WHERE telegram_chat_id=$1",
        [String(chatId)]
      );
      await tg.enviarMensagem(chatId, `👋 Desvinculado. <code>/start</code> para reativar.`);
      return;
    }

    if (texto === "/status") {
      const { rows } = await queryComTimeout(
        "SELECT nome, email FROM usuarios WHERE telegram_chat_id=$1", [String(chatId)]
      );
      if (rows[0]) {
        await tg.enviarMensagem(chatId,
          `✅ <b>${rows[0].nome}</b>\n📧 ${rows[0].email}\n\n<code>/sair</code> para desvincular.`
        );
      } else {
        await tg.enviarMensagem(chatId, `❌ Não vinculado.\n\n<code>/vincular seu@email.com.br</code>`);
      }
      return;
    }

    await tg.enviarMensagem(chatId,
      `🤖 Comandos:\n\n` +
      `<code>/start</code> — Iniciar\n` +
      `<code>/vincular email</code> — Vincular conta\n` +
      `<code>/status</code> — Ver conta\n` +
      `<code>/sair</code> — Desvincular`
    );
  } catch (e) {
    console.error("[TelegramWebhook] Erro:", e.message);
  }
}
