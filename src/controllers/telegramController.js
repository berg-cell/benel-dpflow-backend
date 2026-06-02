// src/controllers/telegramController.js
"use strict";
const tg = require("../services/telegram");
const db = require("../config/database");

exports.webhook = async (req, res) => {
  // Responde imediatamente — crítico para evitar timeout no Vercel
  res.sendStatus(200);

  // Processa em background sem await no res
  processarUpdate(req.body).catch(e =>
    console.error("[TelegramWebhook] Erro:", e.message)
  );
};

async function processarUpdate(update) {
  const msg = update?.message;
  if (!msg) return;

  const chatId = msg.chat?.id;
  const texto  = (msg.text || "").trim();

  if (texto === "/start" || texto.startsWith("/start ")) {
    await tg.enviarMensagem(chatId,
      `👋 <b>Bem-vindo ao DP Flow Benel!</b>\n\n` +
      `Para receber notificações, envie o seu e-mail de acesso:\n\n` +
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

    const { rows } = await db.query(
      "SELECT id, nome FROM usuarios WHERE LOWER(email)=$1 AND ativo=true", [email]
    );
    if (!rows[0]) {
      await tg.enviarMensagem(chatId,
        `❌ E-mail não encontrado no DP Flow.\n\nVerifique e tente novamente.`
      );
      return;
    }

    // Desvincula se já existe outro usuário com esse chat_id
    await db.query(
      "UPDATE usuarios SET telegram_chat_id=NULL WHERE telegram_chat_id=$1 AND id!=$2",
      [String(chatId), rows[0].id]
    );

    await tg.vincularChatId(email, chatId);

    await tg.enviarMensagem(chatId,
      `✅ <b>Vinculado com sucesso!</b>\n\n` +
      `Olá, <b>${rows[0].nome}</b>!\n` +
      `Você receberá notificações de novas solicitações aqui.\n\n` +
      `Envie <code>/sair</code> para desvincular.`
    );
    return;
  }

  if (texto === "/sair") {
    await tg.desvincularChatId(String(chatId));
    await tg.enviarMensagem(chatId,
      `👋 Notificações desativadas.\n\nEnvie <code>/start</code> para reativar.`
    );
    return;
  }

  if (texto === "/status") {
    const { rows } = await db.query(
      "SELECT nome, email FROM usuarios WHERE telegram_chat_id=$1", [String(chatId)]
    );
    if (rows[0]) {
      await tg.enviarMensagem(chatId,
        `✅ <b>Vinculado como:</b> ${rows[0].nome}\n📧 ${rows[0].email}\n\n<code>/sair</code> para desvincular.`
      );
    } else {
      await tg.enviarMensagem(chatId,
        `❌ Não vinculado.\n\n<code>/vincular seu@email.com.br</code>`
      );
    }
    return;
  }

  await tg.enviarMensagem(chatId,
    `🤖 Comandos:\n\n` +
    `<code>/start</code> — Iniciar\n` +
    `<code>/vincular email</code> — Vincular conta\n` +
    `<code>/status</code> — Ver conta vinculada\n` +
    `<code>/sair</code> — Desvincular`
  );
}
