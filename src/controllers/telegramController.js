// src/controllers/telegramController.js
"use strict";
const tg = require("../services/telegram");
const db = require("../config/database");

exports.webhook = async (req, res) => {
  try {
    const msg = req.body?.message;
    if (!msg) { res.sendStatus(200); return; }

    const chatId = msg.chat?.id;
    const texto  = (msg.text || "").trim();

    // /start — sem banco, responde direto
    if (texto === "/start" || texto.startsWith("/start ")) {
      await Promise.race([
        tg.enviarMensagem(chatId,
          `👋 <b>Bem-vindo ao DP Flow Benel!</b>\n\n` +
          `Para receber notificações, envie:\n\n` +
          `<code>/vincular seu@email.com.br</code>`
        ),
        new Promise(r => setTimeout(r, 4000))
      ]);
      res.sendStatus(200);
      return;
    }

    // /vincular email
    if (texto.startsWith("/vincular ")) {
      const email = texto.replace("/vincular ", "").trim().toLowerCase();
      if (!email.includes("@")) {
        await tg.enviarMensagem(chatId, "❌ E-mail inválido.\n<code>/vincular seu@email.com.br</code>");
        res.sendStatus(200); return;
      }
      const { rows } = await Promise.race([
        db.query("SELECT id, nome FROM usuarios WHERE LOWER(email)=$1 AND ativo=true", [email]),
        new Promise((_, rj) => setTimeout(() => rj(new Error("timeout")), 5000))
      ]);
      if (!rows[0]) {
        await tg.enviarMensagem(chatId, `❌ E-mail não encontrado no DP Flow.`);
        res.sendStatus(200); return;
      }
      await db.query(
        "UPDATE usuarios SET telegram_chat_id=NULL WHERE telegram_chat_id=$1 AND id!=$2",
        [String(chatId), rows[0].id]
      );
      await db.query(
        "UPDATE usuarios SET telegram_chat_id=$1, atualizado_em=NOW() WHERE id=$2",
        [String(chatId), rows[0].id]
      );
      await tg.enviarMensagem(chatId,
        `✅ <b>Vinculado com sucesso!</b>\n\nOlá, <b>${rows[0].nome}</b>!\n` +
        `Você receberá notificações de novas solicitações.\n\n` +
        `<code>/sair</code> para desvincular.`
      );
      res.sendStatus(200); return;
    }

    // /sair
    if (texto === "/sair") {
      await db.query(
        "UPDATE usuarios SET telegram_chat_id=NULL WHERE telegram_chat_id=$1", [String(chatId)]
      );
      await tg.enviarMensagem(chatId, `👋 Desvinculado.\n\n<code>/start</code> para reativar.`);
      res.sendStatus(200); return;
    }

    // /status
    if (texto === "/status") {
      const { rows } = await db.query(
        "SELECT nome, email FROM usuarios WHERE telegram_chat_id=$1", [String(chatId)]
      );
      if (rows[0]) {
        await tg.enviarMensagem(chatId,
          `✅ <b>${rows[0].nome}</b>\n📧 ${rows[0].email}\n\n<code>/sair</code> para desvincular.`
        );
      } else {
        await tg.enviarMensagem(chatId, `❌ Não vinculado.\n\n<code>/vincular seu@email.com.br</code>`);
      }
      res.sendStatus(200); return;
    }

    // Mensagem desconhecida
    await tg.enviarMensagem(chatId,
      `🤖 Comandos:\n\n` +
      `<code>/start</code> — Iniciar\n` +
      `<code>/vincular email</code> — Vincular conta\n` +
      `<code>/status</code> — Ver conta\n` +
      `<code>/sair</code> — Desvincular`
    );
    res.sendStatus(200);

  } catch (e) {
    console.error("[TelegramWebhook] Erro:", e.message);
    res.sendStatus(200);
  }
};
