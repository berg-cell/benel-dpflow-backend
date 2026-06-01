// src/controllers/telegramController.js
"use strict";
const tg = require("../services/telegram");
const db = require("../config/database");

// ── Webhook recebido do Telegram ──────────────────────────────────────────────
exports.webhook = async (req, res) => {
  // Responde imediatamente para o Telegram não reenviar
  res.sendStatus(200);

  try {
    const update = req.body;
    const msg    = update?.message;
    if (!msg) return;

    const chatId = msg.chat?.id;
    const texto  = (msg.text || "").trim();

    // ── /start — usuário ainda não vinculado ──────────────────────────────────
    if (texto === "/start" || texto.startsWith("/start ")) {
      await tg.enviarMensagem(chatId,
        `👋 <b>Bem-vindo ao DP Flow!</b>\n\n` +
        `Para receber notificações, envie o seu e-mail de acesso no formato:\n\n` +
        `<code>/vincular seu@email.com.br</code>`
      );
      return;
    }

    // ── /vincular email ───────────────────────────────────────────────────────
    if (texto.startsWith("/vincular ")) {
      const email = texto.replace("/vincular ", "").trim().toLowerCase();
      if (!email.includes("@")) {
        await tg.enviarMensagem(chatId, "❌ E-mail inválido. Tente novamente:\n<code>/vincular seu@email.com.br</code>");
        return;
      }

      // Verifica se o e-mail existe no sistema
      const { rows } = await db.query(
        "SELECT id, nome FROM usuarios WHERE LOWER(email)=$1 AND ativo=true", [email]
      );
      if (!rows[0]) {
        await tg.enviarMensagem(chatId,
          `❌ E-mail não encontrado no DP Flow.\n\nVerifique o e-mail cadastrado e tente novamente.`
        );
        return;
      }

      // Verifica se esse chat_id já está em outro usuário
      const { rows: jaVinculado } = await db.query(
        "SELECT id, nome FROM usuarios WHERE telegram_chat_id=$1", [String(chatId)]
      );
      if (jaVinculado[0] && jaVinculado[0].id !== rows[0].id) {
        // Desvincula do anterior
        await tg.desvincularChatId(String(chatId));
      }

      await tg.vincularChatId(email, chatId);

      await tg.enviarMensagem(chatId,
        `✅ <b>Vinculado com sucesso!</b>\n\n` +
        `Olá, <b>${rows[0].nome}</b>!\n` +
        `A partir de agora você receberá notificações de novas solicitações diretamente aqui.\n\n` +
        `Para desvincular, envie <code>/sair</code>`
      );
      return;
    }

    // ── /sair ─────────────────────────────────────────────────────────────────
    if (texto === "/sair") {
      await tg.desvincularChatId(String(chatId));
      await tg.enviarMensagem(chatId,
        `👋 Notificações desativadas. Você não receberá mais mensagens do DP Flow.\n\n` +
        `Para reativar, envie <code>/start</code>`
      );
      return;
    }

    // ── /status ───────────────────────────────────────────────────────────────
    if (texto === "/status") {
      const { rows } = await db.query(
        "SELECT nome, email FROM usuarios WHERE telegram_chat_id=$1", [String(chatId)]
      );
      if (rows[0]) {
        await tg.enviarMensagem(chatId,
          `✅ <b>Vinculado como:</b> ${rows[0].nome}\n📧 ${rows[0].email}\n\nPara desvincular: <code>/sair</code>`
        );
      } else {
        await tg.enviarMensagem(chatId,
          `❌ Não vinculado.\n\nEnvie <code>/vincular seu@email.com.br</code> para ativar notificações.`
        );
      }
      return;
    }

    // ── Mensagem desconhecida ─────────────────────────────────────────────────
    await tg.enviarMensagem(chatId,
      `🤖 Comandos disponíveis:\n\n` +
      `<code>/start</code> — Iniciar\n` +
      `<code>/vincular email</code> — Vincular sua conta\n` +
      `<code>/status</code> — Ver conta vinculada\n` +
      `<code>/sair</code> — Desvincular`
    );

  } catch (e) {
    console.error("[TelegramWebhook] Erro:", e.message);
  }
};
