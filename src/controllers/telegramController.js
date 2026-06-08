// src/controllers/telegramController.js
"use strict";
const tg = require("../services/telegram");
const db = require("../config/database");

exports.webhook = async (req, res) => {
  res.sendStatus(200);
  processarUpdate(req.body).catch(() => {});
};

async function processarUpdate(update) {
  try {
    // ── Callback Query (botões inline) ───────────────────────────────────────
    if (update?.callback_query) {
      await processarCallback(update.callback_query);
      return;
    }

    // ── Mensagem de texto ────────────────────────────────────────────────────
    const msg   = update?.message;
    if (!msg) return;
    const chatId = msg.chat?.id;
    const texto  = (msg.text || "").trim();

    if (texto === "/start" || texto.startsWith("/start ")) {
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
      const { rows } = await Promise.race([
        db.query("SELECT id, nome FROM usuarios WHERE LOWER(email)=$1 AND ativo=true", [email]),
        new Promise((_, rj) => setTimeout(() => rj(new Error("timeout")), 5000))
      ]);
      if (!rows[0]) {
        await tg.enviarMensagem(chatId, `❌ E-mail não encontrado no DP Flow.`);
        return;
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
        `Você receberá notificações e poderá aprovar solicitações de desligamento aqui.\n\n` +
        `<code>/sair</code> para desvincular.`
      );
      return;
    }

    if (texto === "/sair") {
      await db.query(
        "UPDATE usuarios SET telegram_chat_id=NULL WHERE telegram_chat_id=$1", [String(chatId)]
      );
      await tg.enviarMensagem(chatId, `👋 Desvinculado.\n\n<code>/start</code> para reativar.`);
      return;
    }

    if (texto === "/status") {
      const { rows } = await db.query(
        "SELECT nome, email, perfil FROM usuarios WHERE telegram_chat_id=$1", [String(chatId)]
      );
      if (rows[0]) {
        await tg.enviarMensagem(chatId,
          `✅ <b>${rows[0].nome}</b>\n📧 ${rows[0].email}\n🔑 Perfil: ${rows[0].perfil}\n\n<code>/sair</code> para desvincular.`
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

// ── Processar clique nos botões inline ────────────────────────────────────────
async function processarCallback(cb) {
  const chatId          = cb.from?.id;
  const callbackQueryId = cb.id;
  const data            = cb.data || "";
  const messageId       = cb.message?.message_id;

  // Verificar se o usuário tem permissão (dp ou admin)
  const { rows: usuarios } = await db.query(
    "SELECT id, nome, perfil FROM usuarios WHERE telegram_chat_id=$1 AND perfil IN ('dp','admin','presidente') AND ativo=true",
    [String(chatId)]
  );

  if (!usuarios[0]) {
    await tg.responderCallback(callbackQueryId, "❌ Você não tem permissão para esta ação.");
    return;
  }

  const usuario = usuarios[0];

  // ── Aprovar/Reprovar desligamento ─────────────────────────────────────────
  if (data.startsWith("aprovar_desl_") || data.startsWith("reprovar_desl_")) {
    const acao  = data.startsWith("aprovar_desl_") ? "aprovar" : "reprovar";
    const solId = parseInt(data.replace("aprovar_desl_", "").replace("reprovar_desl_", ""));

    // Buscar solicitação
    const { rows: sols } = await db.query(
      "SELECT * FROM solicitacao_desligamento WHERE id=$1", [solId]
    );

    if (!sols[0]) {
      await tg.responderCallback(callbackQueryId, "❌ Solicitação não encontrada.");
      return;
    }

    const sol = sols[0];

    if (!["pendente_superior","aprovado","ajuste_solicitado"].includes(sol.status)) {
      await tg.responderCallback(callbackQueryId, `⚠️ Solicitação já está em status: ${sol.status}`);
      return;
    }

    // Avançar status
    const PROXIMO = {
      pendente_superior: { aprovar: "aprovado",  reprovar: "reprovado" },
      aprovado:          { aprovar: "finalizado", reprovar: "reprovado" },
      ajuste_solicitado: { aprovar: "aprovado",   reprovar: "reprovado" },
    };
    const novoStatus = PROXIMO[sol.status]?.[acao] || (acao === "aprovar" ? "aprovado" : "reprovado");

    await db.query(
      `UPDATE solicitacao_desligamento SET status=$1, atualizado_em=NOW() WHERE id=$2`,
      [novoStatus, solId]
    );

    await db.query(
      `INSERT INTO solicitacao_desligamento_logs(solicitacao_id, usuario_id, acao, observacao, dados_antes, dados_depois)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [solId, usuario.id, acao,
       `${acao === "aprovar" ? "Aprovado" : "Reprovado"} via Telegram por ${usuario.nome}`,
       JSON.stringify({ status: sol.status }),
       JSON.stringify({ status: novoStatus })]
    );

    const emoji  = acao === "aprovar" ? "✅" : "❌";
    const label  = acao === "aprovar" ? "APROVADO" : "REPROVADO";

    // Responder o callback (remove loading do botão)
    await tg.responderCallback(callbackQueryId, `${emoji} ${label} com sucesso!`);

    // Editar a mensagem original removendo os botões e adicionando status
    const msgOriginal = cb.message?.text || "";
    await tg.editarMensagem(chatId, messageId,
      `${msgOriginal}\n\n${emoji} <b>${label}</b> por ${usuario.nome}`
    );

    // Notificar outros usuários dp/admin sobre a ação
    const { rows: outros } = await db.query(
      "SELECT telegram_chat_id FROM usuarios WHERE perfil IN ('dp','admin') AND ativo=true AND telegram_chat_id IS NOT NULL AND telegram_chat_id!=$1",
      [String(chatId)]
    );
    if (outros.length) {
      const aviso = `${emoji} Solicitação #${solId} foi <b>${label}</b> por <b>${usuario.nome}</b> via Telegram.`;
      await Promise.all(outros.map(u => tg.enviarMensagem(u.telegram_chat_id, aviso)));
    }

    return;
  }

  await tg.responderCallback(callbackQueryId, "Ação não reconhecida.");
}
