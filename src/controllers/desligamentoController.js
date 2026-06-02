// src/controllers/desligamentoController.js
"use strict";
const { DesligamentoModel, AuditoriaModel } = require("../models");
const db = require("../config/database");
const R = require("../utils/response");
const tg = require("../services/telegram");

// ── Validar colaborador para desligamento ─────────────────────────────────────
exports.validarColaborador = async (req, res) => {
  try {
    const { id } = req.params;
    const r = await db.query("SELECT * FROM colaboradores WHERE id = $1", [id]);
    if (!r.rowCount) return R.notFound(res, "Colaborador não encontrado");

    const c = r.rows[0];

    if (c.cod_situacao === "D") {
      return R.success(res, {
        apto: false,
        motivo: "situacao",
        mensagem: "Colaborador não pode ser selecionado para desligamento, pois já consta com situação Demitido.",
      });
    }

    if (c.data_fim_estabilidade) {
      const fimEstab = new Date(c.data_fim_estabilidade);
      fimEstab.setHours(0, 0, 0, 0);
      const hoje = new Date();
      hoje.setHours(0, 0, 0, 0);

      if (fimEstab >= hoje) {
        const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
        return R.success(res, {
          apto: false,
          motivo: "estabilidade",
          mensagem: `Este colaborador não pode ser desligado, pois possui estabilidade ativa: ${c.descricao_estabilidade || "Estabilidade"}. A estabilidade encerra em ${fmtBR(fimEstab)}.`,
          data_fim_estabilidade: c.data_fim_estabilidade,
          descricao_estabilidade: c.descricao_estabilidade,
        });
      }
    }

    return R.success(res, { apto: true });
  } catch (e) { return R.error(res, e.message); }
};

const ALCADA = {
  pendente_superior: ["superior", "dp", "admin"],
  aprovado:          ["dp", "admin"],
  ajuste_solicitado: ["gestor", "dp", "admin"],
};

exports.listar = async (req, res) => {
  try {
    const { status } = req.query;
    const r = await DesligamentoModel.findAll({
      gestor_id: req.usuario.id,
      status,
      perfil: req.usuario.perfil,
    });
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.buscarPorId = async (req, res) => {
  try {
    const r = await DesligamentoModel.findById(req.params.id);
    if (!r.rowCount) return R.notFound(res, "Solicitação não encontrada");
    const sol = r.rows[0];
    if (req.usuario.perfil === "gestor" && sol.gestor_id !== req.usuario.id)
      return R.forbidden(res, "Acesso negado");
    const [logs, anexos] = await Promise.all([
      DesligamentoModel.findLogs(sol.id),
      DesligamentoModel.findAnexos(sol.id),
    ]);
    return R.success(res, { ...sol, logs: logs.rows, anexos: anexos.rows });
  } catch (e) { return R.error(res, e.message); }
};

exports.criar = async (req, res) => {
  try {
    const sol = await DesligamentoModel.create(req.body, req.usuario.id);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "DESLIGAMENTO_CRIADO",
      tabela: "solicitacao_desligamento", registro_id: sol.id,
      dados_depois: req.body, ip: req.ip, user_agent: req.headers["user-agent"],
    });

    // Notificação Telegram
    try {
      const { rows: colabNotif } = await db.query(
        "SELECT nome, chapa, funcao, centro_custo, desc_cc FROM colaboradores WHERE id=$1",
        [req.body.colaborador_id]
      );
      await Promise.race([
        tg.notificar(req.usuario.id, "desligamento", {
          colaborador_nome: colabNotif[0]?.nome,
          chapa:            colabNotif[0]?.chapa,
          funcao:           colabNotif[0]?.funcao,
          centro_custo:     colabNotif[0]?.centro_custo,
          desc_cc:          colabNotif[0]?.desc_cc,
          solicitante:      req.usuario.nome,
          tipo:             req.body.tipo_desligamento || req.body.motivo,
          motivo:           req.body.justificativa || req.body.observacao,
        }),
        new Promise(r => setTimeout(r, 4000))
      ]);
    } catch (_) {}

    return R.created(res, sol, "Solicitação criada com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.enviar = async (req, res) => {
  try {
    const sol = await DesligamentoModel.enviar(req.params.id, req.usuario.id);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "DESLIGAMENTO_ENVIADO",
      tabela: "solicitacao_desligamento", registro_id: sol.id,
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.success(res, sol, "Solicitação enviada para aprovação");
  } catch (e) { return R.error(res, e.message, e.status || 500); }
};

exports.aprovar = async (req, res) => {
  try {
    const { acao, observacao } = req.body;
    const id = parseInt(req.params.id);
    const r = await DesligamentoModel.findById(id);
    if (!r.rowCount) return R.notFound(res, "Solicitação não encontrada");
    const sol = r.rows[0];

    const perfil = req.usuario.perfil;
    const userId = req.usuario.id;

    if (!ALCADA[sol.status]?.includes(perfil))
      return R.forbidden(res, "Você não tem permissão para agir neste status");

    if (sol.status === "pendente_superior" && perfil !== "admin" && perfil !== "dp") {
      if (!sol.superior_id)
        return R.forbidden(res, "Esta solicitação não possui superior vinculado na hierarquia. Contate o administrador.");
      if (sol.superior_id !== userId)
        return R.forbidden(res, "Você não é o superior responsável por esta solicitação conforme a hierarquia cadastrada.");
    }

    const novoStatus = await DesligamentoModel.avancarStatus(id, userId, acao, observacao);
    await AuditoriaModel.registrar({
      usuario_id: userId, acao: `DESLIGAMENTO_${acao.toUpperCase()}`,
      tabela: "solicitacao_desligamento", registro_id: id,
      dados_antes: { status: sol.status },
      dados_depois: { status: novoStatus, observacao },
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.success(res, { novoStatus }, "Ação realizada com sucesso");
  } catch (e) { return R.error(res, e.message, e.status || 500); }
};

exports.addAnexo = async (req, res) => {
  try {
    const { nome_arquivo, tipo_arquivo, dados_base64 } = req.body;
    if (!nome_arquivo || !dados_base64)
      return R.badRequest(res, "Nome e dados do arquivo são obrigatórios");
    if (dados_base64.length > 5 * 1024 * 1024)
      return R.badRequest(res, "Arquivo muito grande (máximo 5MB)");
    const r = await DesligamentoModel.addAnexo(
      req.params.id, req.usuario.id,
      { nome_arquivo, tipo_arquivo, dados_base64 }
    );
    return R.created(res, r.rows[0], "Anexo adicionado com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.getAnexo = async (req, res) => {
  try {
    const r = await DesligamentoModel.getAnexo(req.params.anexoId);
    if (!r.rowCount) return R.notFound(res, "Anexo não encontrado");
    return R.success(res, r.rows[0]);
  } catch (e) { return R.error(res, e.message); }
};

exports.cancelar = async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const r = await DesligamentoModel.findById(id);
    if (!r.rowCount) return R.notFound(res, "Solicitação não encontrada");
    const sol = r.rows[0];
    if (["cancelado","finalizado"].includes(sol.status))
      return R.badRequest(res, `Não é possível cancelar uma solicitação com status "${sol.status}"`);
    await db.query(
      `UPDATE solicitacao_desligamento SET status='cancelado', atualizado_em=NOW() WHERE id=$1`, [id]
    );
    await db.query(
      `INSERT INTO solicitacao_desligamento_logs(solicitacao_id,usuario_id,acao,observacao,dados_antes,dados_depois)
       VALUES($1,$2,'cancelado',$3,$4,$5)`,
      [id, req.usuario.id, "Cancelado pelo administrador",
       JSON.stringify({ status: sol.status }),
       JSON.stringify({ status: "cancelado" })]
    );
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "DESLIGAMENTO_CANCELADO",
      tabela: "solicitacao_desligamento", registro_id: id,
      dados_antes: { status: sol.status }, dados_depois: { status: "cancelado" },
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.success(res, {}, "Solicitação cancelada com sucesso");
  } catch (e) { return R.error(res, e.message); }
};
