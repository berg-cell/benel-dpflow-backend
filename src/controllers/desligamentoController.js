// src/controllers/desligamentoController.js
"use strict";
const { DesligamentoModel, AuditoriaModel } = require("../models");
const R = require("../utils/response");

const ALCADA = {
  pendente_superior: ["superior", "admin"],
  pendente_dp:       ["dp", "admin"],
  aprovado:          ["dp", "admin"],
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
    if (!ALCADA[sol.status]?.includes(req.usuario.perfil))
      return R.forbidden(res, "Você não tem permissão para agir neste status");
    const novoStatus = await DesligamentoModel.avancarStatus(id, req.usuario.id, acao, observacao);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: `DESLIGAMENTO_${acao.toUpperCase()}`,
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
