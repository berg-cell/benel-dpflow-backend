// src/controllers/blocoController.js
"use strict";
const { BlocoModel, AuditoriaModel } = require("../models");
const { processarBlocos } = require("../utils/totvs");
const R = require("../utils/response");

const ALCADA_VALIDA = {
  pendente_gestor:   ["gestor",   "admin"],
  pendente_superior: ["superior", "admin"],
  pendente_dp:       ["dp",       "admin"],
};

exports.listar = async (req, res) => {
  try {
    const { status, competencia } = req.query;
    const filtros = { status, competencia };
    // IDOR: gestor só vê seus próprios blocos
    if (req.usuario.perfil === "gestor") filtros.solicitante_id = req.usuario.id;
    const r = await BlocoModel.findAll(filtros);
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.buscarPorId = async (req, res) => {
  try {
    const r = await BlocoModel.findById(req.params.id);
    if (r.rowCount === 0) return R.notFound(res, "Bloco não encontrado");
    const bloco = r.rows[0];
    // IDOR: gestor só acessa bloco próprio
    if (req.usuario.perfil === "gestor" && bloco.solicitante_id !== req.usuario.id)
      return R.forbidden(res, "Acesso negado a este bloco");
    const linhas   = await BlocoModel.findLinhas(bloco.id);
    const historico = await BlocoModel.findHistorico(bloco.id);
    return R.success(res, { ...bloco, linhas: linhas.rows, historico: historico.rows });
  } catch (e) { return R.error(res, e.message); }
};

exports.criar = async (req, res) => {
  try {
    const bloco = await BlocoModel.create(req.body, req.usuario.id);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "BLOCO_CRIADO",
      tabela: "blocos", registro_id: bloco.id,
      dados_depois: { descricao: bloco.descricao, competencia: bloco.competencia },
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.created(res, bloco, "Bloco criado e enviado para aprovação");
  } catch (e) { return R.error(res, e.message); }
};

exports.aprovar = async (req, res) => {
  try {
    const { acao, justificativa } = req.body;
    const blocoId = parseInt(req.params.id);
    const r = await BlocoModel.findById(blocoId);
    if (r.rowCount === 0) return R.notFound(res, "Bloco não encontrado");
    const bloco = r.rows[0];
    // Verificar alçada correta
    if (!ALCADA_VALIDA[bloco.status]?.includes(req.usuario.perfil))
      return R.forbidden(res, "Você não tem permissão para agir neste status");
    const novoStatus = await BlocoModel.avancarStatus(blocoId, req.usuario.id, acao, justificativa);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: `BLOCO_${acao.toUpperCase()}`,
      tabela: "blocos", registro_id: blocoId,
      dados_antes: { status: bloco.status },
      dados_depois: { status: novoStatus, justificativa },
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    const msgs = { aprovar: "aprovado", rejeitar: "rejeitado", devolver: "devolvido" };
    return R.success(res, { novoStatus }, `Bloco ${msgs[acao]} com sucesso`);
  } catch (e) { return R.error(res, e.message, e.status || 500); }
};

exports.exportarTxt = async (req, res) => {
  try {
    const r = await BlocoModel.findAll({ status: "aprovado_final" });
    if (r.rowCount === 0) return R.badRequest(res, "Nenhum bloco aprovado para exportar");

    // Buscar linhas de cada bloco com dados completos
    const blocos = [];
    for (const bloco of r.rows) {
      const linhasR = await BlocoModel.findLinhas(bloco.id);
      blocos.push({ ...bloco, linhas: linhasR.rows });
    }

    const { linhasTxt, errosBlocos, valido } = processarBlocos(blocos);

    if (!valido)
      return R.badRequest(res, "Erros de validação TOTVS RM", errosBlocos);

    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "TXT_EXPORTADO",
      tabela: "blocos",
      dados_depois: { total_linhas: linhasTxt.length, total_blocos: blocos.length },
      ip: req.ip, user_agent: req.headers["user-agent"],
    });

    const filename = `movimento_rm_${new Date().toISOString().split("T")[0]}.txt`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(linhasTxt.join("\n"));
  } catch (e) { return R.error(res, e.message); }
};
