// src/controllers/eventoController.js
"use strict";
const { EventoModel, AuditoriaModel } = require("../models");
const R = require("../utils/response");

exports.listar = async (req, res) => {
  try {
    const r = await EventoModel.findAll(req.query.ativo === "true");
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.buscarPorId = async (req, res) => {
  try {
    const r = await EventoModel.findById(req.params.id);
    if (r.rowCount === 0) return R.notFound(res, "Evento não encontrado");
    return R.success(res, r.rows[0]);
  } catch (e) { return R.error(res, e.message); }
};

exports.criar = async (req, res) => {
  try {
    const ex = await EventoModel.findByCodigo(req.body.codigo);
    if (ex.rowCount > 0) return R.conflict(res, "Código de evento já cadastrado");
    const r = await EventoModel.create(req.body);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "EVENTO_CRIADO",
      tabela: "eventos", registro_id: r.rows[0].id,
      dados_depois: req.body, ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.created(res, r.rows[0], "Evento criado com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.atualizar = async (req, res) => {
  try {
    const antes = await EventoModel.findById(req.params.id);
    if (antes.rowCount === 0) return R.notFound(res, "Evento não encontrado");
    const r = await EventoModel.update(req.params.id, req.body);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "EVENTO_ATUALIZADO",
      tabela: "eventos", registro_id: req.params.id,
      dados_antes: antes.rows[0], dados_depois: req.body,
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.success(res, r.rows[0], "Evento atualizado");
  } catch (e) { return R.error(res, e.message); }
};
