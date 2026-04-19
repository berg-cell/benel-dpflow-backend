// src/controllers/colaboradorController.js
"use strict";
const { ColaboradorModel, AuditoriaModel } = require("../models");
const R = require("../utils/response");

exports.listar = async (req, res) => {
  try {
    const { situacao, busca } = req.query;
    const r = await ColaboradorModel.findAll({ situacao, busca });
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.buscarPorId = async (req, res) => {
  try {
    const r = await ColaboradorModel.findById(req.params.id);
    if (r.rowCount === 0) return R.notFound(res, "Colaborador não encontrado");
    return R.success(res, r.rows[0]);
  } catch (e) { return R.error(res, e.message); }
};

exports.criar = async (req, res) => {
  try {
    const ex = await ColaboradorModel.findByChapa(req.body.chapa);
    if (ex.rowCount > 0) return R.conflict(res, "Matrícula já cadastrada");
    const r = await ColaboradorModel.create(req.body);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "COLABORADOR_CRIADO",
      tabela: "colaboradores", registro_id: r.rows[0].id,
      dados_depois: req.body, ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.created(res, r.rows[0], "Colaborador criado com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.atualizar = async (req, res) => {
  try {
    const antes = await ColaboradorModel.findById(req.params.id);
    if (antes.rowCount === 0) return R.notFound(res, "Colaborador não encontrado");
    const r = await ColaboradorModel.update(req.params.id, req.body);
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "COLABORADOR_ATUALIZADO",
      tabela: "colaboradores", registro_id: req.params.id,
      dados_antes: antes.rows[0], dados_depois: req.body,
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.success(res, r.rows[0], "Colaborador atualizado");
  } catch (e) { return R.error(res, e.message); }
};

exports.importar = async (req, res) => {
  try {
    const lista = req.body.colaboradores || req.body.lista;
    if (!Array.isArray(lista) || lista.length === 0)
      return R.badRequest(res, "Lista de colaboradores vazia");
    // Filtrar e normalizar registros
    const listaNorm = lista
      .filter(r => r.chapa && r.nome)
      .map(r => ({
        chapa:         String(r.chapa || "").trim(),
        nome:          String(r.nome || "").trim(),
        funcao:        r.funcao || null,
        situacao:      ["Ativo","Inativo"].includes(r.situacao) ? r.situacao : "Ativo",
        centro_custo:  r.centro_custo || null,
        desc_cc:       r.desc_cc || null,
        cpf:           r.cpf || null,
        data_admissao: r.data_admissao && r.data_admissao !== "" ? r.data_admissao : null,
      }));
    if (listaNorm.length === 0)
      return R.badRequest(res, "Nenhum registro válido para importar");
    const resultados = await ColaboradorModel.upsertBatch(listaNorm);
    const inseridos   = resultados.filter(r => r._op === "inserido").length;
    const atualizados = resultados.filter(r => r._op === "atualizado").length;
    await AuditoriaModel.registrar({
      usuario_id: req.usuario.id, acao: "IMPORTACAO_COLABORADORES",
      tabela: "colaboradores",
      dados_depois: { total: lista.length, inseridos, atualizados },
      ip: req.ip, user_agent: req.headers["user-agent"],
    });
    return R.success(res, { inseridos, atualizados, resultados },
      `Importação concluída: ${inseridos} inserido(s), ${atualizados} atualizado(s)`);
  } catch (e) { return R.error(res, e.message); }
};
