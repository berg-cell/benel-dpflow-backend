// src/controllers/hierarquiaAlcadasController.js
"use strict";
const db = require("../config/database");
const R  = require("../utils/response");

// ══════════════════════════════════════════════════════════════
// HIERARQUIA
// ══════════════════════════════════════════════════════════════

exports.listarHierarquia = async (req, res) => {
  try {
    const r = await db.query(`
      SELECT h.*, 
        ug.nome AS gestor_nome, us.nome AS superior_nome
      FROM hierarquia_aprovacao h
      LEFT JOIN usuarios ug ON ug.id = h.gestor_id
      LEFT JOIN usuarios us ON us.id = h.superior_id
      ORDER BY h.criado_em DESC
    `);
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.criarHierarquia = async (req, res) => {
  try {
    const { gestor_id, superior_id, centro_custo, desc_cc } = req.body;
    if (!gestor_id || !superior_id)
      return R.badRequest(res, "Gestor e Superior são obrigatórios");

    const ug = await db.query("SELECT nome FROM usuarios WHERE id=$1", [gestor_id]);
    const us = await db.query("SELECT nome FROM usuarios WHERE id=$1", [superior_id]);

    const r = await db.query(`
      INSERT INTO hierarquia_aprovacao (gestor_id, superior_id, centro_custo, desc_cc, ativo)
      VALUES ($1,$2,$3,$4,true) RETURNING *
    `, [gestor_id, superior_id, centro_custo || null, desc_cc || null]);

    const row = {
      ...r.rows[0],
      gestor_nome: ug.rows[0]?.nome || "",
      superior_nome: us.rows[0]?.nome || "",
    };
    return R.created(res, row, "Regra criada com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.atualizarHierarquia = async (req, res) => {
  try {
    const { gestor_id, superior_id, centro_custo, desc_cc, ativo } = req.body;
    const r = await db.query(`
      UPDATE hierarquia_aprovacao
      SET gestor_id=$1, superior_id=$2, centro_custo=$3, desc_cc=$4, ativo=$5, atualizado_em=NOW()
      WHERE id=$6 RETURNING *
    `, [gestor_id, superior_id, centro_custo || null, desc_cc || null, ativo ?? true, req.params.id]);
    if (r.rowCount === 0) return R.notFound(res, "Regra não encontrada");

    const ug = await db.query("SELECT nome FROM usuarios WHERE id=$1", [gestor_id]);
    const us = await db.query("SELECT nome FROM usuarios WHERE id=$1", [superior_id]);
    return R.success(res, { ...r.rows[0], gestor_nome: ug.rows[0]?.nome || "", superior_nome: us.rows[0]?.nome || "" });
  } catch (e) { return R.error(res, e.message); }
};

// ══════════════════════════════════════════════════════════════
// ALÇADAS
// ══════════════════════════════════════════════════════════════

exports.listarAlcadas = async (req, res) => {
  try {
    const r = await db.query(`
      SELECT a.*, e.descricao AS evento_nome, e.codigo AS evento_codigo
      FROM alcadas_aprovacao a
      LEFT JOIN eventos e ON e.id = a.evento_id
      ORDER BY a.criado_em DESC
    `);
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.criarAlcada = async (req, res) => {
  try {
    const { evento_id, num_alcadas, exige_anexo } = req.body;
    if (!evento_id) return R.badRequest(res, "Evento é obrigatório");

    const ev = await db.query("SELECT descricao FROM eventos WHERE id=$1", [evento_id]);
    const r = await db.query(`
      INSERT INTO alcadas_aprovacao (evento_id, num_alcadas, exige_anexo, ativo)
      VALUES ($1,$2,$3,true) RETURNING *
    `, [evento_id, num_alcadas || 1, exige_anexo || false]);

    return R.created(res, { ...r.rows[0], evento_nome: ev.rows[0]?.descricao || "" });
  } catch (e) { return R.error(res, e.message); }
};

exports.atualizarAlcada = async (req, res) => {
  try {
    const { evento_id, num_alcadas, exige_anexo, ativo } = req.body;
    const r = await db.query(`
      UPDATE alcadas_aprovacao
      SET evento_id=$1, num_alcadas=$2, exige_anexo=$3, ativo=$4, atualizado_em=NOW()
      WHERE id=$5 RETURNING *
    `, [evento_id, num_alcadas || 1, exige_anexo || false, ativo ?? true, req.params.id]);
    if (r.rowCount === 0) return R.notFound(res, "Alçada não encontrada");

    const ev = await db.query("SELECT descricao FROM eventos WHERE id=$1", [evento_id]);
    return R.success(res, { ...r.rows[0], evento_nome: ev.rows[0]?.descricao || "" });
  } catch (e) { return R.error(res, e.message); }
};
