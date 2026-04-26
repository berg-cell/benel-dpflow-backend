// src/controllers/centroCustoController.js
"use strict";
const db = require("../config/database");
const R  = require("../utils/response");

exports.listar = async (req, res) => {
  try {
    const { tipo } = req.query;
    let q = "SELECT * FROM centro_custo WHERE 1=1";
    const p = [];
    if (tipo) { q += " AND tipo=$1"; p.push(tipo.toUpperCase()); }
    q += " ORDER BY codccusto";
    const r = await db.query(q, p);
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.upsertBatch = async (req, res) => {
  try {
    const lista = req.body.lista || req.body;
    if (!Array.isArray(lista) || lista.length === 0)
      return R.badRequest(res, "Lista vazia");

    let inseridos = 0; let atualizados = 0;
    for (const item of lista) {
      if (!item.codccusto || !item.nome) continue;
      const ex = await db.query("SELECT id FROM centro_custo WHERE codccusto=$1", [item.codccusto.trim()]);
      if (ex.rowCount > 0) {
        await db.query(
          "UPDATE centro_custo SET nome=$1, tipo=$2, atualizado_em=NOW() WHERE codccusto=$3",
          [item.nome.trim(), (item.tipo||"ATIVO").toUpperCase(), item.codccusto.trim()]
        );
        atualizados++;
      } else {
        await db.query(
          "INSERT INTO centro_custo(codccusto,nome,tipo) VALUES($1,$2,$3)",
          [item.codccusto.trim(), item.nome.trim(), (item.tipo||"ATIVO").toUpperCase()]
        );
        inseridos++;
      }
    }
    return R.success(res, { inseridos, atualizados },
      `Concluído: ${inseridos} inserido(s), ${atualizados} atualizado(s)`);
  } catch (e) { return R.error(res, e.message); }
};
