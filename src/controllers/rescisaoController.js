// src/controllers/rescisaoController.js
"use strict";
const db = require("../config/database");
const R  = require("../utils/response");

// ── Listar por competência ────────────────────────────────────────────────────
exports.listar = async (req, res) => {
  try {
    const { mes, ano } = req.query;
    const params = [];
    let where = ["1=1"];

    if (mes) { where.push(`competencia_mes=$${params.length+1}`); params.push(parseInt(mes)); }
    if (ano) { where.push(`competencia_ano=$${params.length+1}`); params.push(parseInt(ano)); }

    const { rows } = await db.query(`
      SELECT rv.*
      FROM rescisao_valores rv
      WHERE ${where.join(" AND ")}
      ORDER BY rv.filial, rv.criado_em DESC
    `, params);

    return R.success(res, rows);
  } catch (e) { return R.error(res, e.message); }
};

// ── Lançar / atualizar valor ──────────────────────────────────────────────────
exports.lancar = async (req, res) => {
  try {
    const {
      desligamento_id, chapa, nome, filial,
      valor_total, liquido, proventos, descontos, fgts_rescisorio,
      competencia_mes, competencia_ano, observacao
    } = req.body;

    if ((!desligamento_id && !chapa) || !competencia_mes || !competencia_ano)
      return R.badRequest(res, "desligamento_id ou chapa, competencia_mes e competencia_ano são obrigatórios");

    // Buscar desligamento — por id ou por chapa
    let desl = null;
    if (desligamento_id) {
      const { rows: desls } = await db.query(`
        SELECT sd.*, c.descricao_filial, c.id AS col_id, c.nome AS col_nome, c.chapa AS col_chapa
        FROM solicitacao_desligamento sd
        LEFT JOIN colaboradores c ON c.chapa = sd.chapa
        WHERE sd.id = $1
      `, [desligamento_id]);
      desl = desls[0];
    } else {
      const { rows: desls } = await db.query(`
        SELECT sd.*, c.descricao_filial, c.id AS col_id, c.nome AS col_nome, c.chapa AS col_chapa
        FROM solicitacao_desligamento sd
        LEFT JOIN colaboradores c ON c.id = sd.colaborador_id
        WHERE c.chapa = $1
        ORDER BY sd.criado_em DESC LIMIT 1
      `, [String(chapa).trim()]);
      desl = desls[0];
    }

    if (!desl) {
      // Se não achar desligamento, cria registro sem vínculo
      desl = {
        col_id: null,
        col_nome: nome,
        col_chapa: chapa,
        descricao_filial: filial,
        tipo: null,
        id: null,
      };
    }

    // Upsert — um lançamento por desligamento
    const vTotal   = parseFloat(valor_total || 0);
    const vLiquido = parseFloat(liquido   || 0);
    const vProv    = parseFloat(proventos || 0);
    const vDesc    = parseFloat(descontos || 0);
    const vFgts    = parseFloat(fgts_rescisorio || 0);
    const filialFinal = filial || desl.descricao_filial || "Sem Filial";

    const { rows } = await db.query(`
      INSERT INTO rescisao_valores
        (desligamento_id, colaborador_id, colaborador_nome, colaborador_chapa,
         filial, tipo_desligamento, valor_total,
         liquido, proventos, descontos, fgts_rescisorio,
         competencia_mes, competencia_ano, observacao,
         lancado_por_id, lancado_por_nome)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      ON CONFLICT (desligamento_id, competencia_mes, competencia_ano) DO UPDATE SET
        valor_total       = EXCLUDED.valor_total,
        liquido           = EXCLUDED.liquido,
        proventos         = EXCLUDED.proventos,
        descontos         = EXCLUDED.descontos,
        fgts_rescisorio   = EXCLUDED.fgts_rescisorio,
        observacao        = EXCLUDED.observacao,
        lancado_por_id    = EXCLUDED.lancado_por_id,
        lancado_por_nome  = EXCLUDED.lancado_por_nome,
        atualizado_em     = NOW()
      RETURNING *
    `, [
      desl.id || null,
      desl.col_id || null,
      desl.col_nome || nome,
      desl.col_chapa || chapa,
      filialFinal,
      desl.tipo || null,
      vTotal,
      vLiquido, vProv, vDesc, vFgts,
      parseInt(competencia_mes),
      parseInt(competencia_ano),
      observacao || null,
      req.usuario.id,
      req.usuario.nome,
    ]);

    return R.created(res, rows[0], "Valor lançado com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

// ── Importar em lote (CSV) ───────────────────────────────────────────────────
exports.importarLote = async (req, res) => {
  try {
    const { registros } = req.body;
    if (!Array.isArray(registros) || registros.length === 0)
      return R.badRequest(res, "Lista de registros vazia");

    let inseridos = 0, atualizados = 0;
    const erros = [];

    for (const reg of registros) {
      try {
        const { chapa, nome, filial, liquido, proventos, descontos,
                fgts_rescisorio, valor_total, competencia_mes, competencia_ano } = reg;

        if (!chapa || !competencia_mes || !competencia_ano) {
          erros.push(`Chapa ${chapa}: dados incompletos`);
          continue;
        }

        // Buscar colaborador e desligamento
        const { rows: colabs } = await db.query(
          "SELECT id, descricao_filial, nome FROM colaboradores WHERE chapa=$1 LIMIT 1",
          [String(chapa).trim()]
        );

        const { rows: desls } = await db.query(`
          SELECT sd.id, sd.tipo
          FROM solicitacao_desligamento sd
          LEFT JOIN colaboradores c ON c.id = sd.colaborador_id
          WHERE c.chapa = $1
          ORDER BY sd.criado_em DESC LIMIT 1
        `, [String(chapa).trim()]);

        const col       = colabs[0];
        const desl      = desls[0];
        const filialFinal = col?.descricao_filial || filial || "Sem Filial";

        const { rows: existing } = await db.query(
          "SELECT id FROM rescisao_valores WHERE colaborador_chapa=$1 AND competencia_mes=$2 AND competencia_ano=$3",
          [String(chapa).trim(), parseInt(competencia_mes), parseInt(competencia_ano)]
        );

        if (existing[0]) {
          await db.query(`
            UPDATE rescisao_valores SET
              liquido=$1, proventos=$2, descontos=$3, fgts_rescisorio=$4, valor_total=$5,
              lancado_por_id=$6, lancado_por_nome=$7, atualizado_em=NOW()
            WHERE id=$8
          `, [
            parseFloat(liquido)||0, parseFloat(proventos)||0, parseFloat(descontos)||0,
            parseFloat(fgts_rescisorio)||0, parseFloat(valor_total)||0,
            req.usuario.id, req.usuario.nome, existing[0].id
          ]);
          atualizados++;
        } else {
          await db.query(`
            INSERT INTO rescisao_valores
              (desligamento_id, colaborador_id, colaborador_nome, colaborador_chapa,
               filial, tipo_desligamento, liquido, proventos, descontos,
               fgts_rescisorio, valor_total, competencia_mes, competencia_ano,
               lancado_por_id, lancado_por_nome)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          `, [
            desl?.id || null,
            col?.id  || null,
            col?.nome || nome,
            String(chapa).trim(),
            filialFinal,
            desl?.tipo || null,
            parseFloat(liquido)||0, parseFloat(proventos)||0, parseFloat(descontos)||0,
            parseFloat(fgts_rescisorio)||0, parseFloat(valor_total)||0,
            parseInt(competencia_mes), parseInt(competencia_ano),
            req.usuario.id, req.usuario.nome
          ]);
          inseridos++;
        }
      } catch (e) {
        erros.push(`Chapa ${reg.chapa}: ${e.message}`);
      }
    }

    return R.success(res, { inseridos, atualizados, erros, total: registros.length },
      `Importação concluída: ${inseridos} inserido(s), ${atualizados} atualizado(s)`
    );
  } catch (e) { return R.error(res, e.message); }
};

// ── Excluir lançamento ────────────────────────────────────────────────────────
exports.excluir = async (req, res) => {
  try {
    const { id } = req.params;
    await db.query("DELETE FROM rescisao_valores WHERE id=$1", [id]);
    return R.success(res, {}, "Lançamento excluído");
  } catch (e) { return R.error(res, e.message); }
};

// ── Buscar por desligamento_id ────────────────────────────────────────────────
exports.buscarPorDesligamento = async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await db.query(
      "SELECT * FROM rescisao_valores WHERE desligamento_id=$1", [id]
    );
    return R.success(res, rows[0] || null);
  } catch (e) { return R.error(res, e.message); }
};
