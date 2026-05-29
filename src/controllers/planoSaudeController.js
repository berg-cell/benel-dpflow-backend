// src/controllers/planoSaudeController.js
"use strict";
const db = require("../config/database");
const R = require("../utils/response");

// ── Listar solicitações ───────────────────────────────────────────────────────
exports.listar = async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT pss.*,
             c.nome AS colaborador_nome, c.chapa, c.cpf, c.funcao,
             c.data_admissao, c.centro_custo, c.desc_cc,
             c.rg, c.rg_orgao, c.rg_uf, c.nome_mae, c.estado_civil,
             c.pis, c.ctps, c.ctps_serie,
             c.logradouro, c.complemento, c.bairro, c.cidade, c.uf, c.cep,
             c.telefone1, c.telefone2, c.telefone3
      FROM plano_saude_solicitacoes pss
      JOIN colaboradores c ON pss.colaborador_id = c.id
      ORDER BY pss.criado_em DESC
    `);
    return R.success(res, rows);
  } catch (e) {
    return R.error(res, e.message);
  }
};

// ── Buscar por ID ─────────────────────────────────────────────────────────────
exports.buscarPorId = async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await db.query(`
      SELECT pss.*,
             c.nome AS colaborador_nome, c.chapa, c.cpf, c.funcao,
             c.data_admissao, c.centro_custo, c.desc_cc,
             c.rg, c.rg_orgao, c.rg_uf, c.nome_mae, c.estado_civil,
             c.pis, c.ctps, c.ctps_serie,
             c.logradouro, c.complemento, c.bairro, c.cidade, c.uf, c.cep,
             c.telefone1, c.telefone2, c.telefone3
      FROM plano_saude_solicitacoes pss
      JOIN colaboradores c ON pss.colaborador_id = c.id
      WHERE pss.id = $1
    `, [id]);
    if (!rows[0]) return R.notFound(res, "Solicitação não encontrada");

    // Buscar anexos
    const { rows: anexos } = await db.query(
      `SELECT id, nome_arquivo, tipo_anexo, criado_em FROM plano_saude_anexos WHERE solicitacao_id = $1 ORDER BY criado_em`,
      [id]
    );
    return R.success(res, { ...rows[0], anexos });
  } catch (e) {
    return R.error(res, e.message);
  }
};

// ── Criar solicitação ─────────────────────────────────────────────────────────
exports.criar = async (req, res) => {
  try {
    const {
      tipo, movimentacao, colaborador_id,
      dep_cpf, dep_nome, dep_sexo, dep_data_nasc,
      dep_estado_civil, dep_data_casamento,
      dep_grau_parentesco, dep_nome_mae,
    } = req.body;

    if (!tipo || !movimentacao || !colaborador_id)
      return R.badRequest(res, "tipo, movimentacao e colaborador_id são obrigatórios");

    const { rows } = await db.query(`
      INSERT INTO plano_saude_solicitacoes
        (tipo, movimentacao, colaborador_id,
         dep_cpf, dep_nome, dep_sexo, dep_data_nasc,
         dep_estado_civil, dep_data_casamento,
         dep_grau_parentesco, dep_nome_mae)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *
    `, [
      tipo, movimentacao, colaborador_id,
      dep_cpf || null, dep_nome || null, dep_sexo || null,
      dep_data_nasc || null, dep_estado_civil || null,
      dep_data_casamento || null, dep_grau_parentesco || null, dep_nome_mae || null,
    ]);

    return R.created(res, rows[0], "Solicitacao criada");
  } catch (e) {
    return R.error(res, e.message);
  }
};

// ── Adicionar anexo ───────────────────────────────────────────────────────────
exports.addAnexo = async (req, res) => {
  try {
    const { id } = req.params;
    const { nome_arquivo, tipo_anexo, dados_base64 } = req.body;

    if (!nome_arquivo || !dados_base64)
      return R.badRequest(res, "nome_arquivo e dados_base64 são obrigatórios");

    const { rows } = await db.query(`
      INSERT INTO plano_saude_anexos (solicitacao_id, nome_arquivo, tipo_anexo, dados_base64)
      VALUES ($1, $2, $3, $4) RETURNING id, nome_arquivo, tipo_anexo, criado_em
    `, [id, nome_arquivo, tipo_anexo || null, dados_base64]);

    return R.created(res, rows[0], "Solicitacao criada");
  } catch (e) {
    return R.error(res, e.message);
  }
};

// ── Buscar anexo (download) ───────────────────────────────────────────────────
exports.getAnexo = async (req, res) => {
  try {
    const { id, anexoId } = req.params;
    const { rows } = await db.query(
      `SELECT * FROM plano_saude_anexos WHERE id=$1 AND solicitacao_id=$2`,
      [anexoId, id]
    );
    if (!rows[0]) return R.notFound(res, "Anexo não encontrado");
    return R.success(res, rows[0]);
  } catch (e) {
    return R.error(res, e.message);
  }
};

// ── Cancelar ──────────────────────────────────────────────────────────────────
exports.cancelar = async (req, res) => {
  try {
    const { id } = req.params;
    await db.query(
      `UPDATE plano_saude_solicitacoes SET status='cancelado', atualizado_em=NOW() WHERE id=$1`,
      [id]
    );
    return R.success(res, { message: "Cancelado com sucesso" });
  } catch (e) {
    return R.error(res, e.message);
  }
};
