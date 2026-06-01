// src/controllers/autorizacaoController.js
"use strict";
const db = require("../config/database");
const R  = require("../utils/response");
const tg = require("../services/telegram");

exports.listar = async (req, res) => {
  try {
    const { perfil, id: userId } = req.usuario;
    let q = `SELECT * FROM autorizacao_desconto WHERE 1=1`;
    const p = [];
    if (perfil === "gestor") { q += ` AND gestor_id=$1`; p.push(userId); }
    q += ` ORDER BY criado_em DESC`;
    const r = await db.query(q, p);
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.criar = async (req, res) => {
  try {
    const { colaborador_id, colaborador_nome, colaborador_cpf,
            valor_total, num_parcelas, mes_inicio, ano_inicio,
            data_ocorrido, descricao_prejuizo, observacoes } = req.body;

    if (!valor_total || !mes_inicio || !ano_inicio)
      return R.badRequest(res, "Campos obrigatórios: valor_total, mes_inicio, ano_inicio");

    const r = await db.query(
      `INSERT INTO autorizacao_desconto
         (colaborador_id, colaborador_nome, colaborador_cpf,
          gestor_id, gestor_nome,
          valor_total, num_parcelas, mes_inicio, ano_inicio,
          data_ocorrido, descricao_prejuizo, observacoes, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pendente')
       RETURNING *`,
      [colaborador_id || null, colaborador_nome || null, colaborador_cpf || null,
       req.usuario.id, req.usuario.nome,
       parseFloat(valor_total), parseInt(num_parcelas) || 1,
       mes_inicio, ano_inicio,
       data_ocorrido || null, descricao_prejuizo || null, observacoes || null]
    );

    // Notificação Telegram
    tg.notificar(req.usuario.id, "autorizacao_desconto", {
      colaborador_nome: colaborador_nome,
      solicitante:      req.usuario.nome,
      tipo:             `${num_parcelas || 1}x parcela(s)`,
      motivo:           descricao_prejuizo,
      observacao:       observacoes,
    }).catch(() => {});

    return R.created(res, r.rows[0], "Autorização criada com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.addAnexo = async (req, res) => {
  try {
    const { nome_arquivo, dados_base64 } = req.body;
    if (!nome_arquivo || !dados_base64)
      return R.badRequest(res, "Nome e dados do arquivo são obrigatórios");
    if (dados_base64.length > 5 * 1024 * 1024)
      return R.badRequest(res, "Arquivo muito grande (máximo 5MB)");

    const check = await db.query(
      "SELECT id, gestor_id FROM autorizacao_desconto WHERE id=$1", [req.params.id]
    );
    if (!check.rowCount) return R.notFound(res, "Autorização não encontrada");
    if (req.usuario.perfil === "gestor" && check.rows[0].gestor_id !== req.usuario.id)
      return R.forbidden(res, "Acesso negado");

    const r = await db.query(
      `UPDATE autorizacao_desconto
         SET anexo_nome=$1, anexo_dados=$2, status='anexado', atualizado_em=NOW()
       WHERE id=$3 RETURNING id, anexo_nome, status`,
      [nome_arquivo, dados_base64, req.params.id]
    );
    return R.success(res, r.rows[0], "Anexo salvo com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.cancelar = async (req, res) => {
  try {
    const r = await db.query(
      `UPDATE autorizacao_desconto SET status='cancelado', atualizado_em=NOW()
       WHERE id=$1 AND status != 'cancelado' RETURNING id, status`,
      [req.params.id]
    );
    if (!r.rowCount) return R.notFound(res, "Autorização não encontrada ou já cancelada");
    return R.success(res, r.rows[0], "Autorização cancelada");
  } catch (e) { return R.error(res, e.message); }
};
