// src/controllers/disciplinarController.js
"use strict";
const db = require("../config/database");
const R  = require("../utils/response");
const tg = require("../services/telegram");

// ── Cartilha ──────────────────────────────────────────────────────────────────
exports.listarCartilha = async (req, res) => {
  try {
    const { categoria } = req.query;
    let where = "WHERE ativo=true";
    const p = [];
    if (categoria) { where += " AND categoria=$1"; p.push(categoria); }
    const { rows } = await db.query(
      `SELECT * FROM cartilha_disciplinar ${where} ORDER BY categoria, id`, p
    );
    return R.success(res, rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.criarCartilha = async (req, res) => {
  try {
    const { categoria, descricao, nivel_inicial,
            tem_leve, tem_media, tem_grave, tem_gravissima,
            penalidade_leve, penalidade_media, penalidade_grave, penalidade_gravissima,
            dias_media, dias_grave } = req.body;
    const { rows } = await db.query(`
      INSERT INTO cartilha_disciplinar
        (categoria,descricao,nivel_inicial,tem_leve,tem_media,tem_grave,tem_gravissima,
         penalidade_leve,penalidade_media,penalidade_grave,penalidade_gravissima,dias_media,dias_grave)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *
    `, [categoria,descricao,nivel_inicial,
        tem_leve||false,tem_media||false,tem_grave||false,tem_gravissima||false,
        penalidade_leve||'Advertência Escrita',
        penalidade_media||'Suspensão 2 dias',
        penalidade_grave||'Suspensão 4 dias',
        penalidade_gravissima||'Demissão/Comissão Interna',
        dias_media||2, dias_grave||4]);
    return R.created(res, rows[0], "Enquadramento criado");
  } catch (e) { return R.error(res, e.message); }
};

exports.atualizarCartilha = async (req, res) => {
  try {
    const { id } = req.params;
    const { categoria, descricao, nivel_inicial,
            tem_leve, tem_media, tem_grave, tem_gravissima,
            penalidade_leve, penalidade_media, penalidade_grave, penalidade_gravissima,
            dias_media, dias_grave, ativo } = req.body;
    const { rows } = await db.query(`
      UPDATE cartilha_disciplinar SET
        categoria=$1, descricao=$2, nivel_inicial=$3,
        tem_leve=$4, tem_media=$5, tem_grave=$6, tem_gravissima=$7,
        penalidade_leve=$8, penalidade_media=$9, penalidade_grave=$10, penalidade_gravissima=$11,
        dias_media=$12, dias_grave=$13, ativo=$14, atualizado_em=NOW()
      WHERE id=$15 RETURNING *
    `, [categoria,descricao,nivel_inicial,
        tem_leve,tem_media,tem_grave,tem_gravissima,
        penalidade_leve,penalidade_media,penalidade_grave,penalidade_gravissima,
        dias_media,dias_grave,ativo??true,id]);
    if (!rows[0]) return R.notFound(res, "Enquadramento não encontrado");
    return R.success(res, rows[0], "Atualizado");
  } catch (e) { return R.error(res, e.message); }
};

// ── Sugestão automática baseada em histórico ──────────────────────────────────
exports.sugerirPenalidade = async (req, res) => {
  try {
    const { colaborador_id, cartilha_id } = req.query;
    if (!colaborador_id || !cartilha_id)
      return R.badRequest(res, "colaborador_id e cartilha_id obrigatórios");

    // Buscar enquadramento
    const { rows: cart } = await db.query(
      "SELECT * FROM cartilha_disciplinar WHERE id=$1", [cartilha_id]
    );
    if (!cart[0]) return R.notFound(res, "Enquadramento não encontrado");
    const c = cart[0];

    // Buscar histórico do colaborador para este enquadramento
    const { rows: hist } = await db.query(`
      SELECT nivel_final, status FROM solicitacao_disciplinar
      WHERE colaborador_id=$1 AND cartilha_id=$2
        AND status IN ('aprovado','finalizado')
      ORDER BY criado_em DESC
    `, [colaborador_id, cartilha_id]);

    // Escalonamento automático
    const niveis = [];
    if (c.tem_leve)        niveis.push('LEVE');
    if (c.tem_media)       niveis.push('MEDIA');
    if (c.tem_grave)       niveis.push('GRAVE');
    if (c.tem_gravissima)  niveis.push('GRAVISSIMA');

    // Próximo nível baseado no histórico
    let idx = 0;
    if (hist.length > 0) {
      const ultimoNivel = hist[0].nivel_final || c.nivel_inicial;
      const idxUltimo = niveis.indexOf(ultimoNivel);
      idx = Math.min(idxUltimo + 1, niveis.length - 1);
    } else {
      idx = niveis.indexOf(c.nivel_inicial);
      if (idx < 0) idx = 0;
    }

    const nivelSugerido = niveis[idx] || c.nivel_inicial;
    const penMap = {
      LEVE: c.penalidade_leve || 'Advertência Escrita',
      MEDIA: c.penalidade_media || 'Suspensão 2 dias',
      GRAVE: c.penalidade_grave || 'Suspensão 4 dias',
      GRAVISSIMA: c.penalidade_gravissima || 'Demissão/Comissão Interna',
    };
    const diasMap = { LEVE:0, MEDIA:c.dias_media||2, GRAVE:c.dias_grave||4, GRAVISSIMA:0 };

    // Resumo do histórico
    const historicoResumo = hist.map((h,i) => `${i+1}ª ocorrência: ${h.nivel_final}`).join('; ');

    return R.success(res, {
      nivel_sugerido:    nivelSugerido,
      penalidade_sugerida: penMap[nivelSugerido],
      dias_sugeridos:    diasMap[nivelSugerido],
      total_ocorrencias: hist.length,
      historico_resumo:  historicoResumo || "Primeira ocorrência",
      proximo_nivel_idx: idx,
      niveis_disponiveis: niveis,
    });
  } catch (e) { return R.error(res, e.message); }
};

// ── Listar solicitações ───────────────────────────────────────────────────────
exports.listar = async (req, res) => {
  try {
    const { status, gestor_id } = req.query;
    let where = ["1=1"];
    const p = [];

    if (req.usuario.perfil === "gestor") {
      where.push(`sd.gestor_id=$${p.length+1}`); p.push(req.usuario.id);
    } else if (gestor_id) {
      where.push(`sd.gestor_id=$${p.length+1}`); p.push(gestor_id);
    }
    if (status && status !== "todos") {
      where.push(`sd.status=$${p.length+1}`); p.push(status);
    }

    const { rows } = await db.query(`
      SELECT sd.*,
             c.nome AS colaborador_nome_full, c.chapa AS colaborador_chapa,
             c.funcao, c.descricao_filial,
             cd.descricao AS cartilha_descricao, cd.categoria AS cartilha_categoria
      FROM solicitacao_disciplinar sd
      LEFT JOIN colaboradores c ON c.id = sd.colaborador_id
      LEFT JOIN cartilha_disciplinar cd ON cd.id = sd.cartilha_id
      WHERE ${where.join(" AND ")}
      ORDER BY sd.criado_em DESC
    `, p);
    return R.success(res, rows);
  } catch (e) { return R.error(res, e.message); }
};

// ── Buscar por ID ─────────────────────────────────────────────────────────────
exports.buscarPorId = async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT sd.*,
             c.nome AS colaborador_nome_full, c.chapa AS colaborador_chapa,
             c.funcao, c.descricao_filial, c.cpf,
             cd.descricao AS cartilha_descricao, cd.categoria AS cartilha_categoria,
             cd.tem_leve, cd.tem_media, cd.tem_grave, cd.tem_gravissima
      FROM solicitacao_disciplinar sd
      LEFT JOIN colaboradores c ON c.id = sd.colaborador_id
      LEFT JOIN cartilha_disciplinar cd ON cd.id = sd.cartilha_id
      WHERE sd.id = $1
    `, [req.params.id]);
    if (!rows[0]) return R.notFound(res, "Solicitação não encontrada");
    return R.success(res, rows[0]);
  } catch (e) { return R.error(res, e.message); }
};

// ── Criar solicitação (gestor) ────────────────────────────────────────────────
exports.criar = async (req, res) => {
  try {
    const { colaborador_id, descricao_ocorrido, cartilha_id, sem_enquadramento,
            nivel_sugerido, penalidade_sugerida, dias_sugeridos, historico_resumo } = req.body;

    if (!colaborador_id || !descricao_ocorrido)
      return R.badRequest(res, "colaborador_id e descricao_ocorrido são obrigatórios");

    const { rows: col } = await db.query(
      "SELECT nome, chapa FROM colaboradores WHERE id=$1", [colaborador_id]
    );
    if (!col[0]) return R.notFound(res, "Colaborador não encontrado");

    const { rows } = await db.query(`
      INSERT INTO solicitacao_disciplinar
        (colaborador_id, chapa, nome_colaborador,
         gestor_id, gestor_nome, descricao_ocorrido,
         cartilha_id, sem_enquadramento,
         nivel_sugerido, penalidade_sugerida, dias_sugeridos, historico_resumo,
         status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pendente_juridico')
      RETURNING *
    `, [
      colaborador_id, col[0].chapa, col[0].nome,
      req.usuario.id, req.usuario.nome, descricao_ocorrido,
      cartilha_id||null, sem_enquadramento||false,
      nivel_sugerido||null, penalidade_sugerida||null,
      dias_sugeridos||0, historico_resumo||null,
    ]);

    // Notificar Jurídico
    tg.notificar(req.usuario.id, "ocorrencia_disciplinar", {
      colaborador_nome: col[0].nome,
      chapa: col[0].chapa,
      solicitante: req.usuario.nome,
      tipo: sem_enquadramento ? "Sem enquadramento na cartilha" : "Enquadramento selecionado",
      motivo: descricao_ocorrido?.substring(0,100),
    }).catch(() => {});

    return R.created(res, rows[0], "Solicitação criada e enviada ao Jurídico");
  } catch (e) { return R.error(res, e.message); }
};

// ── Análise do Jurídico ───────────────────────────────────────────────────────
exports.analisar = async (req, res) => {
  try {
    const { id } = req.params;
    const { acao, observacao, nivel_final, penalidade_final,
            dias_final, texto_juridico, cartilha_id } = req.body;

    if (!["aprovar","reprovar","alterar"].includes(acao))
      return R.badRequest(res, "acao deve ser aprovar, reprovar ou alterar");

    const { rows: sols } = await db.query(
      "SELECT * FROM solicitacao_disciplinar WHERE id=$1", [id]
    );
    if (!sols[0]) return R.notFound(res, "Solicitação não encontrada");
    if (sols[0].status !== "pendente_juridico")
      return R.badRequest(res, "Solicitação não está pendente de análise jurídica");

    const novoStatus = acao === "reprovar" ? "reprovado" : "aprovado";

    const { rows } = await db.query(`
      UPDATE solicitacao_disciplinar SET
        juridico_id=$1, juridico_nome=$2, juridico_acao=$3,
        juridico_observacao=$4, nivel_final=$5, penalidade_final=$6,
        dias_final=$7, texto_juridico=$8, status=$9,
        cartilha_id=COALESCE($10, cartilha_id),
        data_analise_juridico=NOW(), atualizado_em=NOW()
      WHERE id=$11 RETURNING *
    `, [
      req.usuario.id, req.usuario.nome, acao,
      observacao||null, nivel_final||sols[0].nivel_sugerido,
      penalidade_final||sols[0].penalidade_sugerida,
      dias_final||0, texto_juridico||null, novoStatus,
      cartilha_id||null, id
    ]);

    return R.success(res, rows[0], `Solicitação ${novoStatus} pelo Jurídico`);
  } catch (e) { return R.error(res, e.message); }
};

// ── Cancelar ──────────────────────────────────────────────────────────────────
exports.cancelar = async (req, res) => {
  try {
    await db.query(
      "UPDATE solicitacao_disciplinar SET status='cancelado', atualizado_em=NOW() WHERE id=$1",
      [req.params.id]
    );
    return R.success(res, {}, "Cancelado");
  } catch (e) { return R.error(res, e.message); }
};
