// src/controllers/ocorrenciasController.js
"use strict";
const db = require("../config/database");
const R  = require("../utils/response");

// ── Listar ────────────────────────────────────────────────────────────────────
exports.listar = async (req, res) => {
  try {
    const { tipo, colaborador_id, data_inicio, data_fim, status } = req.query;
    let where = ["o.status != 'CANCELADO'"];
    const params = [];
    let i = 1;

    // Gestor só vê os seus
    if (req.usuario.perfil === "gestor") {
      where.push(`o.gestor_id = $${i++}`);
      params.push(req.usuario.id);
    }
    if (tipo)           { where.push(`o.tipo = $${i++}`);             params.push(tipo); }
    if (colaborador_id) { where.push(`o.colaborador_id = $${i++}`);   params.push(colaborador_id); }
    if (status)         { where.push(`o.status = $${i++}`);           params.push(status); }
    if (data_inicio)    { where.push(`o.data_ocorrencia >= $${i++}`); params.push(data_inicio); }
    if (data_fim)       { where.push(`o.data_ocorrencia <= $${i++}`); params.push(data_fim); }

    const sql = `
      SELECT o.* FROM ocorrencias_disciplinares o
      WHERE ${where.join(" AND ")}
      ORDER BY o.criado_em DESC
    `;
    const r = await db.query(sql, params);
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

// ── Buscar por ID ─────────────────────────────────────────────────────────────
exports.buscarPorId = async (req, res) => {
  try {
    const r = await db.query(
      "SELECT * FROM ocorrencias_disciplinares WHERE id = $1", [req.params.id]
    );
    if (r.rowCount === 0) return R.notFound(res, "Ocorrência não encontrada");
    const oc = r.rows[0];
    if (req.usuario.perfil === "gestor" && oc.gestor_id !== req.usuario.id)
      return R.forbidden(res, "Acesso negado");
    return R.success(res, oc);
  } catch (e) { return R.error(res, e.message); }
};

// ── Criar ─────────────────────────────────────────────────────────────────────
exports.criar = async (req, res) => {
  try {
    const {
      tipo, chapa, nome_colaborador,
      motivo, data_ocorrencia, data_inicio, dias_suspensao
    } = req.body;

    // Buscar ID real do colaborador pelo chapa
    let colaborador_id = req.body.colaborador_id;
    if (chapa) {
      const cr = await db.query(
        "SELECT id FROM colaboradores WHERE chapa = $1 LIMIT 1",
        [String(chapa).trim()]
      );
      if (cr.rowCount > 0) colaborador_id = cr.rows[0].id;
    }

    // Calcular data_fim para suspensão
    let data_fim = null;
    if (tipo === "SUSPENSAO" && data_inicio && dias_suspensao) {
      const d = new Date(data_inicio);
      d.setDate(d.getDate() + parseInt(dias_suspensao) - 1);
      data_fim = d.toISOString().split("T")[0];
    }

    const r = await db.query(`
      INSERT INTO ocorrencias_disciplinares
        (tipo, colaborador_id, chapa, nome_colaborador, gestor_id, gestor_nome,
         motivo, data_ocorrencia, data_inicio, data_fim, dias_suspensao)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *
    `, [
      tipo, colaborador_id, chapa, nome_colaborador,
      req.usuario.id, req.usuario.nome,
      motivo, data_ocorrencia,
      data_inicio || null, data_fim,
      dias_suspensao || null
    ]);

    return R.created(res, r.rows[0], "Ocorrência registrada com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

// ── Cancelar ──────────────────────────────────────────────────────────────────
exports.cancelar = async (req, res) => {
  try {
    const r = await db.query(
      "SELECT * FROM ocorrencias_disciplinares WHERE id = $1", [req.params.id]
    );
    if (r.rowCount === 0) return R.notFound(res, "Ocorrência não encontrada");
    const oc = r.rows[0];
    if (req.usuario.perfil === "gestor" && oc.gestor_id !== req.usuario.id)
      return R.forbidden(res, "Acesso negado");
    if (oc.flag_exportado)
      return R.badRequest(res, "Não é possível cancelar uma ocorrência já exportada");

    await db.query(
      "UPDATE ocorrencias_disciplinares SET status = 'CANCELADO', atualizado_em = NOW() WHERE id = $1",
      [req.params.id]
    );
    return R.success(res, {}, "Ocorrência cancelada");
  } catch (e) { return R.error(res, e.message); }
};

// ── Exportar CSV TOTVS RM ─────────────────────────────────────────────────────
// Layout: PFUNC.CHAPA ; PANOTAC.NROANOTACAO ; PANOTAC.TEXTO ; PANOTAC.DTANOTACAO ; PANOTAC.DTRESOLUCAO ; PANOTAC.TIPO
// Advertência = NROANOTACAO:10, TIPO:10
// Suspensão   = NROANOTACAO:11, TIPO:11
exports.exportar = async (req, res) => {
  try {
    const r = await db.query(`
      SELECT * FROM ocorrencias_disciplinares
      WHERE status != 'CANCELADO'
      ORDER BY data_ocorrencia ASC
    `);

    if (r.rowCount === 0)
      return R.badRequest(res, "Nenhuma ocorrência para exportar");

    const formatData = (d) => {
      if (!d) return "";
      const dt = new Date(d);
      const dd = String(dt.getUTCDate()).padStart(2, "0");
      const mm = String(dt.getUTCMonth() + 1).padStart(2, "0");
      const yyyy = dt.getUTCFullYear();
      return `${dd}${mm}${yyyy}`;
    };

    const linhas = r.rows.map(oc => {
      const nroAnotacao = oc.tipo === "ADVERTENCIA" ? "10" : "11";
      const tipo        = oc.tipo === "ADVERTENCIA" ? "10" : "11";
      const chapa       = (oc.chapa || "").padEnd(5, " ").slice(0, 5);
      const texto       = `/@${oc.motivo}@/`;
      const dtAnotacao  = formatData(oc.data_ocorrencia);
      const dtResolucao = oc.data_fim ? formatData(oc.data_fim) : "";

      return [chapa, nroAnotacao, texto, dtAnotacao, dtResolucao, tipo].join(";");
    });

    // Registrar exportação sem bloquear reexportação
    const ids = r.rows.map(o => o.id);
    await db.query(`
      UPDATE ocorrencias_disciplinares
      SET flag_exportado = TRUE,
          data_exportacao = NOW(), exportado_por = $1,
          atualizado_em = NOW()
      WHERE id = ANY($2)
    `, [req.usuario.id, ids]);

    // Salvar log
    await db.query(`
      INSERT INTO log_exportacoes_ocorrencias (usuario_id, usuario_nome, quantidade, ids_exportados)
      VALUES ($1, $2, $3, $4)
    `, [req.usuario.id, req.usuario.nome, ids.length, ids]);

    const filename = `anotacoes_rm_${new Date().toISOString().split("T")[0]}.txt`;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(linhas.join("\n"));
  } catch (e) { return R.error(res, e.message); }
};
