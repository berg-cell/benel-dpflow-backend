// src/controllers/rescisaoImportController.js
"use strict";
const db   = require("../config/database");
const R    = require("../utils/response");
let mssql;
try { mssql = require("mssql"); } catch (_) { mssql = null; }

const RM_CONFIG = {
  server:   process.env.RM_DB_HOST,
  port:     parseInt(process.env.RM_DB_PORT || "1433"),
  database: process.env.RM_DB_NAME,
  user:     process.env.RM_DB_USER,
  password: process.env.RM_DB_PASS,
  options: {
    encrypt:                false,
    trustServerCertificate: true,
    connectTimeout:         30000,
    requestTimeout:         60000,
  },
};

const QUERY_RM = `
SELECT
    PFUNC.CHAPA,
    PFUNC.NOME,
    CASE 
        WHEN LEN(CAST(O.CODFILIAL AS VARCHAR(2))) = 2 
            THEN CAST(O.CODFILIAL AS VARCHAR(2)) + '-' + UPPER(SUBSTRING(O.CIDADE, 1, 3))
        ELSE 
            '0' + CAST(O.CODFILIAL AS VARCHAR(2)) + '-' + UPPER(SUBSTRING(O.CIDADE, 1, 3))
    END AS DES_FILIAL,
    O.NOME AS DESC_FILIAL_COMPLETA,
    PFUNC.DATADEMISSAO,
    MONTH(PFUNC.DATADEMISSAO) AS MES_DEMISSAO,
    YEAR(PFUNC.DATADEMISSAO)  AS ANO_DEMISSAO,
    PFFINANC.MESCOMP,
    PFFINANC.ANOCOMP,
    PFFINANC.NROPERIODO,
    PFUNCAO.NOME AS FUNCAO,
    PFUNC.CODSITUACAO,
    CAST(
        SUM(CASE WHEN PEVENTO.PROVDESCBASE = 'P' THEN PFFINANC.VALOR ELSE 0 END) -
        SUM(CASE WHEN PEVENTO.PROVDESCBASE = 'D' THEN PFFINANC.VALOR ELSE 0 END)
    AS NUMERIC(15,2)) AS LIQUIDO,
    CAST(
        SUM(CASE WHEN PEVENTO.PROVDESCBASE = 'P' THEN PFFINANC.VALOR ELSE 0 END)
    AS NUMERIC(15,2)) AS PROVENTOS,
    CAST(
        SUM(CASE WHEN PEVENTO.PROVDESCBASE = 'D' THEN PFFINANC.VALOR ELSE 0 END)
    AS NUMERIC(15,2)) AS DESCONTOS,
    CAST(
        SUM(CASE WHEN PFFINANC.CODEVENTO IN ('0026','0031','0820','0821','0028') THEN PFFINANC.VALOR ELSE 0 END)
    AS NUMERIC(15,2)) AS FGTS_RESCISORIO,
    CAST(
        (
            SUM(CASE WHEN PEVENTO.PROVDESCBASE = 'P' THEN PFFINANC.VALOR ELSE 0 END) -
            SUM(CASE WHEN PEVENTO.PROVDESCBASE = 'D' THEN PFFINANC.VALOR ELSE 0 END)
        ) +
        SUM(CASE WHEN PFFINANC.CODEVENTO IN ('0026','0031','0820','0821','0028') THEN PFFINANC.VALOR ELSE 0 END)
    AS NUMERIC(15,2)) AS TOTAL,
    P.CPF
FROM PFFINANC (NOLOCK)
LEFT JOIN PFUNC     (NOLOCK) ON (PFUNC.CHAPA = PFFINANC.CHAPA AND PFUNC.CODCOLIGADA = PFFINANC.CODCOLIGADA)
LEFT JOIN PEVENTO   (NOLOCK) ON (PEVENTO.CODIGO = PFFINANC.CODEVENTO AND PEVENTO.CODCOLIGADA = PFFINANC.CODCOLIGADA)
LEFT JOIN PFUNCAO   (NOLOCK) ON (PFUNC.CODCOLIGADA = PFUNCAO.CODCOLIGADA AND PFUNC.CODFUNCAO = PFUNCAO.CODIGO)
LEFT JOIN PSECAO S  (NOLOCK) ON (S.CODIGO = PFUNC.CODSECAO AND S.CODCOLIGADA = PFFINANC.CODCOLIGADA)
LEFT JOIN GFILIAL O (NOLOCK) ON (O.CODCOLIGADA = S.CODCOLIGADA AND O.CODFILIAL = S.CODFILIAL)
LEFT JOIN PPESSOA P (NOLOCK) ON (P.CODIGO = PFUNC.CODPESSOA)
WHERE
    PFFINANC.CODCOLIGADA = 6
    AND PFFINANC.ANOCOMP >= 2026
    AND PFFINANC.NROPERIODO BETWEEN 8 AND 10000
    AND PFFINANC.VALOR <> 0
    AND PFUNC.DATADEMISSAO IS NOT NULL
    AND (PEVENTO.PROVDESCBASE IN ('P','D') OR PFFINANC.CODEVENTO IN ('0026','0031','0820','0821','0028'))
GROUP BY
    PFUNC.CHAPA, PFUNC.NOME,
    O.CODFILIAL, O.CIDADE, O.NOME,
    PFUNC.DATADEMISSAO,
    PFFINANC.MESCOMP, PFFINANC.ANOCOMP, PFFINANC.NROPERIODO,
    PFUNCAO.NOME, PFUNC.CODSITUACAO, P.CPF
ORDER BY O.CODFILIAL, PFUNC.NOME, PFFINANC.ANOCOMP, PFFINANC.MESCOMP
`;

// ── Importar do RM ────────────────────────────────────────────────────────────
exports.importar = async (req, res) => {
  if (!mssql) {
    return R.error(res, "Pacote mssql não instalado. Rode: npm install mssql");
  }
  if (!process.env.RM_DB_HOST) {
    return R.error(res, "Variáveis de ambiente do RM não configuradas (RM_DB_HOST, RM_DB_NAME, RM_DB_USER, RM_DB_PASS)");
  }

  let pool;
  try {
    // Conectar no SQL Server do RM
    pool = await mssql.connect(RM_CONFIG);
    const result = await pool.request().query(QUERY_RM);
    const rows = result.recordset;

    if (!rows || rows.length === 0) {
      return R.success(res, { inseridos: 0, atualizados: 0 }, "Nenhum registro encontrado no RM");
    }

    let inseridos   = 0;
    let atualizados = 0;
    const erros     = [];

    for (const row of rows) {
      try {
        // Buscar colaborador_id pelo chapa
        const { rows: colabs } = await db.query(
          "SELECT id, descricao_filial FROM colaboradores WHERE chapa=$1 LIMIT 1",
          [String(row.CHAPA).trim()]
        );
        const colaborador_id    = colabs[0]?.id || null;
        const filial            = colabs[0]?.descricao_filial || row.DESC_FILIAL_COMPLETA || row.DES_FILIAL || "Sem Filial";

        // Buscar desligamento_id pelo chapa
        const { rows: desls } = await db.query(
          `SELECT id FROM solicitacao_desligamento 
           WHERE chapa=$1 
           ORDER BY criado_em DESC LIMIT 1`,
          [String(row.CHAPA).trim()]
        );
        const desligamento_id = desls[0]?.id || null;

        if (!desligamento_id) {
          erros.push(`Chapa ${row.CHAPA} — desligamento não encontrado no DP Flow`);
          continue;
        }

        // Upsert na rescisao_valores
        const { rows: existing } = await db.query(
          "SELECT id FROM rescisao_valores WHERE desligamento_id=$1 AND competencia_mes=$2 AND competencia_ano=$3",
          [desligamento_id, row.MESCOMP, row.ANOCOMP]
        );

        if (existing[0]) {
          await db.query(`
            UPDATE rescisao_valores SET
              liquido          = $1,
              proventos        = $2,
              descontos        = $3,
              fgts_rescisorio  = $4,
              valor_total      = $5,
              lancado_por_id   = $6,
              lancado_por_nome = $7,
              atualizado_em    = NOW()
            WHERE id = $8
          `, [
            parseFloat(row.LIQUIDO)         || 0,
            parseFloat(row.PROVENTOS)       || 0,
            parseFloat(row.DESCONTOS)       || 0,
            parseFloat(row.FGTS_RESCISORIO) || 0,
            parseFloat(row.TOTAL)           || 0,
            req.usuario.id,
            req.usuario.nome,
            existing[0].id,
          ]);
          atualizados++;
        } else {
          await db.query(`
            INSERT INTO rescisao_valores
              (desligamento_id, colaborador_id, colaborador_nome, colaborador_chapa,
               filial, tipo_desligamento, liquido, proventos, descontos,
               fgts_rescisorio, valor_total,
               competencia_mes, competencia_ano,
               lancado_por_id, lancado_por_nome)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          `, [
            desligamento_id,
            colaborador_id,
            row.NOME,
            String(row.CHAPA).trim(),
            filial,
            row.FUNCAO || null,
            parseFloat(row.LIQUIDO)         || 0,
            parseFloat(row.PROVENTOS)       || 0,
            parseFloat(row.DESCONTOS)       || 0,
            parseFloat(row.FGTS_RESCISORIO) || 0,
            parseFloat(row.TOTAL)           || 0,
            row.MESCOMP,
            row.ANOCOMP,
            req.usuario.id,
            req.usuario.nome,
          ]);
          inseridos++;
        }
      } catch (rowErr) {
        erros.push(`Chapa ${row.CHAPA}: ${rowErr.message}`);
      }
    }

    return R.success(res, { inseridos, atualizados, erros, total_rm: rows.length },
      `Importação concluída: ${inseridos} inserido(s), ${atualizados} atualizado(s)${erros.length ? `, ${erros.length} erro(s)` : ""}`
    );

  } catch (e) {
    return R.error(res, `Erro ao conectar no RM: ${e.message}`);
  } finally {
    if (pool) await pool.close().catch(() => {});
  }
};

// ── Testar conexão com RM ─────────────────────────────────────────────────────
exports.testarConexao = async (req, res) => {
  if (!mssql) {
    return R.error(res, "Pacote mssql não instalado. Rode: npm install mssql");
  }
  if (!process.env.RM_DB_HOST) {
    return R.error(res, "Variáveis RM_DB_HOST, RM_DB_NAME, RM_DB_USER, RM_DB_PASS não configuradas");
  }
  let pool;
  try {
    pool = await mssql.connect(RM_CONFIG);
    await pool.request().query("SELECT 1 AS ok");
    return R.success(res, { conectado: true, host: process.env.RM_DB_HOST }, "Conexão com RM OK");
  } catch (e) {
    return R.error(res, `Falha na conexão: ${e.message}`);
  } finally {
    if (pool) await pool.close().catch(() => {});
  }
};
