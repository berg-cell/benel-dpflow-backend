// src/models/index.js
"use strict";
const db = require("../config/database");

// ── Usuário ───────────────────────────────────────────────────────────────────
const UsuarioModel = {
  findAll: () =>
    db.query("SELECT id,nome,email,perfil,ativo,criado_em FROM usuarios ORDER BY nome"),

  findById: (id) =>
    db.query("SELECT id,nome,email,perfil,ativo,criado_em FROM usuarios WHERE id=$1", [id]),

  findByEmail: (email) =>
    db.query("SELECT * FROM usuarios WHERE email=$1 AND ativo=true", [email.toLowerCase().trim()]),

  create: (d) =>
    db.query(
      `INSERT INTO usuarios(nome,email,senha_hash,perfil,ativo)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id,nome,email,perfil,ativo,criado_em`,
      [d.nome, d.email.toLowerCase().trim(), d.senha_hash, d.perfil, d.ativo ?? true]
    ),

  update: (id, d) => {
    const sets = []; const p = []; let i = 1;
    if (d.nome       != null) { sets.push(`nome=$${i++}`);       p.push(d.nome); }
    if (d.email      != null) { sets.push(`email=$${i++}`);      p.push(d.email.toLowerCase()); }
    if (d.perfil     != null) { sets.push(`perfil=$${i++}`);     p.push(d.perfil); }
    if (d.ativo      != null) { sets.push(`ativo=$${i++}`);      p.push(d.ativo); }
    if (d.senha_hash != null) { sets.push(`senha_hash=$${i++}`); p.push(d.senha_hash); }
    sets.push("atualizado_em=NOW()");
    p.push(id);
    return db.query(`UPDATE usuarios SET ${sets.join(",")} WHERE id=$${i} RETURNING id,nome,email,perfil,ativo`, p);
  },

  saveRefreshToken: (userId, token, expiraEm) =>
    db.query(
      `INSERT INTO refresh_tokens(usuario_id,token,expira_em)
       VALUES($1,$2,$3)
       ON CONFLICT(usuario_id) DO UPDATE SET token=$2, expira_em=$3`,
      [userId, token, expiraEm]
    ),

  findRefreshToken: (token) =>
    db.query("SELECT * FROM refresh_tokens WHERE token=$1 AND expira_em>NOW()", [token]),

  deleteRefreshToken: (userId) =>
    db.query("DELETE FROM refresh_tokens WHERE usuario_id=$1", [userId]),
};

// ── Colaborador ───────────────────────────────────────────────────────────────
const ColaboradorModel = {
  findAll: ({ situacao, busca } = {}) => {
    let q = "SELECT * FROM colaboradores WHERE 1=1"; const p = []; let i = 1;
    if (situacao) { q += ` AND situacao=$${i++}`; p.push(situacao); }
    if (busca)    { q += ` AND (nome ILIKE $${i} OR chapa ILIKE $${i})`; p.push(`%${busca}%`); i++; }
    return db.query(q + " ORDER BY nome", p);
  },
  findById:    (id)    => db.query("SELECT * FROM colaboradores WHERE id=$1",    [id]),
  findByChapa: (chapa) => db.query("SELECT * FROM colaboradores WHERE chapa=$1", [chapa]),
  create: (d) =>
    db.query(
      `INSERT INTO colaboradores(chapa,nome,funcao,situacao,centro_custo,desc_cc,cpf,data_admissao)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [d.chapa, d.nome, d.funcao||null, d.situacao||"Ativo", d.centro_custo||null, d.desc_cc||null, d.cpf||null, d.data_admissao||null]
    ),
  update: (id, d) => {
    const sets = []; const p = []; let i = 1;
    ["chapa","nome","funcao","situacao","centro_custo","desc_cc","cpf","data_admissao"].forEach(c => {
      if (d[c] !== undefined) { sets.push(`${c}=$${i++}`); p.push(d[c] || null); }
    });
    sets.push("atualizado_em=NOW()"); p.push(id);
    return db.query(`UPDATE colaboradores SET ${sets.join(",")} WHERE id=$${i} RETURNING *`, p);
  },
  upsertBatch: async (lista) => {
    const out = [];
    for (const item of lista) {
      const ex = await ColaboradorModel.findByChapa(item.chapa);
      if (ex.rowCount > 0) {
        const r = await ColaboradorModel.update(ex.rows[0].id, item);
        out.push({ ...r.rows[0], _op: "atualizado" });
      } else {
        const r = await ColaboradorModel.create(item);
        out.push({ ...r.rows[0], _op: "inserido" });
      }
    }
    return out;
  },
};

// ── Evento ────────────────────────────────────────────────────────────────────
const EventoModel = {
  findAll: (apenasAtivos = false) =>
    db.query(`SELECT * FROM eventos ${apenasAtivos ? "WHERE ativo=true" : ""} ORDER BY codigo`),
  findById:    (id)  => db.query("SELECT * FROM eventos WHERE id=$1",     [id]),
  findByCodigo:(cod) => db.query("SELECT * FROM eventos WHERE codigo=$1", [cod]),
  create: (d) =>
    db.query(
      `INSERT INTO eventos(codigo,descricao,tipo,forma,ativo)
       VALUES($1,$2,$3,$4,$5) RETURNING *`,
      [d.codigo, d.descricao, d.tipo, d.forma, d.ativo ?? true]
    ),
  update: (id, d) => {
    const sets = []; const p = []; let i = 1;
    ["codigo","descricao","tipo","forma","ativo"].forEach(c => {
      if (d[c] !== undefined) { sets.push(`${c}=$${i++}`); p.push(d[c]); }
    });
    sets.push("atualizado_em=NOW()"); p.push(id);
    return db.query(`UPDATE eventos SET ${sets.join(",")} WHERE id=$${i} RETURNING *`, p);
  },
};

// ── Bloco ─────────────────────────────────────────────────────────────────────
const BlocoModel = {
  findAll: ({ status, competencia, solicitante_id } = {}) => {
    let q = `
      SELECT b.*, u.nome AS solicitante_nome,
             e.descricao AS evento_descricao, e.codigo AS evento_codigo
      FROM blocos b
      LEFT JOIN usuarios u ON b.solicitante_id=u.id
      LEFT JOIN eventos  e ON b.evento_id=e.id
      WHERE 1=1
    `;
    const p = []; let i = 1;
    if (status)        { q += ` AND b.status=$${i++}`;         p.push(status); }
    if (competencia)   { q += ` AND b.competencia=$${i++}`;    p.push(competencia); }
    if (solicitante_id){ q += ` AND b.solicitante_id=$${i++}`; p.push(solicitante_id); }
    return db.query(q + " ORDER BY b.criado_em DESC", p);
  },

  findById: (id) =>
    db.query(`
      SELECT b.*, u.nome AS solicitante_nome,
             e.descricao AS evento_descricao, e.codigo AS evento_codigo
      FROM blocos b
      LEFT JOIN usuarios u ON b.solicitante_id=u.id
      LEFT JOIN eventos  e ON b.evento_id=e.id
      WHERE b.id=$1
    `, [id]),

  findLinhas: (blocoId) =>
    db.query(`
      SELECT bl.*, c.nome AS colaborador_nome, c.chapa,
             c.centro_custo, c.desc_cc,
             e.codigo AS evento_codigo, e.descricao AS evento_descricao
      FROM bloco_linhas bl
      LEFT JOIN colaboradores c ON bl.colaborador_id=c.id
      LEFT JOIN blocos b        ON bl.bloco_id=b.id
      LEFT JOIN eventos e       ON b.evento_id=e.id
      WHERE bl.bloco_id=$1
      ORDER BY bl.id
    `, [blocoId]),

  findHistorico: (blocoId) =>
    db.query(`
      SELECT bh.*, u.nome AS usuario_nome
      FROM bloco_historico bh
      LEFT JOIN usuarios u ON bh.usuario_id=u.id
      WHERE bh.bloco_id=$1
      ORDER BY bh.criado_em ASC
    `, [blocoId]),

  create: (dados, solicitanteId) =>
    db.transaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO blocos(descricao,competencia,evento_id,solicitante_id,status,anexo_nome,anexo_tamanho)
         VALUES($1,$2,$3,$4,'pendente_gestor',$5,$6) RETURNING *`,
        [dados.descricao, dados.competencia, dados.evento_id, solicitanteId,
         dados.anexo_nome||null, dados.anexo_tamanho||null]
      );
      const bloco = rows[0];
      for (const l of dados.linhas) {
        await client.query(
          `INSERT INTO bloco_linhas(bloco_id,colaborador_id,data,hora,valor,valor_original,referencia,observacao)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
          [bloco.id, l.colaborador_id, l.data, l.hora||null,
           l.valor, l.valor_original||l.valor, l.referencia||null, l.observacao||null]
        );
      }
      await client.query(
        `INSERT INTO bloco_historico(bloco_id,usuario_id,acao,observacao)
         VALUES($1,$2,'criado','Bloco enviado para aprovação')`,
        [bloco.id, solicitanteId]
      );
      return bloco;
    }),

  avancarStatus: (blocoId, usuarioId, acao, justificativa) =>
    db.transaction(async (client) => {
      const { rows, rowCount } = await client.query("SELECT * FROM blocos WHERE id=$1", [blocoId]);
      if (rowCount === 0) throw Object.assign(new Error("Bloco não encontrado"), { status: 404 });
      const mapa = { pendente_gestor:"pendente_superior", pendente_superior:"pendente_dp", pendente_dp:"aprovado_final" };
      let novoStatus = rows[0].status;
      if (acao === "aprovar")  novoStatus = mapa[novoStatus] || novoStatus;
      if (acao === "rejeitar") novoStatus = "rejeitado";
      if (acao === "devolver") novoStatus = "devolvido";
      await client.query("UPDATE blocos SET status=$1,atualizado_em=NOW() WHERE id=$2", [novoStatus, blocoId]);
      await client.query(
        `INSERT INTO bloco_historico(bloco_id,usuario_id,acao,observacao)
         VALUES($1,$2,$3,$4)`,
        [blocoId, usuarioId, acao, justificativa||null]
      );
      return novoStatus;
    }),
};

// ── Auditoria ─────────────────────────────────────────────────────────────────
const AuditoriaModel = {
  registrar: (d) =>
    db.query(
      `INSERT INTO audit_log(usuario_id,acao,tabela,registro_id,dados_antes,dados_depois,ip,user_agent)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [d.usuario_id||null, d.acao, d.tabela||null, d.registro_id||null,
       d.dados_antes  ? JSON.stringify(d.dados_antes)  : null,
       d.dados_depois ? JSON.stringify(d.dados_depois) : null,
       d.ip||null, d.user_agent||null]
    ),

  findAll: ({ userId, acao, dataInicio, dataFim } = {}) => {
    let q = `
      SELECT al.*, u.nome AS usuario_nome, u.email AS usuario_email
      FROM audit_log al
      LEFT JOIN usuarios u ON al.usuario_id=u.id
      WHERE 1=1
    `;
    const p = []; let i = 1;
    if (userId)    { q += ` AND al.usuario_id=$${i++}`;  p.push(userId); }
    if (acao)      { q += ` AND al.acao=$${i++}`;        p.push(acao); }
    if (dataInicio){ q += ` AND al.criado_em>=$${i++}`;  p.push(dataInicio); }
    if (dataFim)   { q += ` AND al.criado_em<=$${i++}`;  p.push(dataFim); }
    return db.query(q + " ORDER BY al.criado_em DESC LIMIT 1000", p);
  },
};

module.exports = { UsuarioModel, ColaboradorModel, EventoModel, BlocoModel, AuditoriaModel, DesligamentoModel };

// ── Solicitação de Desligamento ───────────────────────────────────────────────
const DesligamentoModel = {
  findAll: ({ gestor_id, status, perfil } = {}) => {
    let q = `
      SELECT sd.*,
             c.nome AS colaborador_nome, c.chapa, c.cpf, c.funcao,
             c.centro_custo, c.desc_cc, c.tipo_contrato, c.data_fim_contrato,
             u.nome AS gestor_nome
      FROM solicitacao_desligamento sd
      LEFT JOIN colaboradores c ON sd.colaborador_id = c.id
      LEFT JOIN usuarios u      ON sd.gestor_id = u.id
      WHERE 1=1
    `;
    const p = []; let i = 1;
    if (status)    { q += ` AND sd.status=$${i++}`;    p.push(status); }
    if (perfil === "gestor" && gestor_id)
                   { q += ` AND sd.gestor_id=$${i++}`; p.push(gestor_id); }
    return db.query(q + " ORDER BY sd.criado_em DESC", p);
  },

  findById: (id) =>
    db.query(`
      SELECT sd.*,
             c.nome AS colaborador_nome, c.chapa, c.cpf, c.funcao,
             c.centro_custo, c.desc_cc, c.tipo_contrato, c.data_fim_contrato,
             u.nome AS gestor_nome
      FROM solicitacao_desligamento sd
      LEFT JOIN colaboradores c ON sd.colaborador_id = c.id
      LEFT JOIN usuarios u      ON sd.gestor_id = u.id
      WHERE sd.id=$1
    `, [id]),

  findLogs: (solicitacaoId) =>
    db.query(`
      SELECT sdl.*, u.nome AS usuario_nome
      FROM solicitacao_desligamento_logs sdl
      LEFT JOIN usuarios u ON sdl.usuario_id = u.id
      WHERE sdl.solicitacao_id=$1
      ORDER BY sdl.criado_em ASC
    `, [solicitacaoId]),

  findAnexos: (solicitacaoId) =>
    db.query(`
      SELECT id, solicitacao_id, nome_arquivo, tipo_arquivo, usuario_id, criado_em
      FROM solicitacao_desligamento_anexos
      WHERE solicitacao_id=$1
      ORDER BY criado_em ASC
    `, [solicitacaoId]),

  create: (dados, gestorId) =>
    db.transaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO solicitacao_desligamento
           (colaborador_id, gestor_id, tipo, data_desligamento, data_aviso,
            reducao_jornada, justificativa, observacoes, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'rascunho') RETURNING *`,
        [dados.colaborador_id, gestorId, dados.tipo,
         dados.data_desligamento, dados.data_aviso || null,
         dados.reducao_jornada || false,
         dados.justificativa || null, dados.observacoes || null]
      );
      const sol = rows[0];
      await client.query(
        `INSERT INTO solicitacao_desligamento_logs
           (solicitacao_id, usuario_id, acao, dados_depois)
         VALUES ($1,$2,'criado',$3)`,
        [sol.id, gestorId, JSON.stringify(dados)]
      );
      return sol;
    }),

  enviar: (id, usuarioId) =>
    db.transaction(async (client) => {
      const { rows } = await client.query(
        `UPDATE solicitacao_desligamento
         SET status='pendente_superior', atualizado_em=NOW()
         WHERE id=$1 AND status='rascunho' RETURNING *`,
        [id]
      );
      if (!rows.length) throw Object.assign(new Error("Solicitação não encontrada ou já enviada"), { status: 400 });
      await client.query(
        `INSERT INTO solicitacao_desligamento_logs(solicitacao_id,usuario_id,acao)
         VALUES ($1,$2,'enviado')`,
        [id, usuarioId]
      );
      return rows[0];
    }),

  avancarStatus: (id, usuarioId, acao, observacao) =>
    db.transaction(async (client) => {
      const { rows, rowCount } = await client.query(
        "SELECT * FROM solicitacao_desligamento WHERE id=$1", [id]
      );
      if (!rowCount) throw Object.assign(new Error("Solicitação não encontrada"), { status: 404 });
      const mapa = {
        pendente_superior: "pendente_dp",
        pendente_dp:       "aprovado",
      };
      let novoStatus = rows[0].status;
      if (acao === "aprovar")           novoStatus = mapa[novoStatus] || "aprovado";
      if (acao === "reprovar")          novoStatus = "reprovado";
      if (acao === "solicitar_ajuste")  novoStatus = "ajuste_solicitado";
      if (acao === "finalizar")         novoStatus = "finalizado";
      await client.query(
        `UPDATE solicitacao_desligamento
         SET status=$1, atualizado_em=NOW() WHERE id=$2`,
        [novoStatus, id]
      );
      await client.query(
        `INSERT INTO solicitacao_desligamento_logs
           (solicitacao_id, usuario_id, acao, observacao, dados_antes, dados_depois)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [id, usuarioId, acao, observacao || null,
         JSON.stringify({ status: rows[0].status }),
         JSON.stringify({ status: novoStatus })]
      );
      return novoStatus;
    }),

  addAnexo: (solicitacaoId, usuarioId, dados) =>
    db.query(
      `INSERT INTO solicitacao_desligamento_anexos
         (solicitacao_id, nome_arquivo, tipo_arquivo, dados_base64, usuario_id)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, nome_arquivo, tipo_arquivo, criado_em`,
      [solicitacaoId, dados.nome_arquivo, dados.tipo_arquivo,
       dados.dados_base64, usuarioId]
    ),

  getAnexo: (anexoId) =>
    db.query(
      "SELECT * FROM solicitacao_desligamento_anexos WHERE id=$1", [anexoId]
    ),
};
