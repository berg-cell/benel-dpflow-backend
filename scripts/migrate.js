// scripts/migrate.js
"use strict";
require("dotenv").config();
const db     = require("../src/config/database");
const logger = require("../src/utils/logger");

const SQL = `
-- ── Extensões ────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Usuários ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usuarios (
  id          SERIAL PRIMARY KEY,
  nome        VARCHAR(150)  NOT NULL,
  email       VARCHAR(255)  NOT NULL UNIQUE,
  senha_hash  VARCHAR(255)  NOT NULL,
  perfil      VARCHAR(20)   NOT NULL CHECK (perfil IN ('gestor','superior','dp','admin')),
  ativo       BOOLEAN       NOT NULL DEFAULT true,
  criado_em   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Refresh tokens ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          SERIAL PRIMARY KEY,
  usuario_id  INTEGER       NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE CASCADE,
  token       TEXT          NOT NULL,
  expira_em   TIMESTAMPTZ   NOT NULL,
  criado_em   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Colaboradores ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS colaboradores (
  id            SERIAL PRIMARY KEY,
  chapa         VARCHAR(16)  NOT NULL UNIQUE,
  nome          VARCHAR(200) NOT NULL,
  funcao        VARCHAR(100),
  situacao      VARCHAR(10)  NOT NULL DEFAULT 'Ativo' CHECK (situacao IN ('Ativo','Inativo')),
  centro_custo  VARCHAR(20),
  desc_cc       VARCHAR(100),
  criado_em     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Eventos ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS eventos (
  id            SERIAL PRIMARY KEY,
  codigo        VARCHAR(4)   NOT NULL UNIQUE,
  descricao     VARCHAR(200) NOT NULL,
  tipo          VARCHAR(10)  NOT NULL CHECK (tipo IN ('provento','desconto')),
  forma         VARCHAR(15)  NOT NULL CHECK (forma IN ('valor','hora','referencia')),
  ativo         BOOLEAN      NOT NULL DEFAULT true,
  criado_em     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Hierarquia ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hierarquia (
  id            SERIAL PRIMARY KEY,
  gestor_id     INTEGER      NOT NULL REFERENCES usuarios(id),
  superior_id   INTEGER      NOT NULL REFERENCES usuarios(id),
  centro_custo  VARCHAR(20),
  desc_cc       VARCHAR(100),
  ativo         BOOLEAN      NOT NULL DEFAULT true,
  criado_em     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Alçadas ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alcadas (
  id            SERIAL PRIMARY KEY,
  evento_id     INTEGER      NOT NULL UNIQUE REFERENCES eventos(id),
  num_alcadas   SMALLINT     NOT NULL DEFAULT 2 CHECK (num_alcadas IN (1,2)),
  exige_anexo   BOOLEAN      NOT NULL DEFAULT false,
  ativo         BOOLEAN      NOT NULL DEFAULT true,
  criado_em     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Blocos ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blocos (
  id              SERIAL PRIMARY KEY,
  descricao       VARCHAR(200)   NOT NULL,
  competencia     VARCHAR(6)     NOT NULL,
  evento_id       INTEGER        NOT NULL REFERENCES eventos(id),
  solicitante_id  INTEGER        NOT NULL REFERENCES usuarios(id),
  status          VARCHAR(20)    NOT NULL DEFAULT 'pendente_gestor'
                  CHECK (status IN ('pendente_gestor','pendente_superior','pendente_dp',
                                    'aprovado_final','rejeitado','devolvido')),
  anexo_nome      VARCHAR(255),
  anexo_tamanho   VARCHAR(20),
  criado_em       TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
  atualizado_em   TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ── Linhas do bloco ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bloco_linhas (
  id              SERIAL PRIMARY KEY,
  bloco_id        INTEGER        NOT NULL REFERENCES blocos(id) ON DELETE CASCADE,
  colaborador_id  INTEGER        NOT NULL REFERENCES colaboradores(id),
  data            DATE           NOT NULL,
  hora            VARCHAR(6),
  valor           NUMERIC(15,2)  NOT NULL,
  valor_original  NUMERIC(15,2)  NOT NULL,
  referencia      NUMERIC(15,2)  DEFAULT 0,
  observacao      VARCHAR(500),
  criado_em       TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ── Histórico do bloco ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bloco_historico (
  id          SERIAL PRIMARY KEY,
  bloco_id    INTEGER       NOT NULL REFERENCES blocos(id) ON DELETE CASCADE,
  usuario_id  INTEGER       REFERENCES usuarios(id),
  acao        VARCHAR(30)   NOT NULL,
  observacao  VARCHAR(500),
  criado_em   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Audit log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id            SERIAL PRIMARY KEY,
  usuario_id    INTEGER,
  acao          VARCHAR(60)   NOT NULL,
  tabela        VARCHAR(60),
  registro_id   INTEGER,
  dados_antes   JSONB,
  dados_depois  JSONB,
  ip            VARCHAR(45),
  user_agent    TEXT,
  criado_em     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Índices de performance ────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_blocos_status        ON blocos(status);
CREATE INDEX IF NOT EXISTS idx_blocos_solicitante   ON blocos(solicitante_id);
CREATE INDEX IF NOT EXISTS idx_blocos_competencia   ON blocos(competencia);
CREATE INDEX IF NOT EXISTS idx_audit_usuario        ON audit_log(usuario_id);
CREATE INDEX IF NOT EXISTS idx_audit_acao           ON audit_log(acao);
CREATE INDEX IF NOT EXISTS idx_audit_criado_em      ON audit_log(criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_colaboradores_chapa  ON colaboradores(chapa);
CREATE INDEX IF NOT EXISTS idx_bloco_linhas_bloco   ON bloco_linhas(bloco_id);
`;

(async () => {
  try {
    logger.info("Iniciando migração...");
    await db.query(SQL);
    logger.info("Migração concluída com sucesso!");
    process.exit(0);
  } catch (e) {
    logger.error("Erro na migração", { msg: e.message });
    process.exit(1);
  }
})();
