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
  id                    SERIAL PRIMARY KEY,
  chapa                 VARCHAR(16)  NOT NULL UNIQUE,
  nome                  VARCHAR(200) NOT NULL,
  funcao                VARCHAR(100),
  situacao              VARCHAR(10)  NOT NULL DEFAULT 'Ativo' CHECK (situacao IN ('Ativo','Inativo')),
  cod_situacao          VARCHAR(5),
  centro_custo          VARCHAR(20),
  desc_cc               VARCHAR(100),
  cpf                   VARCHAR(14),
  data_admissao         DATE,
  tipo_contrato         VARCHAR(30),
  data_fim_contrato     DATE,
  data_fim_estabilidade DATE,
  descricao_estabilidade VARCHAR(200),
  criado_em             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  atualizado_em         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Garante colunas em bancos que já existiam antes dessa versão do migrate
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS cpf                    VARCHAR(14);
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS data_admissao          DATE;
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS tipo_contrato          VARCHAR(30);
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS data_fim_contrato      DATE;
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS cod_situacao           VARCHAR(5);
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS data_fim_estabilidade  DATE;
ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS descricao_estabilidade VARCHAR(200);

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

-- ── Centro de Custo ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS centro_custo (
  id          SERIAL PRIMARY KEY,
  codccusto   VARCHAR(30)  NOT NULL UNIQUE,
  nome        VARCHAR(200) NOT NULL,
  tipo        VARCHAR(20)  NOT NULL DEFAULT 'ATIVO' CHECK (tipo IN ('ATIVO','BLOQUEADO')),
  criado_em   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_centro_custo_cod ON centro_custo(codccusto);
CREATE INDEX IF NOT EXISTS idx_centro_custo_tipo ON centro_custo(tipo);

-- ── Ocorrências disciplinares ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ocorrencias_disciplinares (
  id               SERIAL PRIMARY KEY,
  tipo             VARCHAR(20)   NOT NULL CHECK (tipo IN ('ADVERTENCIA','SUSPENSAO')),
  colaborador_id   INTEGER       REFERENCES colaboradores(id),
  chapa            VARCHAR(16),
  nome_colaborador VARCHAR(200),
  gestor_id        INTEGER       NOT NULL REFERENCES usuarios(id),
  gestor_nome      VARCHAR(150),
  cpf              VARCHAR(14),
  secao            VARCHAR(100),
  admissao         DATE,
  motivo           TEXT          NOT NULL,
  data_ocorrencia  DATE          NOT NULL,
  data_inicio      DATE,
  data_fim         DATE,
  dias_suspensao   SMALLINT,
  status           VARCHAR(20)   NOT NULL DEFAULT 'ATIVO' CHECK (status IN ('ATIVO','CANCELADO')),
  flag_exportado   BOOLEAN       NOT NULL DEFAULT false,
  data_exportacao  TIMESTAMPTZ,
  exportado_por    INTEGER       REFERENCES usuarios(id),
  criado_em        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  atualizado_em    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Anexos de ocorrências disciplinares ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS ocorrencias_disciplinares_anexos (
  id              SERIAL PRIMARY KEY,
  ocorrencia_id   INTEGER       NOT NULL REFERENCES ocorrencias_disciplinares(id) ON DELETE CASCADE,
  nome_arquivo    VARCHAR(255)  NOT NULL,
  tipo_arquivo    VARCHAR(100),
  dados_base64    TEXT          NOT NULL,
  usuario_id      INTEGER       REFERENCES usuarios(id),
  criado_em       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Log de exportações de ocorrências ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_exportacoes_ocorrencias (
  id             SERIAL PRIMARY KEY,
  usuario_id     INTEGER       REFERENCES usuarios(id),
  usuario_nome   VARCHAR(150),
  quantidade     INTEGER       NOT NULL,
  ids_exportados INTEGER[],
  criado_em      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Solicitações de desligamento ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS solicitacao_desligamento (
  id                  SERIAL PRIMARY KEY,
  colaborador_id      INTEGER       NOT NULL REFERENCES colaboradores(id),
  gestor_id           INTEGER       NOT NULL REFERENCES usuarios(id),
  tipo                VARCHAR(30)   NOT NULL,
  data_desligamento   DATE          NOT NULL,
  data_aviso          DATE,
  reducao_jornada     BOOLEAN       NOT NULL DEFAULT false,
  justificativa       TEXT,
  observacoes         TEXT,
  status              VARCHAR(30)   NOT NULL DEFAULT 'rascunho'
                      CHECK (status IN (
                        'rascunho','pendente_superior','pendente_dp',
                        'aprovado','reprovado','ajuste_solicitado','finalizado'
                      )),
  criado_em           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  atualizado_em       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Logs de desligamento ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS solicitacao_desligamento_logs (
  id              SERIAL PRIMARY KEY,
  solicitacao_id  INTEGER       NOT NULL REFERENCES solicitacao_desligamento(id) ON DELETE CASCADE,
  usuario_id      INTEGER       REFERENCES usuarios(id),
  acao            VARCHAR(30)   NOT NULL,
  observacao      TEXT,
  dados_antes     JSONB,
  dados_depois    JSONB,
  criado_em       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Anexos de desligamento ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS solicitacao_desligamento_anexos (
  id              SERIAL PRIMARY KEY,
  solicitacao_id  INTEGER       NOT NULL REFERENCES solicitacao_desligamento(id) ON DELETE CASCADE,
  nome_arquivo    VARCHAR(255)  NOT NULL,
  tipo_arquivo    VARCHAR(100),
  dados_base64    TEXT          NOT NULL,
  usuario_id      INTEGER       REFERENCES usuarios(id),
  criado_em       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Índices de performance ────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_blocos_status              ON blocos(status);
CREATE INDEX IF NOT EXISTS idx_blocos_solicitante         ON blocos(solicitante_id);
CREATE INDEX IF NOT EXISTS idx_blocos_competencia         ON blocos(competencia);
CREATE INDEX IF NOT EXISTS idx_audit_usuario              ON audit_log(usuario_id);
CREATE INDEX IF NOT EXISTS idx_audit_acao                 ON audit_log(acao);
CREATE INDEX IF NOT EXISTS idx_audit_criado_em            ON audit_log(criado_em DESC);
CREATE INDEX IF NOT EXISTS idx_colaboradores_chapa        ON colaboradores(chapa);
CREATE INDEX IF NOT EXISTS idx_bloco_linhas_bloco         ON bloco_linhas(bloco_id);
CREATE INDEX IF NOT EXISTS idx_ocorrencias_gestor         ON ocorrencias_disciplinares(gestor_id);
CREATE INDEX IF NOT EXISTS idx_ocorrencias_colaborador    ON ocorrencias_disciplinares(colaborador_id);
CREATE INDEX IF NOT EXISTS idx_ocorrencias_status         ON ocorrencias_disciplinares(status);
CREATE INDEX IF NOT EXISTS idx_desligamento_gestor        ON solicitacao_desligamento(gestor_id);
CREATE INDEX IF NOT EXISTS idx_desligamento_status        ON solicitacao_desligamento(status);
CREATE INDEX IF NOT EXISTS idx_desligamento_logs_sol      ON solicitacao_desligamento_logs(solicitacao_id);
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
