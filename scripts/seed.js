// scripts/seed.js
"use strict";
require("dotenv").config();
const bcrypt = require("bcryptjs");
const db     = require("../src/config/database");
const logger = require("../src/utils/logger");

const ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || "12");

const USUARIOS = [
  { nome: process.env.ADMIN_NOME || "Administrador", email: process.env.ADMIN_EMAIL || "admin@benel.com.br", senha: process.env.ADMIN_PASSWORD || "Admin@2025!", perfil: "admin" },
  { nome: "Gestor Demo",   email: "gestor@benel.com.br",   senha: "Gestor@2025!",   perfil: "gestor" },
  { nome: "Superior Demo", email: "superior@benel.com.br", senha: "Superior@2025!", perfil: "superior" },
  { nome: "DP Demo",       email: "dp@benel.com.br",       senha: "DP@2025!",       perfil: "dp" },
];

const EVENTOS = [
  { codigo: "1148", descricao: "Auxílio Quilometragem",    tipo: "provento", forma: "valor" },
  { codigo: "1150", descricao: "Ajuda de Custo",           tipo: "provento", forma: "valor" },
  { codigo: "1155", descricao: "Horas Extras 50%",         tipo: "provento", forma: "hora" },
  { codigo: "1160", descricao: "Diária de Viagem",         tipo: "provento", forma: "referencia" },
  { codigo: "1175", descricao: "Sobreaviso",               tipo: "provento", forma: "hora" },
  { codigo: "2001", descricao: "Desconto Multa Trânsito",  tipo: "desconto", forma: "valor" },
];

const COLABORADORES = [
  { chapa: "0001", nome: "João Pedro Silva",    funcao: "Analista",     situacao: "Ativo", centro_custo: "001", desc_cc: "TI" },
  { chapa: "0002", nome: "Maria Fernanda Costa",funcao: "Coordenadora", situacao: "Ativo", centro_custo: "002", desc_cc: "RH" },
  { chapa: "0003", nome: "Roberto Alves",       funcao: "Motorista",    situacao: "Ativo", centro_custo: "003", desc_cc: "Logística" },
  { chapa: "0004", nome: "Luciana Torres",      funcao: "Técnica",      situacao: "Ativo", centro_custo: "001", desc_cc: "TI" },
];

(async () => {
  try {
    logger.info("Iniciando seed...");

    // Usuários
    for (const u of USUARIOS) {
      const ex = await db.query("SELECT id FROM usuarios WHERE email=$1", [u.email]);
      if (ex.rowCount > 0) { logger.info(`Usuário já existe: ${u.email}`); continue; }
      const hash = await bcrypt.hash(u.senha, ROUNDS);
      await db.query(
        "INSERT INTO usuarios(nome,email,senha_hash,perfil) VALUES($1,$2,$3,$4)",
        [u.nome, u.email, hash, u.perfil]
      );
      logger.info(`Usuário criado: ${u.email} [${u.perfil}]`);
    }

    // Eventos
    for (const e of EVENTOS) {
      const ex = await db.query("SELECT id FROM eventos WHERE codigo=$1", [e.codigo]);
      if (ex.rowCount > 0) { logger.info(`Evento já existe: ${e.codigo}`); continue; }
      await db.query(
        "INSERT INTO eventos(codigo,descricao,tipo,forma) VALUES($1,$2,$3,$4)",
        [e.codigo, e.descricao, e.tipo, e.forma]
      );
      logger.info(`Evento criado: ${e.codigo} — ${e.descricao}`);
    }

    // Colaboradores
    for (const c of COLABORADORES) {
      const ex = await db.query("SELECT id FROM colaboradores WHERE chapa=$1", [c.chapa]);
      if (ex.rowCount > 0) { logger.info(`Colaborador já existe: ${c.chapa}`); continue; }
      await db.query(
        "INSERT INTO colaboradores(chapa,nome,funcao,situacao,centro_custo,desc_cc) VALUES($1,$2,$3,$4,$5,$6)",
        [c.chapa, c.nome, c.funcao, c.situacao, c.centro_custo, c.desc_cc]
      );
      logger.info(`Colaborador criado: ${c.chapa} — ${c.nome}`);
    }

    logger.info("Seed concluído com sucesso!");
    logger.info("─────────────────────────────────────────");
    logger.info("Credenciais de acesso:");
    USUARIOS.forEach(u => logger.info(`  ${u.perfil.padEnd(10)} | ${u.email} | ${u.senha}`));
    logger.info("─────────────────────────────────────────");
    process.exit(0);
  } catch (e) {
    logger.error("Erro no seed", { msg: e.message });
    process.exit(1);
  }
})();
