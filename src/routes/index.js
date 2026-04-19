// src/routes/index.js
"use strict";
const router = require("express").Router();

const { autenticar, autorizar, validate, rateLimitLogin, auditLog } = require("../middlewares");

const schemas = require("../validators/schemas");

const authCtrl        = require("../controllers/authController");
const usuarioCtrl     = require("../controllers/usuarioController");
const colaboradorCtrl = require("../controllers/colaboradorController");
const eventoCtrl      = require("../controllers/eventoController");
const blocoCtrl       = require("../controllers/blocoController");
const auditoriaCtrl   = require("../controllers/auditoriaController");
const ocorrenciasCtrl     = require("../controllers/ocorrenciasController");
const hierarquiaCtrl      = require("../controllers/hierarquiaAlcadasController");

const db = require("../config/database");

// ── Health check ──────────────────────────────────────────────────────────────
router.get("/health", async (req, res) => {
  try {
    const info = await db.testConnection();
    res.json({ status: "ok", env: process.env.NODE_ENV, db: info, ts: new Date().toISOString() });
  } catch {
    res.status(503).json({ status: "error", message: "Banco indisponível" });
  }
});

// ── Auth ──────────────────────────────────────────────────────────────────────
/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Realizar login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Login'
 *     responses:
 *       200:
 *         description: Login bem-sucedido
 *       401:
 *         description: Credenciais inválidas
 *       429:
 *         description: Muitas tentativas — bloqueado por 15 min
 */
router.post("/auth/login",         rateLimitLogin, validate(schemas.loginSchema),        auditLog("LOGIN"),        authCtrl.login);
router.post("/auth/refresh",                       validate(schemas.refreshSchema),                                authCtrl.refresh);
router.post("/auth/logout",        autenticar,                                            auditLog("LOGOUT"),       authCtrl.logout);
router.get( "/auth/me",            autenticar,                                                                      authCtrl.me);
router.put( "/auth/alterar-senha", autenticar,     validate(schemas.alterarSenhaSchema), auditLog("ALTERAR_SENHA"), authCtrl.alterarSenha);

// ── Usuários (admin) ──────────────────────────────────────────────────────────
/**
 * @swagger
 * /api/usuarios:
 *   get:
 *     summary: Listar usuários
 *     tags: [Usuários]
 *     security: [{bearerAuth: []}]
 */
router.get( "/usuarios",     autenticar, autorizar("admin"),                                               usuarioCtrl.listar);
router.post("/usuarios",     autenticar, autorizar("admin"), usuarioCtrl.criar);
router.put( "/usuarios/:id",              autenticar, autorizar("admin"), usuarioCtrl.atualizar);
router.put( "/usuarios/:id/reset-senha",  autenticar, autorizar("admin"), auditLog("RESET_SENHA"),                           usuarioCtrl.resetarSenha);

// ── Colaboradores ─────────────────────────────────────────────────────────────
/**
 * @swagger
 * /api/colaboradores:
 *   get:
 *     summary: Listar colaboradores
 *     tags: [Colaboradores]
 *     security: [{bearerAuth: []}]
 */
router.get( "/colaboradores",          autenticar,                                                                    colaboradorCtrl.listar);
router.get( "/colaboradores/:id",      autenticar,                                                                    colaboradorCtrl.buscarPorId);
router.post("/colaboradores",          autenticar, autorizar("dp","admin"), colaboradorCtrl.criar);
router.put( "/colaboradores/:id",      autenticar, autorizar("dp","admin"), colaboradorCtrl.atualizar);
router.post("/colaboradores/importar", autenticar, autorizar("dp","admin"), colaboradorCtrl.importar);

// ── Eventos ───────────────────────────────────────────────────────────────────
router.get( "/eventos",     autenticar,                                          eventoCtrl.listar);
router.get( "/eventos/:id", autenticar,                                          eventoCtrl.buscarPorId);
router.post("/eventos",     autenticar, autorizar("dp","admin"), eventoCtrl.criar);
router.put( "/eventos/:id", autenticar, autorizar("dp","admin"), eventoCtrl.atualizar);

// ── Blocos ────────────────────────────────────────────────────────────────────
/**
 * @swagger
 * /api/blocos:
 *   post:
 *     summary: Criar bloco de solicitações
 *     tags: [Blocos]
 *     security: [{bearerAuth: []}]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [descricao, competencia, evento_id, linhas]
 *             properties:
 *               descricao:   { type: string }
 *               competencia: { type: string, example: "092025" }
 *               evento_id:   { type: integer }
 *               linhas:      { type: array }
 */
router.get( "/blocos",                  autenticar,                                              blocoCtrl.listar);
router.get( "/blocos/exportar/txt",     autenticar, autorizar("dp","admin"), auditLog("EXPORT"), blocoCtrl.exportarTxt);
router.get( "/blocos/:id",              autenticar,                                              blocoCtrl.buscarPorId);
router.post("/blocos",                  autenticar, validate(schemas.blocoSchema),  auditLog("CRIAR_BLOCO"),   blocoCtrl.criar);
router.put( "/blocos/:id/aprovar",      autenticar, validate(schemas.acaoAprovacaoSchema), auditLog("APROVAR"), blocoCtrl.aprovar);

// ── Auditoria ─────────────────────────────────────────────────────────────────
router.get("/auditoria", autenticar, autorizar("dp","admin"), auditoriaCtrl.listar);

// ── Hierarquia ───────────────────────────────────────────────────────────────
router.get( "/hierarquia",      autenticar, autorizar("dp","admin"),                       hierarquiaCtrl.listarHierarquia);
router.post("/hierarquia",      autenticar, autorizar("dp","admin"), auditLog("HIER_CRIAR"), hierarquiaCtrl.criarHierarquia);
router.put( "/hierarquia/:id",  autenticar, autorizar("dp","admin"), auditLog("HIER_EDIT"),  hierarquiaCtrl.atualizarHierarquia);

// ── Alçadas ───────────────────────────────────────────────────────────────────
router.get( "/alcadas",         autenticar, autorizar("dp","admin"),                       hierarquiaCtrl.listarAlcadas);
router.post("/alcadas",         autenticar, autorizar("dp","admin"), auditLog("ALC_CRIAR"),  hierarquiaCtrl.criarAlcada);
router.put( "/alcadas/:id",     autenticar, autorizar("dp","admin"), auditLog("ALC_EDIT"),   hierarquiaCtrl.atualizarAlcada);

// ── Ocorrências Disciplinares ─────────────────────────────────────────────────
router.get( "/ocorrencias",              autenticar,                                                    ocorrenciasCtrl.listar);
router.get( "/ocorrencias/exportar",     autenticar, autorizar("dp","admin","gestor"), auditLog("EXPORT_OCORRENCIAS"), ocorrenciasCtrl.exportar);
router.get( "/ocorrencias/:id",          autenticar,                                                    ocorrenciasCtrl.buscarPorId);
router.post("/ocorrencias",              autenticar, autorizar("gestor","dp","admin"), auditLog("CRIAR_OCORRENCIA"),   ocorrenciasCtrl.criar);
router.put( "/ocorrencias/:id/cancelar", autenticar, autorizar("gestor","dp","admin"), auditLog("CANCELAR_OCORRENCIA"), ocorrenciasCtrl.cancelar);

module.exports = router;
