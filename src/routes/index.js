// src/routes/index.js
"use strict";
const router = require("express").Router();

const { autenticar, autorizar, validate, rateLimitLogin, auditLog } = require("../middlewares");

const schemas = require("../validators/schemas");

const authCtrl         = require("../controllers/authController");
const usuarioCtrl      = require("../controllers/usuarioController");
const colaboradorCtrl  = require("../controllers/colaboradorController");
const eventoCtrl       = require("../controllers/eventoController");
const blocoCtrl        = require("../controllers/blocoController");
const auditoriaCtrl    = require("../controllers/auditoriaController");
const desligamentoCtrl = require("../controllers/desligamentoController");
const ocorrenciasCtrl  = require("../controllers/ocorrenciasController");
const hierarquiaCtrl   = require("../controllers/hierarquiaAlcadasController");

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
router.post("/auth/login",         rateLimitLogin, validate(schemas.loginSchema),        auditLog("LOGIN"),        authCtrl.login);
router.post("/auth/refresh",                       validate(schemas.refreshSchema),                                authCtrl.refresh);
router.post("/auth/logout",        autenticar,                                            auditLog("LOGOUT"),       authCtrl.logout);
router.get( "/auth/me",            autenticar,                                                                      authCtrl.me);
router.put( "/auth/alterar-senha", autenticar,     validate(schemas.alterarSenhaSchema), auditLog("ALTERAR_SENHA"), authCtrl.alterarSenha);

// ── Usuários (admin) ──────────────────────────────────────────────────────────
router.get( "/usuarios",                    autenticar, autorizar("admin"),                                        usuarioCtrl.listar);
router.post("/usuarios",                    autenticar, autorizar("admin"),                                        usuarioCtrl.criar);
router.put( "/usuarios/:id",                autenticar, autorizar("admin"),                                        usuarioCtrl.atualizar);
router.put( "/usuarios/:id/reset-senha",    autenticar, autorizar("admin"), auditLog("RESET_SENHA"),               usuarioCtrl.resetarSenha);

// ── Colaboradores ─────────────────────────────────────────────────────────────
// ATENÇÃO: rotas específicas (/buscar, /importar) ANTES de rotas com parâmetro (/:id)
router.get( "/colaboradores",               autenticar,                                                            colaboradorCtrl.listar);
router.get( "/colaboradores/buscar",        autenticar,                                                            colaboradorCtrl.buscar);
router.post("/colaboradores/importar",      autenticar, autorizar("dp","admin"),                                   colaboradorCtrl.importar);
router.get( "/colaboradores/:id",           autenticar,                                                            colaboradorCtrl.buscarPorId);
router.post("/colaboradores",               autenticar, autorizar("dp","admin"),                                   colaboradorCtrl.criar);
router.put( "/colaboradores/:id",           autenticar, autorizar("dp","admin"),                                   colaboradorCtrl.atualizar);

// ── Eventos ───────────────────────────────────────────────────────────────────
router.get( "/eventos",     autenticar,                                          eventoCtrl.listar);
router.get( "/eventos/:id", autenticar,                                          eventoCtrl.buscarPorId);
router.post("/eventos",     autenticar, autorizar("dp","admin"),                 eventoCtrl.criar);
router.put( "/eventos/:id", autenticar, autorizar("dp","admin"),                 eventoCtrl.atualizar);

// ── Blocos ────────────────────────────────────────────────────────────────────
router.get( "/blocos",                  autenticar,                                              blocoCtrl.listar);
router.get( "/blocos/exportar/txt",     autenticar, autorizar("dp","admin"), auditLog("EXPORT"), blocoCtrl.exportarTxt);
router.get( "/blocos/:id",              autenticar,                                              blocoCtrl.buscarPorId);
router.post("/blocos",                  autenticar, validate(schemas.blocoSchema),  auditLog("CRIAR_BLOCO"),   blocoCtrl.criar);
router.put( "/blocos/:id/aprovar",      autenticar, validate(schemas.acaoAprovacaoSchema), auditLog("APROVAR"), blocoCtrl.aprovar);

// ── Auditoria ─────────────────────────────────────────────────────────────────
router.get("/auditoria", autenticar, autorizar("dp","admin"), auditoriaCtrl.listar);

// ── Desligamento ──────────────────────────────────────────────────────────────
// ATENÇÃO: rotas específicas ANTES de rotas com parâmetro (/:id)
router.get( "/desligamentos/validar-colaborador/:id", autenticar, autorizar("gestor","dp","admin"), desligamentoCtrl.validarColaborador);
router.get( "/desligamentos",                         autenticar,                                   desligamentoCtrl.listar);
router.get( "/desligamentos/:id",                     autenticar,                                   desligamentoCtrl.buscarPorId);
router.post("/desligamentos",                         autenticar, autorizar("gestor","dp","admin"),  desligamentoCtrl.criar);
router.put( "/desligamentos/:id/enviar",              autenticar, autorizar("gestor","dp","admin"),  desligamentoCtrl.enviar);
router.put( "/desligamentos/:id/aprovar",             autenticar, autorizar("superior","dp","admin"), desligamentoCtrl.aprovar);
router.post("/desligamentos/:id/anexos",              autenticar,                                   desligamentoCtrl.addAnexo);
router.get( "/desligamentos/:id/anexos/:anexoId",     autenticar,                                   desligamentoCtrl.getAnexo);

// ── Hierarquia ────────────────────────────────────────────────────────────────
router.get( "/hierarquia",     autenticar, autorizar("dp","admin"),                        hierarquiaCtrl.listarHierarquia);
router.post("/hierarquia",     autenticar, autorizar("dp","admin"), auditLog("HIER_CRIAR"), hierarquiaCtrl.criarHierarquia);
router.put( "/hierarquia/:id", autenticar, autorizar("dp","admin"), auditLog("HIER_EDIT"),  hierarquiaCtrl.atualizarHierarquia);

// ── Alçadas ───────────────────────────────────────────────────────────────────
router.get( "/alcadas",        autenticar, autorizar("dp","admin"),                        hierarquiaCtrl.listarAlcadas);
router.post("/alcadas",        autenticar, autorizar("dp","admin"), auditLog("ALC_CRIAR"),  hierarquiaCtrl.criarAlcada);
router.put( "/alcadas/:id",    autenticar, autorizar("dp","admin"), auditLog("ALC_EDIT"),   hierarquiaCtrl.atualizarAlcada);

// ── Ocorrências Disciplinares ─────────────────────────────────────────────────
// ATENÇÃO: /exportar ANTES de /:id
router.get( "/ocorrencias",              autenticar,                                                     ocorrenciasCtrl.listar);
router.get( "/ocorrencias/exportar",     autenticar, autorizar("dp","admin","gestor"), auditLog("EXPORT_OCORRENCIAS"),  ocorrenciasCtrl.exportar);
router.get( "/ocorrencias/:id",          autenticar,                                                     ocorrenciasCtrl.buscarPorId);
router.post("/ocorrencias",              autenticar, autorizar("gestor","dp","admin"), auditLog("CRIAR_OCORRENCIA"),    ocorrenciasCtrl.criar);
router.put( "/ocorrencias/:id/cancelar", autenticar, autorizar("gestor","dp","admin"), auditLog("CANCELAR_OCORRENCIA"), ocorrenciasCtrl.cancelar);
router.post("/ocorrencias/:id/anexos",   autenticar,                                   auditLog("ANEXO_OCORRENCIA"),    ocorrenciasCtrl.addAnexo);

module.exports = router;
