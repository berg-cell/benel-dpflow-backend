"use strict";
const express    = require("express");
const router     = express.Router();

// ── Middlewares ───────────────────────────────────────────────────────────────
const { autenticar, autorizar } = require("../middlewares");

// ── Controllers ───────────────────────────────────────────────────────────────
const authCtrl             = require("../controllers/authController");
const colaboradorCtrl      = require("../controllers/colaboradorController");
const eventoCtrl           = require("../controllers/eventoController");
const blocoCtrl            = require("../controllers/blocoController");
const usuarioCtrl          = require("../controllers/usuarioController");
const auditoriaCtrl        = require("../controllers/auditoriaController");
const centroCtrl           = require("../controllers/centroCustoController");
const autorizacaoCtrl      = require("../controllers/autorizacaoController");
const hierarquiaCtrl       = require("../controllers/hierarquiaAlcadasController");
const ocorrenciasCtrl      = require("../controllers/ocorrenciasController");
const desligamentoCtrl     = require("../controllers/desligamentoController");
const planoSaudeCtrl       = require("../controllers/planoSaudeController");
const atualizacaoCadastralCtrl = require("../controllers/atualizacaoCadastralController");
const telegramCtrl         = require("../controllers/telegramController");
const rescisaoCtrl         = require("../controllers/rescisaoController");

// ── Health ────────────────────────────────────────────────────────────────────
router.get("/health", (req, res) => res.json({ status: "ok", ts: new Date() }));

// ── Auth ──────────────────────────────────────────────────────────────────────
router.post("/auth/login",    authCtrl.login);
router.post("/auth/logout",   autenticar, authCtrl.logout);
router.post("/auth/refresh",  authCtrl.refresh);
router.get( "/auth/me",       autenticar, authCtrl.me);

// ── Colaboradores ─────────────────────────────────────────────────────────────
router.get(  "/colaboradores",             autenticar,                              colaboradorCtrl.listar);
router.get(  "/colaboradores/buscar",      autenticar,                              colaboradorCtrl.buscar);
router.get(  "/colaboradores/:id",         autenticar,                              colaboradorCtrl.buscarPorId);
router.post( "/colaboradores",             autenticar, autorizar("dp","admin"),     colaboradorCtrl.criar);
router.put(  "/colaboradores/:id",         autenticar, autorizar("dp","admin"),     colaboradorCtrl.atualizar);
router.post( "/colaboradores/importar",    autenticar, autorizar("dp","admin"),     colaboradorCtrl.importar);

// ── Eventos ───────────────────────────────────────────────────────────────────
router.get(  "/eventos",     autenticar,                          eventoCtrl.listar);
router.post( "/eventos",     autenticar, autorizar("dp","admin"), eventoCtrl.criar);
router.put(  "/eventos/:id", autenticar, autorizar("dp","admin"), eventoCtrl.atualizar);

// ── Blocos ────────────────────────────────────────────────────────────────────
router.get(  "/blocos",              autenticar,                              blocoCtrl.listar);
router.get(  "/blocos/exportar/txt", autenticar, autorizar("dp","admin"),     blocoCtrl.exportarTxt);
router.get(  "/blocos/:id",          autenticar,                              blocoCtrl.buscarPorId);
router.post( "/blocos",              autenticar,                              blocoCtrl.criar);
router.put(  "/blocos/:id/aprovar",  autenticar,                              blocoCtrl.aprovar);

// ── Usuários ──────────────────────────────────────────────────────────────────
router.get(  "/usuarios",                  autenticar, autorizar("dp","admin"),         usuarioCtrl.listar);
router.post( "/usuarios",                  autenticar, autorizar("dp","admin"),         usuarioCtrl.criar);
router.put(  "/usuarios/:id",              autenticar, autorizar("dp","admin"),         usuarioCtrl.atualizar);
router.put(  "/usuarios/:id/reset-senha",  autenticar, autorizar("dp","admin"),         usuarioCtrl.resetarSenha);

// ── Auditoria ─────────────────────────────────────────────────────────────────
router.get("/auditoria", autenticar, autorizar("dp","admin"), auditoriaCtrl.listar);

// ── Centro de Custo ───────────────────────────────────────────────────────────
router.get("/centros-custo", autenticar, centroCtrl.listar);

// ── Hierarquia / Alçadas ──────────────────────────────────────────────────────
router.get(  "/hierarquia",     autenticar,                          hierarquiaCtrl.listarHierarquia);
router.post( "/hierarquia",     autenticar, autorizar("dp","admin"), hierarquiaCtrl.criarHierarquia);
router.put(  "/hierarquia/:id", autenticar, autorizar("dp","admin"), hierarquiaCtrl.atualizarHierarquia);
router.get(  "/alcadas",        autenticar,                          hierarquiaCtrl.listarAlcadas);
router.post( "/alcadas",        autenticar, autorizar("dp","admin"), hierarquiaCtrl.criarAlcada);
router.put(  "/alcadas/:id",    autenticar, autorizar("dp","admin"), hierarquiaCtrl.atualizarAlcada);

// ── Ocorrências Disciplinares ─────────────────────────────────────────────────
router.get(  "/ocorrencias",                 autenticar,                              ocorrenciasCtrl.listar);
router.get(  "/ocorrencias/exportar",        autenticar, autorizar("dp","admin"),     ocorrenciasCtrl.exportar);
router.get(  "/ocorrencias/:id",             autenticar,                              ocorrenciasCtrl.buscarPorId);
router.post( "/ocorrencias",                 autenticar,                              ocorrenciasCtrl.criar);
router.put(  "/ocorrencias/:id/cancelar",    autenticar, autorizar("dp","admin"),     ocorrenciasCtrl.cancelar);
router.post( "/ocorrencias/:id/anexos",      autenticar,                              ocorrenciasCtrl.addAnexo);
router.get(  "/ocorrencias/:id/anexos/:anexoId", autenticar,                          ocorrenciasCtrl.getAnexo);

// ── Desligamentos ─────────────────────────────────────────────────────────────
router.get(  "/desligamentos",                           autenticar,                                              desligamentoCtrl.listar);
router.get(  "/desligamentos/validar-colaborador/:id",   autenticar,                                              desligamentoCtrl.validarColaborador);
router.get(  "/desligamentos/:id",                       autenticar,                                              desligamentoCtrl.buscarPorId);
router.post( "/desligamentos",                           autenticar, autorizar("gestor","superior","dp","admin","presidente"), desligamentoCtrl.criar);
router.put(  "/desligamentos/:id/enviar",                autenticar,                                              desligamentoCtrl.enviar);
router.put(  "/desligamentos/:id/aprovar",               autenticar, autorizar("superior","dp","admin","presidente"), desligamentoCtrl.aprovar);
router.put(  "/desligamentos/:id/cancelar",              autenticar, autorizar("dp","admin","presidente"),         desligamentoCtrl.cancelar);
router.post( "/desligamentos/:id/anexos",                autenticar,                                              desligamentoCtrl.addAnexo);

// ── Plano de Saúde ────────────────────────────────────────────────────────────
router.get(  "/plano-saude",                 autenticar,                                  planoSaudeCtrl.listar);
router.get(  "/plano-saude/:id",             autenticar,                                  planoSaudeCtrl.buscarPorId);
router.post( "/plano-saude",                 autenticar, autorizar("gestor","dp","admin"), planoSaudeCtrl.criar);
router.post( "/plano-saude/:id/anexos",      autenticar,                                  planoSaudeCtrl.addAnexo);
router.get(  "/plano-saude/:id/anexos/:anexoId", autenticar,                              planoSaudeCtrl.getAnexo);
router.put(  "/plano-saude/:id/cancelar",    autenticar, autorizar("dp","admin"),         planoSaudeCtrl.cancelar);

// ── Autorização de Desconto ───────────────────────────────────────────────────
router.get(  "/autorizacoes",            autenticar,                                  autorizacaoCtrl.listar);
router.post( "/autorizacoes",            autenticar, autorizar("gestor","dp","admin","presidente"), autorizacaoCtrl.criar);
router.post( "/autorizacoes/:id/anexo",  autenticar,                                  autorizacaoCtrl.addAnexo);
router.put(  "/autorizacoes/:id/cancelar", autenticar, autorizar("gestor","dp","admin","presidente"), autorizacaoCtrl.cancelar);

// ── Atualização Cadastral ─────────────────────────────────────────────────────
router.get( "/atualizacao-cadastral",               autenticar,                                               atualizacaoCadastralCtrl.listar);
router.get( "/atualizacao-cadastral/:id",            autenticar,                                               atualizacaoCadastralCtrl.buscarPorId);
router.post("/atualizacao-cadastral",                autenticar, autorizar("gestor","dp","admin","presidente"), atualizacaoCadastralCtrl.criar);
router.put( "/atualizacao-cadastral/:id/aprovar",    autenticar, autorizar("dp","admin","presidente"),         atualizacaoCadastralCtrl.aprovar);
router.put( "/atualizacao-cadastral/:id/cancelar",   autenticar, autorizar("gestor","dp","admin","presidente"), atualizacaoCadastralCtrl.cancelar);

// ── Telegram ──────────────────────────────────────────────────────────────────
router.post("/telegram/webhook", telegramCtrl.webhook);

// ── Rescisão Valores ──────────────────────────────────────────────────────────
router.get(   "/rescisao-valores",                   autenticar, autorizar("dp","admin","presidente"), rescisaoCtrl.listar);
router.post(  "/rescisao-valores",                   autenticar, autorizar("dp","admin","presidente"), rescisaoCtrl.lancar);
router.delete("/rescisao-valores/:id",               autenticar, autorizar("dp","admin"),              rescisaoCtrl.excluir);
router.get(   "/rescisao-valores/desligamento/:id",  autenticar, autorizar("dp","admin","presidente"), rescisaoCtrl.buscarPorDesligamento);
router.post(  "/rescisao-valores/importar-lote",     autenticar, autorizar("dp","admin","presidente"), rescisaoCtrl.importarLote);

module.exports = router;
