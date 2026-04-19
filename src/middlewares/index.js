// src/middlewares/index.js
"use strict";
const jwt        = require("jsonwebtoken");
const rateLimit  = require("express-rate-limit");
const { sanitizeObj } = require("../utils/sanitize");
const R          = require("../utils/response");
const logger     = require("../utils/logger");

// ── 1. Validação Joi ──────────────────────────────────────────────────────────
const validate = (schema, from = "body") => (req, res, next) => {
  const data = from === "params" ? req.params : from === "query" ? req.query : req.body;
  const { error, value } = schema.validate(data, { abortEarly: false, stripUnknown: true });
  if (error) {
    const erros = error.details.map(d => ({ campo: d.path.join("."), msg: d.message }));
    return R.badRequest(res, "Dados inválidos", erros);
  }
  if (from === "body") req.body = value;
  return next();
};

// ── 2. Autenticação JWT ───────────────────────────────────────────────────────
const autenticar = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer "))
    return R.unauthorized(res, "Token não informado");
  const token = header.slice(7);
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET, {
      issuer:   "benel-dpflow",
      audience: "benel-dpflow-client",
    });
    next();
  } catch (e) {
    if (e.name === "TokenExpiredError") return R.unauthorized(res, "Token expirado");
    return R.unauthorized(res, "Token inválido");
  }
};

// ── 3. Autorização por perfil (RBAC) ─────────────────────────────────────────
const autorizar = (...perfis) => (req, res, next) => {
  if (!req.usuario) return R.unauthorized(res);
  if (!perfis.includes(req.usuario.perfil)) {
    logger.warn("Acesso negado", { userId: req.usuario.id, perfil: req.usuario.perfil, rota: req.path });
    return R.forbidden(res, `Acesso restrito a: ${perfis.join(", ")}`);
  }
  next();
};

// ── 4. Sanitização automática do body ────────────────────────────────────────
const sanitizarBody = (req, res, next) => {
  if (req.body && typeof req.body === "object") req.body = sanitizeObj(req.body);
  next();
};

// ── 5. Rate limit geral ───────────────────────────────────────────────────────
const rateLimitGeral = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000"),
  max:      parseInt(process.env.RATE_LIMIT_MAX        || "100"),
  standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    logger.warn("Rate limit geral", { ip: req.ip });
    return R.tooManyRequests(res);
  },
});

// ── 6. Rate limit do login (mais restritivo) ──────────────────────────────────
const rateLimitLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      parseInt(process.env.LOGIN_RATE_LIMIT_MAX || "5"),
  skipSuccessfulRequests: true,
  standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    logger.warn("Rate limit login", { ip: req.ip, email: req.body?.email });
    return R.tooManyRequests(res, "Bloqueado por 15 min após exceder tentativas de login.");
  },
});

// ── 7. Audit log via res.json ─────────────────────────────────────────────────
const auditLog = (acao) => (req, res, next) => {
  const orig = res.json.bind(res);
  res.json = (data) => {
    logger.info("AUDIT", {
      acao,
      userId:    req.usuario?.id,
      perfil:    req.usuario?.perfil,
      ip:        req.ip,
      metodo:    req.method,
      rota:      req.originalUrl,
      status:    res.statusCode,
      ts:        new Date().toISOString(),
    });
    return orig(data);
  };
  next();
};

// ── 8. Handler global de erros ────────────────────────────────────────────────
const errorHandler = (err, req, res, next) => { // eslint-disable-line no-unused-vars
  logger.error("Erro não tratado", { message: err.message, path: req.path, method: req.method });
  // Erros do PostgreSQL
  if (err.code === "23505") return R.conflict(res, "Registro duplicado");
  if (err.code === "23503") return R.badRequest(res, "Referência inválida");
  if (err.code === "23502") return R.badRequest(res, "Campo obrigatório ausente");
  const msg = process.env.NODE_ENV === "production" ? "Erro interno" : err.message;
  return R.error(res, msg, err.status || 500);
};

module.exports = { validate, autenticar, autorizar, sanitizarBody, rateLimitGeral, rateLimitLogin, auditLog, errorHandler };
