// src/app.js
"use strict";
require("dotenv").config();
const express     = require("express");
const helmet      = require("helmet");
const cors        = require("cors");
const morgan      = require("morgan");
const compression = require("compression");
const swaggerUi   = require("swagger-ui-express");
const swaggerSpec = require("./docs/swagger");
const routes      = require("./routes");
const { rateLimitGeral, sanitizarBody, errorHandler } = require("./middlewares");
const logger      = require("./utils/logger");

const app = express();

// ── Trust proxy — necessário no Railway/Heroku para rate limit funcionar ───────
app.set("trust proxy", 1);

// ── Cabeçalhos de segurança (Helmet + HSTS + CSP) ─────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'"],
      styleSrc:       ["'self'", "'unsafe-inline'"],
      imgSrc:         ["'self'", "data:", "blob:"],
      connectSrc:     ["'self'"],
      frameAncestors: ["'none'"],
      baseUri:        ["'self'"],
      formAction:     ["'self'"],
    },
  },
  hsts:          { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard:    { action: "deny" },
  noSniff:       true,
  referrerPolicy:{ policy: "strict-origin-when-cross-origin" },
}));

// ── CORS restritivo ────────────────────────────────────────────────────────────
const origensPermitidas = (process.env.CORS_ORIGIN || "http://localhost:5173")
  .split(",").map(o => o.trim());

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || origensPermitidas.includes(origin)) return cb(null, true);
    logger.warn("CORS bloqueado", { origin });
    cb(new Error(`Origem não permitida: ${origin}`));
  },
  credentials:    true,
  methods:        ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Requested-With"],
  maxAge:         86400,
}));

// Preflight explícito para todas as rotas
app.options("*", cors());

// ── Parsers e compressão ───────────────────────────────────────────────────────
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(compression());

// ── Sanitização global do body ────────────────────────────────────────────────
app.use(sanitizarBody);

// ── Logs HTTP ─────────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== "test") {
  app.use(morgan("combined", {
    stream: { write: (msg) => logger.info(msg.trim()) },
    skip:   (req)  => req.path === "/api/health",
  }));
}

// ── Rate limit geral ──────────────────────────────────────────────────────────
app.use("/api", rateLimitGeral);

// ── Rotas ─────────────────────────────────────────────────────────────────────
app.use("/api", routes);

// ── Swagger (apenas em não-produção) ─────────────────────────────────────────
if (process.env.NODE_ENV !== "production") {
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    customSiteTitle: "DP Flow API — Benel",
    customCss: ".swagger-ui .topbar { background-color: #0F2447; }",
  }));
}

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Rota não encontrada: ${req.method} ${req.path}` });
});

// ── Handler global de erros ───────────────────────────────────────────────────
app.use(errorHandler);

module.exports = app;
