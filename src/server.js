// src/server.js
"use strict";
require("dotenv").config();
const app    = require("./app");
const db     = require("./config/database");
const logger = require("./utils/logger");

const PORT = parseInt(process.env.PORT || "3001");

(async () => {
  try {
    const dbInfo = await db.testConnection();
    logger.info(`Banco OK: ${dbInfo.banco} — ${dbInfo.agora}`);

    const server = app.listen(PORT, () => {
      logger.info(`DP Flow Backend rodando | porta ${PORT} | env: ${process.env.NODE_ENV || "development"}`);
      logger.info(`Swagger : http://localhost:${PORT}/docs`);
      logger.info(`Health  : http://localhost:${PORT}/api/health`);
    });

    const shutdown = (sig) => {
      logger.info(`${sig} recebido — encerrando...`);
      server.close(() => { logger.info("Servidor encerrado."); process.exit(0); });
      setTimeout(() => process.exit(1), 10000);
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT",  () => shutdown("SIGINT"));
    process.on("uncaughtException",  (e) => { logger.error("uncaughtException",  { msg: e.message }); process.exit(1); });
    process.on("unhandledRejection", (e) => { logger.error("unhandledRejection", { msg: String(e) }); });

  } catch (e) {
    logger.error("Falha ao iniciar", { msg: e.message });
    process.exit(1);
  }
})();
