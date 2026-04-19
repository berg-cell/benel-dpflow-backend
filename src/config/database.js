// src/config/database.js
"use strict";
require("dotenv").config();
const { Pool } = require("pg");
const logger = require("../utils/logger");

const sslConfig = { rejectUnauthorized: false };

// family: 4 força IPv4 — evita ENETUNREACH em ambientes sem IPv6 (Railway)
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: sslConfig,
        family: 4,
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
      }
    : {
        host:     process.env.DB_HOST     || "localhost",
        port:     parseInt(process.env.DB_PORT || "5432"),
        database: process.env.DB_NAME     || "postgres",
        user:     process.env.DB_USER     || "postgres",
        password: process.env.DB_PASSWORD || "",
        ssl:      process.env.DB_SSL === "true" ? sslConfig : false,
        family: 4,
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
      }
);

pool.on("error", (err) => {
  logger.error("Erro no pool PostgreSQL", { message: err.message });
});

const db = {
  query: async (text, params = []) => {
    const start = Date.now();
    try {
      const result = await pool.query(text, params);
      logger.debug("Query OK", { ms: Date.now() - start, rows: result.rowCount });
      return result;
    } catch (err) {
      logger.error("Erro na query", { message: err.message });
      throw err;
    }
  },

  transaction: async (fn) => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  },

  testConnection: async () => {
    const res = await pool.query("SELECT NOW() AS agora, current_database() AS banco");
    return res.rows[0];
  },
};

module.exports = db;
