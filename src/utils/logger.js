// src/utils/logger.js
"use strict";
const winston = require("winston");
const path    = require("path");
const fs      = require("fs");

const logDir = process.env.LOG_DIR || "logs";
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const { combine, timestamp, printf, colorize, json } = winston.format;

const consoleFmt = printf(({ level, message, timestamp: ts, ...meta }) => {
  const extra = Object.keys(meta).length ? " " + JSON.stringify(meta) : "";
  return `${ts} [${level}] ${message}${extra}`;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: combine(timestamp({ format: "YYYY-MM-DD HH:mm:ss" }), json()),
  transports: [
    new winston.transports.Console({
      format: combine(colorize(), timestamp({ format: "HH:mm:ss" }), consoleFmt),
      silent: process.env.NODE_ENV === "test",
    }),
    new winston.transports.File({
      filename: path.join(logDir, "app.log"),
      maxsize: 10 * 1024 * 1024, maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logDir, "error.log"),
      level: "error", maxsize: 10 * 1024 * 1024, maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logDir, "audit.log"),
      maxsize: 50 * 1024 * 1024, maxFiles: 30,
    }),
  ],
});

module.exports = logger;
