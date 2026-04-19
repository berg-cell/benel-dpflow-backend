// src/utils/sanitize.js
"use strict";
const xss = require("xss");

const xssOpts = { whiteList: {}, stripIgnoreTag: true, stripIgnoreTagBody: ["script","style"] };

const sanitizeStr = (v) => (typeof v === "string" ? xss(v.trim(), xssOpts) : v);

const sanitizeObj = (obj) => {
  if (!obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeObj);
  return Object.fromEntries(
    Object.entries(obj).map(([k, v]) => [
      k,
      typeof v === "string" ? sanitizeStr(v) :
      typeof v === "object" ? sanitizeObj(v) : v,
    ])
  );
};

const SQL_RE = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE)\b)/gi,
  /(--|\/\*|\*\/)/g,
  /(\bOR\b\s+\d+=\d+|\bAND\b\s+\d+=\d+)/gi,
];
const PROMPT_RE = [
  /ignore\s+previous/i, /system\s*:/i, /aja\s+como/i,
  /act\s+as/i, /jailbreak/i, /bypass/i, /override\s+instructions/i,
];

const hasSQLInjection   = (v) => typeof v === "string" && SQL_RE.some(r => { r.lastIndex = 0; return r.test(v); });
const hasPromptInjection = (v) => typeof v === "string" && PROMPT_RE.some(r => r.test(v));

const safeField = (value, label = "campo") => {
  const s = String(value || "");
  if (hasSQLInjection(s))    throw Object.assign(new Error(`Conteúdo suspeito em ${label}`),    { status: 400, code: "ERR_SEC_SQL" });
  if (hasPromptInjection(s)) throw Object.assign(new Error(`Conteúdo não permitido em ${label}`), { status: 400, code: "ERR_SEC_PROMPT" });
  return sanitizeStr(s);
};

module.exports = { sanitizeStr, sanitizeObj, hasSQLInjection, hasPromptInjection, safeField };
