// src/config/cors.js
// Substitua FRONTEND_URL pela URL real do Vercel: ex: https://benel-dpflow-5jas.vercel.app
// Adicione também localhost para desenvolvimento local

const ORIGENS_PERMITIDAS = [
  process.env.FRONTEND_URL,           // ex: https://benel-dpflow-5jas.vercel.app
  process.env.FRONTEND_URL_ALT,       // URL alternativa (preview do Vercel, se houver)
  "http://localhost:5173",            // Dev local (Vite)
  "http://localhost:3000",            // Dev local alternativo
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    // Permitir requisições sem origin (Postman, Railway health check, cron jobs)
    if (!origin) return callback(null, true);

    if (ORIGENS_PERMITIDAS.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`[CORS] Origem bloqueada: ${origin}`);
      callback(new Error(`Origem não permitida: ${origin}`));
    }
  },
  credentials: true,                  // Permitir cookies e headers de auth
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["X-Total-Count"],
  maxAge: 86400,                      // Cache preflight por 24h
};

module.exports = corsOptions;

// ─── COMO USAR ────────────────────────────────────────────────────────────────
// No seu app.js/server.js, substitua o cors() atual por:
//
// const cors = require("cors");
// const corsOptions = require("./config/cors");
// app.use(cors(corsOptions));
//
// ─── VARIÁVEIS DE AMBIENTE NO RAILWAY ─────────────────────────────────────────
// Adicione nas variáveis do Railway:
//
// FRONTEND_URL=https://benel-dpflow-5jas.vercel.app
//
// Se tiver preview URLs do Vercel (geradas a cada deploy), adicione:
// FRONTEND_URL_ALT=https://benel-dpflow-*.vercel.app
