// src/docs/swagger.js
"use strict";
const swaggerJsdoc = require("swagger-jsdoc");

module.exports = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title:       "DP Flow API — Benel",
      version:     "1.0.0",
      description: "API do Sistema de Gestão de Variáveis para Folha de Pagamento — Benel Soluções em Transporte e Logística",
      contact: { name: "DP Benel", email: "dp@benel.com.br" },
    },
    servers: [
      { url: "http://localhost:3001", description: "Desenvolvimento" },
      { url: "https://api-dpflow.benel.com.br", description: "Produção" },
    ],
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      },
      schemas: {
        Login: {
          type: "object", required: ["email","senha"],
          properties: {
            email: { type: "string", example: "admin@benel.com.br" },
            senha: { type: "string", example: "Admin@2025!" },
          },
        },
        Erro: {
          type: "object",
          properties: {
            success: { type: "boolean", example: false },
            message: { type: "string" },
          },
        },
      },
    },
    tags: [
      { name: "Auth",          description: "Autenticação e sessão" },
      { name: "Usuários",      description: "Gestão de usuários" },
      { name: "Colaboradores", description: "Cadastro de colaboradores" },
      { name: "Eventos",       description: "Eventos da folha" },
      { name: "Blocos",        description: "Solicitações em bloco" },
      { name: "Auditoria",     description: "Log de auditoria" },
    ],
  },
  apis: ["./src/routes/*.js"],
});
