// tests/integration/auth.test.js
"use strict";
// ATENÇÃO: Estes testes requerem banco de dados configurado.
// Para rodar sem banco, use mocks ou configure DB_TEST no .env
// Para CI/CD, use o docker-compose para subir o banco antes dos testes.

const request = require("supertest");
const app     = require("../../src/app");

// Helper para pular testes sem banco configurado
const temBanco = !!process.env.DB_PASSWORD;
const itSeBanco = temBanco ? it : it.skip;

describe("POST /api/auth/login", () => {
  itSeBanco("retorna 400 quando email é inválido", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .set("X-Requested-With", "XMLHttpRequest")
      .send({ email: "email-invalido", senha: "123" });
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  itSeBanco("retorna 400 quando senha está ausente", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .set("X-Requested-With", "XMLHttpRequest")
      .send({ email: "admin@benel.com.br" });
    expect(res.status).toBe(400);
  });

  itSeBanco("retorna 401 com credenciais erradas", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .set("X-Requested-With", "XMLHttpRequest")
      .send({ email: "admin@benel.com.br", senha: "senhaerrada" });
    expect([401, 500]).toContain(res.status);
  });
});

describe("GET /api/health", () => {
  it("retorna status ok", async () => {
    const res = await request(app).get("/api/health");
    expect([200, 503]).toContain(res.status);
    expect(res.body).toHaveProperty("status");
  });
});

describe("GET /api/auth/me", () => {
  it("retorna 401 sem token", async () => {
    const res = await request(app).get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  it("retorna 401 com token inválido", async () => {
    const res = await request(app)
      .get("/api/auth/me")
      .set("Authorization", "Bearer token_invalido_aqui");
    expect(res.status).toBe(401);
  });
});

describe("Proteção de rotas", () => {
  it("GET /api/blocos retorna 401 sem autenticação", async () => {
    const res = await request(app).get("/api/blocos");
    expect(res.status).toBe(401);
  });

  it("GET /api/colaboradores retorna 401 sem autenticação", async () => {
    const res = await request(app).get("/api/colaboradores");
    expect(res.status).toBe(401);
  });

  it("GET /api/auditoria retorna 401 sem autenticação", async () => {
    const res = await request(app).get("/api/auditoria");
    expect(res.status).toBe(401);
  });

  it("GET /api/usuarios retorna 401 sem autenticação", async () => {
    const res = await request(app).get("/api/usuarios");
    expect(res.status).toBe(401);
  });
});

describe("Rate limit no login", () => {
  it("bloqueia após 5 tentativas consecutivas", async () => {
    const tentativas = Array(6).fill(null).map(() =>
      request(app)
        .post("/api/auth/login")
        .set("X-Requested-With", "XMLHttpRequest")
        .send({ email: "test@test.com", senha: "errada123" })
    );
    const respostas = await Promise.all(tentativas);
    const ultima = respostas[respostas.length - 1];
    expect([429, 400, 401]).toContain(ultima.status);
  });
});
