// src/services/authService.js
"use strict";
const bcrypt = require("bcryptjs");
const jwt    = require("jsonwebtoken");
const { UsuarioModel } = require("../models");
const logger = require("../utils/logger");

const ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || "12");

const gerarTokens = (usuario) => {
  const payload = { id: usuario.id, nome: usuario.nome, email: usuario.email, perfil: usuario.perfil };
  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "8h",
    issuer: "benel-dpflow", audience: "benel-dpflow-client",
  });
  const refreshToken = jwt.sign({ id: usuario.id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  });
  return { accessToken, refreshToken };
};

const AuthService = {
  login: async (email, senha, ip = "") => {
    const res = await UsuarioModel.findByEmail(email);
    // Resposta genérica para não vazar se e-mail existe
    if (res.rowCount === 0) {
      logger.warn("Login falhou — usuário não encontrado", { email, ip });
      throw Object.assign(new Error("Credenciais inválidas"), { status: 401 });
    }
    const usuario = res.rows[0];
    const ok = await bcrypt.compare(senha, usuario.senha_hash);
    if (!ok) {
      logger.warn("Login falhou — senha incorreta", { email, ip });
      throw Object.assign(new Error("Credenciais inválidas"), { status: 401 });
    }
    const tokens = gerarTokens(usuario);
    const expiraEm = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await UsuarioModel.saveRefreshToken(usuario.id, tokens.refreshToken, expiraEm);
    logger.info("Login OK", { userId: usuario.id, email, ip });
    return {
      ...tokens,
      usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, perfil: usuario.perfil },
    };
  },

  refresh: async (refreshToken) => {
    let payload;
    try {
      payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      throw Object.assign(new Error("Refresh token inválido ou expirado"), { status: 401 });
    }
    const tr = await UsuarioModel.findRefreshToken(refreshToken);
    if (tr.rowCount === 0)
      throw Object.assign(new Error("Refresh token não encontrado"), { status: 401 });
    const ur = await UsuarioModel.findById(payload.id);
    if (ur.rowCount === 0 || !ur.rows[0].ativo)
      throw Object.assign(new Error("Usuário inativo"), { status: 401 });
    const tokens = gerarTokens(ur.rows[0]);
    const expiraEm = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await UsuarioModel.saveRefreshToken(payload.id, tokens.refreshToken, expiraEm);
    return tokens;
  },

  logout: async (userId) => {
    await UsuarioModel.deleteRefreshToken(userId);
    logger.info("Logout", { userId });
  },

  hashSenha: (senha) => bcrypt.hash(senha, ROUNDS),

  alterarSenha: async (userId, senhaAtual, novaSenha) => {
    const ur = await UsuarioModel.findById(userId);
    if (ur.rowCount === 0) throw Object.assign(new Error("Usuário não encontrado"), { status: 404 });
    const full = await UsuarioModel.findByEmail(ur.rows[0].email);
    const ok   = await bcrypt.compare(senhaAtual, full.rows[0].senha_hash);
    if (!ok) throw Object.assign(new Error("Senha atual incorreta"), { status: 401 });
    const hash = await bcrypt.hash(novaSenha, ROUNDS);
    await UsuarioModel.update(userId, { senha_hash: hash });
    logger.info("Senha alterada", { userId });
  },
};

module.exports = AuthService;
