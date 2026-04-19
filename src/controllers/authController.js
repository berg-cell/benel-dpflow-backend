// src/controllers/authController.js
"use strict";
const AuthService = require("../services/authService");
const R = require("../utils/response");

exports.login = async (req, res) => {
  try {
    const data = await AuthService.login(req.body.email, req.body.senha, req.ip);
    return R.success(res, data, "Login realizado com sucesso");
  } catch (e) { return R.error(res, e.message, e.status || 500); }
};

exports.refresh = async (req, res) => {
  try {
    const tokens = await AuthService.refresh(req.body.refreshToken);
    return R.success(res, tokens, "Token renovado");
  } catch (e) { return R.error(res, e.message, e.status || 500); }
};

exports.logout = async (req, res) => {
  try {
    await AuthService.logout(req.usuario.id);
    return R.success(res, {}, "Logout realizado");
  } catch (e) { return R.error(res, e.message); }
};

exports.me = (req, res) => R.success(res, { usuario: req.usuario });

exports.alterarSenha = async (req, res) => {
  try {
    await AuthService.alterarSenha(req.usuario.id, req.body.senhaAtual, req.body.novaSenha);
    return R.success(res, {}, "Senha alterada com sucesso");
  } catch (e) { return R.error(res, e.message, e.status || 500); }
};
