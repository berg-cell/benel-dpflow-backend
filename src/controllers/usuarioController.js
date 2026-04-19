// src/controllers/usuarioController.js
"use strict";
const { UsuarioModel } = require("../models");
const AuthService      = require("../services/authService");
const R = require("../utils/response");

exports.listar = async (req, res) => {
  try {
    const r = await UsuarioModel.findAll();
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};

exports.criar = async (req, res) => {
  try {
    const ex = await UsuarioModel.findByEmail(req.body.email);
    if (ex.rowCount > 0) return R.conflict(res, "E-mail já cadastrado");
    const senha_hash = await AuthService.hashSenha(req.body.senha);
    const r = await UsuarioModel.create({ ...req.body, senha_hash });
    return R.created(res, r.rows[0], "Usuário criado com sucesso");
  } catch (e) { return R.error(res, e.message); }
};

exports.atualizar = async (req, res) => {
  try {
    const r = await UsuarioModel.update(req.params.id, req.body);
    if (r.rowCount === 0) return R.notFound(res, "Usuário não encontrado");
    return R.success(res, r.rows[0], "Usuário atualizado");
  } catch (e) { return R.error(res, e.message); }
};

// ── Reset de senha pelo admin ─────────────────────────────────────────────────
exports.resetarSenha = async (req, res) => {
  try {
    const { novaSenha } = req.body;
    if (!novaSenha || novaSenha.length < 6)
      return R.badRequest(res, "A senha deve ter no mínimo 6 caracteres");

    const bcrypt = require("bcryptjs");
    const rounds = parseInt(process.env.BCRYPT_ROUNDS || "12");
    const hash = await bcrypt.hash(novaSenha, rounds);

    const r = await require("../config/database").query(
      "UPDATE usuarios SET senha_hash = $1 WHERE id = $2 RETURNING id, nome, email",
      [hash, req.params.id]
    );
    if (r.rowCount === 0) return R.notFound(res, "Usuário não encontrado");

    return R.success(res, { id: r.rows[0].id }, "Senha redefinida com sucesso");
  } catch (e) { return R.error(res, e.message); }
};
