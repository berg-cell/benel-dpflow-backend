// src/controllers/auditoriaController.js
"use strict";
const { AuditoriaModel } = require("../models");
const R = require("../utils/response");

exports.listar = async (req, res) => {
  try {
    const { userId, acao, dataInicio, dataFim } = req.query;
    const r = await AuditoriaModel.findAll({ userId, acao, dataInicio, dataFim });
    return R.success(res, r.rows);
  } catch (e) { return R.error(res, e.message); }
};
