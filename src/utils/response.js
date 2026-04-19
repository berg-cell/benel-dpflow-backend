// src/utils/response.js
"use strict";

const ok = (res, data = {}, message = "Sucesso", status = 200) =>
  res.status(status).json({ success: true, message, data, timestamp: new Date().toISOString() });

const created = (res, data = {}, message = "Criado com sucesso") => ok(res, data, message, 201);

const fail = (res, message = "Erro interno", status = 500, errors = null) => {
  const body = { success: false, message, timestamp: new Date().toISOString() };
  if (errors) body.errors = errors;
  return res.status(status).json(body);
};

module.exports = {
  success:         ok,
  created,
  error:           (res, msg, status = 500, errors = null) => fail(res, msg, status, errors),
  unauthorized:    (res, msg = "Não autorizado")           => fail(res, msg, 401),
  forbidden:       (res, msg = "Acesso negado")            => fail(res, msg, 403),
  notFound:        (res, msg = "Não encontrado")           => fail(res, msg, 404),
  badRequest:      (res, msg = "Requisição inválida", err = null) => fail(res, msg, 400, err),
  conflict:        (res, msg = "Registro duplicado")       => fail(res, msg, 409),
  tooManyRequests: (res, msg = "Muitas requisições. Tente em 15 minutos.") => fail(res, msg, 429),
};
