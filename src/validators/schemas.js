// src/validators/schemas.js
"use strict";
const Joi = require("joi");

const pt = {
  "string.base":          "{{#label}} deve ser texto",
  "string.empty":         "{{#label}} não pode ser vazio",
  "string.min":           "{{#label}} mínimo {{#limit}} caracteres",
  "string.max":           "{{#label}} máximo {{#limit}} caracteres",
  "string.email":         "{{#label}} deve ser e-mail válido",
  "string.pattern.base":  "{{#label}} formato inválido",
  "number.base":          "{{#label}} deve ser numérico",
  "number.min":           "{{#label}} mínimo {{#limit}}",
  "number.max":           "{{#label}} máximo {{#limit}}",
  "any.required":         "{{#label}} é obrigatório",
  "any.only":             "{{#label}} deve ser: {{#valids}}",
  "array.min":            "{{#label}} deve ter ao menos {{#limit}} item(s)",
};

const senhaFort = Joi.string().min(8).max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
  .messages({ ...pt, "string.pattern.base": "Senha precisa de maiúscula, minúscula, número e símbolo (@$!%*?&)" });

// ── Auth ──────────────────────────────────────────────────────────────────────
exports.loginSchema = Joi.object({
  email: Joi.string().email().max(255).required().label("E-mail"),
  senha: Joi.string().min(3).max(128).required().label("Senha"),
}).messages(pt);

exports.refreshSchema = Joi.object({
  refreshToken: Joi.string().required().label("Refresh token"),
}).messages(pt);

exports.alterarSenhaSchema = Joi.object({
  senhaAtual:     Joi.string().required().label("Senha atual"),
  novaSenha:      senhaFort.required().label("Nova senha"),
  confirmarSenha: Joi.valid(Joi.ref("novaSenha")).required().label("Confirmação")
    .messages({ "any.only": "As senhas não conferem" }),
}).messages(pt);

// ── Usuários ──────────────────────────────────────────────────────────────────
exports.criarUsuarioSchema = Joi.object({
  nome:   Joi.string().min(2).max(150).required().label("Nome"),
  email:  Joi.string().email().max(255).required().label("E-mail"),
  senha:  senhaFort.required().label("Senha"),
  perfil: Joi.string().valid("gestor","superior","dp","admin").required().label("Perfil"),
  ativo:  Joi.boolean().default(true),
}).messages(pt);

exports.atualizarUsuarioSchema = Joi.object({
  nome:   Joi.string().min(2).max(150).label("Nome"),
  email:  Joi.string().email().max(255).label("E-mail"),
  perfil: Joi.string().valid("gestor","superior","dp","admin").label("Perfil"),
  ativo:  Joi.boolean(),
}).min(1).messages(pt);

// ── Colaboradores ─────────────────────────────────────────────────────────────
exports.colaboradorSchema = Joi.object({
  chapa:         Joi.string().max(20).required().label("Chapa"),
  nome:          Joi.string().min(2).max(200).required().label("Nome"),
  funcao:        Joi.string().max(100).allow("",null).label("Função"),
  situacao:      Joi.string().valid("Ativo","Inativo").default("Ativo").label("Situação"),
  centro_custo:  Joi.string().max(50).allow("",null).label("Centro de custo"),
  desc_cc:       Joi.string().max(500).allow("",null).label("Descrição CC"),
  cpf:           Joi.string().max(20).allow("",null).label("CPF"),
  data_admissao: Joi.alternatives().try(
    Joi.string().pattern(/^\d{4}-\d{2}-\d{2}$/),
    Joi.string().allow(""),
    Joi.valid(null)
  ).label("Admissão"),
}).messages(pt);

exports.importarColaboradoresSchema = Joi.object({
  colaboradores: Joi.array().items(exports.colaboradorSchema).min(1).required().label("Colaboradores"),
}).messages(pt);

// ── Eventos ───────────────────────────────────────────────────────────────────
exports.eventoSchema = Joi.object({
  codigo:    Joi.string().pattern(/^[a-zA-Z0-9]{1,4}$/).required().label("Código"),
  descricao: Joi.string().min(2).max(200).required().label("Descrição"),
  tipo:      Joi.string().valid("provento","desconto").required().label("Tipo"),
  forma:     Joi.string().valid("valor","hora","referencia").required().label("Forma"),
  ativo:     Joi.boolean().default(true),
}).messages(pt);

// ── Blocos ────────────────────────────────────────────────────────────────────
const linhaSchema = Joi.object({
  colaborador_id: Joi.number().integer().positive().required().label("Colaborador"),
  data:           Joi.string().pattern(/^\d{4}-\d{2}-\d{2}$/).required().label("Data"),
  hora:           Joi.string().pattern(/^\d{1,3}:\d{2}$/).allow("",null).label("Hora"),
  valor:          Joi.number().min(0).max(999999999999.99).required().label("Valor"),
  valor_original: Joi.number().min(0).allow(null).label("Valor original"),
  referencia:     Joi.number().min(0).allow(null).label("Referência"),
  observacao:     Joi.string().max(500).allow("",null).label("Observação"),
}).messages(pt);

exports.blocoSchema = Joi.object({
  descricao:   Joi.string().min(2).max(200).required().label("Descrição"),
  competencia: Joi.string().pattern(/^\d{6}$/).required().label("Competência"),
  evento_id:   Joi.number().integer().positive().required().label("Evento"),
  linhas:      Joi.array().items(linhaSchema).min(1).required().label("Lançamentos"),
  anexo_nome:  Joi.string().max(255).allow("",null).label("Anexo"),
  anexo_tamanho: Joi.string().max(20).allow("",null).label("Tamanho anexo"),
}).messages(pt);

exports.acaoAprovacaoSchema = Joi.object({
  acao: Joi.string().valid("aprovar","rejeitar","devolver").required().label("Ação"),
  justificativa: Joi.when("acao", {
    is: Joi.valid("rejeitar","devolver"),
    then:      Joi.string().min(5).max(500).required().label("Justificativa"),
    otherwise: Joi.string().allow("",null),
  }),
}).messages(pt);

// ── Hierarquia / Alçadas ──────────────────────────────────────────────────────
exports.hierarquiaSchema = Joi.object({
  gestor_id:    Joi.number().integer().positive().required().label("Gestor"),
  superior_id:  Joi.number().integer().positive().required().label("Superior"),
  centro_custo: Joi.string().max(20).allow("",null).label("Centro de custo"),
  desc_cc:      Joi.string().max(100).allow("",null).label("Descrição CC"),
  ativo:        Joi.boolean().default(true),
}).messages(pt);

exports.alcadaSchema = Joi.object({
  evento_id:   Joi.number().integer().positive().required().label("Evento"),
  num_alcadas: Joi.number().valid(1,2).required().label("Alçadas"),
  exige_anexo: Joi.boolean().default(false),
  ativo:       Joi.boolean().default(true),
}).messages(pt);
