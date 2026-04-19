// src/utils/totvs.js
// Layout RM Labore — 81 caracteres por linha
"use strict";

const gerarLinha = (linha) => {
  // Col 01-16 (16): Chapa
  const chapa = String(linha.chapa || "").padEnd(16, " ").slice(0, 16);

  // Col 17-24 (8): Data DDMMAAAA
  let data = "00000000";
  if (linha.data) {
    const [y, m, d] = String(linha.data).split("-");
    if (y && m && d) data = d + m + y;
  }

  // Col 25-28 (4): Código evento
  const evento = String(linha.evento_codigo || "").padEnd(4, " ").slice(0, 4);

  // Col 29-34 (6): Hora HHH:MM
  let hora = "000:00";
  if (linha.hora) {
    const [hh, mm] = String(linha.hora).split(":");
    hora = String(parseInt(hh || 0)).padStart(3, "0") + ":" + String(parseInt(mm || 0)).padStart(2, "0");
  }

  // Col 35-49 (15): Referência
  const ref     = parseFloat(linha.referencia || 0).toFixed(2).padStart(15, " ");
  // Col 50-64 (15): Valor
  const val     = parseFloat(linha.valor || 0).toFixed(2).padStart(15, " ");
  // Col 65-79 (15): Valor original
  const valOrig = parseFloat(linha.valor_original || linha.valor || 0).toFixed(2).padStart(15, " ");
  // Col 80 (1): Alterado manualmente
  // Col 81 (1): Férias
  return chapa + data + evento + hora + ref + val + valOrig + "N" + "N";
};

const validarLinha = (linha) => {
  const erros = [];
  if (!linha.chapa || !/^\d{1,16}$/.test(String(linha.chapa)))
    erros.push("Chapa inválida (deve ser numérica, até 16 dígitos)");
  if (!linha.data || !/^\d{4}-\d{2}-\d{2}$/.test(String(linha.data)))
    erros.push("Data inválida (formato AAAA-MM-DD)");
  if (!linha.evento_codigo || !/^[a-zA-Z0-9]{1,4}$/.test(String(linha.evento_codigo)))
    erros.push("Código do evento inválido (até 4 caracteres alfanuméricos)");
  const val = parseFloat(linha.valor);
  if (isNaN(val) || val < 0)          erros.push("Valor inválido");
  if (val > 999999999999.99)           erros.push("Valor excede limite RM (999999999999.99)");
  if (linha.hora && !/^\d{1,3}:\d{2}$/.test(String(linha.hora)))
    erros.push("Hora inválida (formato HHH:MM)");
  return erros;
};

const processarBlocos = (blocos) => {
  const linhasTxt   = [];
  const errosBlocos = [];

  for (const bloco of blocos) {
    for (let i = 0; i < bloco.linhas.length; i++) {
      const linha = bloco.linhas[i];
      const erros = validarLinha(linha);
      if (erros.length > 0) {
        errosBlocos.push({ bloco: bloco.descricao, linha: i + 1, erros });
      } else {
        linhasTxt.push(gerarLinha(linha));
      }
    }
  }

  return { linhasTxt, errosBlocos, valido: errosBlocos.length === 0 };
};

module.exports = { gerarLinha, validarLinha, processarBlocos };
