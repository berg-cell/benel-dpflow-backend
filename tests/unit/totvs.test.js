// tests/unit/totvs.test.js
"use strict";
const { gerarLinha, validarLinha, processarBlocos } = require("../../src/utils/totvs");

const linhaValida = {
  chapa: "0001",
  data: "2025-09-30",
  evento_codigo: "1148",
  hora: "004:30",
  valor: "1190.47",
  valor_original: "1190.47",
  referencia: "0",
};

describe("validarLinha", () => {
  it("aceita linha válida",         () => expect(validarLinha(linhaValida)).toHaveLength(0));
  it("rejeita chapa ausente",       () => expect(validarLinha({ ...linhaValida, chapa: "" })).not.toHaveLength(0));
  it("rejeita chapa não numérica",  () => expect(validarLinha({ ...linhaValida, chapa: "AB12" })).not.toHaveLength(0));
  it("rejeita data inválida",       () => expect(validarLinha({ ...linhaValida, data: "30/09/2025" })).not.toHaveLength(0));
  it("rejeita código evento longo", () => expect(validarLinha({ ...linhaValida, evento_codigo: "ABCDE" })).not.toHaveLength(0));
  it("rejeita valor negativo",      () => expect(validarLinha({ ...linhaValida, valor: "-1" })).not.toHaveLength(0));
  it("rejeita hora com formato errado", () => expect(validarLinha({ ...linhaValida, hora: "4:30" })).toHaveLength(0)); // aceita 1 dígito
});

describe("gerarLinha", () => {
  it("gera linha com 81 caracteres", () => {
    const linha = gerarLinha(linhaValida);
    expect(linha).toHaveLength(81);
  });

  it("termina com NN", () => {
    const linha = gerarLinha(linhaValida);
    expect(linha.slice(-2)).toBe("NN");
  });

  it("chapa ocupa primeiros 16 chars", () => {
    const linha = gerarLinha(linhaValida);
    expect(linha.slice(0, 16).trim()).toBe("0001");
  });

  it("data no formato DDMMAAAA nas posições 16-24", () => {
    const linha = gerarLinha(linhaValida);
    expect(linha.slice(16, 24)).toBe("30092025");
  });

  it("código do evento nas posições 24-28", () => {
    const linha = gerarLinha(linhaValida);
    expect(linha.slice(24, 28).trim()).toBe("1148");
  });
});

describe("processarBlocos", () => {
  const blocoValido = {
    descricao: "Teste",
    linhas: [linhaValida],
  };

  it("processa bloco válido sem erros", () => {
    const { valido, errosBlocos, linhasTxt } = processarBlocos([blocoValido]);
    expect(valido).toBe(true);
    expect(errosBlocos).toHaveLength(0);
    expect(linhasTxt).toHaveLength(1);
  });

  it("retorna erros em bloco inválido", () => {
    const blocoInvalido = { descricao: "Erro", linhas: [{ ...linhaValida, chapa: "" }] };
    const { valido, errosBlocos } = processarBlocos([blocoInvalido]);
    expect(valido).toBe(false);
    expect(errosBlocos.length).toBeGreaterThan(0);
  });
});
