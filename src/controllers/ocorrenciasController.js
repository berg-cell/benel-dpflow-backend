import { useState, useContext, createContext, useEffect, useCallback, useRef } from "react";
import { api, setTokens, clearTokens, onSessionExpired } from "./api";

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MODULE — DP Flow | Benel 
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MODULE — DP Flow | Benel Soluções em Transporte e Logística
// Implementação: Sanitização XSS, Rate Limiting, Validação de Schema TOTVS RM,
// Prevenção IDOR, Sessão com expiração, Audit Log, Content Security Policy
// ═══════════════════════════════════════════════════════════════════════════════

// ─── 1. SANITIZAÇÃO XSS ───────────────────────────────────────────────────────
// Remove tags HTML e caracteres perigosos de qualquer string
export function sanitize(value) {
  if (typeof value !== "string") return value;
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;")
    .replace(/`/g, "&#x60;")
    .replace(/=/g, "&#x3D;")
    .trim();
}

// Sanitiza objeto inteiro recursivamente
export function sanitizeObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const clean = {};
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === "string") clean[key] = sanitize(val);
    else if (typeof val === "object") clean[key] = sanitizeObject(val);
    else clean[key] = val;
  }
  return clean;
}

// ─── 2. VALIDAÇÃO DE CAMPOS ────────────────────────────────────────────────────
// Padrões seguros para cada tipo de campo
const PATTERNS = {
  email:       /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,
  chapa:       /^[0-9]{1,16}$/,
  codigoEvento:/^[a-zA-Z0-9]{1,4}$/,
  valor:       /^\d{1,12}(\.\d{1,2})?$/,
  data:        /^\d{4}-\d{2}-\d{2}$/,
  hora:        /^\d{1,3}:\d{2}$/,
  competencia: /^\d{6}$/,
  texto:       /^[^<>'"`;]{0,500}$/,
  senha:       /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#])[A-Za-z\d@$!%*?&_\-#]{8,128}$/,
};

export function validateField(tipo, valor) {
  if (!valor && valor !== 0) return { ok: false, erro: "Campo obrigatório" };
  const pattern = PATTERNS[tipo];
  if (!pattern) return { ok: true };
  if (!pattern.test(String(valor))) return { ok: false, erro: `Formato inválido para ${tipo}` };
  return { ok: true };
}

// ─── 3. VALIDAÇÃO DE SCHEMA TOTVS RM ──────────────────────────────────────────
// Valida linha antes de gerar o TXT — garante conformidade com layout RM Labore
export function validarSchemaTotvs(linha) {
  const erros = [];

  // Col 01-16: Chapa — obrigatória, numérica
  if (!linha.colaborador?.chapa) {
    erros.push("Chapa do colaborador obrigatória");
  } else if (!/^\d{1,16}$/.test(linha.colaborador.chapa)) {
    erros.push("Chapa inválida — deve ser numérica com até 16 dígitos");
  }

  // Col 25-28: Código do evento — obrigatório, alfanumérico 4 chars
  if (!linha.evento?.codigo) {
    erros.push("Código do evento obrigatório");
  } else if (!/^[a-zA-Z0-9]{1,4}$/.test(linha.evento.codigo)) {
    erros.push("Código do evento inválido — máximo 4 caracteres alfanuméricos");
  }

  // Col 17-24: Data — obrigatória, formato YYYY-MM-DD
  if (!linha.data) {
    erros.push("Data obrigatória");
  } else if (!/^\d{4}-\d{2}-\d{2}$/.test(linha.data)) {
    erros.push("Data inválida — use formato AAAA-MM-DD");
  } else {
    const d = new Date(linha.data);
    if (isNaN(d.getTime())) erros.push("Data inválida — data não existe");
  }

  // Col 29-34: Hora — formato HHH:MM
  if (linha.hora && !/^\d{1,3}:\d{2}$/.test(linha.hora)) {
    erros.push("Hora inválida — use formato HHH:MM (ex: 004:30)");
  }

  // Col 50-64: Valor — numérico positivo
  const val = parseFloat(linha.valor);
  if (isNaN(val) || val < 0) {
    erros.push("Valor inválido — deve ser número positivo");
  } else if (val > 999999999999.99) {
    erros.push("Valor excede limite máximo do TOTVS RM");
  }

  // Col 35-49: Referência — numérica se preenchida
  if (linha.referencia && isNaN(parseFloat(linha.referencia))) {
    erros.push("Referência inválida — deve ser numérica");
  }

  return { valido: erros.length === 0, erros };
}

// Valida bloco completo antes de exportar
export function validarBlocoParaExportacao(bloco) {
  const errosBloco = [];
  bloco.linhas.forEach((linha, i) => {
    const { valido, erros } = validarSchemaTotvs(linha);
    if (!valido) {
      erros.forEach(e => errosBloco.push(`Linha ${i + 1}: ${e}`));
    }
  });
  return { valido: errosBloco.length === 0, erros: errosBloco };
}

// ─── 4. RATE LIMITING (frontend) ──────────────────────────────────────────────
// Bloqueia tentativas excessivas de login — simula proteção por IP no cliente
const RATE_LIMIT = {
  MAX_TENTATIVAS: 5,
  JANELA_MS: 15 * 60 * 1000, // 15 minutos
  tentativas: {},
};

export function verificarRateLimit(identificador) {
  const agora = Date.now();
  const key = identificador.toLowerCase().trim();

  if (!RATE_LIMIT.tentativas[key]) {
    RATE_LIMIT.tentativas[key] = { count: 0, inicio: agora, bloqueadoAte: null };
  }

  const registro = RATE_LIMIT.tentativas[key];

  // Verificar se está bloqueado
  if (registro.bloqueadoAte && agora < registro.bloqueadoAte) {
    const restante = Math.ceil((registro.bloqueadoAte - agora) / 60000);
    return { permitido: false, erro: `Muitas tentativas. Tente novamente em ${restante} minuto(s).` };
  }

  // Resetar janela se expirou
  if (agora - registro.inicio > RATE_LIMIT.JANELA_MS) {
    registro.count = 0;
    registro.inicio = agora;
    registro.bloqueadoAte = null;
  }

  registro.count++;

  if (registro.count > RATE_LIMIT.MAX_TENTATIVAS) {
    registro.bloqueadoAte = agora + RATE_LIMIT.JANELA_MS;
    return { permitido: false, erro: `Conta bloqueada por 15 minutos após ${RATE_LIMIT.MAX_TENTATIVAS} tentativas.` };
  }

  const restante = RATE_LIMIT.MAX_TENTATIVAS - registro.count;
  return {
    permitido: true,
    aviso: restante <= 2 ? `Atenção: ${restante} tentativa(s) restante(s) antes do bloqueio.` : null
  };
}

export function resetarRateLimit(identificador) {
  const key = identificador.toLowerCase().trim();
  delete RATE_LIMIT.tentativas[key];
}

// ─── 5. SESSÃO COM EXPIRAÇÃO (JWT simulado) ────────────────────────────────────
// Gera token de sessão com expiração — simula JWT no frontend
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 horas
const INACTIVITY_LIMIT_MS = 15 * 60 * 1000;      // 15 min inatividade

export function criarSessao(user) {
  const agora = Date.now();
  const sessao = {
    userId: user.id,
    perfil: user.perfil,
    email: user.email,
    nome: user.nome,
    avatar: user.avatar,
    criadaEm: agora,
    expiraEm: agora + SESSION_DURATION_MS,
    ultimaAtividade: agora,
    token: gerarToken(),
  };
  try {
    sessionStorage.setItem("dpflow_sessao", JSON.stringify(sessao));
  } catch (_) {}
  return sessao;
}

export function obterSessao() {
  try {
    const raw = sessionStorage.getItem("dpflow_sessao");
    if (!raw) return null;
    const sessao = JSON.parse(raw);
    const agora = Date.now();

    // Verificar expiração absoluta
    if (agora > sessao.expiraEm) {
      encerrarSessao();
      return null;
    }

    // Verificar inatividade
    if (agora - sessao.ultimaAtividade > INACTIVITY_LIMIT_MS) {
      encerrarSessao();
      return null;
    }

    // Atualizar última atividade
    sessao.ultimaAtividade = agora;
    sessionStorage.setItem("dpflow_sessao", JSON.stringify(sessao));
    return sessao;
  } catch (_) {
    return null;
  }
}

export function encerrarSessao() {
  try { sessionStorage.removeItem("dpflow_sessao"); } catch (_) {}
}

function gerarToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, "0")).join("");
}

// ─── 6. PREVENÇÃO IDOR ────────────────────────────────────────────────────────
// Verifica se o usuário tem permissão para acessar determinado recurso
export function verificarPermissaoBloco(bloco, sessao) {
  if (!sessao || !bloco) return false;
  if (sessao.perfil === "admin" || sessao.perfil === "dp") return true;
  if (sessao.perfil === "superior") {
    return bloco.status === "pendente_superior" ||
           bloco.status === "aprovado_final" ||
           bloco.status === "rejeitado";
  }
  if (sessao.perfil === "gestor") {
    return bloco.solicitante_id === sessao.userId ||
           bloco.gestor_id === sessao.userId;
  }
  return false;
}

export function filtrarBlocosPermitidos(blocos, sessao) {
  if (!sessao) return [];
  if (sessao.perfil === "admin" || sessao.perfil === "dp") return blocos;
  return blocos.filter(b => verificarPermissaoBloco(b, sessao));
}

// ─── 7. AUDIT LOG ─────────────────────────────────────────────────────────────
// Registra todas as ações críticas com timestamp
const AUDIT_LOG = [];

export function registrarAuditoria(sessao, acao, detalhes = {}) {
  const entrada = {
    id: Date.now() + Math.random(),
    timestamp: new Date().toISOString(),
    dataHora: new Date().toLocaleString("pt-BR"),
    usuario: sessao?.nome || "Anônimo",
    userId: sessao?.userId,
    perfil: sessao?.perfil,
    acao,
    detalhes: sanitizeObject(detalhes),
    token: sessao?.token?.slice(0, 8) + "...",
  };
  AUDIT_LOG.unshift(entrada);
  // Manter apenas últimas 500 entradas
  if (AUDIT_LOG.length > 500) AUDIT_LOG.pop();
  return entrada;
}

export function obterAuditLog() {
  return [...AUDIT_LOG];
}

// Ações auditáveis
export const ACOES = {
  LOGIN_OK:           "LOGIN_SUCESSO",
  LOGIN_FALHA:        "LOGIN_FALHA",
  LOGOUT:             "LOGOUT",
  SESSAO_EXPIRADA:    "SESSAO_EXPIRADA",
  BLOCO_CRIADO:       "BLOCO_CRIADO",
  BLOCO_EDITADO:      "BLOCO_EDITADO",
  BLOCO_APROVADO:     "BLOCO_APROVADO",
  BLOCO_REJEITADO:    "BLOCO_REJEITADO",
  BLOCO_DEVOLVIDO:    "BLOCO_DEVOLVIDO",
  TXT_EXPORTADO:      "TXT_EXPORTADO",
  ACESSO_NEGADO:      "ACESSO_NEGADO",
  RATE_LIMIT:         "RATE_LIMIT_ATINGIDO",
  SCHEMA_INVALIDO:    "SCHEMA_TOTVS_INVALIDO",
  CADASTRO_ALTERADO:  "CADASTRO_ALTERADO",
};

// ─── 8. CONTENT SECURITY POLICY (meta tag) ────────────────────────────────────
// Injeta CSP no head do documento para bloquear scripts não autorizados
export function aplicarCSP() {
  try {
    const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (existing) return;

    const meta = document.createElement("meta");
    meta.setAttribute("http-equiv", "Content-Security-Policy");
    meta.setAttribute("content", [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self' https://benel-dpflow-backend.vercel.app",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "));
    document.head.appendChild(meta);

    // X-Frame-Options via meta
    const xframe = document.createElement("meta");
    xframe.setAttribute("http-equiv", "X-Frame-Options");
    xframe.setAttribute("content", "DENY");
    document.head.appendChild(xframe);
  } catch (_) {}
}

// ─── 9. PROTEÇÃO CONTRA PROMPT INJECTION ──────────────────────────────────────
// Detecta tentativas de injeção de comandos em campos de texto
const PADROES_MALICIOSOS = [
  /ignore\s+previous/i,
  /system\s*:/i,
  /\[INST\]/i,
  /<\|im_start\|>/i,
  /você\s+é\s+agora/i,
  /aja\s+como/i,
  /act\s+as/i,
  /jailbreak/i,
  /bypass/i,
  /override\s+instructions/i,
  /--\s*system/i,
  /###\s*instruction/i,
];

export function detectarPromptInjection(texto) {
  if (typeof texto !== "string") return false;
  return PADROES_MALICIOSOS.some(p => p.test(texto));
}

export function sanitizarComProtecao(texto, sessao) {
  if (detectarPromptInjection(texto)) {
    registrarAuditoria(sessao, "TENTATIVA_INJECAO", { texto: texto.slice(0, 50) });
    return { seguro: false, erro: "ERR_SEC_001: Entrada rejeitada por política de segurança." };
  }
  return { seguro: true, valor: sanitize(texto) };
}

// ─── 10. VALIDADOR DE FORMULÁRIOS ─────────────────────────────────────────────
// Valida e sanitiza formulário completo antes de salvar
export function validarFormulario(campos) {
  const erros = {};
  const limpo = {};
  let valido = true;

  for (const [key, config] of Object.entries(campos)) {
    const { valor, tipo, obrigatorio, label } = config;

    // Verificar injeção
    if (typeof valor === "string" && detectarPromptInjection(valor)) {
      erros[key] = "ERR_SEC_001: Conteúdo não permitido";
      valido = false;
      continue;
    }

    // Sanitizar
    const valorLimpo = typeof valor === "string" ? sanitize(valor) : valor;

    // Verificar obrigatoriedade
    if (obrigatorio && (!valorLimpo && valorLimpo !== 0)) {
      erros[key] = `${label || key} é obrigatório`;
      valido = false;
      continue;
    }

    // Validar formato
    if (valorLimpo && tipo) {
      const { ok, erro } = validateField(tipo, valorLimpo);
      if (!ok) {
        erros[key] = erro;
        valido = false;
        continue;
      }
    }

    limpo[key] = valorLimpo;
  }

  return { valido, erros, dados: limpo };
}


const LOGO_BENEL = "data:image/jpeg;base64,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";


const ASSINATURA_BENEL = "data:image/jpeg;base64,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";

// ─── CONTEXTO DE AUTH ────────────────────────────────────────────────────────
const AuthContext = createContext(null);

const MOCK_USERS = [
  { id: 1, nome: "Carlos Mendes", email: "gestor@dp.com", senha: "123", perfil: "gestor", avatar: "CM" },
  { id: 2, nome: "Ana Souza", email: "superior@dp.com", senha: "123", perfil: "superior", avatar: "AS" },
  { id: 3, nome: "Fernanda Lima", email: "dp@dp.com", senha: "123", perfil: "dp", avatar: "FL" },
  { id: 4, nome: "Admin", email: "admin@dp.com", senha: "123", perfil: "admin", avatar: "AD" },
];

const MOCK_COLABORADORES = [
  { id: 1, chapa: "0404", nome: "João Pedro Silva", funcao: "Analista", situacao: "Ativo", centro_custo: "001", desc_cc: "TI" },
  { id: 2, chapa: "0512", nome: "Maria Fernanda Costa", funcao: "Coordenadora", situacao: "Ativo", centro_custo: "002", desc_cc: "RH" },
  { id: 3, chapa: "0718", nome: "Roberto Alves", funcao: "Motorista", situacao: "Ativo", centro_custo: "003", desc_cc: "Logística" },
  { id: 4, chapa: "0321", nome: "Luciana Torres", funcao: "Técnica", situacao: "Ativo", centro_custo: "001", desc_cc: "TI" },
];

const MOCK_EVENTOS = [
  { id: 1, codigo: "1148", descricao: "Auxílio Quilometragem", tipo: "provento", forma: "valor" },
  { id: 2, codigo: "1150", descricao: "Ajuda de Custo", tipo: "provento", forma: "valor" },
  { id: 3, codigo: "1155", descricao: "Horas Extras 50%", tipo: "provento", forma: "hora" },
  { id: 4, codigo: "1160", descricao: "Diária de Viagem", tipo: "provento", forma: "referencia" },
  { id: 5, codigo: "2001", descricao: "Desconto Multa Trânsito", tipo: "desconto", forma: "valor" },
  { id: 6, codigo: "1175", descricao: "Sobreaviso", tipo: "provento", forma: "hora" },
];

const MOCK_SOLICITACOES_INIT = [
  {
    id: 1, colaborador_id: 1, evento_id: 1, tipo: "Auxílio Quilometragem",
    data: "2025-09-30", hora: "00:00", referencia: "", valor: "1190.47", valor_original: "1190.47",
    observacao: "Deslocamento filial sul", status: "aprovado_final", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-25",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-25 09:00", obs: "" },
      { acao: "aprovado_gestor", usuario: "Carlos Mendes", data: "2025-09-25 09:05", obs: "" },
      { acao: "aprovado_superior", usuario: "Ana Souza", data: "2025-09-26 10:00", obs: "" },
      { acao: "aprovado_dp", usuario: "Fernanda Lima", data: "2025-09-27 14:00", obs: "" },
    ]
  },
  {
    id: 2, colaborador_id: 3, evento_id: 3, tipo: "Horas Extras 50%",
    data: "2025-09-28", hora: "04:30", referencia: "", valor: "340.00", valor_original: "340.00",
    observacao: "Plantão final de semana", status: "pendente_gestor", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-28",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-28 08:00", obs: "" },
    ]
  },
  {
    id: 3, colaborador_id: 2, evento_id: 2, tipo: "Ajuda de Custo",
    data: "2025-09-20", hora: "", referencia: "", valor: "500.00", valor_original: "500.00",
    observacao: "Curso externo SP", status: "pendente_superior", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-20",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-20 10:00", obs: "" },
      { acao: "aprovado_gestor", usuario: "Carlos Mendes", data: "2025-09-20 10:30", obs: "" },
    ]
  },
  {
    id: 4, colaborador_id: 4, evento_id: 5, tipo: "Desconto Multa Trânsito",
    data: "2025-09-15", hora: "", referencia: "", valor: "293.47", valor_original: "293.47",
    observacao: "Multa via expressa", status: "devolvido", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-15",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-15 11:00", obs: "" },
      { acao: "devolvido", usuario: "Ana Souza", data: "2025-09-16 09:00", obs: "Falta comprovante da infração" },
    ]
  },
];

// ─── UTILITÁRIOS ─────────────────────────────────────────────────────────────
// Converte data do banco para YYYY-MM-DD usando UTC (sem conversão de fuso)
function fmtDateLocal(val) {
  if (!val) return "";
  const d = new Date(val);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}

const STATUS_CONFIG = {
  pendente_gestor:   { label: "Pendente Gestor",   color: "#F59E0B", bg: "#FEF3C7", dot: "#F59E0B" },
  pendente_superior: { label: "Pendente Superior", color: "#8B5CF6", bg: "#EDE9FE", dot: "#8B5CF6" },
  pendente_dp:       { label: "Pendente DP",       color: "#3B82F6", bg: "#DBEAFE", dot: "#3B82F6" },
  aprovado_final:    { label: "Aprovado",           color: "#10B981", bg: "#D1FAE5", dot: "#10B981" },
  rejeitado:         { label: "Rejeitado",          color: "#EF4444", bg: "#FEE2E2", dot: "#EF4444" },
  devolvido:         { label: "Devolvido",          color: "#F97316", bg: "#FFEDD5", dot: "#F97316" },
  rascunho:          { label: "Rascunho",           color: "#6B7280", bg: "#F3F4F6", dot: "#6B7280" },
};

const PERFIL_CONFIG = {
  gestor:    { label: "Gestor",    color: "#3B82F6" },
  superior:  { label: "Superior",  color: "#8B5CF6" },
  dp:        { label: "DP",        color: "#10B981" },
  admin:     { label: "Admin",     color: "#F59E0B" },
};

// ─── LAYOUT OFICIAL RM LABORE ─────────────────────────────────────────────────
// Col 01 | Tam 16 | String       | Chapa do Funcionário
// Col 17 | Tam 08 | String       | Data pagamento (DDMMAAAA)
// Col 25 | Tam 04 | Alfanumérico | Código do evento
// Col 29 | Tam 06 | String       | Hora (HHH:MM)
// Col 35 | Tam 15 | Real         | Referência (999999999999.99)
// Col 50 | Tam 15 | Real         | Valor (999999999999.99)
// Col 65 | Tam 15 | Real         | Valor original (999999999999.99)
// Col 80 | Tam 01 | Caractere    | Dados alterados manualmente (S ou N)
// Col 81 | Tam 01 | Caractere    | Dados de férias (S ou N)
// Total  | 81 caracteres por linha

function formatReal(valor, tam) {
  // Formata número no padrão 999999999999.99 com tamanho fixo, sem ponto de milhar
  const num = parseFloat(valor || 0);
  const str = num.toFixed(2).replace(",", ".");
  // Remove ponto decimal para alinhar: ex "1190.47" -> padStart sem ponto
  return str.padStart(tam, " ");
}

function generateTXTLine(sol, colaboradores, eventos) {
  const colab = colaboradores.find(c => c.id === sol.colaborador_id);
  const evento = eventos.find(e => e.id === sol.evento_id);
  if (!colab || !evento) return "";

  // Col 01-16 (16): Chapa do Funcionário — alinhada à esquerda, preenchida com espaços à direita
  const chapa = (colab.chapa || "").padEnd(16, " ").slice(0, 16);

  // Col 17-24 (8): Data pagamento DDMMAAAA
  let dataTXT = "00000000";
  if (sol.data) {
    const parts = sol.data.split("-");
    if (parts.length === 3) dataTXT = parts[2] + parts[1] + parts[0];
  }
  const data = dataTXT.slice(0, 8);

  // Col 25-28 (4): Código do evento — alfanumérico, espaço à direita
  const codEvento = (evento.codigo || "").padEnd(4, " ").slice(0, 4);

  // Col 29-34 (6): Hora HHH:MM (ex: 004:30 ou 000:00)
  let horaTXT = "000:00";
  if (sol.hora) {
    const hParts = sol.hora.split(":");
    const hh = String(parseInt(hParts[0] || 0)).padStart(3, "0");
    const mm = String(parseInt(hParts[1] || 0)).padStart(2, "0");
    horaTXT = hh + ":" + mm;
  }
  const hora = horaTXT.slice(0, 6);

  // Col 35-49 (15): Referência — Real formatado
  const ref = formatReal(sol.referencia || sol.hora_decimal || 0, 15).slice(0, 15);

  // Col 50-64 (15): Valor
  const val = formatReal(sol.valor || 0, 15).slice(0, 15);

  // Col 65-79 (15): Valor original
  const valOrig = formatReal(sol.valor_original || sol.valor || 0, 15).slice(0, 15);

  // Col 80 (1): Alterado manualmente — N padrão
  const alterado = "N";

  // Col 81 (1): Dados de férias — N padrão
  const ferias = "N";

  const linha = chapa + data + codEvento + hora + ref + val + valOrig + alterado + ferias;
  return linha;
}

// ─── COMPONENTES BASE ─────────────────────────────────────────────────────────
function Badge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.rascunho;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 20, fontSize: 11, fontWeight: 600,
      color: cfg.color, background: cfg.bg, letterSpacing: 0.3
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.dot }} />
      {cfg.label}
    </span>
  );
}

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB",
      padding: "20px 24px", ...style
    }}>
      {children}
    </div>
  );
}

function Button({ children, onClick, variant = "primary", size = "md", disabled = false, style = {} }) {
  const variants = {
    primary: { background: "#1B3A6B", color: "#fff", border: "none" },
    secondary: { background: "#F3F4F6", color: "#374151", border: "1px solid #E5E7EB" },
    success: { background: "#10B981", color: "#fff", border: "none" },
    danger: { background: "#EF4444", color: "#fff", border: "none" },
    warning: { background: "#F59E0B", color: "#fff", border: "none" },
    ghost: { background: "transparent", color: "#1B3A6B", border: "1px solid #1B3A6B" },
  };
  const sizes = {
    sm: { padding: "3px 8px", fontSize: 11 },
    md: { padding: "6px 14px", fontSize: 11 },
    lg: { padding: "8px 18px", fontSize: 13 },
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        ...variants[variant], ...sizes[size],
        borderRadius: 8, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1, fontFamily: "inherit", transition: "all 0.15s",
        ...style
      }}
    >
      {children}
    </button>
  );
}

function Input({ label, value, onChange, type = "text", placeholder = "", required = false, style = {} }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {label && (
        <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
          {label}{required && <span style={{ color: "#EF4444" }}> *</span>}
        </label>
      )}
      <input
        type={type} value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px",
          fontSize: 11, color: "#111827", outline: "none", fontFamily: "inherit",
          background: "#FAFAFA", ...style
        }}
      />
    </div>
  );
}

function Select({ label, value, onChange, options, required = false }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {label && (
        <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
          {label}{required && <span style={{ color: "#EF4444" }}> *</span>}
        </label>
      )}
      <select
        value={value} onChange={e => onChange(e.target.value)}
        style={{
          border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px",
          fontSize: 11, color: "#111827", outline: "none", fontFamily: "inherit",
          background: "#FAFAFA", cursor: "pointer"
        }}
      >
        <option value="">Selecione...</option>
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

function Modal({ open, onClose, title, children, width = 540 }) {
  if (!open) return null;
  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000
    }} onClick={onClose}>
      <div style={{
        background: "#fff", borderRadius: 14, width, maxWidth: "95vw",
        maxHeight: "90vh", overflowY: "auto", boxShadow: "0 20px 60px rgba(0,0,0,0.2)"
      }} onClick={e => e.stopPropagation()}>
        <div style={{
          padding: "18px 24px", borderBottom: "1px solid #F3F4F6",
          display: "flex", alignItems: "center", justifyContent: "space-between"
        }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#111827" }}>{title}</h3>
          <button onClick={onClose} style={{
            background: "none", border: "none", fontSize: 20, cursor: "pointer",
            color: "#6B7280", lineHeight: 1, padding: "0 4px"
          }}>×</button>
        </div>
        <div style={{ padding: "20px 24px" }}>{children}</div>
      </div>
    </div>
  );
}

// ─── VALIDADOR DE FORÇA DE SENHA ─────────────────────────────────────────────
function verificarForcaSenha(senha) {
  const checks = [
    { ok: senha.length >= 8,                        label: "Mínimo 8 caracteres" },
    { ok: /[A-Z]/.test(senha),                       label: "Letra maiúscula" },
    { ok: /[a-z]/.test(senha),                       label: "Letra minúscula" },
    { ok: /\d/.test(senha),                          label: "Número" },
    { ok: /[@$!%*?&_\-#]/.test(senha),              label: "Caractere especial (@$!%*?&_-#)" },
  ];
  const score = checks.filter(c => c.ok).length;
  const forca = score <= 2 ? "fraca" : score <= 3 ? "média" : score === 4 ? "boa" : "forte";
  const cor   = score <= 2 ? "#EF4444" : score <= 3 ? "#F59E0B" : score === 4 ? "#3B82F6" : "#10B981";
  return { checks, score, forca, cor, valida: score === 5 };
}

function IndicadorSenha({ senha }) {
  if (!senha) return null;
  const { checks, score, forca, cor } = verificarForcaSenha(senha);
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ display: "flex", gap: 4, marginBottom: 6 }}>
        {[1,2,3,4,5].map(i => (
          <div key={i} style={{
            flex: 1, height: 4, borderRadius: 2,
            background: i <= score ? cor : "#E5E7EB",
            transition: "background 0.2s"
          }} />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: cor }}>Força: {forca}</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "3px 12px" }}>
        {checks.map(c => (
          <span key={c.label} style={{ fontSize: 10, color: c.ok ? "#10B981" : "#9CA3AF" }}>
            {c.ok ? "✓" : "○"} {c.label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── LOGIN SEGURO ─────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [erro, setErro] = useState("");
  const [aviso, setAviso] = useState("");
  const [loading, setLoading] = useState(false);
  const [bloqueado, setBloqueado] = useState(false);

  // Aplicar CSP ao montar
  useEffect(() => { aplicarCSP(); }, []);

  const handleLogin = async () => {
    setErro(""); setAviso("");

    const emailLimpo = sanitize(email.trim());
    if (!emailLimpo || !/^[^@]+@[^@]+\.[^@]+$/.test(emailLimpo)) {
      setErro("Informe um e-mail válido.");
      return;
    }

    const rate = verificarRateLimit(emailLimpo);
    if (!rate.permitido) {
      setBloqueado(true);
      setErro(rate.erro);
      registrarAuditoria(null, ACOES.RATE_LIMIT, { email: emailLimpo });
      return;
    }
    if (rate.aviso) setAviso(rate.aviso);

    setLoading(true);
    try {
      const data = await api.login(emailLimpo, senha);
      // data = { accessToken, refreshToken, usuario: { id, nome, email, perfil } }
      setTokens(data.accessToken, data.refreshToken);
      resetarRateLimit(emailLimpo);
      const u = {
        ...data.usuario,
        avatar: data.usuario.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase(),
        senha: "",
      };
      const sessao = criarSessao(u);
      registrarAuditoria(sessao, ACOES.LOGIN_OK, { email: emailLimpo });
      onLogin(u, sessao);
    } catch (err) {
      registrarAuditoria(null, ACOES.LOGIN_FALHA, { email: emailLimpo });
      setErro(err.message || "E-mail ou senha inválidos.");
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => { if (e.key === "Enter" && !bloqueado) handleLogin(); };

  return (
    <div style={{
      minHeight: "100vh", background: "linear-gradient(135deg, #0F2447 0%, #1B3A6B 50%, #2D5AA0 100%)",
      display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'DM Sans', sans-serif"
    }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />

      {/* Decoração */}
      <div style={{ position: "fixed", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
        {[...Array(6)].map((_, i) => (
          <div key={i} style={{
            position: "absolute",
            width: [300,200,150,400,250,180][i],
            height: [300,200,150,400,250,180][i],
            borderRadius: "50%",
            border: "1px solid rgba(255,255,255,0.05)",
            left: ["10%","60%","80%","5%","50%","30%"][i],
            top: ["20%","10%","60%","70%","80%","40%"][i],
          }} />
        ))}
      </div>

      <div style={{ position: "relative", zIndex: 1, width: "100%", maxWidth: 420, padding: "0 20px" }}>
        {/* Logo Benel */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{
            background: "rgba(255,255,255,0.95)", backdropFilter: "blur(10px)",
            borderRadius: 16, padding: "16px 28px", marginBottom: 16,
            boxShadow: "0 4px 24px rgba(0,0,0,0.2)",
            display: "inline-block"
          }}>
            <img src={LOGO_BENEL} alt="Benel" style={{ height: 64, display: "block" }} />
          </div>
          <p style={{ color: "rgba(255,255,255,0.55)", margin: "6px 0 0", fontSize: 13 }}>
            Sistema de Gestão de Variáveis para Folha de Pagamento
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: "rgba(255,255,255,0.97)", borderRadius: 18,
          padding: "32px", boxShadow: "0 24px 80px rgba(0,0,0,0.35)"
        }}>
          <h2 style={{ margin: "0 0 6px", fontSize: 18, fontWeight: 700, color: "#0F2447" }}>Entrar</h2>
          <p style={{ margin: "0 0 24px", fontSize: 11, color: "#6B7280" }}>
            Acesse com suas credenciais corporativas
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <Input label="E-mail" value={email} onChange={setEmail} type="email" placeholder="seu@email.com" style={{ onKeyDown: handleKeyDown }} />
            <Input label="Senha" value={senha} onChange={setSenha} type="password" placeholder="••••••••" />

            {aviso && (
              <div style={{
                background: "#FFFBEB", border: "1px solid #FCD34D",
                borderRadius: 8, padding: "3px 6px", fontSize: 12, color: "#92400E"
              }}>
                ⚠️ {aviso}
              </div>
            )}
            {erro && (
              <div style={{
                background: "#FEF2F2", border: "1px solid #FCA5A5",
                borderRadius: 8, padding: "3px 6px", fontSize: 12, color: "#DC2626"
              }}>
                🔒 {erro}
              </div>
            )}

            <Button onClick={handleLogin} disabled={loading || bloqueado} size="lg" style={{ marginTop: 4, width: "100%" }}>
              {loading ? "Verificando..." : bloqueado ? "🔒 Acesso Bloqueado" : "Entrar"}
            </Button>
          </div>

          {/* Suporte */}
          <div style={{
            marginTop: 20, padding: "3px 6px", background: "#F8FAFC",
            borderRadius: 8, border: "1px solid #E2E8F0", textAlign: "center"
          }}>
            <p style={{ margin: 0, fontSize: 11, color: "#94A3B8" }}>
              Problemas de acesso? Contate o administrador do sistema.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── SIDEBAR ─────────────────────────────────────────────────────────────────

// ─── SIDEBAR COM SUBMENU ──────────────────────────────────────────────────────
const CADASTROS_SUBMENU = [
  { id: "cad_colaboradores", label: "Colaboradores",  icon: "👥", perfis: ["dp","admin"] },
  { id: "cad_eventos",       label: "Eventos",         icon: "⚡", perfis: ["dp","admin"] },
  { id: "cad_hierarquia",    label: "Hierarquia",      icon: "🏢", perfis: ["dp","admin"] },
  { id: "cad_alcadas",       label: "Alçadas",         icon: "🔀", perfis: ["dp","admin"] },
  { id: "cad_usuarios",      label: "Usuários",        icon: "🔑", perfis: ["admin"] },
];

const BENEFICIOS_SUBMENU = [
  { id: "plano_saude", label: "Solicitação de Plano de Saúde", icon: "💊", perfis: ["dp","admin","gestor"] },
];

const NAV_ITEMS = [
  { id: "cadastros",     label: "Cadastros",                            icon: "🗂",  perfis: ["dp","admin"], submenu: CADASTROS_SUBMENU },
  { id: "atualizacao_cadastral", label: "Atualização de Dados Cadastrais", icon: "📝", perfis: ["gestor","dp","admin"] },
  { id: "ocorrencias",      label: "Solicitações de Advertências/Suspensões", icon: "⚠️", perfis: ["gestor","dp","admin"] },
  { id: "autorizacoes",     label: "Autorização de Desconto",                icon: "📋", perfis: ["gestor","dp","admin"] },
  { id: "solicitacoes",     label: "Solicitações de Pagamento",               icon: "≡",  perfis: ["gestor","superior","dp","admin"] },
  { id: "desligamentos", label: "Solicitações de Desligamento",         icon: "🚪", perfis: ["gestor","superior","dp","admin"] },
  { id: "beneficios",    label: "Benefícios",                           icon: "🏥", perfis: ["dp","admin","gestor"], submenu: BENEFICIOS_SUBMENU },
  { id: "aprovacoes",    label: "Aprovações",                           icon: "✓",  perfis: ["superior","dp","admin"] },
  { id: "dashboard",     label: "Dashboard",                            icon: "◉",  perfis: ["gestor","superior","dp","admin"] },
  { id: "exportacao",    label: "Exportação TXT",                       icon: "↓",  perfis: ["dp","admin"] },
  { id: "auditoria",     label: "Auditoria",                            icon: "📜", perfis: ["dp","admin"] },
];


// ─── TOPBAR ───────────────────────────────────────────────────────────────────
function Topbar({ title, subtitle, user, onLogout }) {
  return (
    <div style={{
      height: 60, background: "#fff", borderBottom: "1px solid #E5E7EB",
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "0 28px", flexShrink: 0
    }}>
      <div>
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#111827" }}>{title}</h2>
        {subtitle && <p style={{ margin: 0, fontSize: 11, color: "#9CA3AF" }}>{subtitle}</p>}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <button onClick={onLogout} style={{
          background: "none", border: "1px solid #E5E7EB", borderRadius: 8,
          padding: "5px 12px", fontSize: 11, color: "#6B7280", cursor: "pointer", fontFamily: "inherit"
        }}>Sair</button>
      </div>
    </div>
  );
}

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
function Dashboard({ solicitacoes, blocos, user }) {
  const total = blocos.length;
  const pendentes = blocos.filter(b => b.status.startsWith("pendente")).length;
  const aprovados = blocos.filter(b => b.status === "aprovado_final").length;
  const devolvidos = blocos.filter(b => b.status === "devolvido").length;

  const valorTotal = blocos
    .filter(b => b.status === "aprovado_final")
    .reduce((a, b) => a + b.linhas.reduce((s, l) => s + parseFloat(l.valor || 0), 0), 0);

  const stats = [
    { label: "Total de Blocos", value: total,     color: "#3B82F6", bg: "#EFF6FF", icon: "≡" },
    { label: "Pendentes",       value: pendentes,  color: "#F59E0B", bg: "#FFFBEB", icon: "⏳" },
    { label: "Aprovados",       value: aprovados,  color: "#10B981", bg: "#F0FDF4", icon: "✓" },
    { label: "Devolvidos",      value: devolvidos, color: "#F97316", bg: "#FFF7ED", icon: "↩" },
  ];

  return (
    <div style={{ padding: 28, display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        {stats.map(s => (
          <div key={s.label} style={{ background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB", padding: "18px 20px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "#6B7280", textTransform: "uppercase", letterSpacing: 0.5 }}>{s.label}</span>
              <div style={{ width: 30, height: 30, borderRadius: 8, background: s.bg, display: "flex", alignItems: "center", justifyContent: "center", color: s.color, fontSize: 11, fontWeight: 700 }}>{s.icon}</div>
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: "#111827" }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Valor total aprovado */}
        <Card>
          <h3 style={{ margin: "0 0 16px", fontSize: 11, fontWeight: 700, color: "#111827" }}>💰 Valor Total Aprovado</h3>
          <div style={{ fontSize: 32, fontWeight: 700, color: "#10B981" }}>
            R$ {valorTotal.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
          </div>
          <p style={{ margin: "6px 0 0", fontSize: 11, color: "#6B7280" }}>{aprovados} bloco(s) aprovado(s) no período</p>
        </Card>

        {/* Últimos blocos */}
        <Card>
          <h3 style={{ margin: "0 0 14px", fontSize: 11, fontWeight: 700, color: "#111827" }}>🕐 Últimos Blocos</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {blocos.slice(-4).reverse().map(b => (
              <div key={b.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "7px 0", borderBottom: "1px solid #F3F4F6" }}>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: "#111827" }}>{b.descricao}</div>
                  <div style={{ fontSize: 11, color: "#6B7280" }}>{b.linhas.length} lançamento(s) · {b.competencia}</div>
                </div>
                <Badge status={b.status} />
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Distribuição por status */}
      <Card>
        <h3 style={{ margin: "0 0 16px", fontSize: 11, fontWeight: 700, color: "#111827" }}>📊 Distribuição por Status</h3>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {Object.entries(STATUS_CONFIG).map(([key, cfg]) => {
            const count = blocos.filter(b => b.status === key).length;
            if (!count) return null;
            const pct = Math.round((count / Math.max(total, 1)) * 100);
            return (
              <div key={key} style={{ flex: "1 1 150px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                  <span style={{ fontSize: 11, color: "#6B7280" }}>{cfg.label}</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: cfg.color }}>{count}</span>
                </div>
                <div style={{ height: 6, background: "#F3F4F6", borderRadius: 3 }}>
                  <div style={{ height: "100%", width: pct + "%", background: cfg.color, borderRadius: 3 }} />
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

function Sidebar({ active, onNav, user }) {
  const [abertos, setAbertos] = useState(() => {
    const init = {};
    if (active && active.startsWith("cad_")) init["cadastros"] = true;
    if (active === "plano_saude") init["beneficios"] = true;
    return init;
  });

  const toggleMenu = (id) => setAbertos(o => ({ ...o, [id]: !o[id] }));

  const items = NAV_ITEMS.filter(i => i.perfis.includes(user.perfil));

  const btnStyle = (isActive) => ({
    display: "flex", alignItems: "center", gap: 10,
    padding: "3px 6px", borderRadius: 8, border: "none",
    background: isActive ? "rgba(59,130,246,0.2)" : "transparent",
    color: isActive ? "#93C5FD" : "rgba(255,255,255,0.55)",
    cursor: "pointer", textAlign: "left", fontFamily: "inherit",
    fontSize: 13, fontWeight: isActive ? 600 : 400,
    borderLeft: isActive ? "2px solid #3B82F6" : "2px solid transparent",
    transition: "all 0.15s", width: "100%"
  });

  return (
    <div style={{
      width: 224, minHeight: "100vh", background: "#0F2447",
      display: "flex", flexDirection: "column", flexShrink: 0,
      fontFamily: "'DM Sans', sans-serif"
    }}>
      {/* Logo Benel */}
      <div style={{ padding: "16px 16px 14px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
        <div style={{
          background: "rgba(255,255,255,0.95)", borderRadius: 10,
          padding: "3px 6px", display: "flex", alignItems: "center", justifyContent: "center"
        }}>
          <img src={LOGO_BENEL} alt="Benel" style={{ height: 38, display: "block", maxWidth: "100%" }} />
        </div>
        <div style={{ textAlign: "center", marginTop: 6, fontSize: 9, color: "rgba(255,255,255,0.35)", letterSpacing: 1, textTransform: "uppercase" }}>
          Gestão de Folha de Pagamento
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "12px 10px", display: "flex", flexDirection: "column", gap: 2, overflowY: "auto" }}>
        {items.map(item => {
          if (item.submenu) {
            const subItems = item.submenu.filter(s => s.perfis.includes(user.perfil));
            const isOpen = !!abertos[item.id];
            const isParentActive = item.id === "cadastros"
              ? (active && active.startsWith("cad_"))
              : subItems.some(s => s.id === active);
            return (
              <div key={item.id}>
                {/* Botão pai */}
                <button
                  onClick={() => toggleMenu(item.id)}
                  style={{
                    ...btnStyle(isParentActive),
                    justifyContent: "space-between"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontSize: 14 }}>{item.icon}</span>
                    {item.label}
                  </div>
                  <span style={{
                    fontSize: 10, transition: "transform 0.2s",
                    transform: isOpen ? "rotate(180deg)" : "rotate(0deg)",
                    color: "rgba(255,255,255,0.4)"
                  }}>▼</span>
                </button>

                {/* Submenu */}
                {isOpen && (
                  <div style={{
                    marginLeft: 10, marginTop: 2, marginBottom: 4,
                    borderLeft: "1px solid rgba(255,255,255,0.1)",
                    paddingLeft: 10, display: "flex", flexDirection: "column", gap: 1
                  }}>
                    {subItems.map(sub => (
                      <button
                        key={sub.id}
                        onClick={() => onNav(sub.id)}
                        style={{
                          display: "flex", alignItems: "center", gap: 8,
                          padding: "7px 10px", borderRadius: 6, border: "none",
                          background: active === sub.id ? "rgba(59,130,246,0.25)" : "transparent",
                          color: active === sub.id ? "#93C5FD" : "rgba(255,255,255,0.45)",
                          cursor: "pointer", textAlign: "left", fontFamily: "inherit",
                          fontSize: 12, fontWeight: active === sub.id ? 600 : 400,
                          borderLeft: active === sub.id ? "2px solid #3B82F6" : "2px solid transparent",
                          transition: "all 0.15s", width: "100%"
                        }}
                      >
                        <span style={{ fontSize: 11 }}>{sub.icon}</span>
                        {sub.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          }
          return (
            <button key={item.id} onClick={() => onNav(item.id)} style={btnStyle(active === item.id)}>
              <span style={{ fontSize: 14 }}>{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* User */}
      <div style={{ padding: "14px", borderTop: "1px solid rgba(255,255,255,0.07)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 10,
            background: PERFIL_CONFIG[user.perfil]?.color,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, fontWeight: 700, color: "#fff", flexShrink: 0
          }}>{user.avatar}</div>
          <div style={{ overflow: "hidden" }}>
            <div style={{ color: "#fff", fontSize: 11, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{user.nome}</div>
            <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: 0.5, color: PERFIL_CONFIG[user.perfil]?.color, textTransform: "uppercase" }}>
              {PERFIL_CONFIG[user.perfil]?.label}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── HELPERS DE IMPORTAÇÃO ────────────────────────────────────────────────────
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];

  // Detectar separador: ; ou ,
  const sep = lines[0].includes(";") ? ";" : ",";

  // Dividir linha respeitando aspas
  const splitLine = (line) => {
    const result = []; let cur = ""; let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { inQ = !inQ; continue; }
      if (c === sep && !inQ) { result.push(cur.trim()); cur = ""; continue; }
      cur += c;
    }
    result.push(cur.trim());
    return result;
  };

  // Mapa de colunas PT -> EN (com e sem acento)
  const MAPA = {
    "matrícula": "chapa", "matricula": "chapa", "chapa": "chapa",
    "nome": "nome",
    "função": "funcao", "funcao": "funcao", "cargo": "funcao", "desc_funcao": "funcao",
    "seção": "desc_cc", "secao": "desc_cc", "setor": "desc_cc", "desc_cc": "desc_cc",
    "cpf": "cpf",
    "admissão": "data_admissao", "admissao": "data_admissao",
    "data_admissao": "data_admissao", "data admissao": "data_admissao",
    "c. custo": "centro_custo", "centro_custo": "centro_custo", "centro custo": "centro_custo",
    "situação": "situacao", "situacao": "situacao", "status": "situacao",
    "desc_situacao": "situacao",
    "cod_situacao": "cod_situacao", "cód. situação": "cod_situacao", "cod situacao": "cod_situacao",
    "tipo_contrato": "tipo_contrato", "tipo contrato": "tipo_contrato",
    "data_fim_contrato": "data_fim_contrato", "data fim contrato": "data_fim_contrato",
    "prazo45": "prazo45", "prazo90": "prazo90",
    "data_fim_estabilidade": "data_fim_estabilidade", "data fim estabilidade": "data_fim_estabilidade",
    "descricao_estabilidade": "descricao_estabilidade", "descrição estabilidade": "descricao_estabilidade",
    // Novos campos pessoais/endereço
    "rg": "rg",
    "rg_orgemissor": "rg_orgao", "rg_orgao": "rg_orgao",
    "rg_uf": "rg_uf",
    "ctps": "ctps",
    "ctps_serie": "ctps_serie",
    "rua_func": "logradouro", "logradouro": "logradouro",
    "numero_func": "numero", "numero": "numero",
    "compl_func": "complemento", "complemento": "complemento",
    "bairro": "bairro",
    "cidade": "cidade",
    "uf": "uf",
    "cep": "cep",
    "telefone1": "telefone1",
    "sexo": "sexo",
    "estado_civil": "estado_civil", "estadocivil": "estado_civil",
    "nome_mae": "nome_mae",
    "pis": "pis",
    "posicao_escala": "posicao_escala",
    "motorista_lider": "motorista_lider",
    "munkeiro": "munkeiro",
    "prancheiro": "prancheiro",
    "tamanho_macacao": "tamanho_macacao",
    "tamanho_bota": "tamanho_bota",
  };

  const rawHeaders = splitLine(lines[0]);
  const headers = rawHeaders.map(h => MAPA[h.toLowerCase().trim()] || h.toLowerCase().trim());

  // Converter data DD/MM/AAAA -> AAAA-MM-DD
  const fmtData = (v) => {
    if (!v) return "";
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(v)) {
      const [d, m, a] = v.split("/");
      return `${a}-${m}-${d}`;
    }
    return v;
  };

  // Extrair código do centro de custo "01.08 - DIRETORIA" -> "01.08"
  const fmtCC = (v) => {
    if (!v) return "";
    return v.includes(" - ") ? v.split(" - ")[0].trim() : v.trim();
  };

  return lines.slice(1).filter(l => l.trim()).map(line => {
    const vals = splitLine(line);
    const row = Object.fromEntries(headers.map((h, i) => [h, vals[i] || ""]));
    // Aplicar conversões
    if (row.data_admissao)         row.data_admissao         = fmtData(row.data_admissao);
    if (row.data_fim_contrato)     row.data_fim_contrato     = fmtData(row.data_fim_contrato);
    if (row.data_fim_estabilidade) row.data_fim_estabilidade = fmtData(row.data_fim_estabilidade);
    if (row.prazo45)               row.prazo45               = fmtData(row.prazo45);
    if (row.prazo90)               row.prazo90               = fmtData(row.prazo90);
    if (row.centro_custo)          row.centro_custo          = fmtCC(row.centro_custo);
    // Normalizar situacao a partir de desc_situacao se não vier mapeado
    if (!row.situacao && row.desc_situacao) {
      row.situacao = row.desc_situacao.toLowerCase().includes("ativo") ? "Ativo" : "Inativo";
    }
    return row;
  });
}

function ImportacaoModal({ open, onClose, titulo, colunas, exemplo, onImportar }) {
  const [texto, setTexto] = useState("");
  const [resultado, setResultado] = useState(null);
  const [arquivo, setArquivo] = useState(null);

  const onArquivo = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    setArquivo(f.name);
    const reader = new FileReader();
    reader.onload = ev => {
      let text = ev.target.result;
      // Detectar se tem caracteres corrompidos (Latin-1 lido como UTF-8)
      if (text.includes("\uFFFD") || /[\x80-\x9F]/.test(text)) {
        // Reler como Latin-1
        const reader2 = new FileReader();
        reader2.onload = ev2 => setTexto(ev2.target.result);
        reader2.readAsText(f, "ISO-8859-1");
      } else {
        setTexto(text);
      }
    };
    reader.readAsText(f, "UTF-8");
  };

  const processar = () => {
    try {
      const rows = parseCSV(texto);
      const erros = [];
      const validos = [];
      rows.forEach((row, i) => {
        // Usar campo real (antes do "/") para validar
        const faltando = colunas.filter(c => {
          if (!c.obrigatorio) return false;
          const campoReal = c.campo.split("/")[0].trim();
          return !row[campoReal];
        });
        if (faltando.length > 0) {
          erros.push({ linha: i + 2, msg: "Campos obrigatórios faltando: " + faltando.map(c => c.campo).join(", ") });
        } else {
          validos.push(row);
        }
      });
      setResultado({ validos, erros, total: rows.length });
    } catch (e) {
      setResultado({ validos: [], erros: [{ linha: 0, msg: "Erro ao processar arquivo: " + e.message }], total: 0 });
    }
  };

  const [importando, setImportando] = useState(false);

  const confirmar = async () => {
    setImportando(true);
    try {
      await onImportar(resultado.validos);
      setTexto(""); setResultado(null); setArquivo(null);
      onClose();
    } catch(e) {
      alert("Erro ao importar: " + e.message);
    } finally {
      setImportando(false);
    }
  };

  const baixarModelo = () => {
    const header = colunas.map(c => c.campo).join(",");
    const exemplo_row = colunas.map(c => c.exemplo || "").join(",");
    const blob = new Blob([header + "\n" + exemplo_row], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = "modelo_" + titulo.toLowerCase().replace(/ /g, "_") + ".csv"; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal open={open} onClose={() => { setTexto(""); setResultado(null); setArquivo(null); onClose(); }}
      title={"Importar " + titulo} width={640}>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

        {/* Colunas esperadas */}
        <div style={{ background: "#F0F9FF", border: "1px solid #BAE6FD", borderRadius: 8, padding: "12px 14px" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#0369A1", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>
            Colunas esperadas no CSV
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {colunas.map(c => (
              <span key={c.campo} style={{
                padding: "2px 8px", borderRadius: 6, fontSize: 11, fontFamily: "monospace",
                background: c.obrigatorio ? "#1D4ED8" : "#93C5FD",
                color: c.obrigatorio ? "#fff" : "#1E3A5F", fontWeight: 600
              }}>{c.campo}{c.obrigatorio ? " *" : ""}</span>
            ))}
          </div>
          <div style={{ marginTop: 8, display: "flex", gap: 10, alignItems: "center" }}>
            <Button variant="secondary" size="sm" onClick={baixarModelo}>⬇ Baixar modelo CSV</Button>
            <span style={{ fontSize: 11, color: "#0369A1" }}>* = obrigatório</span>
          </div>
        </div>

        {/* Upload */}
        <div style={{
          border: "2px dashed #D1D5DB", borderRadius: 10, padding: "20px",
          textAlign: "center", background: arquivo ? "#F0FDF4" : "#FAFAFA"
        }}>
          <div style={{ fontSize: 28, marginBottom: 8 }}>{arquivo ? "✅" : "📂"}</div>
          <div style={{ fontSize: 11, fontWeight: 600, color: arquivo ? "#065F46" : "#374151", marginBottom: 8 }}>
            {arquivo ? arquivo : "Selecione o arquivo CSV"}
          </div>
          <label style={{
            padding: "7px 16px", background: "#1B3A6B", color: "#fff",
            borderRadius: 8, fontSize: 11, fontWeight: 600, cursor: "pointer"
          }}>
            {arquivo ? "Trocar arquivo" : "Selecionar CSV"}
            <input type="file" accept=".csv,.txt" onChange={onArquivo} style={{ display: "none" }} />
          </label>
        </div>

        {/* Ou colar texto */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: "#374151", marginBottom: 6 }}>
            Ou cole o conteúdo CSV diretamente:
          </div>
          <textarea
            value={texto} onChange={e => setTexto(e.target.value)}
            placeholder={"chapa,nome,funcao...\n0001,João Silva,Analista..."}
            rows={5}
            style={{
              width: "100%", border: "1px solid #D1D5DB", borderRadius: 8,
              padding: "3px 6px", fontSize: 11, fontFamily: "monospace",
              resize: "vertical", boxSizing: "border-box", background: "#FAFAFA"
            }}
          />
        </div>

        {/* Resultado */}
        {resultado && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ display: "flex", gap: 10 }}>
              <div style={{ flex: 1, background: "#D1FAE5", border: "1px solid #6EE7B7", borderRadius: 8, padding: "3px 6px", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: "#065F46" }}>{resultado.validos.length}</div>
                <div style={{ fontSize: 11, color: "#065F46", fontWeight: 600 }}>Registros válidos</div>
              </div>
              <div style={{ flex: 1, background: resultado.erros.length > 0 ? "#FEE2E2" : "#F3F4F6", border: "1px solid " + (resultado.erros.length > 0 ? "#FCA5A5" : "#E5E7EB"), borderRadius: 8, padding: "3px 6px", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: resultado.erros.length > 0 ? "#991B1B" : "#6B7280" }}>{resultado.erros.length}</div>
                <div style={{ fontSize: 11, color: resultado.erros.length > 0 ? "#991B1B" : "#6B7280", fontWeight: 600 }}>Erros</div>
              </div>
            </div>
            {resultado.erros.length > 0 && (
              <div style={{ background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, padding: "3px 6px", maxHeight: 120, overflowY: "auto" }}>
                {resultado.erros.map((e, i) => (
                  <div key={i} style={{ fontSize: 11, color: "#DC2626", marginBottom: 3 }}>
                    Linha {e.linha}: {e.msg}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 4, borderTop: "1px solid #F3F4F6" }}>
          <Button variant="secondary" onClick={() => { setTexto(""); setResultado(null); setArquivo(null); onClose(); }}>Cancelar</Button>
          {!resultado
            ? <Button onClick={processar} disabled={!texto.trim()}>Processar arquivo</Button>
            : <Button variant="success" onClick={confirmar} disabled={resultado.validos.length === 0 || importando}>
                {importando ? "⏳ Importando..." : `Importar ${resultado.validos.length} registros`}
              </Button>
          }
        </div>
      </div>
    </Modal>
  );
}

// ─── CADASTRO: COLABORADORES ──────────────────────────────────────────────────
function CadColaboradores({ colaboradores, setColaboradores }) {
  const [busca, setBusca] = useState("");
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ chapa: "", nome: "", funcao: "", situacao: "Ativo", centro_custo: "", desc_cc: "", cpf: "", data_admissao: "" });
  const [fMatricula, setFMatricula] = useState("");
  const [fNome,      setFNome]      = useState("");
  const [fFuncao,    setFuncao]     = useState("");
  const [fSecao,     setFSecao]     = useState("");
  const [fCpf,       setFCpf]       = useState("");
  const [fAdmissao,  setFAdmissao]  = useState("");
  const [fCC,        setFCC]        = useState("");
  const [fSituacao,  setFSituacao]  = useState("");

  const norm = s => (s||"").toLowerCase();

  useEffect(() => {
    api.listarColaboradores(true).then(data => {
      if (data && data.length > 0) setColaboradores(data);
    }).catch(() => {});
  }, []);

  const lista = colaboradores
    .filter(c => c.cod_situacao !== "D")
    .filter(c => !fMatricula || (c.chapa||"").includes(fMatricula))
    .filter(c => !fNome      || norm(c.nome).includes(norm(fNome)))
    .filter(c => !fFuncao    || norm(c.desc_funcao||c.funcao).includes(norm(fFuncao)))
    .filter(c => !fSecao     || norm(c.desc_cc).includes(norm(fSecao)))
    .filter(c => !fCpf       || (c.cpf||"").includes(fCpf))
    .filter(c => !fAdmissao  || fmtDateLocal(c.data_admissao) === fAdmissao)
    .filter(c => !fCC        || norm((c.centro_custo||"")+" "+(c.desc_cc||"")).includes(norm(fCC)))
    .filter(c => !fSituacao  || norm(c.situacao) === norm(fSituacao));

  const abrirNovo = () => { setForm({ chapa: "", nome: "", funcao: "", situacao: "Ativo", centro_custo: "", desc_cc: "", cpf: "", data_admissao: "" }); setModalForm("novo"); };
  const abrirEditar = (c) => {
    const admissao = c.data_admissao
      ? c.data_admissao.split("T")[0]
      : "";
    setForm({ ...c, data_admissao: admissao });
    setModalForm("editar");
  };

  const salvar = async () => {
    if (!form.chapa || !form.nome) { alert("Chapa e Nome são obrigatórios."); return; }
    try {
      if (modalForm === "novo") {
        const novo = await api.criarColaborador(form);
        setColaboradores(p => [...p, novo]);
      } else {
        await api.atualizarColaborador(form.id, form);
        setColaboradores(p => p.map(c => c.id === form.id ? { ...c, ...form } : c));
      }
      setModalForm(null);
    } catch (err) {
      alert("Erro: " + err.message);
    }
  };

  const inativar = async (id) => {
    const c = colaboradores.find(c => c.id === id);
    if (!c) return;
    const novaSituacao = c.situacao === "Ativo" ? "Inativo" : "Ativo";
    try {
      await api.atualizarColaborador(id, { situacao: novaSituacao });
      setColaboradores(p => p.map(c => c.id === id ? { ...c, situacao: novaSituacao } : c));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const fmtAdmissao = (v) => {
    if (!v) return null;
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(v)) {
      const [d, m, a] = v.split("/");
      return `${a}-${m}-${d}`;
    }
    return v || null;
  };

  const onImportar = async (rows) => {
    const novos = rows.map(r => ({
      chapa:                  r.chapa || "",
      nome:                   r.nome || "",
      funcao:                 r.funcao || "",
      desc_funcao:            r.desc_funcao || "",
      situacao:               r.situacao || "Ativo",
      cod_situacao:           r.cod_situacao || null,
      centro_custo:           r.centro_custo || "",
      desc_cc:                r.desc_cc || "",
      descricao_filial:       r.descricao_filial || "",
      cpf:                    r.cpf || "",
      data_admissao:          fmtAdmissao(r.data_admissao),
      tipo_contrato:          r.tipo_contrato || null,
      data_fim_contrato:      r.data_fim_contrato || null,
      data_fim_estabilidade:  r.data_fim_estabilidade || null,
      descricao_estabilidade: r.descricao_estabilidade || null,
      prazo45:                r.prazo45 || null,
      prazo90:                r.prazo90 || null,
      // Novos campos pessoais/endereço
      rg:                     r.rg || null,
      rg_orgao:               r.rg_orgao || r.rg_orgemissor || null,
      rg_uf:                  r.rg_uf || null,
      ctps:                   r.ctps || null,
      ctps_serie:             r.ctps_serie || null,
      logradouro:             r.logradouro || r.rua_func || null,
      numero:                 r.numero || r.numero_func || null,
      complemento:            r.complemento || r.compl_func || null,
      bairro:                 r.bairro || null,
      cidade:                 r.cidade || null,
      uf:                     r.uf || null,
      cep:                    r.cep || null,
      telefone1:              r.telefone1 || null,
      sexo:                   r.sexo || null,
      estado_civil:           r.estado_civil || null,
      nome_mae:               r.nome_mae || null,
      pis:                    r.pis || null,
      // Campos de atualização cadastral
      posicao_escala:         r.posicao_escala || null,
      motorista_lider:        r.motorista_lider || null,
      munkeiro:               r.munkeiro || null,
      prancheiro:             r.prancheiro || null,
      tamanho_macacao:        r.tamanho_macacao || null,
      tamanho_bota:           r.tamanho_bota || null,
    })).filter(r => r.chapa && r.nome);

    await api.importarColaboradores(novos);
    const atualizados = await api.listarColaboradores(true);
    if (atualizados && atualizados.length > 0) setColaboradores(atualizados);
    alert(`✅ ${novos.length} colaborador(es) importado(s) com sucesso!`);
  };

  const colunas = [
    { campo: "chapa / Matrícula", obrigatorio: true, exemplo: "0001" },
    { campo: "nome / Nome", obrigatorio: true, exemplo: "João da Silva" },
    { campo: "funcao / Função", obrigatorio: false, exemplo: "Analista" },
    { campo: "desc_cc / Seção", obrigatorio: false, exemplo: "BNL - CE FOR - ADM" },
    { campo: "cpf / CPF", obrigatorio: false, exemplo: "64830730382" },
    { campo: "data_admissao / Admissão", obrigatorio: false, exemplo: "01/02/2022" },
    { campo: "centro_custo / C. Custo", obrigatorio: false, exemplo: "01.08 - DIRETORIA" },
    { campo: "situacao / Situação", obrigatorio: false, exemplo: "Ativo" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
<p style={{ margin: 0, fontSize: 11, color: "#6B7280" }}>{colaboradores.length} colaborador(es) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Colaborador</Button>
        </div>
      </div>


      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Matrícula", "Nome", "Função", "Seção", "CPF", "Admissão", "C. Custo", "Situação", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              {(() => {
                const inp = { style: { width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" } };
                const sel = { style: { width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" } };
                return (<>
                  <th style={{ padding:"5px 8px" }}><input value={fMatricula} onChange={e=>setFMatricula(e.target.value)} placeholder="🔍 Matrícula" {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fNome}      onChange={e=>setFNome(e.target.value)}      placeholder="🔍 Nome"      {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fFuncao}    onChange={e=>setFuncao(e.target.value)}     placeholder="🔍 Função"    {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fSecao}     onChange={e=>setFSecao(e.target.value)}     placeholder="🔍 Seção"     {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fCpf}       onChange={e=>setFCpf(e.target.value)}       placeholder="🔍 CPF"       {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input type="date" value={fAdmissao} onChange={e=>setFAdmissao(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fCC}        onChange={e=>setFCC(e.target.value)}        placeholder="🔍 C. Custo"  {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}>
                    <select value={fSituacao} onChange={e=>setFSituacao(e.target.value)} {...sel}>
                      <option value="">Todos</option><option value="Ativo">Ativo</option><option value="Inativo">Inativo</option>
                    </select>
                  </th>
                  <th style={{ padding:"5px 8px" }}>
                    <button onClick={()=>{setFMatricula("");setFNome("");setFuncao("");setFSecao("");setFCpf("");setFAdmissao("");setFCC("");setFSituacao("");}}
                      style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button>
                  </th>
                </>);
              })()}
            </tr>
          </thead>
          <tbody>
            {lista.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhum colaborador encontrado</td></tr>
            ) : lista.map((c, i) => (
              <tr key={c.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, background: "#F3F4F6", padding: "1px 6px", borderRadius: 4 }}>{c.chapa}</span>
                </td>
                <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{c.nome}</td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{c.desc_funcao || c.funcao || "—"}</td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{c.desc_cc || "—"}</td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151", fontFamily: "monospace" }}>{c.cpf || "—"}</td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{c.data_admissao ? new Date(c.data_admissao.split("T")[0]).toLocaleDateString("pt-BR", { timeZone: "UTC" }) : "—"}</td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{c.centro_custo ? (c.centro_custo + " — " + c.desc_cc) : "—"}</td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: c.situacao === "Ativo" ? "#D1FAE5" : "#FEE2E2", color: c.situacao === "Ativo" ? "#065F46" : "#991B1B" }}>
                    {c.situacao}
                  </span>
                </td>
                <td style={{ padding: "3px 7px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(c)}>✏ Editar</Button>
                  <Button variant={c.situacao === "Ativo" ? "secondary" : "success"} size="sm" onClick={() => inativar(c.id)}>
                    {c.situacao === "Ativo" ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Colaboradores" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Novo Colaborador" : "Editar Colaborador"} width={520}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Input label="Matrícula (Chapa) *" value={form.chapa} onChange={v => setForm(p => ({ ...p, chapa: v }))} placeholder="0001" required />
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Situação</label>
              <select value={form.situacao} onChange={e => setForm(p => ({ ...p, situacao: e.target.value }))}
                style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
                <option value="Ativo">Ativo</option>
                <option value="Inativo">Inativo</option>
              </select>
            </div>
          </div>
          <Input label="Nome completo *" value={form.nome} onChange={v => setForm(p => ({ ...p, nome: v }))} placeholder="Nome do colaborador" required />
          <Input label="Função" value={form.funcao} onChange={v => setForm(p => ({ ...p, funcao: v }))} placeholder="Ex: Analista, Motorista..." />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
            <Input label="Cód. Centro de Custo" value={form.centro_custo} onChange={v => setForm(p => ({ ...p, centro_custo: v }))} placeholder="001" />
            <Input label="Descrição CC" value={form.desc_cc} onChange={v => setForm(p => ({ ...p, desc_cc: v }))} placeholder="Ex: TI, RH, Logística..." />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Input label="CPF" value={form.cpf || ""} onChange={v => setForm(p => ({ ...p, cpf: v }))} placeholder="000.000.000-00" />
            <Input label="Data de Admissão" value={form.data_admissao ? form.data_admissao.split("T")[0] : ""} onChange={v => setForm(p => ({ ...p, data_admissao: v }))} type="date" />
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: EVENTOS ────────────────────────────────────────────────────────
function CadEventos({ eventos, setEventos }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ codigo: "", descricao: "", tipo: "provento", forma: "valor" });
  const [fCodigo,  setFCodigo]  = useState("");
  const [fDesc,    setFDesc]    = useState("");
  const [fTipo,    setFTipo]    = useState("");
  const [fForma,   setFForma]   = useState("");
  const norm = s => (s||"").toLowerCase();
  const eventosFiltrados = eventos
    .filter(e => !fCodigo || (e.codigo||"").includes(fCodigo))
    .filter(e => !fDesc   || norm(e.descricao).includes(norm(fDesc)))
    .filter(e => !fTipo   || e.tipo === fTipo)
    .filter(e => !fForma  || e.forma === fForma);

  useEffect(() => {
    api.listarEventos().then(data => {
      if (data && data.length > 0) setEventos(data);
    }).catch(() => {});
  }, []);

  const abrirNovo = () => { setForm({ codigo: "", descricao: "", tipo: "provento", forma: "valor" }); setModalForm("novo"); };
  const abrirEditar = (e) => { setForm({ ...e }); setModalForm("editar"); };

  const salvar = async () => {
    if (!form.codigo || !form.descricao) { alert("Código e Descrição são obrigatórios."); return; }
    try {
      if (modalForm === "novo") {
        const novo = await api.criarEvento(form);
        setEventos(p => [...p, novo]);
      } else {
        await api.atualizarEvento(form.id, form);
        setEventos(p => p.map(e => e.id === form.id ? { ...form } : e));
      }
      setModalForm(null);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const excluir = async (id) => {
    if (!window.confirm("Deseja excluir este evento?")) return;
    try {
      await api.atualizarEvento(id, { ativo: false });
      setEventos(p => p.filter(e => e.id !== id));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = async (rows) => {
    const novos = rows.map(r => ({
      codigo:    r.codigo || r.Codigo || "",
      descricao: r.descricao || r.Descricao || "",
      tipo:      r.tipo || r.Tipo || "provento",
      forma:     r.forma || r.Forma || "valor",
    })).filter(r => r.codigo && r.descricao);
    try {
      for (const ev of novos) {
        try { await api.criarEvento(ev); } catch (_) {}
      }
      const data = await api.listarEventos();
      if (data) setEventos(data);
      alert(`✅ ${novos.length} evento(s) importado(s)!`);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const colunas = [
    { campo: "codigo", obrigatorio: true, exemplo: "1148" },
    { campo: "descricao", obrigatorio: true, exemplo: "Auxílio Quilometragem" },
    { campo: "tipo", obrigatorio: false, exemplo: "provento" },
    { campo: "forma", obrigatorio: false, exemplo: "valor" },
  ];

  const sel = (label, val, onChange, opts) => (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>{label}</label>
      <select value={val} onChange={e => onChange(e.target.value)}
        style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
        {opts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 11, color: "#6B7280" }}>{eventos.length} evento(s) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Evento</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Código", "Descrição", "Tipo", "Forma de Lançamento", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "3px 6px" }}><input value={fCodigo} onChange={e=>setFCodigo(e.target.value)} placeholder="🔍 Código" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "3px 6px" }}><input value={fDesc}   onChange={e=>setFDesc(e.target.value)}   placeholder="🔍 Descrição" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "3px 6px" }}><select value={fTipo}  onChange={e=>setFTipo(e.target.value)}   style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="provento">Provento</option><option value="desconto">Desconto</option></select></th>
              <th style={{ padding: "3px 6px" }}><select value={fForma} onChange={e=>setFForma(e.target.value)}  style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="valor">Valor</option><option value="hora">Hora</option><option value="referencia">Referência</option></select></th>
              <th style={{ padding: "3px 6px" }}><button onClick={()=>{setFCodigo("");setFDesc("");setFTipo("");setFForma("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {eventosFiltrados.map((e, i) => (
              <tr key={e.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, color: "#1B3A6B" }}>{e.codigo}</span>
                </td>
                <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{e.descricao}</td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: e.tipo === "provento" ? "#D1FAE5" : "#FEE2E2", color: e.tipo === "provento" ? "#065F46" : "#991B1B" }}>{e.tipo}</span>
                </td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151", textTransform: "capitalize" }}>{e.forma}</td>
                <td style={{ padding: "3px 7px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(e)}>✏ Editar</Button>
                  <Button variant="danger" size="sm" onClick={() => excluir(e.id)}>🗑</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Eventos" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Novo Evento" : "Editar Evento"} width={480}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <Input label="Código *" value={form.codigo} onChange={v => setForm(p => ({ ...p, codigo: v }))} placeholder="1148" required />
          <Input label="Descrição *" value={form.descricao} onChange={v => setForm(p => ({ ...p, descricao: v }))} placeholder="Nome do evento" required />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {sel("Tipo", form.tipo, v => setForm(p => ({ ...p, tipo: v })), [
              { value: "provento", label: "Provento" }, { value: "desconto", label: "Desconto" }
            ])}
            {sel("Forma de Lançamento", form.forma, v => setForm(p => ({ ...p, forma: v })), [
              { value: "valor", label: "Valor (R$)" }, { value: "hora", label: "Hora" }, { value: "referencia", label: "Referência" }
            ])}
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: HIERARQUIA ─────────────────────────────────────────────────────
const MOCK_HIERARQUIA_INIT = [
  { id: 1, gestor_id: 1, gestor_nome: "Carlos Mendes", superior_id: 2, superior_nome: "Ana Souza", centro_custo: "001", desc_cc: "TI", ativo: true },
  { id: 2, gestor_id: 1, gestor_nome: "Carlos Mendes", superior_id: 2, superior_nome: "Ana Souza", centro_custo: "003", desc_cc: "Logística", ativo: true },
];

function CadHierarquia({ hierarquia, setHierarquia, usuarios }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ gestor_id: "", superior_id: "", centro_custo: "", desc_cc: "" });
  const [filtroGestor,   setFiltroGestor]   = useState("");
  const [filtroSuperior, setFiltroSuperior] = useState("");
  const [filtroCC,       setFiltroCC]       = useState("");
  const [filtroAtivo,    setFiltroAtivo]    = useState("");

  const norm = (s) => (s||"").toLowerCase().trim();

  const hierarquiaFiltrada = hierarquia.filter(h => {
    if (filtroGestor   && !norm(h.gestor_nome).includes(norm(filtroGestor)))     return false;
    if (filtroSuperior && !norm(h.superior_nome).includes(norm(filtroSuperior))) return false;
    if (filtroCC       && !norm(h.centro_custo + " " + h.desc_cc).includes(norm(filtroCC))) return false;
    if (filtroAtivo === "ativo"   && !h.ativo)  return false;
    if (filtroAtivo === "inativo" &&  h.ativo)  return false;
    return true;
  });

  useEffect(() => {
    api.listarHierarquia().then(data => {
      if (data && data.length > 0) setHierarquia(data);
    }).catch(() => {});
  }, []);

  const gestores   = usuarios.filter(u => u.ativo !== false);
  const superiores = usuarios.filter(u => u.ativo !== false);

  const [centrosCusto, setCentrosCusto] = useState([]);
  useEffect(() => {
    api.listarCentrosCusto().then(data => {
      if (Array.isArray(data)) setCentrosCusto(data);
    }).catch(() => {});
  }, []);

  const abrirNovo = () => { setForm({ gestor_id: "", superior_id: "", centro_custo: "", desc_cc: "" }); setModalForm("novo"); };
  const abrirEditar = (h) => { setForm({ ...h }); setModalForm("editar"); };

  const salvar = async () => {
    if (!form.gestor_id || !form.superior_id) { alert("Gestor e Superior são obrigatórios."); return; }
    const payload = { gestor_id: parseInt(form.gestor_id), superior_id: parseInt(form.superior_id), centro_custo: form.centro_custo, desc_cc: form.desc_cc };
    try {
      if (modalForm === "novo") {
        const novo = await api.criarHierarquia(payload);
        setHierarquia(p => [...p, novo]);
      } else {
        const upd = await api.atualizarHierarquia(form.id, { ...payload, ativo: form.ativo ?? true });
        setHierarquia(p => p.map(h => h.id === form.id ? upd : h));
      }
      setModalForm(null);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const toggleAtivo = async (id) => {
    const h = hierarquia.find(h => h.id === id);
    if (!h) return;
    try {
      await api.atualizarHierarquia(id, { gestor_id: h.gestor_id, superior_id: h.superior_id, ativo: !h.ativo });
      setHierarquia(p => p.map(h => h.id === id ? { ...h, ativo: !h.ativo } : h));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => ({
      id: Date.now() + i,
      gestor_nome: r.gestor_nome || r.GestorNome || "",
      superior_nome: r.superior_nome || r.SuperiorNome || "",
      centro_custo: r.centro_custo || r.CentroCusto || "",
      desc_cc: r.desc_cc || r.DescCC || "",
      gestor_id: 0, superior_id: 0, ativo: true,
    }));
    setHierarquia(p => [...p, ...novos]);
  };

  const colunas = [
    { campo: "gestor_nome", obrigatorio: true, exemplo: "Carlos Mendes" },
    { campo: "superior_nome", obrigatorio: true, exemplo: "Ana Souza" },
    { campo: "centro_custo", obrigatorio: false, exemplo: "001" },
    { campo: "desc_cc", obrigatorio: false, exemplo: "TI" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 11, color: "#6B7280" }}>Define quem aprova as solicitações de cada gestor</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Nova Regra</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["1ª Alçada", "2ª Alçada", "Centro de Custo", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "3px 6px" }}>
                <input value={filtroGestor} onChange={e => setFiltroGestor(e.target.value)}
                  placeholder="🔍 Buscar 1ª alçada..."
                  style={{ width: "100%", padding: "3px 6px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit", boxSizing: "border-box" }} />
              </th>
              <th style={{ padding: "3px 6px" }}>
                <input value={filtroSuperior} onChange={e => setFiltroSuperior(e.target.value)}
                  placeholder="🔍 Buscar 2ª alçada..."
                  style={{ width: "100%", padding: "3px 6px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit", boxSizing: "border-box" }} />
              </th>
              <th style={{ padding: "3px 6px" }}>
                <input value={filtroCC} onChange={e => setFiltroCC(e.target.value)}
                  placeholder="🔍 Buscar CC..."
                  style={{ width: "100%", padding: "3px 6px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit", boxSizing: "border-box" }} />
              </th>
              <th style={{ padding: "3px 6px" }}>
                <select value={filtroAtivo} onChange={e => setFiltroAtivo(e.target.value)}
                  style={{ width: "100%", padding: "3px 6px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit" }}>
                  <option value="">Todos</option>
                  <option value="ativo">Ativo</option>
                  <option value="inativo">Inativo</option>
                </select>
              </th>
              <th style={{ padding: "3px 6px" }}>
                <button onClick={() => { setFiltroGestor(""); setFiltroSuperior(""); setFiltroCC(""); setFiltroAtivo(""); }}
                  style={{ fontSize: 10, padding: "3px 6px", borderRadius: 6, border: "1px solid #D1D5DB", background: "#fff", cursor: "pointer", color: "#6B7280" }}>
                  ✕ Limpar
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {hierarquiaFiltrada.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma regra encontrada</td></tr>
            ) : hierarquiaFiltrada.map((h, i) => (
              <tr key={h.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "3px 7px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 28, height: 28, borderRadius: 8, background: "#3B82F6", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>
                      {h.gestor_nome?.charAt(0)}
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "#111827" }}>{h.gestor_nome}</span>
                  </div>
                </td>
                <td style={{ padding: "3px 7px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 28, height: 28, borderRadius: 8, background: "#8B5CF6", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>
                      {h.superior_nome?.charAt(0)}
                    </div>
                    <span style={{ fontSize: 11, fontWeight: 600, color: "#111827" }}>{h.superior_nome}</span>
                  </div>
                </td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{h.centro_custo ? (h.centro_custo + " — " + h.desc_cc) : "Todos"}</td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: h.ativo ? "#D1FAE5" : "#FEE2E2", color: h.ativo ? "#065F46" : "#991B1B" }}>
                    {h.ativo ? "Ativo" : "Inativo"}
                  </span>
                </td>
                <td style={{ padding: "3px 7px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(h)}>✏ Editar</Button>
                  <Button variant={h.ativo ? "secondary" : "success"} size="sm" onClick={() => toggleAtivo(h.id)}>
                    {h.ativo ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Hierarquia" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Nova Regra de Hierarquia" : "Editar Hierarquia"} width={480}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>1ª Alçada *</label>
            <select value={form.gestor_id} onChange={e => setForm(p => ({ ...p, gestor_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {gestores.map(u => <option key={u.id} value={u.id}>{u.nome}</option>)}
            </select>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>2ª Alçada *</label>
            <select value={form.superior_id} onChange={e => setForm(p => ({ ...p, superior_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {superiores.map(u => <option key={u.id} value={u.id}>{u.nome}</option>)}
            </select>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Cód. Centro de Custo</label>
              <select value={form.centro_custo || ""} onChange={e => {
                const cod = e.target.value;
                const cc = centrosCusto.find(c => c.codccusto === cod);
                setForm(p => ({ ...p, centro_custo: cod, desc_cc: cc ? cc.nome : p.desc_cc }));
              }} style={{ width: "100%", padding: "8px 10px", borderRadius: 8, border: "1px solid #D1D5DB", fontSize: 13 }}>
                <option value="">Todos</option>
                {centrosCusto.filter(c => c.tipo !== "BLOQUEADO").map(c => (
                  <option key={c.codccusto} value={c.codccusto}>{c.codccusto}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Descrição CC</label>
              <input value={form.desc_cc || ""} readOnly
                style={{ width: "100%", padding: "8px 10px", borderRadius: 8, border: "1px solid #D1D5DB", fontSize: 13, background: "#F9FAFB", color: "#6B7280", boxSizing: "border-box" }}
                placeholder="Preenchido automaticamente" />
            </div>
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: ALÇADAS ────────────────────────────────────────────────────────
const MOCK_ALCADAS_INIT = [
  { id: 1, evento_id: 1, evento_nome: "Auxílio Quilometragem", num_alcadas: 2, exige_anexo: true, ativo: true },
  { id: 2, evento_id: 2, evento_nome: "Ajuda de Custo",        num_alcadas: 2, exige_anexo: true, ativo: true },
  { id: 3, evento_id: 3, evento_nome: "Horas Extras 50%",      num_alcadas: 1, exige_anexo: false, ativo: true },
  { id: 4, evento_id: 5, evento_nome: "Desconto Multa Trânsito", num_alcadas: 2, exige_anexo: true, ativo: true },
];

function CadAlcadas({ alcadas, setAlcadas, eventos }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ evento_id: "", num_alcadas: 1, exige_anexo: false });
  const [fEvento,  setFEvento]  = useState("");
  const [fAnexo,   setFAnexo]   = useState("");
  const [fStatus,  setFStatus]  = useState("");
  const norm = s => (s||"").toLowerCase();
  const alcadasFiltradas = alcadas
    .filter(a => !fEvento || norm(a.evento_nome).includes(norm(fEvento)))
    .filter(a => fAnexo === "" ? true : fAnexo === "sim" ? a.exige_anexo : !a.exige_anexo)
    .filter(a => fStatus === "" ? true : fStatus === "ativo" ? a.ativo : !a.ativo);

  useEffect(() => {
    api.listarAlcadas().then(data => {
      if (data && data.length > 0) setAlcadas(data);
    }).catch(() => {});
  }, []);

  const abrirNovo = () => { setForm({ evento_id: "", num_alcadas: 1, exige_anexo: false }); setModalForm("novo"); };
  const abrirEditar = (a) => { setForm({ ...a }); setModalForm("editar"); };

  const salvar = async () => {
    if (!form.evento_id) { alert("Selecione o evento."); return; }
    const payload = { evento_id: parseInt(form.evento_id), num_alcadas: parseInt(form.num_alcadas) || 1, exige_anexo: !!form.exige_anexo };
    try {
      if (modalForm === "novo") {
        const nova = await api.criarAlcada(payload);
        setAlcadas(p => [...p, nova]);
      } else {
        const upd = await api.atualizarAlcada(form.id, { ...payload, ativo: form.ativo ?? true });
        setAlcadas(p => p.map(a => a.id === form.id ? upd : a));
      }
      setModalForm(null);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const toggleAtivo = async (id) => {
    const a = alcadas.find(a => a.id === id);
    if (!a) return;
    try {
      await api.atualizarAlcada(id, { evento_id: a.evento_id, num_alcadas: a.num_alcadas, exige_anexo: a.exige_anexo, ativo: !a.ativo });
      setAlcadas(p => p.map(a => a.id === id ? { ...a, ativo: !a.ativo } : a));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => ({
      id: Date.now() + i,
      evento_nome: r.evento_nome || r.EventoNome || "",
      num_alcadas: parseInt(r.num_alcadas || r.NumAlcadas || "1"),
      exige_anexo: (r.exige_anexo || r.ExigeAnexo || "").toLowerCase() === "sim",
      evento_id: 0, ativo: true,
    }));
    setAlcadas(p => [...p, ...novos]);
  };

  const colunas = [
    { campo: "evento_nome", obrigatorio: true, exemplo: "Auxílio Quilometragem" },
    { campo: "num_alcadas", obrigatorio: true, exemplo: "2" },
    { campo: "exige_anexo", obrigatorio: false, exemplo: "sim" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 11, color: "#6B7280" }}>Define quantas aprovações cada tipo de evento exige</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Nova Regra</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Evento", "Nº de Alçadas", "Exige Anexo", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "3px 6px" }}><input value={fEvento} onChange={e=>setFEvento(e.target.value)} placeholder="🔍 Evento" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "3px 6px" }} />
              <th style={{ padding: "3px 6px" }}><select value={fAnexo} onChange={e=>setFAnexo(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="sim">Obrigatório</option><option value="nao">Não exige</option></select></th>
              <th style={{ padding: "3px 6px" }}><select value={fStatus} onChange={e=>setFStatus(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select></th>
              <th style={{ padding: "3px 6px" }}><button onClick={()=>{setFEvento("");setFAnexo("");setFStatus("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {alcadasFiltradas.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma regra encontrada</td></tr>
            ) : alcadasFiltradas.map((a, i) => (
              <tr key={a.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{a.evento_nome}</td>
                <td style={{ padding: "3px 7px" }}>
                  <div style={{ display: "flex", gap: 4 }}>
                    {[...Array(a.num_alcadas)].map((_, idx) => (
                      <span key={idx} style={{ width: 24, height: 24, borderRadius: 6, background: idx === 0 ? "#3B82F6" : "#8B5CF6", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>
                        {idx + 1}
                      </span>
                    ))}
                    <span style={{ fontSize: 11, color: "#6B7280", marginLeft: 4, alignSelf: "center" }}>
                      {a.num_alcadas === 1 ? "Apenas gestor" : "Gestor + Superior"}
                    </span>
                  </div>
                </td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: a.exige_anexo ? "#FEF3C7" : "#F3F4F6", color: a.exige_anexo ? "#92400E" : "#6B7280" }}>
                    {a.exige_anexo ? "📎 Obrigatório" : "Não exige"}
                  </span>
                </td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: a.ativo ? "#D1FAE5" : "#FEE2E2", color: a.ativo ? "#065F46" : "#991B1B" }}>
                    {a.ativo ? "Ativo" : "Inativo"}
                  </span>
                </td>
                <td style={{ padding: "3px 7px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(a)}>✏ Editar</Button>
                  <Button variant={a.ativo ? "secondary" : "success"} size="sm" onClick={() => toggleAtivo(a.id)}>
                    {a.ativo ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Alçadas" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Nova Regra de Alçada" : "Editar Alçada"} width={460}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Evento *</label>
            <select value={form.evento_id} onChange={e => setForm(p => ({ ...p, evento_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {eventos.map(e => <option key={e.id} value={e.id}>{e.codigo} — {e.descricao}</option>)}
            </select>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Número de Alçadas *</label>
            <select value={form.num_alcadas} onChange={e => setForm(p => ({ ...p, num_alcadas: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value={1}>1 alçada — Apenas Gestor</option>
              <option value={2}>2 alçadas — Gestor + Superior</option>
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "3px 6px", background: "#FFFBEB", borderRadius: 8, border: "1px solid #FCD34D" }}>
            <input type="checkbox" id="exige_anexo" checked={!!form.exige_anexo}
              onChange={e => setForm(p => ({ ...p, exige_anexo: e.target.checked }))}
              style={{ width: 16, height: 16, cursor: "pointer" }} />
            <label htmlFor="exige_anexo" style={{ fontSize: 11, fontWeight: 600, color: "#92400E", cursor: "pointer" }}>
              📎 Exige anexo obrigatório
            </label>
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: USUÁRIOS ───────────────────────────────────────────────────────
function CadUsuarios({ usuarios, setUsuarios }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [modalReset, setModalReset] = useState(null);
  const [novaSenha, setNovaSenha] = useState("");
  const [confirmaSenha, setConfirmaSenha] = useState("");
  const [msgReset, setMsgReset] = useState(null);
  const [salvandoReset, setSalvandoReset] = useState(false);
  const [salvando, setSalvando] = useState(false);
  const [form, setForm] = useState({ nome: "", email: "", perfil: "gestor", senha: "Benel@2025", secao: "", ativo: true });
  const [fNomeU,   setFNomeU]   = useState("");
  const [fEmailU,  setFEmailU]  = useState("");
  const [fPerfilU, setFPerfilU] = useState("");
  const [fStatusU, setFStatusU] = useState("");
  const norm = s => (s||"").toLowerCase();
  const usuariosFiltrados = usuarios
    .filter(u => !fNomeU   || norm(u.nome).includes(norm(fNomeU)))
    .filter(u => !fEmailU  || norm(u.email).includes(norm(fEmailU)))
    .filter(u => !fPerfilU || u.perfil === fPerfilU)
    .filter(u => fStatusU === "" ? true : fStatusU === "ativo" ? u.ativo !== false : u.ativo === false);

  const carregarUsuarios = async () => {
    try {
      const data = await api.listarUsuarios();
      if (data && data.length > 0) {
        const comAvatar = data.map(u => ({
          ...u,
          avatar: u.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase()
        }));
        setUsuarios(comAvatar);
      }
    } catch (e) { console.warn("Erro ao carregar usuários:", e.message); }
  };

  useEffect(() => { carregarUsuarios(); }, []);

  const abrirNovo = () => { setForm({ nome: "", email: "", perfil: "gestor", senha: "Benel@2025", secao: "", ativo: true }); setModalForm("novo"); };
  const abrirEditar = (u) => { setForm({ ...u, senha: "" }); setModalForm("editar"); };

  const abrirReset = (u) => {
    setModalReset(u);
    setNovaSenha("");
    setConfirmaSenha("");
    setMsgReset(null);
  };

  const salvar = async () => {
    if (!form.nome || !form.email) { alert("Nome e E-mail são obrigatórios."); return; }
    if (modalForm === "novo" && !form.senha) { alert("Informe uma senha inicial."); return; }
    setSalvando(true);
    try {
      if (modalForm === "novo") {
        const novo = await api.criarUsuario({ nome: form.nome, email: form.email, perfil: form.perfil, senha: form.senha });
        const av = form.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase();
        setUsuarios(p => [...p, { ...novo, avatar: av }]);
      } else {
        await api.atualizarUsuario(form.id, { nome: form.nome, email: form.email, perfil: form.perfil, ativo: form.ativo });
        setUsuarios(p => p.map(u => u.id === form.id ? { ...u, nome: form.nome, email: form.email, perfil: form.perfil, ativo: form.ativo } : u));
      }
      setModalForm(null);
    } catch (err) {
      alert("Erro: " + err.message);
    } finally { setSalvando(false); }
  };

  const executarReset = async () => {
    if (!novaSenha || !verificarForcaSenha(novaSenha).valida) {
      setMsgReset({ tipo: "erro", texto: "A senha deve ter 8+ caracteres, letra maiúscula, minúscula, número e caractere especial (@$!%*?&_-#)." });
      return;
    }
    if (novaSenha !== confirmaSenha) {
      setMsgReset({ tipo: "erro", texto: "As senhas não coincidem." });
      return;
    }
    setSalvandoReset(true);
    try {
      await api.resetarSenhaAdmin(modalReset.id, novaSenha);
      setMsgReset({ tipo: "ok", texto: `Senha de ${modalReset.nome} redefinida com sucesso!` });
      setTimeout(() => { setModalReset(null); setMsgReset(null); }, 1500);
    } catch (err) {
      setMsgReset({ tipo: "erro", texto: err.message || "Erro ao redefinir senha." });
    } finally {
      setSalvandoReset(false);
    }
  };

  const toggleAtivo = async (id) => {
    const u = usuarios.find(u => u.id === id);
    if (!u) return;
    const novoAtivo = u.ativo === false ? true : false;
    try {
      await api.atualizarUsuario(id, { ativo: novoAtivo });
      setUsuarios(p => p.map(u => u.id === id ? { ...u, ativo: novoAtivo } : u));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => {
      const nome = r.nome || r.Nome || "";
      const av = nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase();
      return { id: Date.now() + i, nome, email: r.email || r.Email || "", perfil: r.perfil || r.Perfil || "gestor", senha: r.senha || "123", avatar: av, ativo: true };
    }).filter(r => r.nome && r.email);
    setUsuarios(p => {
      const emailsExistentes = new Set(p.map(u => u.email));
      return [...p, ...novos.filter(n => !emailsExistentes.has(n.email))];
    });
  };

  const colunas = [
    { campo: "nome", obrigatorio: true, exemplo: "João da Silva" },
    { campo: "email", obrigatorio: true, exemplo: "joao@empresa.com" },
    { campo: "perfil", obrigatorio: false, exemplo: "gestor" },
    { campo: "senha", obrigatorio: false, exemplo: "123456" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 11, color: "#6B7280" }}>{usuarios.length} usuário(s) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Usuário</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Avatar", "Nome", "E-mail", "Perfil", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "3px 6px" }} />
              <th style={{ padding: "3px 6px" }}><input value={fNomeU}  onChange={e=>setFNomeU(e.target.value)}  placeholder="🔍 Nome"   style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "3px 6px" }}><input value={fEmailU} onChange={e=>setFEmailU(e.target.value)} placeholder="🔍 E-mail" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "3px 6px" }}><select value={fPerfilU} onChange={e=>setFPerfilU(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="gestor">Gestor</option><option value="superior">Superior</option><option value="dp">DP</option><option value="admin">Admin</option></select></th>
              <th style={{ padding: "3px 6px" }}><select value={fStatusU} onChange={e=>setFStatusU(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select></th>
              <th style={{ padding: "3px 6px" }}><button onClick={()=>{setFNomeU("");setFEmailU("");setFPerfilU("");setFStatusU("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {usuariosFiltrados.map((u, i) => (
              <tr key={u.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "3px 7px" }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: PERFIL_CONFIG[u.perfil]?.color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>{u.avatar}</div>
                </td>
                <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{u.nome}</td>
                <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{u.email}</td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: PERFIL_CONFIG[u.perfil]?.color + "22", color: PERFIL_CONFIG[u.perfil]?.color }}>
                    {PERFIL_CONFIG[u.perfil]?.label}
                  </span>
                </td>
                <td style={{ padding: "3px 7px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: u.ativo !== false ? "#D1FAE5" : "#FEE2E2", color: u.ativo !== false ? "#065F46" : "#991B1B" }}>
                    {u.ativo !== false ? "Ativo" : "Inativo"}
                  </span>
                </td>
                <td style={{ padding: "3px 7px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(u)}>✏ Editar</Button>
                  <Button variant="warning" size="sm" onClick={() => abrirReset(u)}>🔑 Senha</Button>
                  <Button variant={u.ativo !== false ? "secondary" : "success"} size="sm" onClick={() => toggleAtivo(u.id)}>
                    {u.ativo !== false ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Usuários" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Novo Usuário" : "Editar Usuário"} width={460}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <Input label="Nome completo *" value={form.nome} onChange={v => setForm(p => ({ ...p, nome: v }))} placeholder="Nome do usuário" required />
          <Input label="E-mail *" value={form.email} onChange={v => setForm(p => ({ ...p, email: v }))} type="email" placeholder="email@empresa.com" required />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Perfil</label>
              <select value={form.perfil} onChange={e => setForm(p => ({ ...p, perfil: e.target.value }))}
                style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
                <option value="gestor">Gestor</option>
                <option value="superior">Superior</option>
                <option value="dp">DP</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <Input label="Seção / Departamento" value={form.secao || ""} onChange={v => setForm(p => ({ ...p, secao: v }))} placeholder="Ex: Logística, RH..." />
          </div>
          {modalForm === "novo" && (
            <div>
              <Input label="Senha inicial *" value={form.senha} onChange={v => setForm(p => ({ ...p, senha: v }))} type="password" placeholder="Ex: Benel@2026" required />
              <IndicadorSenha senha={form.senha} />
            </div>
          )}
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar} disabled={salvando}>{salvando ? "Salvando..." : modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>

      {/* Modal Reset de Senha — somente Admin */}
      <Modal open={!!modalReset} onClose={() => setModalReset(null)}
        title="🔑 Redefinir Senha" width={420}>
        {modalReset && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ background: "#FFF7ED", border: "1px solid #FCD34D", borderRadius: 8, padding: "3px 6px" }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#92400E" }}>Usuário</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#111827" }}>{modalReset.nome}</div>
              <div style={{ fontSize: 11, color: "#6B7280" }}>{modalReset.email}</div>
            </div>
            {msgReset && (
              <div style={{
                padding: "3px 6px", borderRadius: 8, fontSize: 12,
                background: msgReset.tipo === "ok" ? "#D1FAE5" : "#FEE2E2",
                color: msgReset.tipo === "ok" ? "#065F46" : "#991B1B",
                border: `1px solid ${msgReset.tipo === "ok" ? "#6EE7B7" : "#FCA5A5"}`
              }}>
                {msgReset.tipo === "ok" ? "✅" : "❌"} {msgReset.texto}
              </div>
            )}
            <div>
              <Input
                label="Nova Senha *"
                value={novaSenha}
                onChange={setNovaSenha}
                type="password"
                placeholder="Mín. 8 chars, maiúscula, número e especial"
                required
              />
              <IndicadorSenha senha={novaSenha} />
            </div>
            <Input
              label="Confirmar Nova Senha *"
              value={confirmaSenha}
              onChange={setConfirmaSenha}
              type="password"
              placeholder="Repita a nova senha"
              required
            />
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
              <Button variant="secondary" onClick={() => setModalReset(null)}>Cancelar</Button>
              <Button variant="warning" onClick={executarReset} disabled={salvandoReset}>
                {salvandoReset ? "Salvando..." : "🔑 Redefinir Senha"}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
// ─── SOLICITAÇÕES EM BLOCO ────────────────────────────────────────────────────

const LINHA_VAZIA = () => ({
  _id: Date.now() + Math.random(),
  colaborador_id: "", colaborador: null,
  hora: "", valor: "", referencia: "", observacao: ""
});

function Solicitacoes({ solicitacoes, setSolicitacoes, blocos, setBlocos, user, colaboradores = [], eventos = [], recarregarDados }) {
  const [filtroStatus, setFiltroStatus] = useState("");
  const [modalNovoBloco, setModalNovoBloco] = useState(false);
  const [modalBloco, setModalBloco] = useState(null);
  const [modalRelatorio, setModalRelatorio] = useState(null);
  const [editandoBloco, setEditandoBloco] = useState(null);

  const blocosFiltrados = blocos.filter(b => !filtroStatus || b.status === filtroStatus);

  const abrirNovoBloco = () => {
    setEditandoBloco({ id: null, competencia: "", descricao: "", evento_id: "", anexo_nome: null, anexo_tamanho: null, linhas: [LINHA_VAZIA(), LINHA_VAZIA()] });
    setModalNovoBloco(true);
  };

  const abrirEdicaoBloco = (bloco) => {
    setEditandoBloco({ ...bloco, linhas: bloco.linhas.map(l => ({ ...l })) });
    setModalNovoBloco(true);
  };

  const salvarBloco = async () => {
    if (!editandoBloco.evento_id)   { alert("Selecione o Evento do Bloco."); return; }
    if (!editandoBloco.competencia) { alert("Selecione a Competência."); return; }

    // Buscar evento primeiro (necessário para determinar forma)
    const eventoObj = eventos.find(e => e.id === parseInt(editandoBloco.evento_id))
                   || MOCK_EVENTOS.find(e => e.id === parseInt(editandoBloco.evento_id));

    const forma = eventoObj?.forma || "valor";
    const linhasValidas = editandoBloco.linhas.filter(l => {
      if (!l.colaborador_id || String(l.colaborador_id) === "") return false;
      if (forma === "hora")       return !!(l.hora);
      if (forma === "referencia") return parseFloat(l.referencia) > 0;
      return parseFloat(l.valor) > 0;
    });

    // Descrição automática: Evento + Competência
    const mesLabel = MESES.find(m => m.value === editandoBloco.competencia)?.label || editandoBloco.competencia;
    const descricaoAuto = editandoBloco.descricao || `${eventoObj?.descricao || "Bloco"} — ${mesLabel}`;

    // Data automática: último dia da competência (MMAAAA → AAAA-MM-DD)
    const comp = editandoBloco.competencia; // ex: "042026"
    const dataComp = comp.length === 6
      ? `${comp.slice(2)}-${comp.slice(0,2)}-01`
      : new Date().toISOString().split("T")[0];

    const payload = {
      descricao: descricaoAuto,
      competencia: editandoBloco.competencia,
      evento_id: parseInt(editandoBloco.evento_id),
      linhas: linhasValidas.map(l => ({
        colaborador_id: parseInt(l.colaborador_id) || 0,
        data: dataComp,
        hora: eventoObj?.forma === "hora" ? (l.hora || null) : null,
        referencia: eventoObj?.forma === "referencia" ? (parseFloat(l.referencia) || null) : null,
        valor: parseFloat(l.valor) || 0,
        observacao: l.observacao || "",
      })),
    };

    try {
      if (editandoBloco.id) {
        await api.aprovarBloco(editandoBloco.id, "editar", "");
      } else {
        await api.criarBloco(payload);
      }
      // Recarregar blocos do banco com colaboradores e eventos resolvidos
      if (recarregarDados) await recarregarDados();
    } catch (err) {
      alert("Erro ao salvar: " + err.message);
    }
    setModalNovoBloco(false);
    setEditandoBloco(null);
  };

  const podeEditar = (bloco) => bloco.status === "pendente_gestor" || bloco.status === "devolvido";

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
        </div>
        <Button onClick={abrirNovoBloco}>+ Nova Solicitação de Pagamento</Button>
      </div>

      {/* Filtro */}
      <Card style={{ marginBottom: 18, padding: "12px 18px" }}>
        <div style={{ display: "flex", gap: 14, alignItems: "flex-end" }}>
          <Select label="Status" value={filtroStatus} onChange={setFiltroStatus}
            options={Object.entries(STATUS_CONFIG).map(([k, v]) => ({ value: k, label: v.label }))} />
          <Button variant="secondary" size="sm" onClick={() => setFiltroStatus("")}>Limpar</Button>
        </div>
      </Card>

      {/* Lista de blocos */}
      {blocosFiltrados.length === 0 ? (
        <Card style={{ textAlign: "center", padding: "40px 0" }}>
          <div style={{ fontSize: 36, marginBottom: 10 }}>📋</div>
          <p style={{ margin: 0, fontSize: 14, color: "#6B7280" }}>Nenhum bloco encontrado. Crie o primeiro!</p>
        </Card>
      ) : blocosFiltrados.map(bloco => {
        const totalBloco = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
        return (
          <Card key={bloco.id} style={{ marginBottom: 14, padding: 0, overflow: "hidden" }}>
            {/* Cabeçalho do bloco */}
            <div style={{ padding: "14px 20px", background: "#F8FAFC", borderBottom: "1px solid #E5E7EB", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "#111827" }}>{bloco.descricao}</span>
                  <Badge status={bloco.status} />
                  {bloco.evento && (
                    <span style={{ fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 6, background: "#EFF6FF", color: "#1D4ED8" }}>
                      ⚡ {bloco.evento.codigo} — {bloco.evento.descricao}
                    </span>
                  )}
                  {bloco.anexo_nome && (
                    <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 6, background: "#FFFBEB", color: "#92400E", border: "1px solid #FCD34D" }}>
                      📎 {bloco.anexo_nome}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11, color: "#6B7280" }}>
                  Competência: <b>{bloco.competencia}</b> · Solicitante: <b>{bloco.solicitante}</b> · Criado em: <b>{bloco.criado_em}</b>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ textAlign: "right", marginRight: 8 }}>
                  <div style={{ fontSize: 11, color: "#6B7280" }}>{bloco.linhas.length} lançamento(s)</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#10B981" }}>R$ {totalBloco.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</div>
                </div>
                {podeEditar(bloco) && (
                  <Button variant="secondary" size="sm" onClick={() => abrirEdicaoBloco(bloco)}>✏ Editar</Button>
                )}
                <Button variant="ghost" size="sm" onClick={() => setModalBloco(bloco)}>Ver</Button>
                <Button variant="secondary" size="sm" onClick={() => setModalRelatorio(bloco)}>📄 Relatório</Button>
              </div>
            </div>
            {/* Linhas do bloco */}
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#FAFAFA" }}>
                  {["Matrícula", "Colaborador", "Data", "Hora", "Valor", "Observação"].map(h => (
                    <th key={h} style={{ padding: "7px 16px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#9CA3AF", textTransform: "uppercase", letterSpacing: 0.4 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bloco.linhas.map((l, i) => (
                  <tr key={i} style={{ borderTop: "1px solid #F3F4F6" }}>
                    <td style={{ padding: "3px 7px" }}>
                      <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, background: "#F3F4F6", padding: "1px 6px", borderRadius: 4 }}>{l.colaborador?.chapa}</span>
                    </td>
                    <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{l.data}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{l.hora || "—"}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 700, color: "#059669" }}>R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#6B7280", fontStyle: "italic" }}>{l.observacao || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        );
      })}

      {editandoBloco && (
        <ModalNovoBloco
          open={modalNovoBloco}
          onClose={() => { setModalNovoBloco(false); setEditandoBloco(null); }}
          bloco={editandoBloco}
          setBloco={setEditandoBloco}
          onSalvar={salvarBloco}
          colaboradores={colaboradores}
          eventos={eventos}
        />
      )}

      {modalBloco && (
        <Modal open={!!modalBloco} onClose={() => setModalBloco(null)} title={"Bloco: " + modalBloco.descricao} width={700}>
          <DetalhesBloco bloco={modalBloco} />
        </Modal>
      )}

      {modalRelatorio && (
        <Modal open={!!modalRelatorio} onClose={() => setModalRelatorio(null)} title={"Relatório — " + modalRelatorio.descricao} width={750}>
          <RelatorioBloco bloco={modalRelatorio} />
        </Modal>
      )}
    </div>
  );
}



// ─── MODAL NOVO/EDITAR BLOCO ──────────────────────────────────────────────────
const MESES = [
  { value: "012026", label: "Janeiro/2026" },
  { value: "022026", label: "Fevereiro/2026" },
  { value: "032026", label: "Março/2026" },
  { value: "042026", label: "Abril/2026" },
  { value: "052026", label: "Maio/2026" },
  { value: "062026", label: "Junho/2026" },
  { value: "072026", label: "Julho/2026" },
  { value: "082026", label: "Agosto/2026" },
  { value: "092025", label: "Setembro/2025" },
  { value: "102025", label: "Outubro/2025" },
  { value: "112025", label: "Novembro/2025" },
  { value: "122025", label: "Dezembro/2025" },
  { value: "012025", label: "Janeiro/2025" },
  { value: "022025", label: "Fevereiro/2025" },
  { value: "032025", label: "Março/2025" },
];

function CelulaColaborador({ linha, idx, updateLinha, colaboradores = [] }) {
  const [buscaNome, setBuscaNome] = useState(linha.colaborador?.nome || "");
  const [buscaChapa, setBuscaChapa] = useState(linha.colaborador?.chapa || "");
  const [sugestoesNome, setSugestoesNome] = useState([]);
  const [sugestoesChapa, setSugestoesChapa] = useState([]);

  const selecionarColaborador = (colab) => {
    setBuscaNome(colab.nome);
    setBuscaChapa(colab.chapa);
    setSugestoesNome([]);
    setSugestoesChapa([]);
    updateLinha(idx, "colaborador_id", parseInt(colab.id));
    updateLinha(idx, "colaborador", colab);
  };

  const normalizar = (s) =>
    (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

  const onChangeNome = (v) => {
    setBuscaNome(v);
    updateLinha(idx, "colaborador_id", "");
    updateLinha(idx, "colaborador", null);
    setBuscaChapa("");
    if (v.length >= 2) {
      const termo = normalizar(v);
      setSugestoesNome(
        colaboradores
          .filter(c => c.cod_situacao !== "D")
          .filter(c => normalizar(c.nome).includes(termo))
          .slice(0, 10)
      );
    } else {
      setSugestoesNome([]);
    }
  };

  const onChangeChapa = (v) => {
    setBuscaChapa(v);
    updateLinha(idx, "colaborador_id", "");
    updateLinha(idx, "colaborador", null);
    setBuscaNome("");
    if (v.length >= 2) {
      setSugestoesChapa(
        colaboradores
          .filter(c => c.cod_situacao !== "D")
          .filter(c => (c.chapa || "").includes(v.trim()))
          .slice(0, 10)
      );
    } else {
      setSugestoesChapa([]);
    }
  };

  const inputStyle = {
    width: "100%", border: "1px solid #D1D5DB", borderRadius: 6,
    padding: "5px 7px", fontSize: 11, fontFamily: "inherit", background: "#fff",
    boxSizing: "border-box"
  };
  const selectedStyle = { ...inputStyle, borderColor: "#10B981", background: "#F0FDF4" };
  const dropStyle = {
    position: "absolute", top: "100%", left: 0, right: 0, zIndex: 100,
    background: "#fff", border: "1px solid #D1D5DB", borderRadius: 6,
    boxShadow: "0 4px 16px rgba(0,0,0,0.12)", maxHeight: 160, overflowY: "auto"
  };
  const dropItemStyle = {
    padding: "7px 10px", fontSize: 11, cursor: "pointer",
    borderBottom: "1px solid #F3F4F6", color: "#111827"
  };

  return (
    <div style={{ display: "flex", gap: 4 }}>
      {/* Matrícula */}
      <div style={{ position: "relative", width: 72 }}>
        <input
          value={buscaChapa}
          onChange={e => onChangeChapa(e.target.value)}
          placeholder="Matrícula"
          style={linha.colaborador_id ? selectedStyle : inputStyle}
        />
        {sugestoesChapa.length > 0 && (
          <div style={dropStyle}>
            {sugestoesChapa.map(c => (
              <div key={c.id} style={dropItemStyle}
                onMouseDown={() => selecionarColaborador(c)}>
                <b>{c.chapa}</b>
              </div>
            ))}
          </div>
        )}
      </div>
      {/* Nome */}
      <div style={{ position: "relative", flex: 1 }}>
        <input
          value={buscaNome}
          onChange={e => onChangeNome(e.target.value)}
          placeholder="Nome do colaborador"
          style={linha.colaborador_id ? selectedStyle : inputStyle}
        />
        {sugestoesNome.length > 0 && (
          <div style={dropStyle}>
            {sugestoesNome.map(c => (
              <div key={c.id} style={dropItemStyle}
                onMouseDown={() => selecionarColaborador(c)}>
                <span style={{ color: "#6B7280", marginRight: 6 }}>{c.chapa}</span>{c.nome}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ModalNovoBloco({ open, onClose, bloco, setBloco, onSalvar, colaboradores = [], eventos = [] }) {
  const addLinha = () => setBloco(b => ({ ...b, linhas: [...b.linhas, LINHA_VAZIA()] }));
  const removeLinha = (idx) => setBloco(b => ({ ...b, linhas: b.linhas.filter((_, i) => i !== idx) }));
  const updateLinha = (idx, campo, val) => setBloco(b => ({
    ...b, linhas: b.linhas.map((l, i) => i === idx ? { ...l, [campo]: val } : l)
  }));

  if (!bloco) return null;

  const totalBloco = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const eventoSelecionado = eventos.find(e => e.id === parseInt(bloco.evento_id));

  const onAnexo = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setBloco(b => ({ ...b, anexo_nome: file.name, anexo_tamanho: (file.size / 1024).toFixed(1) + " KB" }));
  };

  return (
    <Modal open={open} onClose={onClose} title={bloco.id ? "Editar Solicitação de Pagamento" : "Nova Solicitação de Pagamento"} width={980}>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

        {/* ── Cabeçalho do Bloco ── */}
        <div style={{ background: "#F8FAFC", borderRadius: 10, border: "1px solid #E5E7EB", padding: "16px 18px" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 12 }}>
            Cabeçalho do Bloco
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 14 }}>
            <Input
              label="Descrição do Bloco (automática)"
              value={bloco.descricao}
              onChange={v => setBloco(b => ({ ...b, descricao: v }))}
              placeholder="Preenchido automaticamente..."
            />

            {/* Competência — select de meses */}
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
                Competência <span style={{ color: "#EF4444" }}>*</span>
              </label>
              <select
                value={bloco.competencia}
                onChange={e => {
                  const comp = e.target.value;
                  // Calcular data predefinida: dia 05 do mês seguinte
                  let dataPredef = "";
                  if (comp && comp.length === 6) {
                    const mes = parseInt(comp.slice(0, 2));
                    const ano = parseInt(comp.slice(2));
                    const proxMes = mes === 12 ? 1 : mes + 1;
                    const proxAno = mes === 12 ? ano + 1 : ano;
                    dataPredef = `${proxAno}-${String(proxMes).padStart(2,"0")}-05`;
                  }
                  setBloco(b => ({
                    ...b,
                    competencia: comp,
                    linhas: b.linhas.map(l => ({ ...l, data: dataPredef || l.data }))
                  }));
                }}
                style={{
                  border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px",
                  fontSize: 13, fontFamily: "inherit", background: "#fff", cursor: "pointer",
                  color: bloco.competencia ? "#111827" : "#9CA3AF"
                }}
              >
                <option value="">Selecione o mês...</option>
                {MESES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>

            {/* Evento único do bloco */}
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
                Evento do Bloco <span style={{ color: "#EF4444" }}>*</span>
              </label>
              <select
                value={bloco.evento_id || ""}
                onChange={e => setBloco(b => ({ ...b, evento_id: e.target.value }))}
                style={{
                  border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px",
                  fontSize: 13, fontFamily: "inherit", background: "#fff", cursor: "pointer",
                  color: bloco.evento_id ? "#111827" : "#9CA3AF"
                }}
              >
                <option value="">Selecione o evento...</option>
                {eventos.filter(e => e.ativo !== false).map(e => (
                  <option key={e.id} value={e.id}>{e.codigo} — {e.descricao}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Info do evento selecionado */}
          {eventoSelecionado && (
            <div style={{
              marginTop: 10, display: "flex", alignItems: "center", gap: 10,
              padding: "3px 6px", background: "#EFF6FF", borderRadius: 8, border: "1px solid #BFDBFE"
            }}>
              <span style={{ fontSize: 11, color: "#1D4ED8" }}>
                ⚡ Todos os lançamentos deste bloco serão do evento
                <b style={{ marginLeft: 4 }}>{eventoSelecionado.codigo} — {eventoSelecionado.descricao}</b>
              </span>
              <span style={{
                padding: "1px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700,
                background: eventoSelecionado.tipo === "provento" ? "#D1FAE5" : "#FEE2E2",
                color: eventoSelecionado.tipo === "provento" ? "#065F46" : "#991B1B"
              }}>{eventoSelecionado.tipo}</span>
              <span style={{
                padding: "1px 8px", borderRadius: 6, fontSize: 10, fontWeight: 600,
                background: "#F3F4F6", color: "#374151"
              }}>{eventoSelecionado.forma}</span>
            </div>
          )}
        </div>

        {/* ── Anexo do Bloco ── */}
        <div style={{
          display: "flex", alignItems: "center", gap: 14,
          padding: "12px 16px", background: "#FFFBEB", border: "1px dashed #FCD34D", borderRadius: 10
        }}>
          <span style={{ fontSize: 20 }}>📎</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#92400E" }}>Anexo do Bloco</div>
            {bloco.anexo_nome ? (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
                <span style={{ fontSize: 12, color: "#065F46", fontWeight: 600 }}>✓ {bloco.anexo_nome}</span>
                <span style={{ fontSize: 11, color: "#6B7280" }}>({bloco.anexo_tamanho})</span>
                <button
                  onClick={() => setBloco(b => ({ ...b, anexo_nome: null, anexo_tamanho: null }))}
                  style={{ background: "none", border: "none", color: "#EF4444", cursor: "pointer", fontSize: 11 }}
                >✕ Remover</button>
              </div>
            ) : (
              <div style={{ fontSize: 11, color: "#92400E", marginTop: 2 }}>
                Nenhum arquivo selecionado. Formatos aceitos: PDF, JPG, PNG, XLSX.
              </div>
            )}
          </div>
          <label style={{
            padding: "7px 14px", background: "#F59E0B", color: "#fff", borderRadius: 8,
            fontSize: 11, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap"
          }}>
            {bloco.anexo_nome ? "Trocar arquivo" : "Selecionar arquivo"}
            <input type="file" accept=".pdf,.jpg,.jpeg,.png,.xlsx,.xls" onChange={onAnexo}
              style={{ display: "none" }} />
          </label>
        </div>

        {/* ── Tabela de Lançamentos ── */}
        {!bloco.evento_id ? (
          <div style={{
            padding: "28px", textAlign: "center", background: "#F8FAFC",
            border: "2px dashed #D1D5DB", borderRadius: 10
          }}>
            <div style={{ fontSize: 28, marginBottom: 8 }}>⚡</div>
            <p style={{ margin: 0, fontSize: 11, color: "#6B7280" }}>
              Selecione o <b>Evento do Bloco</b> acima para liberar os lançamentos
            </p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "#374151" }}>
                Lançamentos — <span style={{ color: "#1D4ED8" }}>{eventoSelecionado?.descricao}</span>
                <span style={{ marginLeft: 6, fontSize: 11, color: "#6B7280" }}>({bloco.linhas.length} linha{bloco.linhas.length !== 1 ? "s" : ""})</span>
              </span>
              <Button variant="secondary" size="sm" onClick={addLinha}>+ Adicionar linha</Button>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 600 }}>
              <thead>
                <tr style={{ background: "#0F2447" }}>
                  {["Matrícula / Colaborador *",
                    ...(eventoSelecionado?.forma === "hora"       ? ["Hora *"]        : []),
                    ...(eventoSelecionado?.forma === "referencia" ? ["Referência *"]   : []),
                    ...(eventoSelecionado?.forma === "valor"      ? ["Valor (R$) *"]   : ["Valor (R$)"]),
                    "Observação", ""].map(h => (
                    <th key={h} style={{
                      padding: "9px 10px", textAlign: "left", fontSize: 10, fontWeight: 700,
                      color: "rgba(255,255,255,0.7)", textTransform: "uppercase", letterSpacing: 0.4
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bloco.linhas.map((linha, idx) => (
                  <tr key={linha._id} style={{ borderBottom: "1px solid #F3F4F6", background: idx % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                    {/* Matrícula + Nome — sem alteração */}
                    <td style={{ padding: "6px 8px", minWidth: 260 }}>
                      <CelulaColaborador linha={linha} idx={idx} updateLinha={updateLinha} colaboradores={colaboradores} />
                    </td>
                    {/* Hora — somente para forma=hora */}
                    {eventoSelecionado?.forma === "hora" && (
                      <td style={{ padding: "6px 8px", minWidth: 100 }}>
                        <input type="time" value={linha.hora || ""} onChange={e => updateLinha(idx, "hora", e.target.value)}
                          style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                      </td>
                    )}
                    {/* Referência — somente para forma=referencia */}
                    {eventoSelecionado?.forma === "referencia" && (
                      <td style={{ padding: "6px 8px", minWidth: 110 }}>
                        <input type="number" step="0.01" min="0" value={linha.referencia || ""}
                          onChange={e => updateLinha(idx, "referencia", e.target.value)}
                          placeholder="0.00"
                          style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                      </td>
                    )}
                    {/* Valor — somente para forma=valor obrigatório; para hora/referencia é opcional */}
                    {eventoSelecionado?.forma === "valor" && (
                      <td style={{ padding: "6px 8px", minWidth: 110 }}>
                        <input type="number" step="0.01" min="0" value={linha.valor || ""}
                          onChange={e => updateLinha(idx, "valor", e.target.value)}
                          placeholder="0.00"
                          style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                      </td>
                    )}
                    {/* Observação */}
                    <td style={{ padding: "6px 8px", minWidth: 160 }}>
                      <input value={linha.observacao || ""} onChange={e => updateLinha(idx, "observacao", e.target.value)}
                        placeholder="Opcional"
                        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                    </td>
                    <td style={{ padding: "6px 8px" }}>
                      {bloco.linhas.length > 1 && (
                        <button onClick={() => removeLinha(idx)} style={{
                          background: "#FEE2E2", border: "none", borderRadius: 6,
                          padding: "3px 6px", color: "#EF4444", cursor: "pointer", fontSize: 11, fontWeight: 700
                        }}>✕</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr style={{ background: "#F0FDF4", borderTop: "2px solid #10B981" }}>
                  <td colSpan={3} style={{ padding: "3px 6px", fontSize: 11, fontWeight: 700, color: "#065F46" }}>
                    TOTAL — {bloco.linhas.filter(l => l.valor && l.colaborador_id).length} lançamento(s) preenchidos
                  </td>
                  <td colSpan={3} style={{ padding: "3px 6px", fontSize: 15, fontWeight: 800, color: "#065F46" }}>
                    R$ {totalBloco.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </td>
                </tr>
              </tfoot>
            </table>
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 8, borderTop: "1px solid #F3F4F6" }}>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button onClick={onSalvar}>
            {bloco.id ? "Salvar Alterações" : "Enviar para Aprovação"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}


// ─── DETALHES DO BLOCO ────────────────────────────────────────────────────────
function DetalhesBloco({ bloco }) {
  if (!bloco) return null;
  const total = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const ACAO_COLOR = {
    criado: "#3B82F6", editado: "#F59E0B",
    aprovado_gestor: "#10B981", aprovado_superior: "#8B5CF6",
    aprovado_dp: "#059669", devolvido: "#F97316", rejeitado: "#EF4444",
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <Badge status={bloco.status} />
        <span style={{ fontSize: 11, color: "#6B7280" }}>Competência: <b>{bloco.competencia}</b> · {bloco.linhas.length} lançamento(s)</span>
        <span style={{ marginLeft: "auto", fontSize: 15, fontWeight: 700, color: "#10B981" }}>
          R$ {total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
        </span>
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#F9FAFB" }}>
            {["Colaborador", "Evento", "Data", "Hora", "Valor", "Observação"].map(h => (
              <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {bloco.linhas.map((l, i) => (
            <tr key={i} style={{ borderTop: "1px solid #F3F4F6" }}>
              <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
              <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.evento?.descricao}</td>
              <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.data}</td>
              <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.hora || "—"}</td>
              <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 700, color: "#10B981" }}>R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</td>
              <td style={{ padding: "3px 6px", fontSize: 11, color: "#6B7280", fontStyle: "italic" }}>{l.observacao || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div>
        <h4 style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, color: "#374151" }}>Histórico do Bloco</h4>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {bloco.historico.map((h, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: 12,
              padding: "3px 6px", background: "#F9FAFB", borderRadius: 8,
              borderLeft: `3px solid ${ACAO_COLOR[h.acao] || "#6B7280"}`
            }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: "#111827" }}>{h.usuario}</span>
                <span style={{ fontSize: 11, color: "#6B7280" }}> · {h.acao.replace(/_/g, " ")} · {h.data}</span>
                {h.obs && <div style={{ fontSize: 11, color: "#F97316", marginTop: 2 }}>"{h.obs}"</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── RELATÓRIO DO BLOCO ───────────────────────────────────────────────────────
function RelatorioBloco({ bloco }) {
  if (!bloco) return null;
  const total = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const ACAO_LABEL = {
    criado: "Criação", editado: "Edição", aprovado_gestor: "Aprovação Gestor",
    aprovado_superior: "Aprovação Superior", aprovado_dp: "Aprovação DP",
    devolvido: "Devolução", rejeitado: "Rejeição"
  };
  const ACAO_COLOR = {
    criado: "#3B82F6", editado: "#F59E0B", aprovado_gestor: "#10B981",
    aprovado_superior: "#8B5CF6", aprovado_dp: "#059669", devolvido: "#F97316", rejeitado: "#EF4444"
  };

  const imprimir = () => window.print();

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Cabeçalho do relatório */}
      <div style={{ background: "#0F2447", borderRadius: 10, padding: "18px 22px", color: "#fff" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ background: "rgba(255,255,255,0.95)", borderRadius: 8, padding: "6px 14px", display: "inline-block" }}>
                <img src={LOGO_BENEL} alt="Benel" style={{ height: 32, display: "block" }} />
              </div>
            </div>
            <div style={{ fontSize: 11, letterSpacing: 1, color: "rgba(255,255,255,0.5)", textTransform: "uppercase", marginBottom: 4 }}>Relatório de Bloco</div>
            <div style={{ fontSize: 20, fontWeight: 800 }}>{bloco.descricao}</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.6)", marginTop: 4 }}>
              Competência: <b style={{ color: "#93C5FD" }}>{bloco.competencia}</b> · Solicitante: <b style={{ color: "#93C5FD" }}>{bloco.solicitante}</b>
            </div>
          </div>
          <div style={{ textAlign: "right" }}>
            <Badge status={bloco.status} />
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", marginTop: 6 }}>Gerado em: {new Date().toLocaleString("pt-BR")}</div>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginTop: 16 }}>
          {[
            { label: "Total de lançamentos", value: bloco.linhas.length },
            { label: "Valor total", value: `R$ ${total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}` },
            { label: "Etapas no histórico", value: bloco.historico.length },
          ].map(c => (
            <div key={c.label} style={{ background: "rgba(255,255,255,0.07)", borderRadius: 8, padding: "3px 6px" }}>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.45)", textTransform: "uppercase", letterSpacing: 0.5 }}>{c.label}</div>
              <div style={{ fontSize: 18, fontWeight: 800, marginTop: 2 }}>{c.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Lançamentos */}
      <div>
        <h4 style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, color: "#111827", textTransform: "uppercase", letterSpacing: 0.5 }}>
          Lançamentos
        </h4>
        <table style={{ width: "100%", borderCollapse: "collapse", border: "1px solid #E5E7EB", borderRadius: 8, overflow: "hidden" }}>
          <thead>
            <tr style={{ background: "#1B3A6B" }}>
              {["#", "Colaborador", "Chapa", "C.Custo", "Evento", "Cód.", "Data", "Hora", "Valor"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "rgba(255,255,255,0.75)", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {bloco.linhas.map((l, i) => (
              <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#F8FAFC" }}>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#9CA3AF" }}>{i + 1}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, fontFamily: "monospace", color: "#374151" }}>{l.colaborador?.chapa}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.colaborador?.centro_custo} — {l.colaborador?.desc_cc}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.evento?.descricao}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, fontFamily: "monospace", color: "#374151" }}>{l.evento?.codigo}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.data}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.hora || "—"}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 800, color: "#059669" }}>
                  R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr style={{ background: "#F0FDF4", borderTop: "2px solid #10B981" }}>
              <td colSpan={8} style={{ padding: "3px 6px", fontSize: 11, fontWeight: 700, color: "#065F46" }}>TOTAL</td>
              <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 800, color: "#065F46" }}>
                R$ {total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
              </td>
            </tr>
          </tfoot>
        </table>
      </div>

      {/* Trilha de aprovação */}
      <div>
        <h4 style={{ margin: "0 0 12px", fontSize: 11, fontWeight: 700, color: "#111827", textTransform: "uppercase", letterSpacing: 0.5 }}>
          Trilha Completa de Aprovação
        </h4>
        <div style={{ position: "relative", paddingLeft: 28 }}>
          <div style={{ position: "absolute", left: 9, top: 0, bottom: 0, width: 2, background: "#E5E7EB" }} />
          {bloco.historico.map((h, i) => (
            <div key={i} style={{ position: "relative", marginBottom: 14 }}>
              <div style={{
                position: "absolute", left: -28, top: 2,
                width: 18, height: 18, borderRadius: "50%",
                background: ACAO_COLOR[h.acao] || "#6B7280",
                border: "3px solid #fff",
                boxShadow: `0 0 0 2px ${ACAO_COLOR[h.acao] || "#6B7280"}33`
              }} />
              <div style={{ background: "#F9FAFB", borderRadius: 10, padding: "3px 6px", border: "1px solid #E5E7EB" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 6,
                      background: (ACAO_COLOR[h.acao] || "#6B7280") + "18",
                      color: ACAO_COLOR[h.acao] || "#6B7280"
                    }}>{ACAO_LABEL[h.acao] || h.acao}</span>
                    <span style={{ marginLeft: 8, fontSize: 11, fontWeight: 600, color: "#111827" }}>{h.usuario}</span>
                  </div>
                  <span style={{ fontSize: 11, color: "#9CA3AF" }}>{h.data}</span>
                </div>
                {h.obs && (
                  <div style={{ marginTop: 6, fontSize: 11, color: "#374151", fontStyle: "italic", borderLeft: "2px solid #F97316", paddingLeft: 8 }}>
                    {h.obs}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, borderTop: "1px solid #F3F4F6", paddingTop: 12 }}>
        <Button variant="secondary" onClick={imprimir}>🖨 Imprimir</Button>
      </div>
    </div>
  );
}

// ─── EXPORTAÇÃO TXT ───────────────────────────────────────────────────────────
const LAYOUT_RM = [
  { col: "01", tam: 16, tipo: "String",       desc: "Chapa do Funcionário" },
  { col: "17", tam: 8,  tipo: "String",       desc: "Data pagamento (DDMMAAAA)" },
  { col: "25", tam: 4,  tipo: "Alfanumérico", desc: "Código do evento" },
  { col: "29", tam: 6,  tipo: "String",       desc: "Hora (HHH:MM)" },
  { col: "35", tam: 15, tipo: "Real",         desc: "Referência (999999999999.99)" },
  { col: "50", tam: 15, tipo: "Real",         desc: "Valor (999999999999.99)" },
  { col: "65", tam: 15, tipo: "Real",         desc: "Valor original (999999999999.99)" },
  { col: "80", tam: 1,  tipo: "Caractere",    desc: "Dados alterados manualmente (S ou N)" },
  { col: "81", tam: 1,  tipo: "Caractere",    desc: "Dados de férias (S ou N)" },
];

function Exportacao({ solicitacoes, blocos }) {
  const blocosAprov = (blocos || []).filter(b => b.status === "aprovado_final");
  const [preview, setPreview] = useState(false);
  const [showLayout, setShowLayout] = useState(false);

  // Gera todas as linhas a partir dos blocos aprovados
  const linhas = blocosAprov.flatMap(bloco =>
    bloco.linhas.map(l => {
      const solFormatada = {
        ...l,
        valor_original: l.valor,
        competencia: bloco.competencia,
        status: bloco.status,
      };
      const colabs = [l.colaborador].filter(Boolean);
      const evts = [l.evento].filter(Boolean);
      if (!l.colaborador || !l.evento) return "";
      // Montar linha direto com objeto colaborador/evento já resolvidos
      const chapa = (l.colaborador.chapa || "").padEnd(16, " ").slice(0, 16);
      let dataTXT = "00000000";
      if (l.data) { const p = l.data.split("-"); if (p.length === 3) dataTXT = p[2] + p[1] + p[0]; }
      const codEvento = (l.evento.codigo || "").padEnd(4, " ").slice(0, 4);
      let horaTXT = "000:00";
      if (l.hora) { const hp = l.hora.split(":"); horaTXT = String(parseInt(hp[0]||0)).padStart(3,"0") + ":" + String(parseInt(hp[1]||0)).padStart(2,"0"); }
      const hora = horaTXT.slice(0, 6);
      const fmtReal = (v, t) => parseFloat(v||0).toFixed(2).padStart(t, " ");
      const ref     = fmtReal(l.referencia || 0, 15);
      const val     = fmtReal(l.valor || 0, 15);
      const valOrig = fmtReal(l.valor_original || l.valor || 0, 15);
      return chapa + dataTXT.slice(0,8) + codEvento + hora + ref + val + valOrig + "N" + "N";
    })
  ).filter(Boolean);

  const totalValor = blocosAprov.reduce((a, b) =>
    a + b.linhas.reduce((s, l) => s + parseFloat(l.valor || 0), 0), 0
  );

  const baixarTXT = () => {
    const conteudo = linhas.join("\n");
    const blob = new Blob([conteudo], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "movimento_rm_" + new Date().toISOString().split("T")[0] + ".txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <div>

        </div>
        <Button variant="secondary" size="sm" onClick={() => setShowLayout(l => !l)}>
          {showLayout ? "Ocultar layout" : "📋 Ver layout RM"}
        </Button>
      </div>

      {/* Layout RM Labore */}
      {showLayout && (
        <Card style={{ marginBottom: 20, padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", background: "#0F2447", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#fff" }}>Layout de Importação do Movimento (RM Labore)</span>
            <span style={{ fontSize: 11, color: "#93C5FD", background: "rgba(255,255,255,0.1)", padding: "1px 6px", borderRadius: 4 }}>81 caracteres por linha</span>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#F1F5F9" }}>
                {["Coluna", "Tamanho", "Tipo", "Descrição"].map(h => (
                  <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: 0.4 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {LAYOUT_RM.map((row, i) => (
                <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#F8FAFC" }}>
                  <td style={{ padding: "3px 6px", fontFamily: "monospace", fontSize: 11, fontWeight: 700, color: "#1B3A6B" }}>{row.col}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{row.tam}</td>
                  <td style={{ padding: "3px 6px" }}>
                    <span style={{ padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                      background: row.tipo === "Real" ? "#EFF6FF" : row.tipo === "String" ? "#F0FDF4" : "#FEF3C7",
                      color: row.tipo === "Real" ? "#1D4ED8" : row.tipo === "String" ? "#065F46" : "#92400E"
                    }}>{row.tipo}</span>
                  </td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{row.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Cards de resumo */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 20 }}>
        {[
          { label: "Blocos aprovados", value: blocosAprov.length, color: "#10B981" },
          { label: "Linhas no arquivo", value: linhas.length, color: "#3B82F6" },
          { label: "Valor total", value: "R$ " + totalValor.toLocaleString("pt-BR", { minimumFractionDigits: 2 }), color: "#8B5CF6" },
        ].map(c => (
          <Card key={c.label}>
            <div style={{ fontSize: 11, color: "#6B7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>{c.label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: c.color }}>{c.value}</div>
          </Card>
        ))}
      </div>

      {/* Tabela de registros */}
      <Card style={{ marginBottom: 16, padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "12px 16px", borderBottom: "1px solid #F3F4F6" }}>
          <h3 style={{ margin: 0, fontSize: 11, fontWeight: 700, color: "#111827" }}>Registros para exportar</h3>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Bloco", "Chapa", "Colaborador", "Evento (Cód.)", "Data", "Hora", "Referência", "Valor", "Valor Original"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {blocosAprov.length === 0 ? (
              <tr><td colSpan={9} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>
                Nenhum bloco aprovado para exportar
              </td></tr>
            ) : blocosAprov.flatMap(bloco =>
              bloco.linhas.map((l, i) => (
                <tr key={bloco.id + "-" + i} style={{ borderTop: "1px solid #F3F4F6" }}>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#6B7280" }}>{bloco.descricao}</td>
                  <td style={{ padding: "3px 6px" }}>
                    <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, background: "#F3F4F6", padding: "1px 6px", borderRadius: 4 }}>{l.colaborador?.chapa}</span>
                  </td>
                  <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>
                    {l.evento?.descricao} <span style={{ color: "#9CA3AF" }}>({l.evento?.codigo})</span>
                  </td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.data}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.hora || "—"}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.referencia || "0.00"}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 700, color: "#059669" }}>
                    R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>
                    R$ {parseFloat(l.valor_original || l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Card>

      {/* Prévia TXT */}
      <Card style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 11, fontWeight: 700, color: "#111827" }}>Prévia do arquivo TXT</h3>
            <p style={{ margin: "2px 0 0", fontSize: 11, color: "#6B7280" }}>Layout posicional — 81 caracteres por linha</p>
          </div>
          <Button variant="secondary" size="sm" onClick={() => setPreview(!preview)}>
            {preview ? "Ocultar" : "Mostrar prévia"}
          </Button>
        </div>
        {preview && (
          <div>
            {/* Régua de posições */}
            <div style={{ fontFamily: "monospace", fontSize: 10, color: "#475569", marginBottom: 4, paddingLeft: 48, letterSpacing: 0 }}>
              {"1               17      25  29    35             50             65             80"}
            </div>
            <div style={{ fontFamily: "monospace", fontSize: 10, color: "#334155", marginBottom: 8, paddingLeft: 48 }}>
              {"|←── chapa ────→||← data→||ev||hora||←─── ref ───→||←── valor ──→||←─valorOrig─→|AN"}
            </div>
            <div style={{
              background: "#0F172A", borderRadius: 8, padding: "14px 16px",
              fontFamily: "'DM Mono', monospace", fontSize: 12, color: "#94A3B8",
              overflowX: "auto", whiteSpace: "nowrap"
            }}>
              {linhas.length === 0
                ? <span style={{ color: "#475569" }}>Nenhum registro aprovado para exportar.</span>
                : linhas.map((l, i) => (
                  <div key={i} style={{ marginBottom: 4, display: "flex", gap: 12 }}>
                    <span style={{ color: "#475569", userSelect: "none", minWidth: 32 }}>{String(i + 1).padStart(3, "0")}</span>
                    <span>
                      <span style={{ color: "#34D399" }}>{l.slice(0, 16)}</span>
                      <span style={{ color: "#60A5FA" }}>{l.slice(16, 24)}</span>
                      <span style={{ color: "#FBBF24" }}>{l.slice(24, 28)}</span>
                      <span style={{ color: "#F472B6" }}>{l.slice(28, 34)}</span>
                      <span style={{ color: "#A78BFA" }}>{l.slice(34, 49)}</span>
                      <span style={{ color: "#38BDF8" }}>{l.slice(49, 64)}</span>
                      <span style={{ color: "#FB923C" }}>{l.slice(64, 79)}</span>
                      <span style={{ color: "#E2E8F0" }}>{l.slice(79)}</span>
                    </span>
                  </div>
                ))}
            </div>
            {/* Legenda de cores */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 10 }}>
              {[
                { cor: "#34D399", label: "Chapa (1-16)" },
                { cor: "#60A5FA", label: "Data (17-24)" },
                { cor: "#FBBF24", label: "Evento (25-28)" },
                { cor: "#F472B6", label: "Hora (29-34)" },
                { cor: "#A78BFA", label: "Referência (35-49)" },
                { cor: "#38BDF8", label: "Valor (50-64)" },
                { cor: "#FB923C", label: "Valor Original (65-79)" },
                { cor: "#E2E8F0", label: "Flags (80-81)" },
              ].map(c => (
                <div key={c.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: c.cor }} />
                  <span style={{ fontSize: 10, color: "#6B7280" }}>{c.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      <Button onClick={baixarTXT} disabled={linhas.length === 0} size="lg">
        ↓ Baixar arquivo TXT — TOTVS RM Labore
      </Button>
    </div>
  );
}

// ─── AUDITORIA SEGURA ────────────────────────────────────────────────────────
function Auditoria({ solicitacoes, blocos, sessao }) {
  const [aba, setAba] = useState("seguranca");

  const logsSeguranca = obterAuditLog();

  const logsBlocos = blocos.flatMap(b =>
    (b.historico || []).map(h => ({ ...h, bloco_id: b.id, bloco: b.descricao }))
  ).sort((a, b) => new Date(b.data) - new Date(a.data));

  const ACAO_COLOR = {
    criado: "#3B82F6", editado: "#F59E0B",
    aprovado_gestor: "#10B981", aprovado_superior: "#8B5CF6",
    aprovado_dp: "#059669", devolvido: "#F97316", rejeitado: "#EF4444",
    LOGIN_SUCESSO: "#10B981", LOGIN_FALHA: "#EF4444", LOGOUT: "#6B7280",
    RATE_LIMIT_ATINGIDO: "#EF4444", TENTATIVA_INJECAO: "#EF4444",
    TXT_EXPORTADO: "#3B82F6", SESSAO_EXPIRADA: "#F97316",
    BLOCO_APROVADO: "#10B981", BLOCO_REJEITADO: "#EF4444",
    SCHEMA_TOTVS_INVALIDO: "#F97316", ACESSO_NEGADO: "#EF4444",
  };

  const abas = [
    { id: "seguranca", label: "🔒 Log de Segurança", count: logsSeguranca.length },
    { id: "blocos", label: "📋 Log de Blocos", count: logsBlocos.length },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 20 }}>
      </div>

      {/* Abas */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "2px solid #E5E7EB", paddingBottom: 0 }}>
        {abas.map(a => (
          <button key={a.id} onClick={() => setAba(a.id)} style={{
            padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
            fontSize: 13, fontWeight: aba === a.id ? 700 : 400,
            color: aba === a.id ? "#1B3A6B" : "#6B7280",
            borderBottom: aba === a.id ? "2px solid #1B3A6B" : "2px solid transparent",
            marginBottom: -2, fontFamily: "inherit"
          }}>
            {a.label}
            <span style={{
              marginLeft: 6, padding: "1px 7px", borderRadius: 10, fontSize: 10,
              background: aba === a.id ? "#1B3A6B" : "#F3F4F6",
              color: aba === a.id ? "#fff" : "#6B7280", fontWeight: 700
            }}>{a.count}</span>
          </button>
        ))}
      </div>

      {/* Log de Segurança */}
      {aba === "seguranca" && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", background: "#0F2447", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#fff" }}>🔒 Log de Segurança — Eventos do Sistema</span>
            <span style={{ fontSize: 11, color: "#93C5FD" }}>{logsSeguranca.length} registro(s)</span>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#F9FAFB" }}>
                {["Data/Hora", "Ação", "Usuário", "Perfil", "Detalhes"].map(h => (
                  <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logsSeguranca.length === 0 ? (
                <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhum evento registrado nesta sessão</td></tr>
              ) : logsSeguranca.map((l, i) => (
                <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#6B7280", fontFamily: "monospace" }}>{l.dataHora}</td>
                  <td style={{ padding: "3px 6px" }}>
                    <span style={{
                      padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700,
                      background: (ACAO_COLOR[l.acao] || "#6B7280") + "18",
                      color: ACAO_COLOR[l.acao] || "#6B7280"
                    }}>{l.acao}</span>
                  </td>
                  <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.usuario}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151", textTransform: "capitalize" }}>{l.perfil || "—"}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#6B7280" }}>
                    {Object.keys(l.detalhes || {}).length > 0
                      ? Object.entries(l.detalhes).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 8 }}>
                          <b>{k}:</b> {String(v).slice(0, 40)}
                        </span>
                      ))
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Log de Blocos */}
      {aba === "blocos" && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#F9FAFB" }}>
                {["Bloco", "Ação", "Usuário", "Data/Hora", "Observação"].map(h => (
                  <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logsBlocos.length === 0 ? (
                <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhum evento de bloco registrado</td></tr>
              ) : logsBlocos.map((l, i) => (
                <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{l.bloco}</td>
                  <td style={{ padding: "3px 6px" }}>
                    <span style={{
                      padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700,
                      background: (ACAO_COLOR[l.acao] || "#6B7280") + "18",
                      color: ACAO_COLOR[l.acao] || "#6B7280"
                    }}>{l.acao.replace(/_/g, " ")}</span>
                  </td>
                  <td style={{ padding: "3px 6px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.usuario}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: "#6B7280" }}>{l.data}</td>
                  <td style={{ padding: "3px 6px", fontSize: 11, color: l.obs ? "#F97316" : "#9CA3AF", fontStyle: l.obs ? "italic" : "normal" }}>{l.obs || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

// ─── USUARIOS (placeholder) ───────────────────────────────────────────────────
function Usuarios() {
  return (
    <div style={{ padding: 28 }}>
      <Card style={{ padding: 0 }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Avatar", "Nome", "E-mail", "Perfil", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MOCK_USERS.map((u, i) => (
              <tr key={u.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "12px 16px" }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: 8,
                    background: PERFIL_CONFIG[u.perfil]?.color,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 11, fontWeight: 700, color: "#fff"
                  }}>{u.avatar}</div>
                </td>
                <td style={{ padding: "12px 16px", fontSize: 11, fontWeight: 600, color: "#111827" }}>{u.nome}</td>
                <td style={{ padding: "12px 16px", fontSize: 11, color: "#374151" }}>{u.email}</td>
                <td style={{ padding: "12px 16px" }}>
                  <span style={{
                    padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600,
                    background: PERFIL_CONFIG[u.perfil]?.color + "22",
                    color: PERFIL_CONFIG[u.perfil]?.color
                  }}>{PERFIL_CONFIG[u.perfil]?.label}</span>
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <span style={{ padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: "#D1FAE5", color: "#065F46" }}>Ativo</span>
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <Button variant="ghost" size="sm">Editar</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}


const MOCK_BLOCOS_INIT = [
  {
    id: 1,
    descricao: "Variáveis Setembro 2025",
    competencia: "092025",
    status: "aprovado_final",
    solicitante: "Carlos Mendes",
    solicitante_id: 1,
    criado_em: "25/09/2025 09:00:00",
    linhas: [
      { _id: 1, colaborador_id: 1, evento_id: 1, data: "2025-09-30", hora: "00:00", valor: "1190.47", observacao: "Deslocamento filial sul", colaborador: MOCK_COLABORADORES[0], evento: MOCK_EVENTOS[0] },
      { _id: 2, colaborador_id: 2, evento_id: 2, data: "2025-09-20", hora: "", valor: "500.00", observacao: "Curso externo SP", colaborador: MOCK_COLABORADORES[1], evento: MOCK_EVENTOS[1] },
    ],
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "25/09/2025 09:00:00", obs: "Bloco enviado para aprovação" },
      { acao: "aprovado_gestor", usuario: "Carlos Mendes", data: "25/09/2025 09:30:00", obs: "" },
      { acao: "aprovado_superior", usuario: "Ana Souza", data: "26/09/2025 10:00:00", obs: "" },
      { acao: "aprovado_dp", usuario: "Fernanda Lima", data: "27/09/2025 14:00:00", obs: "" },
    ]
  },
  {
    id: 2,
    descricao: "Horas Extras Operação",
    competencia: "092025",
    status: "pendente_gestor",
    solicitante: "Carlos Mendes",
    solicitante_id: 1,
    criado_em: "28/09/2025 08:00:00",
    linhas: [
      { _id: 3, colaborador_id: 3, evento_id: 3, data: "2025-09-28", hora: "04:30", valor: "340.00", observacao: "Plantão final de semana", colaborador: MOCK_COLABORADORES[2], evento: MOCK_EVENTOS[2] },
      { _id: 4, colaborador_id: 4, evento_id: 6, data: "2025-09-29", hora: "02:00", valor: "210.00", observacao: "", colaborador: MOCK_COLABORADORES[3], evento: MOCK_EVENTOS[5] },
    ],
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "28/09/2025 08:00:00", obs: "Bloco enviado para aprovação" },
    ]
  },
  {
    id: 3,
    descricao: "Ajudas de Custo Outubro",
    competencia: "102025",
    status: "devolvido",
    solicitante: "Carlos Mendes",
    solicitante_id: 1,
    criado_em: "01/10/2025 10:00:00",
    linhas: [
      { _id: 5, colaborador_id: 4, evento_id: 5, data: "2025-10-01", hora: "", valor: "293.47", observacao: "Multa via expressa", colaborador: MOCK_COLABORADORES[3], evento: MOCK_EVENTOS[4] },
    ],
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "01/10/2025 10:00:00", obs: "Bloco enviado para aprovação" },
      { acao: "devolvido", usuario: "Ana Souza", data: "02/10/2025 09:00:00", obs: "Falta comprovante da infração" },
    ]
  },
];

function Aprovacoes({ blocos, setBlocos, user, recarregarDados }) {
  const [justificativa, setJustificativa] = useState("");
  const [modalAcao, setModalAcao] = useState(null);

  const getFilaParaUsuario = () => {
    if (user.perfil === "superior") return blocos.filter(b => b.status === "pendente_superior");
    if (user.perfil === "dp") return blocos.filter(b => b.status === "pendente_dp");
    if (user.perfil === "admin") return blocos.filter(b => b.status.startsWith("pendente"));
    return [];
    return [];
  };

  const fila = getFilaParaUsuario();

  const avancarStatus = (bloco) => {
    const mapa = {
      pendente_gestor: "pendente_superior",
      pendente_superior: "pendente_dp",
      pendente_dp: "aprovado_final",
    };
    return mapa[bloco.status] || bloco.status;
  };

  const executarAcao = async (acao) => {
    const { bloco } = modalAcao;
    const ts = new Date().toLocaleString("pt-BR");

    // Optimistic update imediato
    setBlocos(prev => prev.map(b => {
      if (b.id !== bloco.id) return b;
      let novoStatus = b.status;
      if (acao === "aprovar") novoStatus = avancarStatus(b);
      if (acao === "rejeitar") novoStatus = "rejeitado";
      if (acao === "devolver") novoStatus = "devolvido";
      const acaoNome = acao === "aprovar" ? ("aprovado_" + user.perfil) : acao;
      return {
        ...b, status: novoStatus,
        historico: [...b.historico, { acao: acaoNome, usuario: user.nome, data: ts, obs: justificativa }]
      };
    }));

    try {
      await api.aprovarBloco(bloco.id, acao, justificativa);
      if (recarregarDados) await recarregarDados();
    } catch (err) {
      console.warn("API indisponível, ação aplicada localmente:", err.message);
    }

    setModalAcao(null);
    setJustificativa("");
  };

  return (
    <div style={{ padding: 28 }}>

      {fila.length === 0 ? (
        <Card style={{ textAlign: "center", padding: "40px 0" }}>
          <div style={{ fontSize: 36, marginBottom: 10 }}>✅</div>
          <p style={{ margin: 0, fontSize: 14, fontWeight: 600, color: "#6B7280" }}>Nenhum bloco pendente para aprovação</p>
        </Card>
      ) : fila.map(bloco => {
        const total = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
        return (
          <Card key={bloco.id} style={{ marginBottom: 14, padding: 0, overflow: "hidden" }}>
            <div style={{ padding: "14px 20px", background: "#F8FAFC", borderBottom: "1px solid #E5E7EB", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: "#111827" }}>{bloco.descricao}</span>
                  <Badge status={bloco.status} />
                </div>
                <div style={{ fontSize: 11, color: "#6B7280" }}>
                  Competência: <b>{bloco.competencia}</b> · Solicitante: <b>{bloco.solicitante}</b> · Criado: <b>{bloco.criado_em}</b>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ textAlign: "right", marginRight: 8 }}>
                  <div style={{ fontSize: 11, color: "#6B7280" }}>{bloco.linhas.length} lançamento(s)</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#10B981" }}>R$ {total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</div>
                </div>
                <Button variant="success" size="sm" onClick={() => setModalAcao({ bloco, acao: "aprovar" })}>✓ Aprovar Bloco</Button>
                <Button variant="warning" size="sm" onClick={() => setModalAcao({ bloco, acao: "devolver" })}>↩ Devolver</Button>
                <Button variant="danger" size="sm" onClick={() => setModalAcao({ bloco, acao: "rejeitar" })}>✕ Rejeitar</Button>
              </div>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#FAFAFA" }}>
                  {["Colaborador", "Evento", "Data", "Hora", "Valor", "Observação"].map(h => (
                    <th key={h} style={{ padding: "7px 16px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#9CA3AF", textTransform: "uppercase" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bloco.linhas.map((l, i) => (
                  <tr key={i} style={{ borderTop: "1px solid #F3F4F6" }}>
                    <td style={{ padding: "3px 7px" }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</div>
                      <div style={{ fontSize: 10, color: "#6B7280" }}>Chapa: {l.colaborador?.chapa}</div>
                    </td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{l.evento?.descricao}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{l.data}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#374151" }}>{l.hora || "—"}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, fontWeight: 700, color: "#059669" }}>R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</td>
                    <td style={{ padding: "3px 7px", fontSize: 11, color: "#6B7280", fontStyle: "italic" }}>{l.observacao || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        );
      })}

      <Modal open={!!modalAcao} onClose={() => setModalAcao(null)} title={
        modalAcao?.acao === "aprovar" ? "Aprovar Bloco" :
        modalAcao?.acao === "devolver" ? "Devolver Bloco" : "Rejeitar Bloco"
      }>
        {modalAcao && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <p style={{ margin: 0, fontSize: 11, color: "#374151" }}>
              {modalAcao.acao === "aprovar"
                ? ("Confirma a aprovação do bloco " + modalAcao.bloco.descricao + " com " + modalAcao.bloco.linhas.length + " lançamento(s)?")
                : "Informe o motivo:"}
            </p>
            {modalAcao.acao !== "aprovar" && (
              <Input label="Justificativa *" value={justificativa} onChange={setJustificativa} placeholder="Descreva o motivo..." required />
            )}
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <Button variant="secondary" onClick={() => setModalAcao(null)}>Cancelar</Button>
              <Button
                variant={modalAcao.acao === "aprovar" ? "success" : modalAcao.acao === "devolver" ? "warning" : "danger"}
                onClick={() => executarAcao(modalAcao.acao)}
                disabled={modalAcao.acao !== "aprovar" && !justificativa}
              >
                {modalAcao.acao === "aprovar" ? "Confirmar Aprovação" : modalAcao.acao === "devolver" ? "Devolver" : "Rejeitar"}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}




// ─── ADVERTÊNCIAS / SUSPENSÕES ────────────────────────────────────────────────
// ─── AUTORIZAÇÃO DE DESCONTO ──────────────────────────────────────────────────
const MESES_AUTORIZACAO = [
  { value: "01", label: "Janeiro" }, { value: "02", label: "Fevereiro" },
  { value: "03", label: "Março" },   { value: "04", label: "Abril" },
  { value: "05", label: "Maio" },    { value: "06", label: "Junho" },
  { value: "07", label: "Julho" },   { value: "08", label: "Agosto" },
  { value: "09", label: "Setembro" },{ value: "10", label: "Outubro" },
  { value: "11", label: "Novembro" },{ value: "12", label: "Dezembro" },
];

function valorPorExtenso(valor) {
  if (!valor || isNaN(valor)) return "";
  const n = parseFloat(valor);
  const inteiro = Math.floor(n);
  const centavos = Math.round((n - inteiro) * 100);
  const unidades = ["","um","dois","três","quatro","cinco","seis","sete","oito","nove","dez",
    "onze","doze","treze","quatorze","quinze","dezesseis","dezessete","dezoito","dezenove"];
  const dezenas = ["","","vinte","trinta","quarenta","cinquenta","sessenta","setenta","oitenta","noventa"];
  const centenas = ["","cem","duzentos","trezentos","quatrocentos","quinhentos","seiscentos","setecentos","oitocentos","novecentos"];
  function conv(n) {
    if (n === 0) return "";
    if (n === 100) return "cem";
    if (n < 20) return unidades[n];
    if (n < 100) return dezenas[Math.floor(n/10)] + (n%10 ? " e " + unidades[n%10] : "");
    return centenas[Math.floor(n/100)] + (n%100 ? " e " + conv(n%100) : "");
  }
  function convMilhar(n) {
    if (n === 0) return "zero";
    if (n < 1000) return conv(n);
    const mil = Math.floor(n/1000);
    const resto = n % 1000;
    return (mil === 1 ? "mil" : conv(mil) + " mil") + (resto ? " e " + conv(resto) : "");
  }
  let txt = convMilhar(inteiro) + (inteiro === 1 ? " real" : " reais");
  if (centavos > 0) txt += " e " + conv(centavos) + (centavos === 1 ? " centavo" : " centavos");
  return txt;
}

function gerarHTMLAutorizacao(dados, colaborador, logoBase64) {
  const {
    valor_total, num_parcelas, mes_inicio, ano_inicio,
    data_ocorrido, descricao_prejuizo, gestor_nome
  } = dados;

  const valorNum  = parseFloat(valor_total) || 0;
  const parcelas  = parseInt(num_parcelas) || 1;
  const valorParc = (valorNum / parcelas).toFixed(2).replace(".", ",");
  const mesLabel  = MESES_AUTORIZACAO.find(m => m.value === mes_inicio)?.label || mes_inicio;
  const valorExt  = valorPorExtenso(valorNum);
  const cpfFmt    = colaborador?.cpf || "_______________";
  const nome      = colaborador?.nome || "_______________";
  const valorFmt  = valorNum.toFixed(2).replace(".", ",");

  const hoje = new Date();
  const mesesNome = ["janeiro","fevereiro","março","abril","maio","junho","julho","agosto","setembro","outubro","novembro","dezembro"];
  const dataDoc   = `${hoje.getDate()} de ${mesesNome[hoje.getMonth()]} de ${hoje.getFullYear()}`;
  const dataOcorr = (() => {
    if (!data_ocorrido) return "___/___/______";
    try {
      const d = new Date(String(data_ocorrido).includes("T") ? data_ocorrido : data_ocorrido + "T12:00:00");
      return isNaN(d.getTime()) ? "___/___/______" : d.toLocaleDateString("pt-BR");
    } catch { return "___/___/______"; }
  })();

  return `
    <div style="font-family:Arial,sans-serif;font-size:10.5pt;line-height:1.45;max-width:680px;margin:0 auto;padding:24px 32px;color:#000;text-align:justify;">
      ${logoBase64 ? `<div style="text-align:center;margin-bottom:10px;"><img src="${logoBase64}" alt="Benel" style="height:52px;" /></div>` : ""}
      <h3 style="text-align:center;font-size:12pt;font-weight:bold;text-transform:uppercase;text-decoration:underline;margin:0 0 14px 0;letter-spacing:.5px;">
        Autorização para Desconto na Folha de Pagamento
      </h3>
      <p style="margin:0 0 12px 0;">
        Pelo presente, eu <u>${nome}</u>, CPF nº <u>${cpfFmt}</u>,
        AUTORIZO a <strong>BENEL–TRANPORTE E LOGÍSTICA LTDA</strong>, a proceder desconto no meu salário,
        a título de reparação da importância de <strong>R$&nbsp;${valorFmt}</strong>
        (<em>${valorExt}</em>), decorrentes de prejuízos causados à Empregadora,
        conforme exposto abaixo, sendo parcelados em <strong>${parcelas}</strong>
        parcela${parcelas > 1 ? "s" : ""} de <strong>R$&nbsp;${valorParc}</strong>,
        a começar na próxima folha de pagamento em <strong>${mesLabel}&nbsp;/&nbsp;${ano_inicio}</strong>.
      </p>
      <p style="font-weight:bold;margin:0 0 2px 0;">DESCRIÇÃO DO PREJUÍZO:</p>
      <p style="margin:0 0 10px 0;min-height:28px;">${descricao_prejuizo || "&nbsp;"}</p>
      <p style="margin:0 0 12px 0;">DATA DO OCORRIDO:&nbsp;<u>${dataOcorr}</u></p>
      <p style="margin:0 0 8px 0;">Declaro estar ciente do referido desconto, conforme parágrafo primeiro do artigo 462, da CLT e cláusula quinta do meu contrato de trabalho, transcritos abaixo:</p>
      <div style="border:1px solid #aaa;margin:0 0 8px 0;padding:7px 12px;font-size:9.5pt;">
        <p style="margin:0 0 4px 0;">Art. 462 – Ao empregador é vedado efetuar qualquer desconto nos salários do empregado, salvo quando este resultar de adiantamentos, de dispositivos de lei ou de contrato coletivo.</p>
        <p style="margin:0;"><strong>§ 1º</strong> – Em caso de dano causado pelo empregado, o desconto será lícito, <u>desde de que esta possibilidade tenha sido acordada ou na ocorrência de dolo do empregado.</u></p>
      </div>
      <div style="border:1px solid #aaa;margin:0 0 10px 0;padding:7px 12px;font-size:9.5pt;">
        <p style="margin:0;"><strong>5.</strong> Além dos descontos permitidos na legislação, a EMPREGADORA poderá descontar da remuneração do EMPREGADO(A) <strong>toda e qualquer importância</strong> que este seja devedor por prejuízo que vier a dar causa, contra a EMPREGADORA ou terceiros, por culpa ou dolo, e, ainda, por outras obrigações que porventura incidam em sua remuneração.</p>
      </div>
      <p style="margin:0 0 6px 0;">Declaro estar ciente de que o presente instrumento serve para fins de advertência disciplinar em virtude dos fatos acima discriminados, os quais decorrem do descumprimento às normas internas da empresa.</p>
      <p style="margin:0 0 6px 0;">Declaro, também, estar ciente que em caso de rescisão do contrato de trabalho, será descontado o valor remanescente do prejuízo, até o limite legal.</p>
      <p style="margin:0 0 18px 0;">Posto isso, assino de livre e espontânea vontade a presente autorização, para que produza os efeitos jurídicos necessários.</p>
      <p style="margin:0 0 36px 0;">___________________, ${dataDoc}.</p>
      <div style="display:flex;justify-content:space-around;margin-top:24px;">
        <div style="text-align:center;width:44%;">
          <div style="border-top:1px solid #000;padding-top:6px;font-size:10pt;">${nome}</div>
          <div style="font-size:9pt;color:#444;margin-top:2px;">Colaborador(a)</div>
        </div>
        <div style="text-align:center;width:44%;">
          <div style="border-top:1px solid #000;padding-top:6px;font-size:10pt;">${gestor_nome || "Gestor"}</div>
          <div style="font-size:9pt;color:#444;margin-top:2px;">Gestor(a)</div>
        </div>
      </div>
    </div>
  `;
}

function Autorizacoes({ user, colaboradores }) {
  const anoAtual = new Date().getFullYear();
  const FORM_VAZIO = {
    colaborador_id: "", valor_total: "", num_parcelas: "1",
    mes_inicio: String(new Date().getMonth() + 1).padStart(2, "0"),
    ano_inicio: String(anoAtual),
    data_ocorrido: "", descricao_prejuizo: "", observacoes: "",
  };

  const [lista, setLista]             = useState([]);
  const [carregando, setCarregando]   = useState(true);
  const [modalNovo, setModalNovo]     = useState(false);
  const [form, setForm]               = useState(FORM_VAZIO);
  const [colaboradorSel, setColabSel] = useState(null);
  const [buscaColab, setBuscaColab]   = useState("");
  const [sugestoes, setSugestoes]     = useState([]);
  const [erro, setErro]               = useState("");
  const [modalDoc, setModalDoc]       = useState(null);

  useEffect(() => {
    api.listarAutorizacoes()
      .then(data => { if (Array.isArray(data)) setLista(data); })
      .catch(() => {})
      .finally(() => setCarregando(false));
  }, []);

  const normalizar = (s) => (s||"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().trim();
  const buscaTimer = useRef(null);

  const onBusca = (v) => {
    setBuscaColab(v);
    setForm(f => ({ ...f, colaborador_id: "" }));
    setColabSel(null);
    if (v.length < 2) { setSugestoes([]); return; }
    const termo = normalizar(v);
    const local = colaboradores
      .filter(c => c.cod_situacao !== "D")
      .filter(c => normalizar(c.nome).includes(termo) || (c.chapa||"").includes(v.trim()))
      .slice(0, 15);
    setSugestoes(local);
  };

  const selecionarColab = (c) => {
    setColabSel(c);
    setBuscaColab(c.nome);
    setForm(f => ({ ...f, colaborador_id: c.id }));
    setSugestoes([]);
  };

  const valorParc = () => {
    const v = parseFloat(form.valor_total) || 0;
    const p = parseInt(form.num_parcelas) || 1;
    return p > 0 ? (v / p).toFixed(2) : "0.00";
  };

  const salvar = async () => {
    if (!form.colaborador_id)   return setErro("Selecione um colaborador.");
    if (!form.valor_total || parseFloat(form.valor_total) <= 0) return setErro("Informe o valor total.");
    if (!form.num_parcelas || parseInt(form.num_parcelas) < 1)  return setErro("Informe o número de parcelas.");
    if (!form.data_ocorrido)    return setErro("Informe a data do ocorrido.");
    if (!form.descricao_prejuizo.trim()) return setErro("Informe a descrição do prejuízo.");
    setErro("");
    try {
      const payload = {
        ...form,
        colaborador_nome: colaboradorSel?.nome,
        colaborador_cpf:  colaboradorSel?.cpf,
      };
      const nova = await api.criarAutorizacao(payload);
      setLista(l => [{ ...nova, colaborador: colaboradorSel, gestor_nome: user.nome }, ...l]);
      setModalNovo(false);
      setForm(FORM_VAZIO);
      setColabSel(null);
      setBuscaColab("");
    } catch(e) { setErro(e.message || "Erro ao salvar"); }
  };

  const anexar = async (id, file) => {
    if (file.size > 5*1024*1024) { alert("Arquivo muito grande (máx 5MB)"); return; }
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        await api.addAnexoAutorizacao(id, { nome_arquivo: file.name, dados_base64: ev.target.result });
        setLista(l => l.map(s => s.id === id ? { ...s, anexo_nome: file.name, anexo_dados: ev.target.result, status: "anexado" } : s));
      } catch(e) { alert("Erro ao anexar: " + e.message); }
    };
    reader.readAsDataURL(file);
  };

  const cancelar = async (id) => {
    if (!window.confirm("Cancelar esta autorização?")) return;
    try {
      await api.cancelarAutorizacao(id);
      setLista(l => l.map(s => s.id === id ? { ...s, status: "cancelado" } : s));
    } catch(e) { alert("Erro: " + e.message); }
  };

  const [modalAnexo, setModalAnexo] = useState(null); // { nome, dados }

  const verAnexo = (s) => {
    const dados = s.anexo_dados || s.anexo_base64;
    if (!dados) { alert("Anexo não disponível. Tente recarregar a página."); return; }
    setModalAnexo({ nome: s.anexo_nome || "anexo", dados });
  };

  const STATUS_CORES = {
    pendente:  { bg: "#FEF3C7", color: "#92400E", label: "Pendente" },
    anexado:   { bg: "#D1FAE5", color: "#065F46", label: "Anexado"  },
    cancelado: { bg: "#F3F4F6", color: "#6B7280", label: "Cancelado"},
  };

  const [fAColab,  setFAColab]  = useState("");
  const [fAStatus, setFAStatus] = useState("");
  const [fAGestor, setFAGestor] = useState("");
  const normA = s => (s||"").toLowerCase();
  const listaFiltradaA = lista
    .filter(s => s.status !== "cancelado")
    .filter(s => !fAColab  || normA(s.colaborador?.nome || s.colaborador_nome).includes(normA(fAColab)) || (s.colaborador?.chapa||"").includes(fAColab))
    .filter(s => !fAStatus || s.status === fAStatus)
    .filter(s => !fAGestor || normA(s.gestor_nome).includes(normA(fAGestor)));

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: "#6B7280" }}>{lista.filter(s=>s.status!=="cancelado").length} autorização(ões)</div>
        {["gestor","dp","admin"].includes(user.perfil) && (
          <button onClick={() => { setModalNovo(true); setErro(""); setForm(FORM_VAZIO); setColabSel(null); setBuscaColab(""); }}
            style={{ padding: "10px 20px", background: "#0F2447", color: "#fff", border: "none", borderRadius: 8, fontWeight: 600, fontSize: 14, cursor: "pointer" }}>
            + Nova Autorização
          </button>
        )}
      </div>

      <div style={{ background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Colaborador", "Valor / Parcelas", "Início", "Solicitante", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding:"5px 8px" }}><input value={fAColab} onChange={e=>setFAColab(e.target.value)} placeholder="🔍 Colaborador/Chapa" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }}><input value={fAGestor} onChange={e=>setFAGestor(e.target.value)} placeholder="🔍 Solicitante" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}>
                <select value={fAStatus} onChange={e=>setFAStatus(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}>
                  <option value="">Todos</option>
                  <option value="pendente">Pendente</option>
                  <option value="anexado">Anexado</option>
                </select>
              </th>
              <th style={{ padding:"5px 8px" }}><button onClick={()=>{setFAColab("");setFAStatus("");setFAGestor("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {carregando ? (
              <tr><td colSpan={6} style={{ padding:32, textAlign:"center", color:"#9CA3AF" }}>Carregando...</td></tr>
            ) : listaFiltradaA.length === 0 ? (
              <tr><td colSpan={6} style={{ padding:40, textAlign:"center", color:"#9CA3AF" }}>
                <div style={{ fontSize:32, marginBottom:8 }}>📋</div>Nenhuma autorização encontrada
              </td></tr>
            ) : listaFiltradaA.map((s, i) => {
              const st = STATUS_CORES[s.status] || STATUS_CORES.pendente;
              const nomeColab = s.colaborador?.nome || s.colaborador_nome || "—";
              const docData = { ...s, gestor_nome: s.gestor_nome };
              const colabData = s.colaborador || { nome: s.colaborador_nome, cpf: s.colaborador_cpf };
              return (
                <tr key={s.id} style={{ borderTop:"1px solid #F3F4F6", background: i%2===0?"#fff":"#FAFAFA" }}>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ fontWeight:600, fontSize:13, color:"#111827" }}>{nomeColab}</div>
                    <div style={{ fontSize:11, color:"#6B7280" }}>Data: {new Date(s.criado_em).toLocaleDateString("pt-BR")}</div>
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>
                    R$ {parseFloat(s.valor_total).toFixed(2).replace(".",",")} · {s.num_parcelas}x de R$ {(parseFloat(s.valor_total)/parseInt(s.num_parcelas)).toFixed(2).replace(".",",")}
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>
                    {MESES_AUTORIZACAO.find(m=>m.value===s.mes_inicio)?.label}/{s.ano_inicio}
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{s.gestor_nome}</td>
                  <td style={{ padding:"10px 14px" }}>
                    <span style={{ padding:"3px 10px", borderRadius:20, fontSize:11, fontWeight:600, background:st.bg, color:st.color }}>{st.label}</span>
                  </td>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ display:"flex", gap:6 }}>
                      <button onClick={() => setModalDoc({ ...docData, colaborador: colabData })} style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #D1D5DB", background:"#fff", fontSize:12, cursor:"pointer", fontWeight:600 }}>📄 Doc</button>
                      <label style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46", fontSize:12, cursor:"pointer", fontWeight:600 }}>
                        📎 {s.anexo_nome ? "Substituir" : "Anexar"}
                        <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                          onChange={e => { const f = e.target.files[0]; if (f) anexar(s.id, f); }} />
                      </label>
                      {s.anexo_nome && (
                        <button onClick={() => verAnexo(s)}
                          style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #3B82F6", background:"#EFF6FF", color:"#1D4ED8", fontSize:12, cursor:"pointer", fontWeight:600 }}>
                          👁️ Ver
                        </button>
                      )}
                      {["dp","admin"].includes(user.perfil) && (
                        <button onClick={() => cancelar(s.id)} style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #EF4444", background:"#FEF2F2", color:"#DC2626", fontSize:12, cursor:"pointer", fontWeight:600 }}>🚫</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modal Nova Autorização */}
      <Modal open={modalNovo} onClose={() => setModalNovo(false)} title="Nova Autorização de Desconto" width={620}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Colaborador */}
          <div style={{ position: "relative" }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Colaborador *</label>
            <input value={buscaColab} onChange={e => onBusca(e.target.value)} placeholder="Buscar por nome ou matrícula..."
              style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }} />
            {sugestoes.length > 0 && (
              <div style={{ position: "absolute", top: "100%", left: 0, right: 0, background: "#fff", border: "1px solid #E5E7EB", borderRadius: 8, boxShadow: "0 4px 12px rgba(0,0,0,0.1)", zIndex: 100, maxHeight: 200, overflowY: "auto" }}>
                {sugestoes.map(c => (
                  <div key={c.id} onMouseDown={() => selecionarColab(c)}
                    style={{ padding: "3px 6px", cursor: "pointer", fontSize: 13, borderBottom: "1px solid #F3F4F6" }}
                    onMouseEnter={e => e.currentTarget.style.background="#F9FAFB"}
                    onMouseLeave={e => e.currentTarget.style.background="#fff"}>
                    <b>{c.chapa}</b> — {c.nome} · {c.desc_funcao || c.funcao}
                  </div>
                ))}
              </div>
            )}
            {colaboradorSel && (
              <div style={{ marginTop: 6, padding: "3px 6px", background: "#F0FDF4", borderRadius: 8, fontSize: 12, color: "#166534", border: "1px solid #BBF7D0" }}>
                ✅ <b>{colaboradorSel.nome}</b> · {colaboradorSel.descricao_filial || colaboradorSel.desc_cc || "—"} · Matrícula: {colaboradorSel.chapa} · Função: {colaboradorSel.desc_funcao || colaboradorSel.funcao || "—"} · CC: {colaboradorSel.centro_custo} — {colaboradorSel.desc_cc} · CPF: {colaboradorSel.cpf || "—"}
              </div>
            )}
          </div>

          {/* Valor e Parcelas */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Valor Total (R$) *</label>
              <input type="number" step="0.01" min="0" value={form.valor_total}
                onChange={e => setForm(f => ({ ...f, valor_total: e.target.value }))}
                placeholder="0.00"
                style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }} />
            </div>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Nº de Parcelas *</label>
              <input type="number" min="1" max="24" value={form.num_parcelas}
                onChange={e => setForm(f => ({ ...f, num_parcelas: e.target.value }))}
                style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }} />
            </div>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Valor da Parcela</label>
              <input readOnly value={"R$ " + valorParc().replace(".",",")}
                style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, background: "#F9FAFB", color: "#6B7280", boxSizing: "border-box" }} />
            </div>
          </div>

          {/* Início do desconto */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Mês de Início do Desconto *</label>
              <select value={form.mes_inicio} onChange={e => setForm(f => ({ ...f, mes_inicio: e.target.value }))}
                style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }}>
                {MESES_AUTORIZACAO.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Ano de Início do Desconto *</label>
              <select value={form.ano_inicio} onChange={e => setForm(f => ({ ...f, ano_inicio: e.target.value }))}
                style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }}>
                {[0,1,2].map(i => <option key={i} value={anoAtual+i}>{anoAtual+i}</option>)}
              </select>
            </div>
          </div>

          {/* Data do ocorrido */}
          <div>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Data do Ocorrido *</label>
            <input type="date" value={form.data_ocorrido} onChange={e => setForm(f => ({ ...f, data_ocorrido: e.target.value }))}
              style={{ padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13 }} />
          </div>

          {/* Descrição do prejuízo */}
          <div>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Descrição do Prejuízo *</label>
            <textarea value={form.descricao_prejuizo} onChange={e => setForm(f => ({ ...f, descricao_prejuizo: e.target.value }))}
              rows={3} placeholder="Descreva o motivo do desconto..."
              style={{ width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, resize: "vertical", boxSizing: "border-box", fontFamily: "inherit" }} />
          </div>

          {erro && <div style={{ padding: "3px 6px", background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, fontSize: 11, color: "#DC2626" }}>⚠️ {erro}</div>}

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 8, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalNovo(false)}>Cancelar</Button>
            <Button onClick={salvar}>Gerar Autorização</Button>
          </div>
        </div>
      </Modal>

      {/* Modal Visualizar Anexo */}
      {modalAnexo && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,.7)", zIndex:2000, display:"flex", alignItems:"center", justifyContent:"center" }}>
          <div style={{ background:"#fff", borderRadius:14, width:"90vw", maxWidth:900, height:"90vh", display:"flex", flexDirection:"column", boxShadow:"0 20px 60px rgba(0,0,0,.4)" }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 20px", borderBottom:"1px solid #E5E7EB" }}>
              <span style={{ fontWeight:700, fontSize:14, color:"#0F2447" }}>📎 {modalAnexo.nome}</span>
              <div style={{ display:"flex", gap:8 }}>
                <button onClick={() => {
                  const win = window.open("","_blank");
                  win.document.write(`<!DOCTYPE html><html><head><title>${modalAnexo.nome}</title><style>body{margin:0;display:flex;justify-content:center;align-items:flex-start;min-height:100vh;background:#f3f4f6;}iframe{border:none;}img{max-width:100%;}</style></head><body>`);
                  if (modalAnexo.dados.startsWith("data:application/pdf") || modalAnexo.nome.toLowerCase().endsWith(".pdf")) {
                    win.document.write(`<iframe src="${modalAnexo.dados}" width="100%" height="100%" style="position:fixed;inset:0;border:none;"></iframe>`);
                  } else {
                    win.document.write(`<img src="${modalAnexo.dados}" />`);
                  }
                  win.document.write(`</body></html>`);
                  win.document.close();
                  win.print();
                }} style={{ padding:"6px 14px", borderRadius:8, border:"1px solid #3B82F6", background:"#EFF6FF", color:"#1D4ED8", fontSize:12, fontWeight:700, cursor:"pointer" }}>
                  🖨️ Imprimir / Salvar
                </button>
                <button onClick={() => setModalAnexo(null)} style={{ padding:"6px 14px", borderRadius:8, border:"1px solid #D1D5DB", background:"#F3F4F6", color:"#374151", fontSize:12, fontWeight:700, cursor:"pointer" }}>
                  ✕ Fechar
                </button>
              </div>
            </div>
            <div style={{ flex:1, overflow:"hidden", padding:8 }}>
              {(modalAnexo.dados.startsWith("data:application/pdf") || modalAnexo.nome.toLowerCase().endsWith(".pdf")) ? (
                <iframe src={modalAnexo.dados} style={{ width:"100%", height:"100%", border:"none", borderRadius:8 }} />
              ) : (
                <div style={{ width:"100%", height:"100%", overflow:"auto", display:"flex", alignItems:"center", justifyContent:"center" }}>
                  <img src={modalAnexo.dados} alt={modalAnexo.nome} style={{ maxWidth:"100%", maxHeight:"100%", objectFit:"contain", borderRadius:8 }} />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Modal Visualizar Documento */}
      {modalDoc && (
        <Modal open={!!modalDoc} onClose={() => setModalDoc(null)} title="Autorização de Desconto" width={760}>
          <div style={{ maxHeight: "65vh", overflowY: "auto", border: "1px solid #E5E7EB", borderRadius: 8 }}
            dangerouslySetInnerHTML={{ __html: gerarHTMLAutorizacao(modalDoc, modalDoc.colaborador, LOGO_BENEL) }}
          />
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 16, borderTop: "1px solid #F3F4F6", marginTop: 16 }}>
            <Button variant="secondary" onClick={() => setModalDoc(null)}>Fechar</Button>
            <Button onClick={() => {
              const html = gerarHTMLAutorizacao(modalDoc, modalDoc.colaborador, LOGO_BENEL);
              const janela = window.open("", "_blank");
              janela.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8">
                <title>Autorização de Desconto</title>
                <style>body{margin:0;padding:0;}@media print{@page{margin:1.5cm;size:A4;}}</style>
              </head><body>${html}</body></html>`);
              janela.document.close();
              janela.focus();
              setTimeout(() => { janela.print(); }, 500);
            }}>⬇ Baixar PDF</Button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function Ocorrencias({ user, colaboradores }) {
  const [lista, setLista] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalForm, setModalForm] = useState(false);
  const [modalPDF, setModalPDF] = useState(null);
  const [filtros, setFiltros] = useState({ tipo: "", colaborador_id: "", data_inicio: "", data_fim: "" });
  const [form, setForm] = useState({
    tipo: "ADVERTENCIA", colaborador_id: "", chapa: "", nome_colaborador: "",
    cpf: "", secao: "", admissao: "",
    motivo: "", data_ocorrencia: "", data_inicio: "", dias_suspensao: "",
    anexo_nome: "", anexo_base64: ""
  });
  const [salvando, setSalvando] = useState(false);
  const [exportando, setExportando] = useState(false);
  const [msg, setMsg] = useState(null);
  const [modalAnexoOc, setModalAnexoOc] = useState(null);

  // Filtros inline da tabela
  const [fColab,  setFColab]  = useState("");
  const [fTipo,   setFTipo]   = useState("");
  const [fGestor, setFGestor] = useState("");
  const [fStatus, setFStatus] = useState("");
  const [fData,   setFData]   = useState("");
  const norm = s => (s||"").toLowerCase();

  const listaFiltrada = lista
    .filter(o => !fColab  || norm(o.nome_colaborador).includes(norm(fColab)) || (o.chapa||"").includes(fColab))
    .filter(o => !fTipo   || o.tipo === fTipo)
    .filter(o => !fGestor || norm(o.gestor_nome).includes(norm(fGestor)))
    .filter(o => !fStatus || o.status === fStatus)
    .filter(o => !fData || fmtDateLocal(o.data_ocorrencia) === fData);

  const carregarOcorrencias = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams(Object.fromEntries(Object.entries(filtros).filter(([,v]) => v))).toString();
      const data = await api.listarOcorrencias(qs);
      setLista(Array.isArray(data) ? data : []);
    } catch (e) {
      setMsg({ tipo: "erro", texto: "Erro ao carregar: " + e.message });
    } finally { setLoading(false); }
  };

  useEffect(() => { carregarOcorrencias(); }, []);

  const [colabSel, setColabSel] = useState(null);

  const selecionarColaborador = (colab) => {
    const admissao = colab.data_admissao || colab.admissao || "";
    setColabSel(colab);
    setForm(f => ({
      ...f,
      colaborador_id: colab.id,
      chapa: colab.chapa,
      nome_colaborador: colab.nome,
      cpf: colab.cpf || "",
      secao: colab.desc_cc || colab.secao || "",
      admissao: admissao ? admissao.split("T")[0] : "",
    }));
  };

  const calcularDataFim = () => {
    if (!form.data_inicio || !form.dias_suspensao) return "";
    const d = new Date(form.data_inicio);
    d.setDate(d.getDate() + parseInt(form.dias_suspensao) - 1);
    return d.toISOString().split("T")[0];
  };

  const salvar = async () => {
    if (!form.colaborador_id) { setMsg({ tipo: "erro", texto: "Selecione o colaborador." }); return; }
    if (!form.motivo.trim())  { setMsg({ tipo: "erro", texto: "Informe o motivo." }); return; }
    if (!form.data_ocorrencia) { setMsg({ tipo: "erro", texto: "Informe a data." }); return; }
    if (form.tipo === "SUSPENSAO" && (!form.data_inicio || !form.dias_suspensao)) {
      setMsg({ tipo: "erro", texto: "Informe data de início e quantidade de dias da suspensão." }); return;
    }
    setSalvando(true);
    try {
      await api.criarOcorrencia(form);
      setMsg({ tipo: "ok", texto: "Ocorrência registrada com sucesso!" });
      setModalForm(false);
      setForm({ tipo: "ADVERTENCIA", colaborador_id: "", chapa: "", nome_colaborador: "", motivo: "", data_ocorrencia: "", data_inicio: "", dias_suspensao: "" });
      carregarOcorrencias();
    } catch (e) {
      setMsg({ tipo: "erro", texto: e.message });
    } finally { setSalvando(false); }
  };

  const cancelarOcorrencia = async (id) => {
    if (!window.confirm("Deseja cancelar esta ocorrência?")) return;
    try {
      await api.cancelarOcorrencia(id);
      setMsg({ tipo: "ok", texto: "Ocorrência cancelada." });
      carregarOcorrencias();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
  };

  const exportarCSV = async () => {
    setExportando(true);
    try {
      const url = api.exportarOcorrenciasUrl();
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${api.getToken()}` } });
      if (!resp.ok) { const d = await resp.json(); throw new Error(d.message); }
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `anotacoes_rm_${new Date().toISOString().split("T")[0]}.txt`;
      a.click();
      URL.revokeObjectURL(a.href);
      setMsg({ tipo: "ok", texto: "Exportação concluída! Registros marcados como exportados." });
      carregarOcorrencias();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setExportando(false); }
  };

  const pendentesExportacao = lista.filter(o => o.status !== "CANCELADO").length;

  const gerarPDF = (oc) => setModalPDF(oc);

  const formatarData = (d) => {
    if (!d) return "—";
    return new Date(d).toLocaleDateString("pt-BR", { timeZone: "UTC" });
  };

  return (
    <div style={{ padding: 28 }}>
      {/* Cabeçalho */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: "4px 0 0", fontSize: 11, color: "#6B7280" }}>Registro de ocorrências disciplinares</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          {(user.perfil === "dp" || user.perfil === "admin") && (
            <Button variant="secondary" onClick={exportarCSV} disabled={exportando || pendentesExportacao === 0}>
              {exportando ? "Exportando..." : `↓ Exportar RM (${pendentesExportacao})`}
            </Button>
          )}
          <Button onClick={() => { setModalForm(true); setMsg(null); }}>+ Nova Ocorrência</Button>
        </div>
      </div>

      {/* Mensagem */}
      {msg && (
        <div style={{
          marginBottom: 16, padding: "3px 6px", borderRadius: 8, fontSize: 13,
          background: msg.tipo === "ok" ? "#D1FAE5" : "#FEE2E2",
          color: msg.tipo === "ok" ? "#065F46" : "#991B1B",
          border: `1px solid ${msg.tipo === "ok" ? "#6EE7B7" : "#FCA5A5"}`
        }}>
          {msg.tipo === "ok" ? "✅" : "❌"} {msg.texto}
        </div>
      )}

      {/* Filtros */}
      <Card style={{ marginBottom: 16, padding: "14px 18px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr auto", gap: 12, alignItems: "flex-end" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Tipo</label>
            <select value={filtros.tipo} onChange={e => setFiltros(f => ({ ...f, tipo: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "7px 10px", fontSize: 12, fontFamily: "inherit" }}>
              <option value="">Todos</option>
              <option value="ADVERTENCIA">Advertência</option>
              <option value="SUSPENSAO">Suspensão</option>
            </select>
          </div>
          <Input label="Data início" value={filtros.data_inicio} onChange={v => setFiltros(f => ({ ...f, data_inicio: v }))} type="date" />
          <Input label="Data fim" value={filtros.data_fim} onChange={v => setFiltros(f => ({ ...f, data_fim: v }))} type="date" />
          <div /> 
          <Button variant="secondary" onClick={carregarOcorrencias}>🔍 Filtrar</Button>
        </div>
      </Card>

      {/* Tabela */}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Colaborador", "Tipo", "Data", "Período/Dias", "Gestor", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding:"5px 8px" }}><input value={fColab} onChange={e=>setFColab(e.target.value)} placeholder="🔍 Colaborador/Chapa" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}><select value={fTipo} onChange={e=>setFTipo(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ADVERTENCIA">Advertência</option><option value="SUSPENSAO">Suspensão</option></select></th>
              <th style={{ padding:"5px 8px" }}>
                <input type="date" value={fData} onChange={e=>setFData(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} />
              </th>
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }}><input value={fGestor} onChange={e=>setFGestor(e.target.value)} placeholder="🔍 Gestor" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}><select value={fStatus} onChange={e=>setFStatus(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ATIVO">Ativo</option><option value="EXPORTADO">Exportado</option><option value="CANCELADO">Cancelado</option></select></th>
              <th style={{ padding:"5px 8px" }}><button onClick={()=>{setFColab("");setFTipo("");setFGestor("");setFStatus("");setFData("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Carregando...</td></tr>
            ) : listaFiltrada.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma ocorrência encontrada</td></tr>
            ) : listaFiltrada.map((oc, i) => {
              const btnBase = { padding:"5px 10px", borderRadius:6, fontSize:11, fontWeight:600, cursor:"pointer", whiteSpace:"nowrap", fontFamily:"inherit" };
              return (
              <tr key={oc.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "3px 6px" }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: "#111827" }}>{oc.nome_colaborador}</div>
                  <div style={{ fontSize: 10, color: "#6B7280" }}>Chapa: {oc.chapa}</div>
                </td>
                <td style={{ padding: "3px 6px" }}>
                  <span style={{
                    padding: "3px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                    background: oc.tipo === "ADVERTENCIA" ? "#FEF3C7" : "#FEE2E2",
                    color: oc.tipo === "ADVERTENCIA" ? "#92400E" : "#991B1B",
                    whiteSpace: "nowrap", display: "inline-block"
                  }}>
                    {oc.tipo === "ADVERTENCIA" ? "⚠️ Advertência" : "🚫 Suspensão"}
                  </span>
                </td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{formatarData(oc.data_ocorrencia)}</td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>
                  {oc.tipo === "SUSPENSAO"
                    ? <span>{formatarData(oc.data_inicio)} → {formatarData(oc.data_fim)}<br/><b>{oc.dias_suspensao} dia(s)</b></span>
                    : "—"}
                </td>
                <td style={{ padding: "3px 6px", fontSize: 11, color: "#374151" }}>{oc.gestor_nome}</td>
                <td style={{ padding: "3px 6px" }}>
                  <span style={{
                    padding: "3px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                    background: oc.status === "ATIVO" ? "#D1FAE5" : oc.status === "EXPORTADO" ? "#DBEAFE" : "#FEE2E2",
                    color: oc.status === "ATIVO" ? "#065F46" : oc.status === "EXPORTADO" ? "#1D4ED8" : "#991B1B"
                  }}>{oc.status}</span>
                </td>
                <td style={{ padding: "3px 6px" }}>
                  <div style={{ display:"flex", gap:4, alignItems:"center", flexWrap:"nowrap" }}>
                    <button onClick={() => gerarPDF(oc)} style={{ ...btnBase, border:"1px solid #D1D5DB", background:"#fff", color:"#374151" }}>📄 PDF</button>
                    <label style={{ ...btnBase, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46", display:"inline-block" }}>
                      📎 Anexar
                      <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                        onChange={async (e) => {
                          const file = e.target.files[0]; if (!file) return;
                          if (file.size > 5*1024*1024) { alert("Arquivo muito grande (max 5MB)"); return; }
                          const reader = new FileReader();
                          reader.onload = async (ev) => {
                            try {
                              await api.addAnexoOcorrencia(oc.id, { nome_arquivo: file.name, tipo_arquivo: file.type, dados_base64: ev.target.result });
                              setLista(list => list.map(o => o.id === oc.id ? { ...o, anexo_nome: file.name, anexo_dados: ev.target.result } : o));
                              alert("Anexo adicionado com sucesso!");
                            } catch(err) { alert(err.message); }
                          };
                          reader.readAsDataURL(file);
                        }} />
                    </label>
                    {oc.anexo_nome && (
                      <button onClick={() => {
                        const dados = oc.anexo_dados || oc.anexo_base64;
                        if (!dados) { alert("Recarregue a página para visualizar o anexo."); return; }
                        setModalAnexoOc({ nome: oc.anexo_nome, dados });
                      }} style={{ ...btnBase, border:"1px solid #3B82F6", background:"#EFF6FF", color:"#1D4ED8" }}>👁️ Ver</button>
                    )}
                    {oc.status === "ATIVO" && (
                      <button onClick={() => cancelarOcorrencia(oc.id)} style={{ ...btnBase, border:"1px solid #EF4444", background:"#FEF2F2", color:"#DC2626" }}>🚫</button>
                    )}
                  </div>
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </Card>

      {/* Modal Visualizar Anexo Ocorrência */}
      {modalAnexoOc && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,.7)", zIndex:2000, display:"flex", alignItems:"center", justifyContent:"center" }}>
          <div style={{ background:"#fff", borderRadius:14, width:"90vw", maxWidth:900, height:"90vh", display:"flex", flexDirection:"column", boxShadow:"0 20px 60px rgba(0,0,0,.4)" }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 20px", borderBottom:"1px solid #E5E7EB" }}>
              <span style={{ fontWeight:700, fontSize:14, color:"#0F2447" }}>📎 {modalAnexoOc.nome}</span>
              <div style={{ display:"flex", gap:8 }}>
                <button onClick={() => {
                  const win = window.open("","_blank");
                  win.document.write(`<!DOCTYPE html><html><head><title>${modalAnexoOc.nome}</title></head><body style="margin:0">`);
                  if (modalAnexoOc.dados.startsWith("data:application/pdf") || modalAnexoOc.nome.toLowerCase().endsWith(".pdf")) {
                    win.document.write(`<iframe src="${modalAnexoOc.dados}" width="100%" height="100%" style="position:fixed;inset:0;border:none;"></iframe>`);
                  } else {
                    win.document.write(`<img src="${modalAnexoOc.dados}" style="max-width:100%" />`);
                  }
                  win.document.write(`</body></html>`);
                  win.document.close();
                  setTimeout(() => win.print(), 500);
                }} style={{ padding:"6px 14px", borderRadius:8, border:"1px solid #3B82F6", background:"#EFF6FF", color:"#1D4ED8", fontSize:12, fontWeight:700, cursor:"pointer" }}>
                  🖨️ Imprimir / Salvar
                </button>
                <button onClick={() => setModalAnexoOc(null)} style={{ padding:"6px 14px", borderRadius:8, border:"1px solid #D1D5DB", background:"#F3F4F6", color:"#374151", fontSize:12, fontWeight:700, cursor:"pointer" }}>
                  ✕ Fechar
                </button>
              </div>
            </div>
            <div style={{ flex:1, overflow:"hidden", padding:8 }}>
              {(modalAnexoOc.dados.startsWith("data:application/pdf") || modalAnexoOc.nome.toLowerCase().endsWith(".pdf")) ? (
                <iframe src={modalAnexoOc.dados} style={{ width:"100%", height:"100%", border:"none", borderRadius:8 }} />
              ) : (
                <div style={{ width:"100%", height:"100%", overflow:"auto", display:"flex", alignItems:"center", justifyContent:"center" }}>
                  <img src={modalAnexoOc.dados} alt={modalAnexoOc.nome} style={{ maxWidth:"100%", maxHeight:"100%", objectFit:"contain", borderRadius:8 }} />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Modal Nova Ocorrência */}
      <Modal open={modalForm} onClose={() => setModalForm(false)} title="Registrar Ocorrência Disciplinar" width={600}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {msg && modalForm && (
            <div style={{ padding: "3px 6px", borderRadius: 8, fontSize: 12, background: "#FEE2E2", color: "#991B1B" }}>❌ {msg.texto}</div>
          )}

          {/* Tipo */}
          <div style={{ display: "flex", gap: 10 }}>
            {["ADVERTENCIA", "SUSPENSAO"].map(t => (
              <button key={t} onClick={() => setForm(f => ({ ...f, tipo: t }))} style={{
                flex: 1, padding: "12px", borderRadius: 10, cursor: "pointer", fontFamily: "inherit",
                border: form.tipo === t ? "2px solid #1B3A6B" : "2px solid #E5E7EB",
                background: form.tipo === t ? "#EFF6FF" : "#FAFAFA",
                color: form.tipo === t ? "#1B3A6B" : "#6B7280",
                fontWeight: form.tipo === t ? 700 : 400, fontSize: 13
              }}>
                {t === "ADVERTENCIA" ? "⚠️ Advertência" : "🚫 Suspensão"}
              </button>
            ))}
          </div>

          {/* Colaborador */}
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Colaborador *</label>
            <ColabSelect colaboradores={colaboradores} onSelect={selecionarColaborador} selecionado={form.nome_colaborador} />
            {colabSel && (
              <div style={{ marginTop: 4, padding: "3px 6px", background: "#F0FDF4", borderRadius: 8, fontSize: 12, color: "#166534", border: "1px solid #BBF7D0" }}>
                ✅ <b>{colabSel.nome}</b> · {colabSel.descricao_filial || colabSel.desc_cc || "—"} · Matrícula: {colabSel.chapa} · Função: {colabSel.desc_funcao || colabSel.funcao || "—"} · CC: {colabSel.centro_custo} — {colabSel.desc_cc}
              </div>
            )}
          </div>

          {/* Campos adicionais */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <Input label="CPF" value={form.cpf} onChange={v => setForm(f => ({ ...f, cpf: v }))} placeholder="000.000.000-00" />
            <Input label="Seção / Departamento" value={form.secao} onChange={v => setForm(f => ({ ...f, secao: v }))} placeholder="Ex: Logística" />
            <Input label="Data de Admissão" value={form.admissao ? form.admissao.split("T")[0] : ""} onChange={v => setForm(f => ({ ...f, admissao: v }))} type="date" />
          </div>

          {/* Motivo */}
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Motivo *</label>
            <textarea value={form.motivo} onChange={e => setForm(f => ({ ...f, motivo: e.target.value }))}
              placeholder="Descreva detalhadamente o motivo da ocorrência..." rows={4}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", resize: "vertical" }} />
          </div>

          {/* Campos por tipo */}
          {form.tipo === "ADVERTENCIA" ? (
            <Input label="Data da Advertência *" value={form.data_ocorrencia}
              onChange={v => setForm(f => ({ ...f, data_ocorrencia: v }))} type="date" required />
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
              <Input label="Data de Início *" value={form.data_inicio}
                onChange={v => setForm(f => ({ ...f, data_inicio: v, data_ocorrencia: v }))} type="date" required />
              <Input label="Quantidade de Dias *" value={form.dias_suspensao}
                onChange={v => setForm(f => ({ ...f, dias_suspensao: v }))} type="number" placeholder="Ex: 3" required />
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Data de Fim</label>
                <div style={{ padding: "3px 6px", border: "1px solid #E5E7EB", borderRadius: 8, fontSize: 13, background: "#F9FAFB", color: "#374151" }}>
                  {calcularDataFim() ? new Date(calcularDataFim()).toLocaleDateString("pt-BR", { timeZone: "UTC" }) : "—"}
                </div>
              </div>
            </div>
          )}

          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(false)}>Cancelar</Button>
            <Button onClick={salvar} disabled={salvando}>{salvando ? "Salvando..." : "Registrar Ocorrência"}</Button>
          </div>
        </div>
      </Modal>

      {/* Modal PDF */}
      {modalPDF && (
        <Modal open={!!modalPDF} onClose={() => setModalPDF(null)}
          title={`Documento — ${modalPDF.tipo === "ADVERTENCIA" ? "Advertência" : "Suspensão"}`} width={700}>
          <PDFOcorrencia oc={modalPDF} />
        </Modal>
      )}
    </div>
  );
}

// ─── SELECT DE COLABORADOR COM AUTOCOMPLETE ───────────────────────────────────
function ColabSelect({ colaboradores, onSelect, selecionado }) {
  const [busca, setBusca] = useState(selecionado || "");
  const [sugestoes, setSugestoes] = useState([]);

  const normalizar = (s) =>
    (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

  const onBusca = (v) => {
    setBusca(v);
    if (v.length >= 2) {
      const termo = normalizar(v);
      setSugestoes(
        colaboradores
          .filter(c => c.cod_situacao !== "D")
          .filter(c =>
            normalizar(c.nome).includes(termo) ||
            (c.chapa || "").includes(v.trim())
          )
          .slice(0, 10)
      );
    } else { setSugestoes([]); }
  };

  return (
    <div style={{ position: "relative" }}>
      <input value={busca} onChange={e => onBusca(e.target.value)}
        placeholder="Digite nome ou matrícula..."
        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 13, fontFamily: "inherit", boxSizing: "border-box" }} />
      {sugestoes.length > 0 && (
        <div style={{ position: "absolute", top: "100%", left: 0, right: 0, zIndex: 100, background: "#fff", border: "1px solid #D1D5DB", borderRadius: 8, boxShadow: "0 4px 16px rgba(0,0,0,0.12)", maxHeight: 200, overflowY: "auto" }}>
          {sugestoes.map(c => (
            <div key={c.id} onMouseDown={() => { onSelect(c); setBusca(c.nome); setSugestoes([]); }}
              style={{ padding: "3px 6px", fontSize: 13, cursor: "pointer", borderBottom: "1px solid #F3F4F6", display: "flex", gap: 10 }}>
              <span style={{ fontFamily: "monospace", fontSize: 11, color: "#6B7280", minWidth: 50 }}>{c.chapa}</span>
              <span style={{ fontWeight: 600, color: "#111827" }}>{c.nome}</span>
              <span style={{ fontSize: 11, color: "#9CA3AF", marginLeft: "auto" }}>{c.funcao}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── TEMPLATE PDF DE OCORRÊNCIA — fiel ao modelo Benel ───────────────────────
function PDFOcorrencia({ oc }) {
  const isAdv = oc.tipo === "ADVERTENCIA";
  const MESES_EXT = ["Janeiro","Fevereiro","Março","Abril","Maio","Junho","Julho","Agosto","Setembro","Outubro","Novembro","Dezembro"];
  const fmt = (d) => {
    if (!d) return "___ de ________ de ____";
    const dt = new Date(d);
    const dia = dt.getUTCDate();
    const mes = MESES_EXT[dt.getUTCMonth()];
    const ano = dt.getUTCFullYear();
    return `${dia} de ${mes} de ${ano}`;
  };
  const hoje = new Date().toLocaleDateString("pt-BR");

  const imprimir = () => {
    const conteudo = document.getElementById("pdf-ocorrencia-benel").innerHTML;
    const win = window.open("", "_blank");
    win.document.write(`<!DOCTYPE html>
<html><head><title>${isAdv ? "Advertência" : "Suspensão"} — ${oc.nome_colaborador}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; font-size: 13px; color: #000; padding: 40px 50px; line-height: 1.5; }
  .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
  .logo-area img { height: 52px; }
  .titulo { font-size: 20px; font-weight: 900; text-transform: uppercase; letter-spacing: 2px; }
  .ficha { border: 1.5px solid #000; padding: 10px 14px; margin-bottom: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 4px 20px; }
  .ficha span { font-size: 12px; }
  .suspensao-dias { font-size: 14px; font-weight: 700; margin-bottom: 16px; }
  .motivo-titulo { font-size: 18px; font-weight: 900; margin: 20px 0 10px; }
  .motivo-texto { text-align: justify; line-height: 1.7; margin-bottom: 20px; }
  .data-centro { text-align: center; margin: 30px 0 20px; font-size: 14px; }
  .assinaturas { margin-top: 40px; }
  .ass-empresa { text-align: center; margin-bottom: 30px; }
  .ass-linha { border-top: 1px solid #000; width: 320px; margin: 0 auto 6px; padding-top: 6px; font-weight: 700; font-size: 13px; }
  .ass-sublabel { font-size: 12px; color: #333; text-align: center; }
  .testemunhas { display: flex; justify-content: space-between; margin-top: 30px; }
  .testemunha { display: flex; align-items: flex-end; gap: 8px; font-size: 13px; }
  .testemunha-linha { border-bottom: 1px solid #000; width: 200px; height: 20px; }
  @media print { body { padding: 20px 30px; } }
</style></head>
<body>${conteudo}</body></html>`);
    win.document.close();
    setTimeout(() => win.print(), 400);
  };

  return (
    <div>
      <div id="pdf-ocorrencia-benel" style={{ fontFamily: "Arial, sans-serif", fontSize: 11, color: "#000", lineHeight: 1.5, background: "#fff" }}>

        {/* Cabeçalho: Logo + Título */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <img src={LOGO_BENEL} alt="Benel" style={{ height: 52 }} />
          <div style={{ fontSize: 20, fontWeight: 900, textTransform: "uppercase", letterSpacing: 2, textAlign: "right" }}>
            {isAdv ? "ADVERTÊNCIA DISCIPLINAR" : "SUSPENSÃO DISCIPLINAR"}
          </div>
        </div>

        {/* Ficha do colaborador */}
        <div style={{ border: "1.5px solid #000", padding: "3px 6px", marginBottom: 20, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 20px" }}>
          <div style={{ fontWeight: 700 }}>Sr. (a) {oc.nome_colaborador}</div>
          <div style={{ fontWeight: 700 }}>{oc.chapa}{oc.secao ? `    SEÇÃO : ${oc.secao}` : ""}</div>
          <div>C.P.F : {oc.cpf || "___.___.___-__"}</div>
          <div>Admissão: {oc.admissao || oc.data_admissao ? fmt(oc.admissao || oc.data_admissao) : "__/__/____"}</div>
        </div>

        {/* Linha de tipo */}
        {isAdv ? (
          <div style={{ marginBottom: 16, fontWeight: 600 }}>Advertido Escrito:</div>
        ) : (
          <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 16 }}>
            Suspensão de: {oc.dias_suspensao} DIA(S)
          </div>
        )}

        {/* Motivo */}
        <div style={{ fontSize: 18, fontWeight: 900, margin: "20px 0 10px" }}>MOTIVO:</div>
        <div style={{ textAlign: "justify", lineHeight: 1.7, marginBottom: 24 }}>{oc.motivo}</div>

        {/* Texto legal */}
        {isAdv ? (
          <div style={{ textAlign: "justify", fontSize: 12, color: "#333", marginBottom: 20 }}>
            Esta advertência é aplicada em conformidade com as normas internas da empresa e a Consolidação das Leis do Trabalho (CLT).
            Informamos que a reincidência poderá acarretar em penalidades mais severas, incluindo suspensão ou rescisão por justa causa.
          </div>
        ) : (
          <div style={{ textAlign: "justify", fontSize: 12, color: "#333", marginBottom: 20 }}>
            A presente suspensão disciplinar refere-se ao período de {fmt(oc.data_inicio)} a {fmt(oc.data_fim)}, totalizando {oc.dias_suspensao} dia(s),
            aplicada em conformidade com o Art. 474 da CLT e as normas internas da empresa.
            Durante o período de suspensão o colaborador não deverá comparecer ao trabalho, não fazendo jus à remuneração dos dias suspensos.
          </div>
        )}

        {/* Data */}
        <div style={{ textAlign: "center", margin: "28px 0 20px", fontSize: 14 }}>
          {fmt(oc.data_ocorrencia)}
        </div>

        {/* Assinatura empresa */}
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <img src={ASSINATURA_BENEL} alt="Assinatura Benel" style={{ height: 80, display: "block", margin: "0 auto 4px", objectFit: "contain" }} />
          <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 6px", paddingTop: 6, fontWeight: 700 }}>
            BENEL TRANSPORTES E LOGISTICA LTDA-ES
          </div>
        </div>

        {/* Assinatura colaborador */}
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ height: 60 }} />
          <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 6px", paddingTop: 6, fontWeight: 700 }}>
            {oc.nome_colaborador}
          </div>
          <div style={{ fontSize: 11 }}>Assinatura do Empregado</div>
        </div>

        {/* Anexo no PDF */}
        {oc.anexo_base64 && (
          <div style={{ marginTop: 20, textAlign: "center" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#374151", marginBottom: 8 }}>📎 ANEXO: {oc.anexo_nome}</div>
            <img src={oc.anexo_base64} alt="Anexo" style={{ maxWidth: "100%", maxHeight: 300, border: "1px solid #E5E7EB", borderRadius: 4 }} />
          </div>
        )}

        {/* Testemunhas */}
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 20 }}>
          <div style={{ fontSize: 13 }}>
            Testemunha 1 <span style={{ display: "inline-block", borderBottom: "1px solid #000", width: 180, marginLeft: 4 }}>&nbsp;</span>
          </div>
          <div style={{ fontSize: 13 }}>
            Testemunha 2 <span style={{ display: "inline-block", borderBottom: "1px solid #000", width: 180, marginLeft: 4 }}>&nbsp;</span>
          </div>
        </div>

        {/* Anexo no PDF */}
        {oc.anexo_base64 && (
          <div style={{ marginTop: 24, borderTop: "1px solid #E5E7EB", paddingTop: 16 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#374151", marginBottom: 8 }}>📎 ANEXO: {oc.anexo_nome}</div>
            <img src={oc.anexo_base64} alt="Anexo" style={{ maxWidth: "100%", maxHeight: 400, border: "1px solid #E5E7EB", borderRadius: 4 }} />
          </div>
        )}

      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 16, borderTop: "1px solid #F3F4F6", marginTop: 20 }}>
        <Button variant="primary" onClick={imprimir}>🖨 Imprimir / Salvar PDF</Button>
      </div>
    </div>
  );
}

// ─── DESLIGAMENTOS ────────────────────────────────────────────────────────────
const TIPOS_DESL = [
  { value: "aviso_trabalhado",    label: "Aviso Prévio Trabalhado" },
  { value: "aviso_indenizado",    label: "Aviso Prévio Indenizado" },
  { value: "pedido_demissao",     label: "Pedido de Demissão" },
  { value: "termino_contrato",    label: "Término de Contrato" },
  { value: "antecipacao_contrato",label: "Antecipação de Término de Contrato" },
];

const STATUS_DESL = {
  rascunho:           { label: "Rascunho",           color: "#6B7280" },
  pendente_superior:  { label: "Pend. Superior",     color: "#F59E0B" },
  pendente_dp:        { label: "Pend. DP",           color: "#3B82F6" },
  aprovado:           { label: "Aprovado",           color: "#10B981" },
  reprovado:          { label: "Reprovado",          color: "#EF4444" },
  ajuste_solicitado:  { label: "Ajuste Solicitado",  color: "#8B5CF6" },
  finalizado:         { label: "Finalizado",         color: "#0F2447" },
  cancelado:          { label: "Cancelado",          color: "#9CA3AF" },
};

const ALCADA_DESL = {
  pendente_superior:  ["superior", "dp", "admin"],
  // 2ª alçada — descomente quando quiser ativar:
  // pendente_dp:     ["dp", "admin"],
  aprovado:           ["dp", "admin"],
  ajuste_solicitado:  ["gestor", "dp", "admin"],
};

function Desligamentos({ user, colaboradores, api, recarregarDados }) {
  const [lista,          setLista]          = useState([]);
  const [modalNovo,      setModalNovo]      = useState(false);
  const [modalDetalhe,   setModalDetalhe]   = useState(null);
  const [modalAcao,      setModalAcao]      = useState(null);
  const [carregando,     setCarregando]     = useState(true);
  const [salvando,       setSalvando]       = useState(false);
  const [erro,           setErro]           = useState("");
  const [modalPDF,       setModalPDF]       = useState(null);
  const [modalAnexoPedido, setModalAnexoPedido] = useState(null);

  const FORM_VAZIO = {
    colaborador_id: "", tipo: "", data_desligamento: "",
    data_aviso: "", reducao_jornada: false,
    justificativa: "", observacoes: "",
    pedido_anexo_nome: "", pedido_anexo_base64: "",
  };
  const [form, setForm] = useState(FORM_VAZIO);
  const [colaboradorSel, setColaboradorSel] = useState(null);
  const [buscaColab, setBuscaColab] = useState("");
  const [sugestoesColab, setSugestoesColab] = useState([]);

  const carregar = async () => {
    setCarregando(true);
    try {
      const r = await api.listarDesligamentos("");
      setLista(Array.isArray(r) ? r : (r.data || []));
    } catch (e) { setErro(e.message); }
    finally { setCarregando(false); }
  };

  useEffect(() => { carregar(); }, []);

  const normalizar = (s) =>
    (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

  const buscaTimer = useRef(null);

  const onBuscaColab = (v) => {
    setBuscaColab(v);
    setForm(f => ({ ...f, colaborador_id: "" }));
    setColaboradorSel(null);
    setBloqueioColab(null);

    if (v.length < 2) { setSugestoesColab([]); return; }

    const termo = normalizar(v);

    // Resultado local imediato como preview
    const local = colaboradores
      .filter(c => c.cod_situacao !== "D")
      .filter(c =>
        normalizar(c.nome).includes(termo) ||
        (c.chapa || "").includes(v.trim())
      )
      .slice(0, 15);
    setSugestoesColab(local);

    // Busca na API com debounce (sempre — não depende do resultado local)
    clearTimeout(buscaTimer.current);
    buscaTimer.current = setTimeout(async () => {
      try {
        const resultado = await api.buscarColaboradores(v.trim());
        const filtrado = (Array.isArray(resultado) ? resultado : [])
          .filter(c => c.cod_situacao !== "D")
          .slice(0, 15);
        if (filtrado.length > 0) setSugestoesColab(filtrado);
      } catch (_) { /* mantém o resultado local */ }
    }, 300);
  };

  const [validandoColab, setValidandoColab] = useState(false);
  const [bloqueioColab,  setBloqueioColab]  = useState(null); // { motivo, mensagem }

  const selecionarColab = async (c) => {
    setColaboradorSel(c);
    setBuscaColab(c.nome);
    setForm(f => ({ ...f, colaborador_id: c.id }));
    setSugestoesColab([]);
    setBloqueioColab(null);

    // Validação extra no frontend antes de chamar API (rápida, sem rede)
    if (c.cod_situacao === "D") {
      setBloqueioColab({
        motivo: "situacao",
        mensagem: "Colaborador não pode ser selecionado para desligamento, pois já consta com situação Demitido.",
      });
      return;
    }

    // Validação via backend (estabilidade e outros bloqueios persistidos)
    setValidandoColab(true);
    try {
      const v = await api.validarColaboradorDesligamento(c.id);
      if (!v.apto) {
        setBloqueioColab({ motivo: v.motivo, mensagem: v.mensagem });
      }
    } catch (_) {
      // Se API falhar, aplica validação local de estabilidade como fallback
      if (c.data_fim_estabilidade) {
        const fimEstab = new Date(c.data_fim_estabilidade.split("T")[0]);
        const hoje = new Date(); hoje.setHours(0,0,0,0);
        if (fimEstab >= hoje) {
          const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
          setBloqueioColab({
            motivo: "estabilidade",
            mensagem: `Este colaborador não pode ser desligado, pois possui estabilidade ativa: ${c.descricao_estabilidade || "Estabilidade"}. A estabilidade encerra em ${fmtBR(fimEstab)}.`,
          });
        }
      }
    } finally {
      setValidandoColab(false);
    }
  };

  const validarForm = () => {
    if (!form.colaborador_id)    return "Selecione um colaborador.";

    // Bloquear se houver bloqueio identificado ao selecionar o colaborador
    if (bloqueioColab) return bloqueioColab.mensagem;

    // Bloquear desligamento de colaborador com estabilidade ativa (fallback local)
    if (colaboradorSel?.data_fim_estabilidade) {
      const fimEstab = new Date(colaboradorSel.data_fim_estabilidade.split("T")[0]);
      const hoje = new Date(); hoje.setHours(0,0,0,0);
      if (fimEstab >= hoje) {
        const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
        return (
          "Solicitação não permitida.\n" +
          "Este colaborador possui estabilidade ativa e não pode ser desligado.\n\n" +
          "Detalhes da estabilidade:\n" +
          "• Motivo: " + (colaboradorSel.descricao_estabilidade || "—") + "\n" +
          "• Válida até: " + fmtBR(fimEstab)
        );
      }
    }
    if (!form.tipo)              return "Selecione o tipo de desligamento.";
    if (!form.data_desligamento) return "Informe a data de desligamento.";
    if (form.tipo === "antecipacao_contrato" && !form.justificativa)
      return "Justificativa obrigatória para antecipação de contrato.";

    if (["aviso_trabalhado","aviso_indenizado"].includes(form.tipo)) {
      if (colaboradorSel?.data_admissao) {
        const admissao = new Date(colaboradorSel.data_admissao.split("T")[0]);
        const d90  = new Date(admissao); d90.setDate(d90.getDate() + 89);
        const d45  = new Date(admissao); d45.setDate(d45.getDate() + 44);
        const hoje = new Date(); hoje.setHours(0,0,0,0);
        const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
        if (hoje <= d90) {
          return (
            "Solicitação não permitida para este colaborador.\n" +
            "Colaboradores em contrato de experiência (até 90 dias) não podem receber Aviso Prévio.\n\n" +
            "Detalhes do contrato:\n" +
            "• Início: " + fmtBR(admissao) + "\n" +
            "• Fim 1º período (admissão + 44 dias): " + fmtBR(d45) + "\n" +
            "• Fim 2º período (admissão + 89 dias): " + fmtBR(d90) + "\n\n" +
            "Use \"Término de Contrato\" ou \"Antecipação de Término\"."
          );
        }
      }
    }

    if (form.tipo === "termino_contrato" && colaboradorSel?.data_admissao) {
      const admissao = new Date(colaboradorSel.data_admissao.split("T")[0]);
      const d90  = new Date(admissao); d90.setDate(d90.getDate() + 89);
      const d45  = new Date(admissao); d45.setDate(d45.getDate() + 44);
      const hoje = new Date(); hoje.setHours(0,0,0,0);
      const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
      if (hoje > d90) {
        return (
          "Solicitação não permitida.\n" +
          "O colaborador já ultrapassou a data limite do contrato de experiência.\n\n" +
          "Detalhes do contrato:\n" +
          "• Início: " + fmtBR(admissao) + "\n" +
          "• Fim 1º período (admissão + 44 dias): " + fmtBR(d45) + "\n" +
          "• Fim 2º período (admissão + 89 dias): " + fmtBR(d90)
        );
      }
    }
    return null;
  };

  // Calcular data aviso (30 dias antes)
  const calcularDataAviso = (dataDesl) => {
    if (!dataDesl) return "";
    const d = new Date(dataDesl);
    d.setDate(d.getDate() - 30);
    return d.toISOString().split("T")[0];
  };

  const calcularDataTermino = (dataAdmissao) => {
    if (!dataAdmissao) return "";
    const admissao = new Date(dataAdmissao.split("T")[0]);
    const d45 = new Date(admissao); d45.setDate(d45.getDate() + 44);
    const d90 = new Date(admissao); d90.setDate(d90.getDate() + 89);
    const hoje = new Date(); hoje.setHours(0,0,0,0);
    return (hoje > d45 ? d90 : d45).toISOString().split("T")[0];
  };

  const salvar = async (enviar = false) => {
    const errVal = validarForm();
    if (errVal) { setErro(errVal); return; }
    setSalvando(true); setErro("");
    try {
      const payload = { ...form };
      if (form.tipo === "aviso_trabalhado" && !form.data_aviso)
        payload.data_aviso = calcularDataAviso(form.data_desligamento);

      const r = await api.criarDesligamento(payload);
      const id = r.id || r.data?.id;

      // Pedido de demissão: envia e aprova automaticamente (não precisa de aprovação)
      if (form.tipo === "pedido_demissao") {
        await api.enviarDesligamento(id);
        await api.aprovarDesligamento(id, "aprovar", "Aprovado automaticamente — pedido de demissão do colaborador");
      } else if (enviar) {
        await api.enviarDesligamento(id);
      }

      await carregar();
      setModalNovo(false);
      setForm(FORM_VAZIO);
      setColaboradorSel(null);
      setBuscaColab("");
    } catch (e) { setErro(e.message); }
    finally { setSalvando(false); }
  };

  const executarAcao = async () => {
    if (!modalAcao) return;
    setSalvando(true);
    try {
      await api.aprovarDesligamento(modalAcao.id, modalAcao.acao, modalAcao.observacao);
      await carregar();
      setModalAcao(null);
    } catch (e) { setErro(e.message); }
    finally { setSalvando(false); }
  };

  const abrirDetalhe = async (id) => {
    try {
      const r = await api.buscarDesligamento(id);
      setModalDetalhe(r);
    } catch (e) { setErro(e.message); }
  };

  const [fColab,   setFColab]   = useState("");
  const [fTipo,    setFTipo]    = useState("");
  const [fStatus2, setFStatus2] = useState("");
  const [fGestor2, setFGestor2] = useState("");
  const [fDataD,   setFDataD]   = useState("");
  const norm2 = s => (s||"").toLowerCase();

  const listaFiltrada = lista
    .filter(s => !fColab   || norm2(s.colaborador_nome).includes(norm2(fColab)) || (s.chapa||"").includes(fColab))
    .filter(s => !fTipo    || s.tipo === fTipo)
    .filter(s => !fStatus2 || s.status === fStatus2)
    .filter(s => !fGestor2 || norm2(s.gestor_nome).includes(norm2(fGestor2)))
    .filter(s => !fDataD || fmtDateLocal(s.data_desligamento) === fDataD);

  const podeAgir = (sol) => {
    if (!ALCADA_DESL[sol.status]?.includes(user.perfil)) return false;
    if (["dp", "admin"].includes(user.perfil)) return true;
    if (user.perfil === "superior") {
      return !sol.superior_id || sol.superior_id === user.id;
    }
    return true;
  };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
        {["gestor","dp","admin"].includes(user.perfil) && (
          <button onClick={() => { setModalNovo(true); setErro(""); setForm(FORM_VAZIO); setColaboradorSel(null); setBuscaColab(""); setBloqueioColab(null); }}
            style={{ padding: "10px 20px", background: "#0F2447", color: "#fff", border: "none", borderRadius: 8, fontWeight: 600, fontSize: 14, cursor: "pointer" }}>
            + Nova Solicitação
          </button>
        )}
      </div>

      {erro && <div style={{ background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, padding: "3px 6px", marginBottom: 16, color: "#DC2626", fontSize: 13 }}>⚠️ {erro}</div>}

      <div style={{ background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Colaborador", "Tipo", "Desligamento", "Solicitante", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding:"5px 8px" }}><input value={fColab} onChange={e=>setFColab(e.target.value)} placeholder="🔍 Colaborador/Chapa" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}>
                <select value={fTipo} onChange={e=>setFTipo(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}>
                  <option value="">Todos</option>
                  {TIPOS_DESL.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </th>
              <th style={{ padding:"5px 8px" }}>
                <input type="date" value={fDataD} onChange={e=>setFDataD(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} />
              </th>
              <th style={{ padding:"5px 8px" }}><input value={fGestor2} onChange={e=>setFGestor2(e.target.value)} placeholder="🔍 Solicitante" style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}>
                <select value={fStatus2} onChange={e=>setFStatus2(e.target.value)} style={{ width:"100%", padding:"3px 6px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}>
                  <option value="">Todos</option>
                  {Object.entries(STATUS_DESL).map(([v,d]) => <option key={v} value={v}>{d.label}</option>)}
                </select>
              </th>
              <th style={{ padding:"5px 8px" }}><button onClick={()=>{setFColab("");setFTipo("");setFStatus2("");setFGestor2("");setFDataD("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {carregando ? (
              <tr><td colSpan={6} style={{ padding:32, textAlign:"center", color:"#9CA3AF" }}>Carregando...</td></tr>
            ) : listaFiltrada.length === 0 ? (
              <tr><td colSpan={6} style={{ padding:40, textAlign:"center", color:"#9CA3AF" }}>
                <div style={{ fontSize:32, marginBottom:8 }}>🚪</div>Nenhuma solicitação encontrada
              </td></tr>
            ) : listaFiltrada.map((sol, i) => {
              const st = STATUS_DESL[sol.status] || STATUS_DESL.rascunho;
              const tipo = TIPOS_DESL.find(t => t.value === sol.tipo);
              const btnBase = { padding:"5px 10px", borderRadius:6, fontSize:11, fontWeight:600, cursor:"pointer", whiteSpace:"nowrap", fontFamily:"inherit" };
              return (
                <tr key={sol.id} style={{ borderTop:"1px solid #F3F4F6", background: i%2===0?"#fff":"#FAFAFA" }}>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ fontWeight:600, fontSize:13, color:"#111827" }}>{sol.colaborador_nome}</div>
                    <div style={{ fontSize:11, color:"#6B7280" }}>Chapa: {sol.chapa}</div>
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{tipo?.label || sol.tipo}</td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{sol.data_desligamento ? new Date(sol.data_desligamento).toLocaleDateString("pt-BR", { timeZone:"UTC" }) : "—"}</td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{sol.gestor_nome}</td>
                  <td style={{ padding:"10px 14px" }}>
                    <span style={{ background: st.color+"22", color: st.color, borderRadius:6, padding:"3px 8px", fontSize:11, fontWeight:600 }}>{st.label}</span>
                  </td>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ display:"flex", gap:4, flexWrap:"nowrap", alignItems:"center" }}>
                      <button onClick={() => abrirDetalhe(sol.id)} style={{ ...btnBase, border:"1px solid #E5E7EB", background:"#fff", color:"#374151" }}>Ver</button>

                      {sol.tipo !== "pedido_demissao" && (
                        <button onClick={async () => { try { const r = await api.buscarDesligamento(sol.id); setModalPDF(r); } catch(e){ setErro(e.message); } }}
                          style={{ ...btnBase, border:"1px solid #D1D5DB", background:"#fff", color:"#374151" }}>📄 Doc</button>
                      )}
                      {sol.tipo === "pedido_demissao" && (
                        <button onClick={async () => { try { const r = await api.buscarDesligamento(sol.id); setModalAnexoPedido(r); } catch(e){ setErro(e.message); } }}
                          style={{ ...btnBase, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46" }}>📎 Anexo</button>
                      )}
                      {podeAgir(sol) && sol.tipo !== "pedido_demissao" && (
                        <button onClick={() => setModalAcao({ id: sol.id, status: sol.status, acao: "aprovar", observacao: "" })}
                          style={{ ...btnBase, border:"none", background:"#0F2447", color:"#fff" }}>Analisar</button>
                      )}
                      {sol.status === "rascunho" && sol.gestor_id === user.id && (
                        <button onClick={async () => { try { await api.enviarDesligamento(sol.id); await carregar(); } catch(e){setErro(e.message);} }}
                          style={{ ...btnBase, border:"none", background:"#10B981", color:"#fff" }}>Enviar</button>
                      )}
                      {["aprovado","finalizado"].includes(sol.status) && sol.tipo !== "pedido_demissao" && (
                        <label style={{ ...btnBase, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46", display:"inline-block" }}>
                          📎 Anexar
                          <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                            onChange={async (e) => {
                              const file = e.target.files[0]; if (!file) return;
                              if (file.size > 5*1024*1024) { setErro("Arquivo muito grande (max 5MB)"); return; }
                              const reader = new FileReader();
                              reader.onload = async (ev) => {
                                try {
                                  await api.post("/desligamentos/"+sol.id+"/anexos", { nome_arquivo: file.name, tipo_arquivo: file.type, dados_base64: ev.target.result });
                                  alert("Anexo adicionado com sucesso!"); setErro("");
                                } catch(err) { setErro(err.message); }
                              };
                              reader.readAsDataURL(file);
                            }} />
                        </label>
                      )}
                      {["admin","dp"].includes(user.perfil) && !["cancelado","finalizado"].includes(sol.status) && (
                        <button onClick={async () => {
                          if (!window.confirm(`Cancelar a solicitação de desligamento de ${sol.colaborador_nome}?\n\nEsta ação não pode ser desfeita.`)) return;
                          try { await api.cancelarDesligamento(sol.id); await carregar(); } catch(e) { setErro(e.message); }
                        }} style={{ ...btnBase, border:"1px solid #EF4444", background:"#FEF2F2", color:"#DC2626" }}>🚫</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modal Novo */}
      {modalNovo && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 600, maxHeight: "90vh", overflowY: "auto", padding: 28 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
              <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>Nova Solicitação de Desligamento</h3>
              <button onClick={() => setModalNovo(false)} style={{ background: "none", border: "none", fontSize: 20, cursor: "pointer" }}>×</button>
            </div>

            {erro && (
              <div style={{ background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, padding: "3px 6px", marginBottom: 16, color: "#DC2626", fontSize: 11 }}>
                {erro.split("\n").map((linha, i) => (
                  <div key={i} style={{ marginBottom: linha === "" ? 6 : 2 }}>{linha ? `${i === 0 ? "⚠️ " : ""}${linha}` : ""}</div>
                ))}
              </div>
            )}

            {/* Colaborador */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>Colaborador *</label>
              <div style={{ position: "relative" }}>
                <input value={buscaColab} onChange={e => onBuscaColab(e.target.value)}
                  placeholder="Buscar por nome ou matrícula..."
                  style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, boxSizing: "border-box" }} />
                {sugestoesColab.length > 0 && (
                  <div style={{ position: "absolute", top: "100%", left: 0, right: 0, background: "#fff", border: "1px solid #E5E7EB", borderRadius: 8, zIndex: 10, maxHeight: 200, overflowY: "auto", boxShadow: "0 4px 12px rgba(0,0,0,0.1)" }}>
                    {sugestoesColab.map(c => (
                      <div key={c.id} onClick={() => selecionarColab(c)}
                        style={{ padding: "3px 6px", cursor: "pointer", fontSize: 13, borderBottom: "1px solid #F3F4F6" }}
                        onMouseEnter={e => e.target.style.background="#F8FAFC"}
                        onMouseLeave={e => e.target.style.background="#fff"}>
                        <b>{c.chapa}</b> — {c.nome} <span style={{ color: "#94A3B8" }}>{c.funcao}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              {validandoColab && (
                <div style={{ marginTop: 8, padding: "3px 6px", background: "#EFF6FF", borderRadius: 8, fontSize: 12, color: "#1D4ED8" }}>
                  🔄 Verificando aptidão do colaborador...
                </div>
              )}
              {!validandoColab && colaboradorSel && !bloqueioColab && (
                <div style={{ marginTop: 8, padding: "3px 6px", background: "#F0FDF4", borderRadius: 8, fontSize: 12, color: "#166534" }}>
                  ✅ <b>{colaboradorSel.nome}</b> · {colaboradorSel.descricao_filial || colaboradorSel.desc_cc || "—"} · Matrícula: {colaboradorSel.chapa} · Função: {colaboradorSel.desc_funcao || colaboradorSel.funcao || "—"} · CC: {colaboradorSel.centro_custo} — {colaboradorSel.desc_cc}
                  {colaboradorSel.tipo_contrato === "determinado" && <span style={{ marginLeft: 8, background: "#FEF3C7", color: "#92400E", padding: "1px 6px", borderRadius: 4 }}>Contrato até {colaboradorSel.data_fim_contrato ? new Date(colaboradorSel.data_fim_contrato).toLocaleDateString("pt-BR") : "—"}</span>}
                </div>
              )}
              {!validandoColab && bloqueioColab && (
                <div style={{ marginTop: 8, padding: "12px 14px", background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, fontSize: 12, color: "#DC2626" }}>
                  🚫 <b>Colaborador bloqueado para desligamento</b>
                  <div style={{ marginTop: 6, lineHeight: 1.6 }}>{bloqueioColab.mensagem}</div>
                </div>
              )}
            </div>

            {/* Tipo */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>Tipo de Desligamento *</label>
              <select value={form.tipo} onChange={e => {
                const novoTipo = e.target.value;
                if (novoTipo === "termino_contrato" && colaboradorSel?.data_admissao) {
                  setForm(f => ({ ...f, tipo: novoTipo, data_desligamento: calcularDataTermino(colaboradorSel.data_admissao) }));
                } else {
                  setForm(f => ({ ...f, tipo: novoTipo }));
                }
              }}
                style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13 }}>
                <option value="">Selecione...</option>
                {TIPOS_DESL.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>

            {/* Datas */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>Data de Desligamento *</label>
                <input type="date" value={form.data_desligamento}
                  onChange={e => setForm(f => ({ ...f, data_desligamento: e.target.value }))}
                  readOnly={form.tipo === "termino_contrato"}
                  style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, boxSizing: "border-box",
                    background: form.tipo === "termino_contrato" ? "#F3F4F6" : "#fff",
                    cursor: form.tipo === "termino_contrato" ? "not-allowed" : "auto" }} />
              </div>
              {form.tipo === "aviso_trabalhado" && (
                <div>
                  <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>Data de Aviso</label>
                  <input type="date" value={form.data_aviso || calcularDataAviso(form.data_desligamento)}
                    onChange={e => setForm(f => ({ ...f, data_aviso: e.target.value }))}
                    style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, boxSizing: "border-box" }} />
                </div>
              )}
            </div>

            {/* Redução jornada */}
            {form.tipo === "aviso_trabalhado" && (
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}>
                  <input type="checkbox" checked={form.reducao_jornada}
                    onChange={e => setForm(f => ({ ...f, reducao_jornada: e.target.checked }))} />
                  Colaborador terá redução de jornada durante o aviso
                </label>
              </div>
            )}

            {/* Justificativa */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>
                Justificativa {form.tipo === "antecipacao_contrato" ? "*" : "(opcional)"}
              </label>
              <textarea value={form.justificativa} onChange={e => setForm(f => ({ ...f, justificativa: e.target.value }))}
                rows={3} placeholder="Descreva o motivo do desligamento..."
                style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, resize: "vertical", boxSizing: "border-box" }} />
            </div>

            {/* Observações */}
            <div style={{ marginBottom: form.tipo === "pedido_demissao" ? 12 : 20 }}>
              <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>Observações</label>
              <textarea value={form.observacoes} onChange={e => setForm(f => ({ ...f, observacoes: e.target.value }))}
                rows={2} placeholder="Observações adicionais..."
                style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, resize: "vertical", boxSizing: "border-box" }} />
            </div>

            {/* Anexo do Pedido de Demissão — só para pedido_demissao */}
            {form.tipo === "pedido_demissao" && (
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 6 }}>
                  📎 Pedido de Demissão Assinado *
                </label>
                <div style={{
                  border: form.pedido_anexo_nome ? "2px solid #10B981" : "2px dashed #D1D5DB",
                  borderRadius: 10, padding: "14px 16px", background: form.pedido_anexo_nome ? "#F0FDF4" : "#FAFAFA",
                  display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12
                }}>
                  <div>
                    {form.pedido_anexo_nome ? (
                      <div>
                        <div style={{ fontSize: 11, fontWeight: 600, color: "#065F46" }}>✅ {form.pedido_anexo_nome}</div>
                        <div style={{ fontSize: 11, color: "#6B7280", marginTop: 2 }}>Documento anexado com sucesso</div>
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontSize: 11, color: "#374151", fontWeight: 600 }}>Nenhum arquivo selecionado</div>
                        <div style={{ fontSize: 11, color: "#9CA3AF", marginTop: 2 }}>PDF, JPG ou PNG — máx. 5MB</div>
                      </div>
                    )}
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <label style={{
                      padding: "7px 14px", borderRadius: 8, fontSize: 11, fontWeight: 600,
                      background: "#0F2447", color: "#fff", cursor: "pointer", whiteSpace: "nowrap"
                    }}>
                      {form.pedido_anexo_nome ? "Trocar arquivo" : "Selecionar arquivo"}
                      <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display: "none" }}
                        onChange={e => {
                          const file = e.target.files[0];
                          if (!file) return;
                          if (file.size > 5 * 1024 * 1024) { alert("Arquivo muito grande (máx 5MB)"); return; }
                          const reader = new FileReader();
                          reader.onload = ev => setForm(f => ({ ...f, pedido_anexo_nome: file.name, pedido_anexo_base64: ev.target.result }));
                          reader.readAsDataURL(file);
                        }} />
                    </label>
                    {form.pedido_anexo_nome && (
                      <button onClick={() => setForm(f => ({ ...f, pedido_anexo_nome: "", pedido_anexo_base64: "" }))}
                        style={{ padding: "7px 10px", borderRadius: 8, border: "1px solid #EF4444", background: "#FEF2F2", color: "#DC2626", fontSize: 12, cursor: "pointer" }}>
                        ✕
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, borderTop: "1px solid #F3F4F6", paddingTop: 16 }}>
              <button onClick={() => setModalNovo(false)} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>
                Cancelar
              </button>
              {form.tipo !== "pedido_demissao" && (
                <button onClick={() => salvar(false)} disabled={salvando}
                  style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #0F2447", background: "#fff", color: "#0F2447", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>
                  {salvando ? "Salvando..." : "Salvar Rascunho"}
                </button>
              )}
              <button onClick={() => salvar(form.tipo !== "pedido_demissao")} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "none", background: "#0F2447", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>
                {salvando
                  ? "Processando..."
                  : form.tipo === "pedido_demissao"
                  ? "Registrar Pedido de Demissão"
                  : "Enviar para Aprovação"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Detalhe */}
      {modalDetalhe && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 650, maxHeight: "90vh", overflowY: "auto", padding: 28 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
              <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>Detalhes da Solicitação #{modalDetalhe.id}</h3>
              <button onClick={() => setModalDetalhe(null)} style={{ background: "none", border: "none", fontSize: 20, cursor: "pointer" }}>×</button>
            </div>

            {/* Dados */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
              {[
                ["Colaborador",  modalDetalhe.colaborador_nome],
                ["Matrícula",    modalDetalhe.chapa],
                ["CPF",          modalDetalhe.cpf || "—"],
                ["Cargo",        modalDetalhe.funcao || "—"],
                ["Tipo",         TIPOS_DESL.find(t => t.value === modalDetalhe.tipo)?.label],
                ["Status",       STATUS_DESL[modalDetalhe.status]?.label],
                ["Desligamento", modalDetalhe.data_desligamento ? new Date(modalDetalhe.data_desligamento).toLocaleDateString("pt-BR") : "—"],
                ["Data Aviso",   modalDetalhe.data_aviso ? new Date(modalDetalhe.data_aviso).toLocaleDateString("pt-BR") : "—"],
                ["Solicitante",  modalDetalhe.gestor_nome],
                ["Centro Custo", `${modalDetalhe.centro_custo || "—"} — ${modalDetalhe.desc_cc || "—"}`],
              ].map(([l, v]) => (
                <div key={l} style={{ background: "#F8FAFC", borderRadius: 8, padding: "3px 6px" }}>
                  <div style={{ fontSize: 11, color: "#94A3B8", fontWeight: 600, marginBottom: 2 }}>{l}</div>
                  <div style={{ fontSize: 11, fontWeight: 600 }}>{v || "—"}</div>
                </div>
              ))}
            </div>

            {modalDetalhe.justificativa && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "#94A3B8", marginBottom: 4 }}>JUSTIFICATIVA</div>
                <div style={{ background: "#F8FAFC", borderRadius: 8, padding: "3px 6px", fontSize: 13 }}>{modalDetalhe.justificativa}</div>
              </div>
            )}

            {/* Histórico */}
            {modalDetalhe.logs?.length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "#94A3B8", marginBottom: 8 }}>HISTÓRICO</div>
                {modalDetalhe.logs.map((l, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, fontSize: 11 }}>
                    <div style={{ width: 32, height: 32, borderRadius: "50%", background: "#0F2447", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, flexShrink: 0 }}>
                      {l.usuario_nome?.slice(0,2).toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>{l.usuario_nome} <span style={{ color: "#94A3B8", fontWeight: 400 }}>· {l.acao}</span></div>
                      <div style={{ color: "#6B7280" }}>{l.observacao || ""} · {new Date(l.criado_em).toLocaleString("pt-BR")}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", paddingTop: 16, borderTop: "1px solid #F3F4F6" }}>
              <button onClick={() => setModalDetalhe(null)}
                style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Ação */}
      {modalAcao && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 460, padding: 28 }}>
            <h3 style={{ margin: "0 0 16px", fontSize: 17, fontWeight: 700 }}>Analisar Solicitação</h3>
            <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
              {["aprovar","reprovar","solicitar_ajuste"].map(a => (
                <button key={a} onClick={() => setModalAcao(m => ({ ...m, acao: a }))}
                  style={{ flex: 1, padding: "8px 0", borderRadius: 8, border: "2px solid",
                    borderColor: modalAcao.acao === a ? "#0F2447" : "#E5E7EB",
                    background: modalAcao.acao === a ? "#0F2447" : "#fff",
                    color: modalAcao.acao === a ? "#fff" : "#374151",
                    fontSize: 11, fontWeight: 600, cursor: "pointer" }}>
                  {a === "aprovar" ? "✅ Aprovar" : a === "reprovar" ? "❌ Reprovar" : "🔄 Ajuste"}
                </button>
              ))}
            </div>
            <textarea value={modalAcao.observacao}
              onChange={e => setModalAcao(m => ({ ...m, observacao: e.target.value }))}
              rows={3} placeholder="Observação (opcional para aprovação)..."
              style={{ width: "100%", padding: "3px 6px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, resize: "none", boxSizing: "border-box", marginBottom: 16 }} />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button onClick={() => setModalAcao(null)} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>
                Cancelar
              </button>
              <button onClick={executarAcao} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "none", background: "#0F2447", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>
                {salvando ? "Processando..." : "Confirmar"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal PDF Desligamento */}
      {/* Modal Ver Anexo — Pedido de Demissão */}
      {modalAnexoPedido && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.55)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:1100 }}>
          <div style={{ background:"#fff", borderRadius:16, width:"100%", maxWidth:700, maxHeight:"90vh", overflowY:"auto", padding:28 }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:20 }}>
              <h3 style={{ margin:0, fontSize:16, fontWeight:700 }}>📎 Pedido de Demissão — {modalAnexoPedido.colaborador_nome}</h3>
              <button onClick={() => setModalAnexoPedido(null)} style={{ background:"none", border:"none", fontSize:22, cursor:"pointer" }}>×</button>
            </div>
            {(modalAnexoPedido.pedido_anexo_dados || modalAnexoPedido.pedido_anexo_base64) ? (
              <div style={{ textAlign:"center" }}>
                <div style={{ fontSize:12, color:"#6B7280", marginBottom:12 }}>📄 {modalAnexoPedido.pedido_anexo_nome}</div>
                {(modalAnexoPedido.pedido_anexo_dados || modalAnexoPedido.pedido_anexo_base64).startsWith("data:image") ? (
                  <img src={modalAnexoPedido.pedido_anexo_dados || modalAnexoPedido.pedido_anexo_base64}
                    alt="Pedido de Demissão"
                    style={{ maxWidth:"100%", border:"1px solid #E5E7EB", borderRadius:8 }} />
                ) : (
                  <div style={{ padding:"30px 0" }}>
                    <div style={{ fontSize:48, marginBottom:12 }}>📄</div>
                    <div style={{ fontSize:14, color:"#374151", marginBottom:16, fontWeight:600 }}>{modalAnexoPedido.pedido_anexo_nome}</div>
                    <a href={modalAnexoPedido.pedido_anexo_dados || modalAnexoPedido.pedido_anexo_base64}
                      download={modalAnexoPedido.pedido_anexo_nome}
                      style={{ padding:"10px 24px", background:"#0F2447", color:"#fff", borderRadius:8, fontSize:14, fontWeight:600, textDecoration:"none" }}>
                      ⬇ Baixar PDF
                    </a>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ textAlign:"center", padding:"40px 0", color:"#9CA3AF" }}>
                <div style={{ fontSize:40, marginBottom:10 }}>📎</div>
                <div>Nenhum documento anexado nesta solicitação</div>
              </div>
            )}
            <div style={{ display:"flex", justifyContent:"flex-end", paddingTop:16, borderTop:"1px solid #F3F4F6", marginTop:20 }}>
              <button onClick={() => setModalAnexoPedido(null)}
                style={{ padding:"9px 20px", borderRadius:8, border:"1px solid #E5E7EB", background:"#fff", fontSize:14, cursor:"pointer" }}>
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

      {modalPDF && <ModalPDFDesligamento sol={modalPDF} onClose={() => setModalPDF(null)} />}
    </div>
  );
}

function ModalPDFDesligamento({ sol, onClose }) {
  const fmt = (d) => d ? new Date(d).toLocaleDateString("pt-BR", { timeZone: "UTC" }) : "__/__/____";
  const TIPOS = {
    aviso_trabalhado:     "AVISO PRÉVIO TRABALHADO",
    aviso_indenizado:     "AVISO PRÉVIO INDENIZADO",
    pedido_demissao:      "PEDIDO DE DEMISSÃO",
    termino_contrato:     "TÉRMINO DE CONTRATO DE TRABALHO",
    antecipacao_contrato: "RESCISÃO ANTECIPADA DO CONTRATO DE EXPERIÊNCIA PELO EMPREGADOR",
  };
  const titulo = TIPOS[sol.tipo] || "SOLICITAÇÃO DE DESLIGAMENTO";
  const temDeclaracao = ["aviso_indenizado","termino_contrato"].includes(sol.tipo);

  const imprimir = () => {
    const conteudo = document.getElementById("pdf-desligamento-benel").innerHTML;
    const win = window.open("", "_blank");
    win.document.write(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${titulo}</title>
    <style>body{font-family:Arial,sans-serif;font-size:13px;color:#000;line-height:1.6;padding:30px 40px;margin:0;}@media print{body{padding:20px 30px;}}</style>
    </head><body>${conteudo}</body></html>`);
    win.document.close();
    setTimeout(() => win.print(), 400);
  };

  const Ficha = () => (
    <div style={{ border: "1.5px solid #000", padding: "3px 6px", marginBottom: 20,
      display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 20px" }}>
      <div style={{ fontWeight: 700 }}>Sr. (a) &nbsp;{sol.colaborador_nome}</div>
      <div style={{ fontWeight: 700 }}>{sol.chapa}{sol.desc_cc ? `    SEÇÃO : ${sol.desc_cc}` : ""}</div>
      <div>C.P.F : &nbsp;{sol.cpf || "___.___.___-__"}</div>
      <div>Admissão: &nbsp;{(sol.data_admissao||sol.admissao) ? fmt((sol.data_admissao||sol.admissao).split("T")[0]) : "__/__/____"}</div>
    </div>
  );

  const Assinaturas = () => (
    <>
      <div style={{ marginBottom: 8 }}>Fortaleza</div>
      <div style={{ marginBottom: 28, textAlign: "left" }}>
        <img src={ASSINATURA_BENEL} alt="Assinatura" style={{ height: 70, display: "block", margin: "0 auto 4px", objectFit: "contain" }} />
        <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 6px", paddingTop: 4, fontWeight: 700, textAlign: "center" }}>
          BENEL TRANSPORTES E LOGISTICA LTDA
        </div>
      </div>
      <div style={{ marginBottom: 28 }}><strong>Ciente:</strong> &nbsp;{fmt(sol.data_desligamento)}</div>
      <div style={{ textAlign: "center", marginTop: 20 }}>
        <div style={{ height: 56 }} />
        <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 4px", paddingTop: 6, fontWeight: 700 }}>{sol.colaborador_nome}</div>
        <div style={{ fontSize: 11 }}>Assinatura do Empregado</div>
      </div>
    </>
  );

  const Declaracao = () => (
    <>
      <hr style={{ border: "none", borderTop: "1px dotted #000", margin: "24px 0" }} />
      <div style={{ textAlign: "center", fontWeight: 900, fontSize: 14, marginBottom: 16 }}>DECLARAÇÃO DE CIÊNCIA DE PAGAMENTO</div>
      <p style={{ textAlign: "justify", marginBottom: 16 }}>Estou ciente que devo comparecer a sede da empresa e/ou agente homologador, até o dia __/___/_____, para confirmar o recebimento das minhas verbas rescisórias, feito dentro dos prazos legais. O não comparecimento na data acima citada automaticamente dará a minha ciência.</p>
      <p style={{ fontSize: 12, marginBottom: 24 }}>Obs.: Para homologação das verbas rescisórias a data, local e horário a combinar, dentro do prazo legal previsto na CLT.</p>
      <div style={{ textAlign: "center", marginTop: 20 }}>
        <div style={{ height: 56 }} />
        <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 4px", paddingTop: 6, fontWeight: 700 }}>{sol.colaborador_nome}</div>
        <div style={{ fontSize: 11 }}>Assinatura do Empregado</div>
      </div>
    </>
  );

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "flex-start", justifyContent: "center", zIndex: 1100, overflowY: "auto", padding: "20px 0" }}>
      <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 760, margin: "auto", padding: 28 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Documento de Desligamento</h3>
          <button onClick={onClose} style={{ background: "none", border: "none", fontSize: 22, cursor: "pointer" }}>×</button>
        </div>
        <div id="pdf-desligamento-benel" style={{ fontFamily: "Arial,sans-serif", fontSize: 11, color: "#000", lineHeight: 1.6 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
            <img src={LOGO_BENEL} alt="Benel" style={{ height: 52 }} />
            <div style={{ fontSize: 16, fontWeight: 900, textTransform: "uppercase", letterSpacing: 2, textAlign: "right", maxWidth: "55%" }}>{titulo}</div>
          </div>
          <Ficha />
          {sol.tipo === "aviso_trabalhado" && (<>
            <p style={{ textAlign: "justify", marginBottom: 16 }}>Pelo presente, notificamos que a partir desta data nossa parceria (Contrato de Trabalho), que foi construída ao longo da trajetória na <strong>BENEL TRANSPORTES E LOGISTICA LTDA</strong>, chegou ao fim, e por isso, vimos avisá-lo(la) que os efeitos do disposto art. 487, inc. II da CLT, deverá assinar umas das possibilidades abaixo:</p>
            <p style={{ marginBottom: 8 }}>( &nbsp;) &nbsp;Escolho reduzir minha jornada em duas horas, conforme determina o art. 488 da CLT.</p>
            <p style={{ marginBottom: 8 }}>( &nbsp;) &nbsp;Escolho faltar 07 (sete) dias corridos, sem prejuízo do salário, caso em que sua jornada diária de trabalho nos 30 dias restantes não será reduzida.</p>
            <p style={{ marginTop: 12, marginBottom: 8 }}>Favor marcar abaixo se concorda com o pedido da Empresa em reconsiderar o presente aviso prévio, conforme previsão do parágrafo único do art. 489 da CLT.</p>
            <p style={{ marginBottom: 16 }}>( &nbsp;) Sim &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ( &nbsp;) Não</p>
            <p style={{ fontStyle: "italic", fontSize: 12, marginBottom: 20 }}>Agradecemos a cooperação prestada por V.Sa., pedimos a devolução do presente aviso com o seu ciente.</p>
            <div style={{ marginBottom: 20 }}><strong>Início do Aviso:</strong> &nbsp;{sol.data_aviso ? fmt(sol.data_aviso) : "__/__/____"}&nbsp;&nbsp;&nbsp;&nbsp;<strong>Fim do Aviso:</strong> &nbsp;{fmt(sol.data_desligamento)}</div>
            <Assinaturas />
          </>)}
          {sol.tipo === "aviso_indenizado" && (<>
            <p style={{ textAlign: "justify", marginBottom: 24 }}>Comunicamos a V.Sa., nossa iniciativa de rescindir seu contrato de trabalho, para o que lhe damos o presente AVISO PRÉVIO que será indenizado pelo valor correspondente, conforme Artigo 487, parágrafo 1o. da Consolidação das Leis do Trabalho.</p>
            <Assinaturas />
            <p style={{ fontSize: 12, marginTop: 12 }}>Obs.: Para homologação das verbas rescisórias a data, local e horário a combinar, dentro do prazo legal previsto na CLT.</p>
            <Declaracao />
          </>)}
          {sol.tipo === "termino_contrato" && (<>
            <p style={{ textAlign: "justify", marginBottom: 24 }}>Comunicamos por meio desta, que seu contrato de trabalho por prazo determinado será rescindido no seu termo, em <strong>{fmt(sol.data_desligamento)}</strong>.</p>
            <Assinaturas />
            <p style={{ fontSize: 12, marginTop: 12 }}>Obs.: Para homologação das verbas rescisórias a data, local e horário a combinar, dentro do prazo legal previsto na CLT.</p>
            <Declaracao />
          </>)}
          {sol.tipo === "antecipacao_contrato" && (<>
            <p style={{ textAlign: "justify", marginBottom: 24 }}>Vimos pela presente comunicar-lhe que por não mais convir a esta empresa manter seu contrato de experiência{sol.data_fim_contrato ? `, cujo término estava previsto para o dia ${fmt(sol.data_fim_contrato)},` : ","} achamos por bem rescindi-lo antes do prazo acordado. Sendo assim, a partir de <strong>{fmt(sol.data_desligamento)}</strong>, não serão mais necessários seus serviços.</p>
            <Assinaturas />
          </>)}
          {sol.tipo === "pedido_demissao" && (<>
            <div style={{ background: "#F0FDF4", border: "1px solid #6EE7B7", borderRadius: 10, padding: "16px 20px", marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#065F46", marginBottom: 8 }}>
                📎 Pedido de Demissão — Documento Original do Colaborador
              </div>
              <p style={{ fontSize: 11, color: "#374151", margin: 0 }}>
                Este tipo de desligamento é formalizado pelo próprio colaborador a próprio punho.
                O documento original deve ser anexado abaixo.
              </p>
            </div>
            {sol.pedido_anexo_dados || sol.pedido_anexo_base64 ? (
              <div style={{ textAlign: "center", marginBottom: 20 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#374151", marginBottom: 8 }}>
                  📄 {sol.pedido_anexo_nome}
                </div>
                {sol.pedido_anexo_dados || sol.pedido_anexo_base64.startsWith("data:image") ? (
                  <img src={sol.pedido_anexo_dados || sol.pedido_anexo_base64} alt="Pedido de Demissão"
                    style={{ maxWidth: "100%", maxHeight: 500, border: "1px solid #E5E7EB", borderRadius: 8 }} />
                ) : (
                  <a href={sol.pedido_anexo_dados || sol.pedido_anexo_base64} download={sol.pedido_anexo_nome}
                    style={{ padding: "10px 20px", background: "#0F2447", color: "#fff", borderRadius: 8, fontSize: 11, fontWeight: 600, textDecoration: "none" }}>
                    ⬇ Baixar PDF anexado
                  </a>
                )}
              </div>
            ) : (
              <div style={{ textAlign: "center", padding: "30px 0", color: "#9CA3AF" }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>📎</div>
                <div>Nenhum documento anexado ainda</div>
              </div>
            )}
            <Assinaturas />
          </>)}
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 16, borderTop: "1px solid #F3F4F6", marginTop: 20 }}>
          <button onClick={onClose} style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>Fechar</button>
          <button onClick={imprimir} style={{ padding: "9px 20px", borderRadius: 8, border: "none", background: "#0F2447", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>🖨 Imprimir / Salvar PDF</button>
        </div>
      </div>
    </div>
  );
}


// ── Helpers PlanoSaude ────────────────────────────────────────────────────────
function fmtDataPS(v) {
  if (!v) return "";
  try {
    const d = new Date(v.includes("T") ? v : v + "T12:00:00");
    return isNaN(d.getTime()) ? v : d.toLocaleDateString("pt-BR");
  } catch { return v; }
}

function gerarHTMLTitular(colab, movimentacao) {
  const f = (v) => v || "_______________";
  const movMap = {
    INCLUSAO:    "(X) INCLUSÃO &nbsp; ( ) NÃO OPTANTE &nbsp; ( ) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    NAO_OPTANTE: "( ) INCLUSÃO &nbsp; (X) NÃO OPTANTE &nbsp; ( ) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    ALTERACAO:   "( ) INCLUSÃO &nbsp; ( ) NÃO OPTANTE &nbsp; (X) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    EXCLUSAO:    "( ) INCLUSÃO &nbsp; ( ) NÃO OPTANTE &nbsp; ( ) ALTERAÇÃO &nbsp; (X) EXCLUSÃO",
  };
  return `
    <div style="font-family:Arial,sans-serif;font-size:10pt;line-height:1.5;max-width:700px;margin:0 auto;padding:20px 28px;color:#000;">
      <div style="text-align:center;margin-bottom:6px;"><img src="${LOGO_BENEL}" alt="Benel" style="height:55px;" /></div>
      <h2 style="text-align:center;font-size:12pt;font-weight:bold;text-transform:uppercase;margin:0 0 2px 0;">PROPOSTA PLANO DE ASSISTÊNCIA MÉDICA</h2>
      <h3 style="text-align:center;font-size:11pt;font-weight:bold;text-transform:uppercase;margin:0 0 12px 0;">TITULAR</h3>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS DA MOVIMENTAÇÃO</p>
      <div style="border:1px solid #000;padding:6px 14px;margin-bottom:12px;font-size:9.5pt;">${movMap[movimentacao] || movMap.INCLUSAO}</div>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS PESSOAIS</p>
      <div style="border:1px solid #000;padding:10px 14px;margin-bottom:12px;font-size:9.5pt;">
        <p style="margin:0 0 6px 0;">C.P.F.: <u>${f(colab?.cpf)}</u> &nbsp;&nbsp; DATA DE ADMISSÃO: <u>${fmtDataPS(colab?.data_admissao) || "___/___/______"}</u></p>
        <p style="margin:0 0 6px 0;">NOME: <u>${f(colab?.nome)}</u> &nbsp;&nbsp; DATA DE NASC.: <u>${fmtDataPS(colab?.data_nascimento) || "___/___/______"}</u></p>
        <p style="margin:0 0 6px 0;">SEXO: <u>${colab?.sexo || "___________"}</u> &nbsp;&nbsp; RG: <u>${f(colab?.rg)}</u> &nbsp; ÓRGÃO: <u>${f(colab?.rg_orgao)}</u> &nbsp; UF: <u>${f(colab?.rg_uf)}</u></p>
        <p style="margin:0 0 6px 0;">ESTADO CIVIL: <u>${f(colab?.estado_civil)}</u> &nbsp;&nbsp; NOME DA MÃE: <u>${f(colab?.nome_mae)}</u></p>
        <p style="margin:0;">MATRÍCULA: <u>${f(colab?.chapa)}</u> &nbsp; PIS: <u>${f(colab?.pis)}</u> &nbsp; CTPS: <u>${f(colab?.ctps)}</u> &nbsp; SÉRIE: <u>${f(colab?.ctps_serie)}</u></p>
      </div>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS DO ENDEREÇO</p>
      <div style="border:1px solid #000;padding:10px 14px;margin-bottom:12px;font-size:9.5pt;">
        <p style="margin:0 0 6px 0;">LOGRADOURO: <u>${f(colab?.logradouro)}</u> &nbsp; Nº: <u>${f(colab?.numero)}</u></p>
        <p style="margin:0 0 6px 0;">COMPLEMENTO: <u>${f(colab?.complemento)}</u> &nbsp; BAIRRO: <u>${f(colab?.bairro)}</u></p>
        <p style="margin:0 0 6px 0;">CIDADE: <u>${f(colab?.cidade)}</u> &nbsp; UF: <u>${f(colab?.uf)}</u> &nbsp; CEP: <u>${f(colab?.cep)}</u></p>
        <p style="margin:0;">TELEFONES: ( ) <u>${f(colab?.telefone1)}</u></p>
      </div>
      <p style="margin:0 0 40px 0;font-size:9.5pt;">_________________, _____ de ________________ de _________.</p>
      <div style="border-top:1px solid #000;width:260px;padding-top:5px;font-size:9.5pt;text-align:center;">ASSINATURA DO TITULAR</div>
    </div>`;
}

function gerarHTMLDependente(colab, dep, movimentacao) {
  const movMap = {
    INCLUSAO: "(X) INCLUSÃO &nbsp; ( ) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    ALTERACAO: "( ) INCLUSÃO &nbsp; (X) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    EXCLUSAO:  "( ) INCLUSÃO &nbsp; ( ) ALTERAÇÃO &nbsp; (X) EXCLUSÃO",
  };
  const parentescoMap = {
    CONJUGE:     "(X) CÔNJUGE &nbsp; ( ) FILHO(A) &nbsp; ( ) COMPANHEIRO(A) &nbsp; ( ) OUTROS",
    FILHO:       "( ) CÔNJUGE &nbsp; (X) FILHO(A) &nbsp; ( ) COMPANHEIRO(A) &nbsp; ( ) OUTROS",
    COMPANHEIRO: "( ) CÔNJUGE &nbsp; ( ) FILHO(A) &nbsp; (X) COMPANHEIRO(A) &nbsp; ( ) OUTROS",
    OUTROS:      "( ) CÔNJUGE &nbsp; ( ) FILHO(A) &nbsp; ( ) COMPANHEIRO(A) &nbsp; (X) OUTROS",
  };
  return `
    <div style="font-family:Arial,sans-serif;font-size:10pt;line-height:1.5;max-width:700px;margin:0 auto;padding:20px 28px;color:#000;">
      <div style="text-align:center;margin-bottom:6px;"><img src="${LOGO_BENEL}" alt="Benel" style="height:55px;" /></div>
      <h2 style="text-align:center;font-size:12pt;font-weight:bold;text-transform:uppercase;margin:0 0 2px 0;">PROPOSTA PLANO DE ASSISTÊNCIA MÉDICA</h2>
      <h3 style="text-align:center;font-size:11pt;font-weight:bold;text-transform:uppercase;margin:0 0 12px 0;">DEPENDENTES</h3>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS DA MOVIMENTAÇÃO</p>
      <div style="border:1px solid #000;padding:6px 14px;margin-bottom:12px;font-size:9.5pt;">${movMap[movimentacao] || movMap.INCLUSAO}</div>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS PESSOAIS DO DEPENDENTE</p>
      <div style="border:1px solid #000;padding:10px 14px;margin-bottom:12px;font-size:9.5pt;">
        <p style="margin:0 0 6px 0;">C.P.F.: <u>${dep?.dep_cpf || "_______________"}</u> &nbsp;&nbsp; NOME: <u>${dep?.dep_nome || "___________________________"}</u></p>
        <p style="margin:0 0 6px 0;">SEXO: ${dep?.dep_sexo === "M" ? "(X) MASCULINO &nbsp; ( ) FEMININO" : "(  ) MASCULINO &nbsp; (X) FEMININO"} &nbsp;&nbsp; DATA NASC.: <u>${fmtDataPS(dep?.dep_data_nasc) || "___/___/______"}</u> &nbsp; ESTADO CIVIL: <u>${dep?.dep_estado_civil || "_______________"}</u></p>
        <p style="margin:0 0 6px 0;">DATA DE CASAMENTO: <u>${fmtDataPS(dep?.dep_data_casamento) || "___/___/______"}</u></p>
        <p style="margin:0 0 4px 0;">GRAU DE PARENTESCO:</p>
        <p style="margin:0 0 6px 16px;">${parentescoMap[dep?.dep_grau_parentesco] || parentescoMap.CONJUGE}</p>
        <p style="margin:0;">NOME DA MÃE: <u>${dep?.dep_nome_mae || "___________________________"}</u></p>
      </div>
      <p style="font-size:8.5pt;color:#555;margin:0 0 6px 0;">Titular: ${colab?.nome || ""} — Matrícula: ${colab?.chapa || ""}</p>
      <p style="margin:0 0 40px 0;font-size:9.5pt;">_________________, _____ de ________________ de _________.</p>
      <div style="border-top:1px solid #000;width:260px;padding-top:5px;font-size:9.5pt;text-align:center;">ASSINATURA DO TITULAR</div>
    </div>`;
}

// ── Componente PlanoSaude ─────────────────────────────────────────────────────
function PlanoSaude({ user, colaboradores }) {
  const [lista, setLista]         = useState([]);
  const [loading, setLoading]     = useState(false);
  const [tipo, setTipo]           = useState(null); // null | "TITULAR" | "DEPENDENTE"
  const [modalPreview, setModalPreview] = useState(null);
  const [salvando, setSalvando]   = useState(false);
  const [msg, setMsg]             = useState(null);
  const [anexosModal, setAnexosModal] = useState(null);

  const [colabSel, setColabSel]   = useState(null);
  const [buscaColab, setBuscaColab] = useState("");
  const [movimentacao, setMovimentacao] = useState("INCLUSAO");

  const [depTitularSel, setDepTitularSel] = useState(null);
  const [buscaDep, setBuscaDep]   = useState("");
  const [depMov, setDepMov]       = useState("INCLUSAO");
  const [dep, setDep]             = useState({ dep_cpf:"", dep_nome:"", dep_sexo:"M", dep_data_nasc:"", dep_estado_civil:"", dep_data_casamento:"", dep_grau_parentesco:"CONJUGE", dep_nome_mae:"" });
  const [anexos, setAnexos]       = useState([]);

  const norm = s => (s||"").toLowerCase();
  const colsFilt = colaboradores
    .filter(c => c.cod_situacao !== "D")
    .filter(c => !buscaColab || norm(c.nome).includes(norm(buscaColab)) || (c.chapa||"").includes(buscaColab));
  const colsDepFilt = colaboradores
    .filter(c => c.cod_situacao !== "D")
    .filter(c => !buscaDep || norm(c.nome).includes(norm(buscaDep)) || (c.chapa||"").includes(buscaDep));

  const carregar = async () => {
    setLoading(true);
    try { const d = await api.listarPlanoSaude(); setLista(Array.isArray(d) ? d : []); }
    catch (e) { setMsg({ tipo:"erro", texto:"Erro: "+e.message }); }
    finally { setLoading(false); }
  };
  useEffect(() => { carregar(); }, []);

  const reset = () => {
    setColabSel(null); setBuscaColab(""); setMovimentacao("INCLUSAO");
    setDepTitularSel(null); setBuscaDep(""); setDepMov("INCLUSAO");
    setDep({ dep_cpf:"", dep_nome:"", dep_sexo:"M", dep_data_nasc:"", dep_estado_civil:"", dep_data_casamento:"", dep_grau_parentesco:"CONJUGE", dep_nome_mae:"" });
    setAnexos([]);
  };

  const onAnexo = (tipo_anexo) => (e) => {
    const file = e.target.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => setAnexos(prev => [...prev.filter(a=>a.tipo_anexo!==tipo_anexo), { nome_arquivo:file.name, tipo_anexo, dados_base64:ev.target.result.split(",")[1] }]);
    reader.readAsDataURL(file);
  };

  const FILIAIS_BLOQUEADAS = ["7"];
  const checarFilialBloqueada = (colab) => {
    if (colab && FILIAIS_BLOQUEADAS.includes(String(colab.cod_filial))) {
      setMsg({ tipo:"erro", texto:"⚠️ O plano Hapvida não atende a filial 7 — São Mateus. Solicitação não permitida." });
      return true;
    }
    return false;
  };

  const salvarTitular = async () => {
    if (!colabSel) { setMsg({ tipo:"erro", texto:"Selecione o colaborador." }); return; }
    if (checarFilialBloqueada(colabSel)) return;
    setSalvando(true);
    try {
      const novo = await api.criarPlanoSaude({ tipo:"TITULAR", movimentacao, colaborador_id:colabSel.id });
      for (const a of anexos) await api.addAnexoPlanoSaude(novo.id, a);
      setMsg({ tipo:"ok", texto:"Solicitação criada!" }); setTipo(null); reset(); carregar();
    } catch(e) { setMsg({ tipo:"erro", texto:e.message }); }
    finally { setSalvando(false); }
  };

  const salvarDependente = async () => {
    if (!depTitularSel) { setMsg({ tipo:"erro", texto:"Selecione o titular." }); return; }
    if (checarFilialBloqueada(depTitularSel)) return;
    if (!dep.dep_nome.trim()) { setMsg({ tipo:"erro", texto:"Informe o nome do dependente." }); return; }
    setSalvando(true);
    try {
      const novo = await api.criarPlanoSaude({ tipo:"DEPENDENTE", movimentacao:depMov, colaborador_id:depTitularSel.id, ...dep });
      for (const a of anexos) await api.addAnexoPlanoSaude(novo.id, a);
      setMsg({ tipo:"ok", texto:"Dependente registrado!" }); setTipo(null); reset(); carregar();
    } catch(e) { setMsg({ tipo:"erro", texto:e.message }); }
    finally { setSalvando(false); }
  };

  const imprimir = () => {
    const w = window.open("","_blank");
    w.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Plano de Saúde</title></head><body>${modalPreview}</body></html>`);
    w.document.close(); setTimeout(()=>{ w.focus(); w.print(); }, 400);
  };

  // ── Estilos compactos seguindo padrão do sistema ──────────────────────────
  const salvarEdicao = async () => {
    const itensList = Object.entries(itensEdit).filter(([,v]) => v).map(([campo, novo_valor]) => ({ campo, novo_valor }));
    if (itensList.length === 0) { setMsg({ tipo: "erro", texto: "Selecione ao menos um campo para alterar." }); return; }
    setSalvando(true);
    try {
      // Cancela a atual e cria nova
      await api.cancelarAtualizacaoCadastral(modalDetalhe.id);
      await api.criarAtualizacaoCadastral({ colaborador_id: modalDetalhe.colaborador_id, itens: itensList, observacao: obsEdit });
      setMsg({ tipo: "ok", texto: "Solicitação atualizada com sucesso!" });
      setModalDetalhe(null); setEditando(false); setItensEdit({}); setObsEdit("");
      carregarSols();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setSalvando(false); }
  };

  const S = {
    page:   { padding:"16px 20px", maxWidth:960, margin:"0 auto" },
    header: { display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 },
    title:  { margin:0, fontSize:16, fontWeight:800, color:"#111827" },
    sub:    { margin:"2px 0 0", fontSize:11, color:"#6B7280" },
    btnP:   { background:"#0F2447", color:"#fff", border:"none", borderRadius:8, padding:"8px 18px", fontSize:12, fontWeight:700, cursor:"pointer" },
    btnS:   { background:"#F3F4F6", color:"#374151", border:"1px solid #D1D5DB", borderRadius:8, padding:"8px 14px", fontSize:12, fontWeight:600, cursor:"pointer" },
    card:   { background:"#fff", borderRadius:10, border:"1px solid #E5E7EB", padding:"10px 16px", marginBottom:8, display:"flex", alignItems:"center", justifyContent:"space-between" },
    inp:    { width:"100%", padding:"6px 10px", border:"1px solid #D1D5DB", borderRadius:6, fontSize:12, boxSizing:"border-box" },
    lbl:    { fontSize:11, fontWeight:600, color:"#374151", display:"block", marginBottom:3 },
    modal:  { position:"fixed", inset:0, background:"rgba(0,0,0,.5)", zIndex:1000, display:"flex", alignItems:"center", justifyContent:"center" },
    mbox:   { background:"#fff", borderRadius:14, padding:"24px 28px", width:"100%", maxWidth:680, maxHeight:"90vh", overflowY:"auto", boxShadow:"0 20px 60px rgba(0,0,0,.25)" },
  };

  // Seletor de tipo igual ao padrão Advertência/Suspensão
  const SeletorTipo = () => (
    <div style={S.modal}>
      <div style={{ ...S.mbox, maxWidth:420 }}>
        <h3 style={{ margin:"0 0 20px", fontSize:15, fontWeight:800, color:"#0F2447" }}>Nova Solicitação — Plano de Saúde</h3>
        <div style={{ display:"flex", gap:12, marginBottom:20 }}>
          <button
            onClick={() => setTipo("TITULAR")}
            style={{ flex:1, padding:"18px 12px", borderRadius:10, border:"2px solid #0F2447", background:"#EFF6FF", cursor:"pointer", textAlign:"center" }}>
            <div style={{ fontSize:22, marginBottom:6 }}>👤</div>
            <div style={{ fontSize:13, fontWeight:700, color:"#0F2447" }}>Titular</div>
            <div style={{ fontSize:11, color:"#6B7280", marginTop:2 }}>Inclusão do colaborador</div>
          </button>
          <button
            onClick={() => setTipo("DEPENDENTE")}
            style={{ flex:1, padding:"18px 12px", borderRadius:10, border:"2px solid #7C3AED", background:"#F5F3FF", cursor:"pointer", textAlign:"center" }}>
            <div style={{ fontSize:22, marginBottom:6 }}>👨‍👩‍👧</div>
            <div style={{ fontSize:13, fontWeight:700, color:"#7C3AED" }}>Dependente</div>
            <div style={{ fontSize:11, color:"#6B7280", marginTop:2 }}>Inclusão de dependente</div>
          </button>
        </div>
        <div style={{ textAlign:"right" }}>
          <button style={S.btnS} onClick={() => { setTipo(null); reset(); }}>Cancelar</button>
        </div>
      </div>
    </div>
  );

  const BuscaColab = ({ busca, setBusca, sel, onSel, lista, label }) => (
    <div style={{ marginBottom:14 }}>
      <label style={S.lbl}>{label} *</label>
      {sel ? (
        <div style={{ padding:"6px 10px", background:"#EFF6FF", borderRadius:6, fontSize:12, color:"#1E40AF", fontWeight:600, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          ✓ {sel.nome} — {sel.chapa}
          <button onClick={() => { onSel(null); setBusca(""); }} style={{ background:"none", border:"none", cursor:"pointer", color:"#6B7280", fontSize:14 }}>×</button>
        </div>
      ) : (
        <>
          <input style={S.inp} placeholder="Digite nome ou matrícula..." value={busca}
            onChange={e => setBusca(e.target.value)} autoFocus />
          {busca.length > 0 && lista.length > 0 && (
            <div style={{ border:"1px solid #E5E7EB", borderRadius:6, maxHeight:160, overflowY:"auto", marginTop:2, background:"#fff", boxShadow:"0 4px 12px rgba(0,0,0,.1)" }}>
              {lista.slice(0,8).map(c => (
                <div key={c.id} onClick={() => { onSel(c); setBusca(""); }}
                  style={{ padding:"7px 10px", cursor:"pointer", fontSize:12, borderBottom:"1px solid #F3F4F6" }}
                  onMouseEnter={e=>e.currentTarget.style.background="#F3F4F6"}
                  onMouseLeave={e=>e.currentTarget.style.background=""}>
                  <strong>{c.nome}</strong> <span style={{ color:"#6B7280" }}>• {c.chapa} • {c.funcao}</span>
                </div>
              ))}
            </div>
          )}
          {busca.length > 0 && lista.length === 0 && (
            <div style={{ padding:"8px 10px", fontSize:12, color:"#9CA3AF", border:"1px solid #E5E7EB", borderRadius:6, marginTop:2 }}>Nenhum resultado.</div>
          )}
        </>
      )}
    </div>
  );

  const InfoColab = ({ c }) => c ? (
    <div style={{ background:"#FFFBEB", border:"1px solid #FDE68A", borderRadius:8, padding:"10px 14px", marginBottom:14 }}>
      {["7"].includes(String(c.cod_filial)) && (
        <div style={{ background:"#FEE2E2", border:"1px solid #FECACA", borderRadius:6, padding:"8px 12px", marginBottom:10, fontSize:12, fontWeight:700, color:"#991B1B" }}>
          ⚠️ Filial 7 — São Mateus: o plano Hapvida não atende esta localidade. Solicitação não permitida.
        </div>
      )}
      <p style={{ margin:"0 0 8px", fontSize:11, fontWeight:700, color:"#92400E" }}>ℹ️ Dados no sistema — campos em vermelho aparecerão em branco no formulário</p>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:6, fontSize:11 }}>
        {[["CPF",c.cpf],["RG",c.rg],["PIS",c.pis],["CTPS",c.ctps],["Nome da Mãe",c.nome_mae],["Endereço",c.logradouro]].map(([k,v])=>(
          <div key={k} style={{ background:v?"#F0FDF4":"#FEF2F2", border:`1px solid ${v?"#BBF7D0":"#FECACA"}`, borderRadius:5, padding:"3px 8px" }}>
            <span style={{ color:"#6B7280" }}>{k}: </span>
            <strong style={{ color:v?"#065F46":"#991B1B" }}>{v||"Não informado"}</strong>
          </div>
        ))}
      </div>
    </div>
  ) : null;

  return (
    <div style={S.page}>
      {/* Header */}
      <div style={S.header}>
        <div>
          <h2 style={S.title}>💊 Solicitação de Plano de Saúde</h2>
          <p style={S.sub}>Proposta de Assistência Médica — Hapvida</p>
        </div>
        <button style={S.btnP} onClick={() => { reset(); setTipo("SELECIONAR"); }}>+ Nova Solicitação</button>
      </div>

      {/* Msg */}
      {msg && (
        <div style={{ padding:"8px 14px", borderRadius:7, marginBottom:12, background:msg.tipo==="ok"?"#D1FAE5":"#FEE2E2", color:msg.tipo==="ok"?"#065F46":"#991B1B", fontSize:12, fontWeight:600, display:"flex", justifyContent:"space-between" }}>
          {msg.texto}
          <button onClick={()=>setMsg(null)} style={{ background:"none", border:"none", cursor:"pointer", fontSize:14 }}>×</button>
        </div>
      )}

      {/* Lista */}
      {loading ? null : lista.length === 0 ? (
        <div style={{ textAlign:"center", padding:60, color:"#9CA3AF", fontSize:13 }}>Nenhuma solicitação registrada.</div>
      ) : lista.map(s => (
        <div key={s.id} style={S.card}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px", borderRadius:8, background:s.tipo==="TITULAR"?"#DBEAFE":"#EDE9FE", color:s.tipo==="TITULAR"?"#1E40AF":"#5B21B6" }}>{s.tipo}</span>
            <span style={{ fontSize:12, fontWeight:700, color:"#111827" }}>{s.colaborador_nome}</span>
            <span style={{ fontSize:11, color:"#6B7280" }}>#{s.chapa}</span>
            {s.tipo==="DEPENDENTE" && <span style={{ fontSize:11, color:"#7C3AED" }}>→ {s.dep_nome}</span>}
            <span style={{ fontSize:10, color:"#9CA3AF" }}>• {s.movimentacao} • {new Date(s.criado_em).toLocaleDateString("pt-BR")}</span>
          </div>
          <div style={{ display:"flex", gap:6 }}>
            <button style={{ ...S.btnS, padding:"4px 10px", fontSize:11 }}
              onClick={() => setModalPreview(s.tipo==="TITULAR" ? gerarHTMLTitular(s,s.movimentacao) : gerarHTMLDependente(s,s,s.movimentacao))}>
              🖨 Imprimir
            </button>
            <button style={{ ...S.btnS, padding:"4px 10px", fontSize:11 }} onClick={() => setAnexosModal(s)}>📎 Anexos</button>
          </div>
        </div>
      ))}

      {/* MODAL SELETOR TIPO */}
      {tipo === "SELECIONAR" && <SeletorTipo />}

      {/* MODAL TITULAR */}
      {tipo === "TITULAR" && (
        <div style={S.modal}>
          <div style={S.mbox}>
            <h3 style={{ margin:"0 0 16px", fontSize:15, fontWeight:800, color:"#0F2447" }}>Nova Solicitação — Titular</h3>
            <BuscaColab busca={buscaColab} setBusca={setBuscaColab} sel={colabSel} onSel={setColabSel} lista={colsFilt} label="Colaborador" />
            <InfoColab c={colabSel} />
            <div style={{ marginBottom:14 }}>
              <label style={S.lbl}>Movimentação *</label>
              <select style={S.inp} value={movimentacao} onChange={e=>setMovimentacao(e.target.value)}>
                <option value="INCLUSAO">Inclusão</option>
                <option value="NAO_OPTANTE">Não Optante</option>
                <option value="ALTERACAO">Alteração</option>
                <option value="EXCLUSAO">Exclusão</option>
              </select>
            </div>
            <button style={{ ...S.btnS, width:"100%", marginBottom:4 }}
              onClick={() => { if (!colabSel) { setMsg({tipo:"erro",texto:"Selecione o colaborador."}); return; } setModalPreview(gerarHTMLTitular(colabSel,movimentacao)); }}>
              👁 Visualizar / Imprimir Formulário
            </button>
            <p style={{ fontSize:10, color:"#6B7280", margin:"0 0 16px" }}>Após imprimir, o titular assina e data manualmente.</p>
            <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
              <button style={S.btnS} onClick={() => { setTipo(null); reset(); }}>Cancelar</button>
              <button style={S.btnP} onClick={salvarTitular} disabled={salvando}>{salvando?"Salvando...":"Registrar Solicitação"}</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL DEPENDENTE */}
      {tipo === "DEPENDENTE" && (
        <div style={S.modal}>
          <div style={S.mbox}>
            <h3 style={{ margin:"0 0 16px", fontSize:15, fontWeight:800, color:"#0F2447" }}>Nova Solicitação — Dependente</h3>
            <BuscaColab busca={buscaDep} setBusca={setBuscaDep} sel={depTitularSel} onSel={setDepTitularSel} lista={colsDepFilt} label="Titular (Colaborador)" />
            <div style={{ marginBottom:14 }}>
              <label style={S.lbl}>Movimentação *</label>
              <select style={S.inp} value={depMov} onChange={e=>setDepMov(e.target.value)}>
                <option value="INCLUSAO">Inclusão</option>
                <option value="ALTERACAO">Alteração</option>
                <option value="EXCLUSAO">Exclusão</option>
              </select>
            </div>
            <div style={{ background:"#F9FAFB", border:"1px solid #E5E7EB", borderRadius:8, padding:"12px 14px", marginBottom:14 }}>
              <p style={{ margin:"0 0 10px", fontSize:11, fontWeight:700, color:"#374151" }}>DADOS DO DEPENDENTE</p>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                <div><label style={S.lbl}>CPF</label><input style={S.inp} value={dep.dep_cpf} onChange={e=>setDep(p=>({...p,dep_cpf:e.target.value}))} placeholder="000.000.000-00" /></div>
                <div><label style={S.lbl}>Nome *</label><input style={S.inp} value={dep.dep_nome} onChange={e=>setDep(p=>({...p,dep_nome:e.target.value}))} /></div>
                <div><label style={S.lbl}>Sexo</label>
                  <select style={S.inp} value={dep.dep_sexo} onChange={e=>setDep(p=>({...p,dep_sexo:e.target.value}))}>
                    <option value="M">Masculino</option><option value="F">Feminino</option>
                  </select>
                </div>
                <div><label style={S.lbl}>Data de Nascimento</label><input type="date" style={S.inp} value={dep.dep_data_nasc} onChange={e=>setDep(p=>({...p,dep_data_nasc:e.target.value}))} /></div>
                <div><label style={S.lbl}>Estado Civil</label>
                  <select style={S.inp} value={dep.dep_estado_civil} onChange={e=>setDep(p=>({...p,dep_estado_civil:e.target.value}))}>
                    <option value="">Selecione</option><option>Solteiro(a)</option><option>Casado(a)</option>
                    <option>Divorciado(a)</option><option>Viúvo(a)</option><option>União Estável</option>
                  </select>
                </div>
                <div><label style={S.lbl}>Data de Casamento</label><input type="date" style={S.inp} value={dep.dep_data_casamento} onChange={e=>setDep(p=>({...p,dep_data_casamento:e.target.value}))} /></div>
                <div style={{ gridColumn:"1/-1" }}><label style={S.lbl}>Grau de Parentesco</label>
                  <select style={S.inp} value={dep.dep_grau_parentesco} onChange={e=>setDep(p=>({...p,dep_grau_parentesco:e.target.value}))}>
                    <option value="CONJUGE">Cônjuge</option><option value="FILHO">Filho(a)</option>
                    <option value="COMPANHEIRO">Companheiro(a)</option><option value="OUTROS">Outros</option>
                  </select>
                </div>
                <div style={{ gridColumn:"1/-1" }}><label style={S.lbl}>Nome da Mãe do Dependente</label><input style={S.inp} value={dep.dep_nome_mae} onChange={e=>setDep(p=>({...p,dep_nome_mae:e.target.value}))} /></div>
              </div>
            </div>
            <div style={{ background:"#F9FAFB", border:"1px solid #E5E7EB", borderRadius:8, padding:"12px 14px", marginBottom:14 }}>
              <p style={{ margin:"0 0 10px", fontSize:11, fontWeight:700, color:"#374151" }}>📎 DOCUMENTOS</p>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8 }}>
                {[
                  { key:"FORMULARIO_ASSINADO", label:"Formulário Assinado" },
                  { key:"RG_DEPENDENTE", label:"RG do Dependente" },
                  { key:dep.dep_grau_parentesco==="FILHO"?"CERTIDAO_NASCIMENTO":"CERTIDAO_CASAMENTO", label:dep.dep_grau_parentesco==="FILHO"?"Certidão de Nascimento":"Certidão de Casamento" },
                ].map(({key,label}) => {
                  const found = anexos.find(a=>a.tipo_anexo===key);
                  return (
                    <div key={key} style={{ border:`1px dashed ${found?"#34D399":"#D1D5DB"}`, borderRadius:7, padding:10, textAlign:"center", background:found?"#F0FDF4":"#fff" }}>
                      <p style={{ margin:"0 0 6px", fontSize:10, fontWeight:600, color:found?"#065F46":"#6B7280" }}>{label}</p>
                      {found ? (
                        <div>
                          <p style={{ margin:"0 0 3px", fontSize:10, color:"#065F46" }}>✓ {found.nome_arquivo}</p>
                          <button onClick={()=>setAnexos(prev=>prev.filter(a=>a.tipo_anexo!==key))} style={{ fontSize:10, color:"#991B1B", background:"none", border:"none", cursor:"pointer" }}>Remover</button>
                        </div>
                      ) : (
                        <label style={{ cursor:"pointer", fontSize:11, color:"#3B82F6" }}>
                          📁 Selecionar
                          <input type="file" style={{ display:"none" }} accept=".pdf,.jpg,.jpeg,.png" onChange={onAnexo(key)} />
                        </label>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
            <button style={{ ...S.btnS, width:"100%", marginBottom:4 }}
              onClick={() => { if (!depTitularSel) { setMsg({tipo:"erro",texto:"Selecione o titular."}); return; } setModalPreview(gerarHTMLDependente(depTitularSel,dep,depMov)); }}>
              👁 Visualizar / Imprimir Formulário
            </button>
            <p style={{ fontSize:10, color:"#6B7280", margin:"0 0 16px" }}>
              Imprima, assine e date manualmente. Anexe RG e {dep.dep_grau_parentesco==="FILHO"?"certidão de nascimento":"certidão de casamento"}.
            </p>
            <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
              <button style={S.btnS} onClick={() => { setTipo(null); reset(); }}>Cancelar</button>
              <button style={S.btnP} onClick={salvarDependente} disabled={salvando}>{salvando?"Salvando...":"Registrar Solicitação"}</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL PREVIEW */}
      {modalPreview && (
        <div style={{ ...S.modal, zIndex:1100 }}>
          <div style={{ background:"#fff", borderRadius:12, width:"100%", maxWidth:760, maxHeight:"90vh", overflowY:"auto", boxShadow:"0 20px 60px rgba(0,0,0,.3)" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"12px 20px", borderBottom:"1px solid #E5E7EB" }}>
              <h4 style={{ margin:0, fontSize:14, fontWeight:700, color:"#0F2447" }}>📄 Pré-visualização</h4>
              <div style={{ display:"flex", gap:8 }}>
                <button style={{ ...S.btnP, padding:"6px 14px" }} onClick={imprimir}>🖨 Imprimir</button>
                <button style={S.btnS} onClick={()=>setModalPreview(null)}>Fechar</button>
              </div>
            </div>
            <div dangerouslySetInnerHTML={{ __html:modalPreview }} style={{ padding:"12px 20px" }} />
          </div>
        </div>
      )}

      {/* MODAL ANEXOS */}
      {anexosModal && (
        <div style={{ ...S.modal, zIndex:1100 }}>
          <div style={{ background:"#fff", borderRadius:12, padding:"20px 24px", width:"100%", maxWidth:480 }}>
            <h4 style={{ margin:"0 0 12px", fontSize:14, fontWeight:700, color:"#0F2447" }}>📎 Anexos — #{anexosModal.id} {anexosModal.colaborador_nome}</h4>
            {[
              { key:"FORMULARIO_ASSINADO", label:"Formulário Assinado" },
              { key:"RG_DEPENDENTE", label:"RG do Dependente" },
              { key:"CERTIDAO_CASAMENTO", label:"Certidão de Casamento/Nascimento" },
            ].map(({key,label}) => (
              <div key={key} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"8px 0", borderBottom:"1px solid #F3F4F6" }}>
                <span style={{ fontSize:12, color:"#374151" }}>{label}</span>
                <label style={{ cursor:"pointer", fontSize:11, color:"#3B82F6", fontWeight:600 }}>
                  📁 Enviar
                  <input type="file" style={{ display:"none" }} accept=".pdf,.jpg,.jpeg,.png"
                    onChange={async(e) => {
                      const file = e.target.files[0]; if (!file) return;
                      const reader = new FileReader();
                      reader.onload = async(ev) => {
                        try {
                          await api.addAnexoPlanoSaude(anexosModal.id, { nome_arquivo:file.name, tipo_anexo:key, dados_base64:ev.target.result.split(",")[1] });
                          setMsg({tipo:"ok",texto:`${label} enviado!`});
                        } catch(err) { setMsg({tipo:"erro",texto:err.message}); }
                      };
                      reader.readAsDataURL(file);
                    }}
                  />
                </label>
              </div>
            ))}
            <div style={{ marginTop:14, textAlign:"right" }}>
              <button style={S.btnS} onClick={()=>setAnexosModal(null)}>Fechar</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENTE: AtualizacaoCadastral
// ════════════════════════════════════════════════════════════════════════════

const DOMINIO_POSICAO_ESCALA = [
  { cod: "FA", desc: "Faltista" },
  { cod: "FE", desc: "Ferista" },
  { cod: "FO", desc: "Folguista" },
  { cod: "NA", desc: "Não Aplica" },
  { cod: "TI", desc: "Titular" },
];
const DOMINIO_SIM_NAO = [{ cod: "T", desc: "Sim" }, { cod: "F", desc: "Não" }];
const DOMINIO_MACACAO = ["PP","P","M","G","GG","EG","EEG"];
const DOMINIO_BOTA    = Array.from({ length: 15 }, (_, i) => String(34 + i));

const CAMPOS_CONFIG = {
  posicao_escala:  { label: "Posição Escala",  dominio: DOMINIO_POSICAO_ESCALA, tipo: "select_obj" },
  motorista_lider: { label: "Motorista Líder", dominio: DOMINIO_SIM_NAO,        tipo: "select_obj" },
  munkeiro:        { label: "Munkeiro",         dominio: DOMINIO_SIM_NAO,        tipo: "select_obj" },
  prancheiro:      { label: "Prancheiro",       dominio: DOMINIO_SIM_NAO,        tipo: "select_obj" },
  tamanho_macacao: { label: "Tamanho Macacão",  dominio: DOMINIO_MACACAO,        tipo: "select_str" },
  tamanho_bota:    { label: "Tamanho Bota",     dominio: DOMINIO_BOTA,           tipo: "select_str" },
};

const AC_STATUS_CONFIG = {
  solicitado:  { label: "Solicitado",  bg: "#FEF3C7", color: "#92400E" },
  em_analise:  { label: "Em Análise", bg: "#DBEAFE", color: "#1E40AF" },
  aprovado:    { label: "Aprovado",   bg: "#D1FAE5", color: "#065F46" },
  reprovado:   { label: "Reprovado",  bg: "#FEE2E2", color: "#991B1B" },
  finalizado:  { label: "Finalizado", bg: "#F3F4F6", color: "#374151" },
};

function labelValor(campo, val) {
  if (!val) return "—";
  const cfg = CAMPOS_CONFIG[campo];
  if (!cfg) return val;
  if (cfg.tipo === "select_obj") {
    const found = cfg.dominio.find(d => d.cod === val);
    return found ? `${found.cod} — ${found.desc}` : val;
  }
  return val;
}

function AtualizacaoCadastral({ user, colaboradores }) {
  const [aba, setAba]           = useState("colaboradores"); // "colaboradores" | "solicitacoes"
  const [solicitacoes, setSolicitacoes] = useState([]);
  const [loadingSols, setLoadingSols]   = useState(false);
  const [msg, setMsg]           = useState(null);
  const [salvando, setSalvando] = useState(false);

  // Filtros colaboradores
  const [fNome, setFNome]             = useState("");
  const [fNomeCompleto, setFNomeCompleto] = useState("");
  const [fFuncao, setFuncao]          = useState("");
  const [fFilial, setFFilial]         = useState("");
  const [fPosEscala, setFPosEscala]   = useState("");
  const [fMotLider, setFMotLider]     = useState("");
  const [fMunkeiro, setFMunkeiro]     = useState("");
  const [fPrancheiro, setFPrancheiro] = useState("");
  const [fMacacao, setFMacacao]       = useState("");
  const [fBota, setFBota]             = useState("");

  // Filtros solicitações
  const [fStatus, setFStatus]   = useState("todos");
  const [fDataIni, setFDataIni] = useState("");
  const [fDataFim, setFDataFim] = useState("");
  const [fSolic, setFSolic]     = useState("");

  // Modal solicitação
  const [modalNova, setModalNova]   = useState(null); // colaborador selecionado
  const [itens, setItens]           = useState({});
  const [observacao, setObservacao] = useState("");

  // Modal detalhe
  const [modalDetalhe, setModalDetalhe] = useState(null);
  const [obsAprov, setObsAprov]         = useState("");
  const [editando, setEditando]         = useState(false);
  const [itensEdit, setItensEdit]       = useState({});
  const [obsEdit, setObsEdit]           = useState("");

  const norm = s => (s || "").toLowerCase();
  const canAprovar = user.perfil === "dp" || user.perfil === "admin";
  const canEditar  = (s) => s && s.status !== "finalizado" && s.status !== "reprovado";

  const colabsAtivos = colaboradores.filter(c => c.cod_situacao !== "D");
  const fmtFilial = (c) => {
    const f = c.descricao_filial || c.desc_cc || "";
    return f.replace(/^BENEL TRANSPORTES\s*[-–]\s*/i, "").trim();
  };

  const colabsFiltrados = colabsAtivos.filter(c =>
    (!fNome          || (c.chapa||"").toLowerCase().includes(fNome.toLowerCase())) &&
    (!fNomeCompleto  || norm(c.nome).includes(norm(fNomeCompleto))) &&
    (!fFuncao        || norm(c.funcao||"").includes(norm(fFuncao))) &&
    (!fFilial        || norm(fmtFilial(c)).includes(norm(fFilial)) || norm(c.desc_cc||"").includes(norm(fFilial))) &&
    (!fPosEscala     || norm(c.posicao_escala||"").includes(norm(fPosEscala))) &&
    (!fMotLider      || (fMotLider   === "S" ? c.motorista_lider === "T" : c.motorista_lider !== "T")) &&
    (!fMunkeiro      || (fMunkeiro   === "S" ? c.munkeiro        === "T" : c.munkeiro        !== "T")) &&
    (!fPrancheiro    || (fPrancheiro === "S" ? c.prancheiro      === "T" : c.prancheiro      !== "T")) &&
    (!fMacacao       || norm(c.tamanho_macacao||"").includes(norm(fMacacao))) &&
    (!fBota          || norm(String(c.tamanho_bota||"")).includes(norm(fBota)))
  );

  const carregarSols = async () => {
    setLoadingSols(true);
    try {
      const params = {};
      if (fStatus !== "todos") params.status = fStatus;
      if (fDataIni) params.data_inicio = fDataIni;
      if (fDataFim) params.data_fim = fDataFim;
      if (fSolic)   params.solicitante = fSolic;
      const data = await api.listarAtualizacaoCadastral(params);
      let sols = Array.isArray(data) ? data : [];
      // Gestor e Superior só veem as próprias solicitações
      if (user.perfil === "gestor" || user.perfil === "superior") {
        sols = sols.filter(s => s.usuario_solicitante_id === user.id);
      }
      setSolicitacoes(sols);
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setLoadingSols(false); }
  };

  useEffect(() => { if (aba === "solicitacoes") carregarSols(); }, [aba]);

  const salvar = async () => {
    if (!modalNova) return;
    const itensList = Object.entries(itens).filter(([,v]) => v).map(([campo, novo_valor]) => ({ campo, novo_valor }));
    if (itensList.length === 0) { setMsg({ tipo: "erro", texto: "Selecione ao menos um campo para alterar." }); return; }
    setSalvando(true);
    try {
      await api.criarAtualizacaoCadastral({ colaborador_id: modalNova.id, itens: itensList, observacao });
      setMsg({ tipo: "ok", texto: "Solicitação criada com sucesso!" });
      setModalNova(null); setItens({}); setObservacao("");
      if (aba === "solicitacoes") carregarSols();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setSalvando(false); }
  };

  const aprovar = async (acao) => {
    setSalvando(true);
    try {
      await api.aprovarAtualizacaoCadastral(modalDetalhe.id, acao, obsAprov);
      setMsg({ tipo: "ok", texto: `Solicitação ${acao === "aprovar" ? "aprovada" : "reprovada"}!` });
      setModalDetalhe(null); setObsAprov(""); carregarSols();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setSalvando(false); }
  };

  const salvarEdicao = async () => {
    const itensList = Object.entries(itensEdit).filter(([,v]) => v).map(([campo, novo_valor]) => ({ campo, novo_valor }));
    if (itensList.length === 0) { setMsg({ tipo: "erro", texto: "Selecione ao menos um campo para alterar." }); return; }
    setSalvando(true);
    try {
      // Cancela a atual e cria nova
      await api.cancelarAtualizacaoCadastral(modalDetalhe.id);
      await api.criarAtualizacaoCadastral({ colaborador_id: modalDetalhe.colaborador_id, itens: itensList, observacao: obsEdit });
      setMsg({ tipo: "ok", texto: "Solicitação atualizada com sucesso!" });
      setModalDetalhe(null); setEditando(false); setItensEdit({}); setObsEdit("");
      carregarSols();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setSalvando(false); }
  };

  const S = {
    inp:  { width: "100%", padding: "3px 6px", border: "1px solid #D1D5DB", borderRadius: 6, fontSize: 12, boxSizing: "border-box" },
    lbl:  { fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 3 },
    btnP: { background: "#0F2447", color: "#fff", border: "none", borderRadius: 8, padding: "8px 18px", fontSize: 11, fontWeight: 700, cursor: "pointer" },
    btnS: { background: "#F3F4F6", color: "#374151", border: "1px solid #D1D5DB", borderRadius: 8, padding: "3px 6px", fontSize: 11, fontWeight: 600, cursor: "pointer" },
    btnV: { background: "#059669", color: "#fff", border: "none", borderRadius: 8, padding: "3px 6px", fontSize: 11, fontWeight: 700, cursor: "pointer" },
    btnR: { background: "#DC2626", color: "#fff", border: "none", borderRadius: 8, padding: "3px 6px", fontSize: 11, fontWeight: 700, cursor: "pointer" },
    modal:{ position: "fixed", inset: 0, background: "rgba(0,0,0,.5)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" },
    mbox: { background: "#fff", borderRadius: 14, padding: "24px 28px", width: "100%", maxWidth: 700, maxHeight: "90vh", overflowY: "auto", boxShadow: "0 20px 60px rgba(0,0,0,.25)" },
    th:   { padding: "3px 6px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", letterSpacing: 0.5, whiteSpace: "nowrap" },
    td:   { padding: "3px 6px", fontSize: 11, borderBottom: "1px solid #F3F4F6" },
  };

  const SimNaoTag = ({ val }) => {
    if (!val) return <span style={{ color: "#9CA3AF" }}>—</span>;
    return <span style={{ padding: "1px 6px", borderRadius: 8, fontSize: 10, fontWeight: 700, background: val === "T" ? "#D1FAE5" : "#FEE2E2", color: val === "T" ? "#065F46" : "#991B1B" }}>{val === "T" ? "Sim" : "Não"}</span>;
  };

  return (
    <div style={{ padding: "16px 20px", maxWidth: 1200, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#111827" }}>📝 Atualização de Dados Cadastrais</h2>
          <p style={{ margin: "2px 0 0", fontSize: 11, color: "#6B7280" }}>Solicitação de alteração com aprovação do DP</p>
        </div>
      </div>

      {/* Msg */}
      {msg && (
        <div style={{ padding: "3px 6px", borderRadius: 7, marginBottom: 12, background: msg.tipo === "ok" ? "#D1FAE5" : "#FEE2E2", color: msg.tipo === "ok" ? "#065F46" : "#991B1B", fontSize: 11, fontWeight: 600, display: "flex", justifyContent: "space-between" }}>
          {msg.texto}
          <button onClick={() => setMsg(null)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 14 }}>×</button>
        </div>
      )}

      {/* Abas */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "2px solid #E5E7EB" }}>
        {[["colaboradores","👥 Colaboradores"], ["solicitacoes","📋 Solicitações"]].map(([id, label]) => (
          <button key={id} onClick={() => setAba(id)} style={{
            padding: "8px 18px", fontSize: 11, fontWeight: 600, border: "none", cursor: "pointer",
            background: "none", borderBottom: aba === id ? "2px solid #0F2447" : "2px solid transparent",
            color: aba === id ? "#0F2447" : "#6B7280", marginBottom: -2
          }}>{label}</button>
        ))}
      </div>

      {/* ABA COLABORADORES */}
      {aba === "colaboradores" && (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", lineHeight: "1.2", background: "#fff", borderRadius: 10, overflow: "hidden", border: "1px solid #E5E7EB", fontSize: 11 }}>
              <thead>
                <tr style={{ background: "#F9FAFB", borderBottom: "1px solid #E5E7EB" }}>
                  <th style={S.th}>Filial</th>
                  <th style={S.th}>Matrícula</th>
                  <th style={S.th}>Nome</th>
                  <th style={S.th}>Função</th>
                  <th style={S.th}>Pos. Escala</th>
                  <th style={S.th}>Mot. Líder</th>
                  <th style={S.th}>Munkeiro</th>
                  <th style={S.th}>Prancheiro</th>
                  <th style={S.th}>Macacão</th>
                  <th style={S.th}>Bota</th>
                  <th style={S.th}>Ação</th>
                </tr>
                <tr style={{ background: "#F9FAFB", borderBottom: "2px solid #E5E7EB" }}>
                  <td style={{ padding: "3px 5px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Filial" value={fFilial} onChange={e => setFFilial(e.target.value)} /></td>
                  <td style={{ padding: "3px 5px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Matrícula" value={fNome} onChange={e => setFNome(e.target.value)} /></td>
                  <td style={{ padding: "3px 5px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Nome" value={fNomeCompleto} onChange={e => setFNomeCompleto(e.target.value)} /></td>
                  <td style={{ padding: "3px 5px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Função" value={fFuncao} onChange={e => setFuncao(e.target.value)} /></td>
                  <td style={{ padding: "3px 5px" }}>
                    <select style={{ ...S.inp, fontSize: 11 }} value={fPosEscala} onChange={e => setFPosEscala(e.target.value)}>
                      <option value="">Todas</option>
                      <option value="FA">FA</option>
                      <option value="FE">FE</option>
                      <option value="FO">FO</option>
                      <option value="NA">NA</option>
                      <option value="TI">TI</option>
                    </select>
                  </td>
                  <td style={{ padding: "3px 5px" }}>
                    <select style={{ ...S.inp, fontSize: 11 }} value={fMotLider} onChange={e => setFMotLider(e.target.value)}>
                      <option value="">Todos</option>
                      <option value="S">Sim</option>
                      <option value="N">Não</option>
                    </select>
                  </td>
                  <td style={{ padding: "3px 5px" }}>
                    <select style={{ ...S.inp, fontSize: 11 }} value={fMunkeiro} onChange={e => setFMunkeiro(e.target.value)}>
                      <option value="">Todos</option>
                      <option value="S">Sim</option>
                      <option value="N">Não</option>
                    </select>
                  </td>
                  <td style={{ padding: "3px 5px" }}>
                    <select style={{ ...S.inp, fontSize: 11 }} value={fPrancheiro} onChange={e => setFPrancheiro(e.target.value)}>
                      <option value="">Todos</option>
                      <option value="S">Sim</option>
                      <option value="N">Não</option>
                    </select>
                  </td>
                  <td style={{ padding: "3px 5px" }}>
                    <select style={{ ...S.inp, fontSize: 11 }} value={fMacacao} onChange={e => setFMacacao(e.target.value)}>
                      <option value="">Todos</option>
                      {["PP","P","M","G","GG","EG","EEG"].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </td>
                  <td style={{ padding: "3px 5px" }}>
                    <input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Bota" value={fBota} onChange={e => setFBota(e.target.value)} />
                  </td>
                  <td style={{ padding: "3px 5px", whiteSpace: "nowrap" }}>
                    <button onClick={() => { setFNome(""); setFNomeCompleto(""); setFuncao(""); setFFilial(""); setFPosEscala(""); setFMotLider(""); setFMunkeiro(""); setFPrancheiro(""); setFMacacao(""); setFBota(""); }}
                      style={{ padding: "3px 7px", border: "1px solid #D1D5DB", borderRadius: 6, background: "#fff", color: "#374151", fontSize: 11, cursor: "pointer" }}>
                      × Limpar
                    </button>
                    <span style={{ marginLeft: 8, fontSize: 11, color: "#6B7280" }}>{colabsFiltrados.length}</span>
                  </td>
                </tr>
              </thead>
              <tbody>
                {colabsFiltrados.slice(0, 100).map(c => (
                  <tr key={c.id} onMouseEnter={e => e.currentTarget.style.background = "#F9FAFB"} onMouseLeave={e => e.currentTarget.style.background = ""}>
                    <td style={S.td}>{fmtFilial(c)}</td>
                    <td style={{ ...S.td, fontWeight: 700 }}>{c.chapa}</td>
                    <td style={S.td}>{c.nome}</td>
                    <td style={{ ...S.td, color: "#6B7280" }}>{c.funcao}</td>
                    <td style={S.td}>{c.posicao_escala ? labelValor("posicao_escala", c.posicao_escala) : <span style={{ color: "#9CA3AF" }}>—</span>}</td>
                    <td style={S.td}><SimNaoTag val={c.motorista_lider} /></td>
                    <td style={S.td}><SimNaoTag val={c.munkeiro} /></td>
                    <td style={S.td}><SimNaoTag val={c.prancheiro} /></td>
                    <td style={S.td}>{c.tamanho_macacao || <span style={{ color: "#9CA3AF" }}>—</span>}</td>
                    <td style={S.td}>{c.tamanho_bota || <span style={{ color: "#9CA3AF" }}>—</span>}</td>
                    <td style={S.td}>
                      <button style={{ ...S.btnP, padding: "4px 10px", fontSize: 11 }}
                        onClick={() => { setModalNova(c); setItens({}); setObservacao(""); }}>
                        Solicitar
                      </button>
                    </td>
                  </tr>
                ))}
                {colabsFiltrados.length > 100 && (
                  <tr><td colSpan={11} style={{ ...S.td, textAlign: "center", color: "#6B7280" }}>
                    Mostrando 100 de {colabsFiltrados.length}. Use os filtros para refinar.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ABA SOLICITAÇÕES */}
      {aba === "solicitacoes" && (
        <>
          <div style={{ background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 10, padding: "12px 16px", marginBottom: 12 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr auto", gap: 10, alignItems: "end" }}>
              <div>
                <label style={S.lbl}>Status</label>
                <select style={S.inp} value={fStatus} onChange={e => setFStatus(e.target.value)}>
                  <option value="todos">Todos</option>
                  <option value="solicitado">Solicitado</option>
                  <option value="em_analise">Em Análise</option>
                  <option value="aprovado">Aprovado</option>
                  <option value="reprovado">Reprovado</option>
                  <option value="finalizado">Finalizado</option>
                </select>
              </div>
              <div><label style={S.lbl}>Data início</label><input type="date" style={S.inp} value={fDataIni} onChange={e => setFDataIni(e.target.value)} /></div>
              <div><label style={S.lbl}>Data fim</label><input type="date" style={S.inp} value={fDataFim} onChange={e => setFDataFim(e.target.value)} /></div>
              <div><label style={S.lbl}>Solicitante</label><input style={S.inp} placeholder="Nome..." value={fSolic} onChange={e => setFSolic(e.target.value)} /></div>
              <button style={S.btnP} onClick={carregarSols}>🔍 Filtrar</button>
            </div>
          </div>

          {loadingSols ? (
            <div style={{ textAlign: "center", padding: 40, color: "#9CA3AF" }}>Carregando...</div>
          ) : solicitacoes.length === 0 ? (
            <div style={{ textAlign: "center", padding: 60, color: "#9CA3AF" }}>Nenhuma solicitação encontrada.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", lineHeight: "1.2", background: "#fff", borderRadius: 10, overflow: "hidden", border: "1px solid #E5E7EB" }}>
              <thead>
                <tr style={{ background: "#F9FAFB", borderBottom: "2px solid #E5E7EB" }}>
                  {["Filial","Matrícula","Nome","Função","Admissão","Solicitante","Data","Status","Ações"].map(h => (
                    <th key={h} style={S.th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {solicitacoes.map(s => {
                  const stCfg = AC_STATUS_CONFIG[s.status] || {};
                  return (
                    <tr key={s.id} onMouseEnter={e => e.currentTarget.style.background = "#F9FAFB"} onMouseLeave={e => e.currentTarget.style.background = ""}>
                      <td style={{ ...S.td, fontSize: 10 }}>{(s.descricao_filial || s.desc_cc || "").replace(/^BENEL TRANSPORTES\s*[-–]\s*/i,"").trim() || "—"}</td>
                      <td style={{ ...S.td, fontWeight: 700 }}>{s.chapa}</td>
                      <td style={S.td}>{s.colaborador_nome}</td>
                      <td style={{ ...S.td, color: "#6B7280" }}>{s.funcao}</td>
                      <td style={{ ...S.td, color: "#6B7280" }}>{s.data_admissao ? new Date(s.data_admissao).toLocaleDateString("pt-BR") : "—"}</td>
                      <td style={S.td}>{s.usuario_solicitante_nome}</td>
                      <td style={{ ...S.td, color: "#6B7280" }}>{new Date(s.criado_em).toLocaleDateString("pt-BR")}</td>
                      <td style={S.td}>
                        <span style={{ padding: "1px 6px", borderRadius: 8, fontSize: 10, fontWeight: 700, background: stCfg.bg, color: stCfg.color }}>
                          {stCfg.label || s.status}
                        </span>
                      </td>
                      <td style={S.td}>
                        <button style={{ ...S.btnS, padding: "4px 10px", fontSize: 11 }} onClick={() => { setModalDetalhe(s); setObsAprov(""); }}>
                          Ver
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </>
      )}

      {/* MODAL SOLICITAR ALTERAÇÃO */}
      {modalNova && (
        <div style={S.modal}>
          <div style={S.mbox}>
            <h3 style={{ margin: "0 0 6px", fontSize: 15, fontWeight: 800, color: "#0F2447" }}>Solicitar Alteração Cadastral</h3>
            <div style={{ padding: "3px 6px", background: "#EFF6FF", borderRadius: 8, marginBottom: 16, fontSize: 12, color: "#1E40AF" }}>
              <strong>{fmtFilial(modalNova)}</strong> | {modalNova.chapa} | {modalNova.nome} | {modalNova.funcao} | {modalNova.data_admissao ? new Date(modalNova.data_admissao).toLocaleDateString("pt-BR") : "—"}
            </div>

            <div style={{ background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 8, padding: "14px", marginBottom: 14 }}>
              <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 700, color: "#374151" }}>CAMPOS PARA ALTERAR</p>
              <p style={{ margin: "0 0 12px", fontSize: 11, color: "#6B7280" }}>Selecione apenas os campos que deseja alterar.</p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                {Object.entries(CAMPOS_CONFIG).map(([campo, cfg]) => (
                  <div key={campo}>
                    <label style={S.lbl}>{cfg.label}</label>
                    <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 4 }}>
                      Atual: <strong style={{ color: modalNova[campo] ? "#374151" : "#9CA3AF" }}>
                        {modalNova[campo] ? labelValor(campo, modalNova[campo]) : "Não informado"}
                      </strong>
                    </div>
                    <select style={S.inp} value={itens[campo] || ""} onChange={e => setItens(p => ({ ...p, [campo]: e.target.value || undefined }))}>
                      <option value="">— sem alteração —</option>
                      {cfg.tipo === "select_obj"
                        ? cfg.dominio.map(d => <option key={d.cod} value={d.cod}>{d.cod} — {d.desc}</option>)
                        : cfg.dominio.map(v => <option key={v} value={v}>{v}</option>)
                      }
                    </select>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={S.lbl}>Observação</label>
              <textarea style={{ ...S.inp, height: 56, resize: "vertical" }} value={observacao} onChange={e => setObservacao(e.target.value)} placeholder="Justificativa ou observação..." />
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button style={S.btnS} onClick={() => setModalNova(null)}>Cancelar</button>
              <button style={S.btnP} onClick={salvar} disabled={salvando}>{salvando ? "Salvando..." : "Registrar Solicitação"}</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL DETALHE */}
      {modalDetalhe && (
        <div style={{ ...S.modal, zIndex: 1100 }}>
          <div style={{ ...S.mbox, maxWidth: 580 }}>
            <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 800, color: "#0F2447" }}>Solicitação #{modalDetalhe.id}</h3>
            <p style={{ margin: "0 0 14px", fontSize: 11, color: "#6B7280" }}>{modalDetalhe.chapa} | {modalDetalhe.colaborador_nome}</p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 14, fontSize: 11 }}>
              <div style={{ background: "#F9FAFB", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 2 }}>SOLICITANTE</div>
                <strong>{modalDetalhe.usuario_solicitante_nome}</strong>
              </div>
              <div style={{ background: "#F9FAFB", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 2 }}>DATA</div>
                <strong>{new Date(modalDetalhe.criado_em).toLocaleDateString("pt-BR")}</strong>
              </div>
              <div style={{ background: "#F9FAFB", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 2 }}>STATUS</div>
                <span style={{ padding: "1px 6px", borderRadius: 8, fontSize: 10, fontWeight: 700, background: AC_STATUS_CONFIG[modalDetalhe.status]?.bg, color: AC_STATUS_CONFIG[modalDetalhe.status]?.color }}>
                  {AC_STATUS_CONFIG[modalDetalhe.status]?.label}
                </span>
              </div>
            </div>

            <div style={{ background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 8, padding: "12px 14px", marginBottom: 14 }}>
              <p style={{ margin: "0 0 8px", fontSize: 11, fontWeight: 700, color: "#374151" }}>ALTERAÇÕES</p>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #E5E7EB" }}>
                    <th style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, color: "#6B7280" }}>Campo</th>
                    <th style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, color: "#6B7280" }}>Antes</th>
                    <th style={{ padding: "3px 6px", textAlign: "left", fontSize: 10, color: "#6B7280" }}>Depois</th>
                  </tr>
                </thead>
                <tbody>
                  {(modalDetalhe.itens || []).map((item, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid #F3F4F6" }}>
                      <td style={{ padding: "3px 6px", fontWeight: 600 }}>{CAMPOS_CONFIG[item.campo]?.label || item.campo}</td>
                      <td style={{ padding: "3px 6px", color: "#991B1B" }}>{labelValor(item.campo, item.valor_anterior)}</td>
                      <td style={{ padding: "3px 6px", color: "#065F46", fontWeight: 700 }}>{labelValor(item.campo, item.novo_valor)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {modalDetalhe.observacao && (
              <div style={{ background: "#FFFBEB", border: "1px solid #FDE68A", borderRadius: 6, padding: "3px 6px", marginBottom: 14, fontSize: 11 }}>
                <strong>Obs:</strong> {modalDetalhe.observacao}
              </div>
            )}

            {canAprovar && ["solicitado","em_analise"].includes(modalDetalhe.status) && (
              <div style={{ marginBottom: 14 }}>
                <label style={S.lbl}>Observação do aprovador</label>
                <textarea style={{ ...S.inp, height: 44, resize: "vertical" }} value={obsAprov} onChange={e => setObsAprov(e.target.value)} placeholder="Opcional..." />
              </div>
            )}

            {/* EDIÇÃO INLINE */}
            {editando && (
              <div style={{ background: "#F0FDF4", border: "1px solid #BBF7D0", borderRadius: 8, padding: "14px", marginBottom: 14 }}>
                <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, color: "#065F46" }}>✏️ EDITAR SOLICITAÇÃO</p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                  {Object.entries(CAMPOS_CONFIG).map(([campo, cfg]) => (
                    <div key={campo}>
                      <label style={S.lbl}>{cfg.label}</label>
                      <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 3 }}>
                        Atual: <strong>{(modalDetalhe.itens||[]).find(i=>i.campo===campo) ? labelValor(campo,(modalDetalhe.itens||[]).find(i=>i.campo===campo).novo_valor) : "—"}</strong>
                      </div>
                      <select style={S.inp} value={itensEdit[campo]||""} onChange={e => setItensEdit(p => ({ ...p, [campo]: e.target.value || undefined }))}>
                        <option value="">— sem alteração —</option>
                        {cfg.tipo === "select_obj"
                          ? cfg.dominio.map(d => <option key={d.cod} value={d.cod}>{d.cod} — {d.desc}</option>)
                          : cfg.dominio.map(v => <option key={v} value={v}>{v}</option>)
                        }
                      </select>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 10 }}>
                  <label style={S.lbl}>Observação</label>
                  <textarea style={{ ...S.inp, height: 44, resize: "vertical" }} value={obsEdit} onChange={e => setObsEdit(e.target.value)} placeholder="Justificativa..." />
                </div>
              </div>
            )}

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button style={S.btnS} onClick={() => { setModalDetalhe(null); setEditando(false); setItensEdit({}); setObsEdit(""); }}>Fechar</button>
              {canEditar(modalDetalhe) && !editando && (
                <button style={{ ...S.btnS, borderColor: "#3B82F6", color: "#3B82F6" }}
                  onClick={() => {
                    const prefill = {};
                    (modalDetalhe.itens||[]).forEach(i => { prefill[i.campo] = i.novo_valor; });
                    setItensEdit(prefill);
                    setObsEdit(modalDetalhe.observacao || "");
                    setEditando(true);
                  }}>
                  ✏️ Editar
                </button>
              )}
              {editando && (
                <>
                  <button style={S.btnS} onClick={() => { setEditando(false); setItensEdit({}); setObsEdit(""); }}>Cancelar edição</button>
                  <button style={{ ...S.btnP, background: "#059669" }} onClick={salvarEdicao} disabled={salvando}>{salvando ? "Salvando..." : "💾 Salvar alterações"}</button>
                </>
              )}
              {canAprovar && !editando && ["solicitado","em_analise"].includes(modalDetalhe.status) && (
                <>
                  <button style={S.btnR} onClick={() => aprovar("reprovar")} disabled={salvando}>✗ Reprovar</button>
                  <button style={S.btnV} onClick={() => aprovar("aprovar")} disabled={salvando}>✓ Aprovar</button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


export default function App() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState("dashboard");

  // ── Estado global dos cadastros ──
  const [colaboradores, setColaboradores] = useState([]);
  const [eventos, setEventos] = useState([]);
  const [usuarios, setUsuarios] = useState([]);
  const [hierarquia, setHierarquia] = useState([]);
  const [alcadas, setAlcadas] = useState([]);
  const [solicitacoes, setSolicitacoes] = useState([]);
  const [blocos, setBlocos] = useState([]);
  const [sessao, setSessao] = useState(null);
  const [sessaoAviso, setSessaoAviso] = useState(false);

  // ── Carregar dados reais da API após login ────────────────────────────────
  const carregarDados = useCallback(async () => {
    try {
      const [cols, evts, blcs, usrs, hier, alcs] = await Promise.all([
        api.listarColaboradores().catch(() => null),
        api.listarEventos().catch(() => null),
        api.listarBlocos().catch(() => null),
        api.listarUsuarios().catch(() => null),
        api.listarHierarquia().catch(() => null),
        api.listarAlcadas().catch(() => null),
      ]);
      if (cols && cols.length > 0) setColaboradores(cols);
      if (evts && evts.length > 0) setEventos(evts);
      if (hier && hier.length > 0) setHierarquia(hier);
      if (alcs && alcs.length > 0) setAlcadas(alcs);
      if (usrs && usrs.length > 0) {
        const comAvatar = usrs.map(u => ({
          ...u,
          avatar: u.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase()
        }));
        setUsuarios(comAvatar);
      }
      if (blcs && blcs.length > 0) {
        const evtsRef = evts || [];
        const colsRef = cols || [];
        const blocsNorm = blcs.map(b => {
          const ev = evtsRef.find(e => e.id === b.evento_id) || null;
          return {
            ...b,
            linhas: (b.linhas || []).map(l => ({
              ...l,
              colaborador: l.colaborador || colsRef.find(c => c.id === l.colaborador_id),
              evento: l.evento || ev,
            })),
            historico: b.historico || [],
            evento: ev,
            solicitante: b.solicitante_nome || b.solicitante || "",
          };
        });
        setBlocos(blocsNorm);
      }
    } catch (err) {
      console.warn("Usando dados locais — API indisponível:", err.message);
    }
  }, []);

  // Verificar expiração de sessão a cada minuto + registrar callback API
  useEffect(() => {
    if (!user) return;

    // Callback quando sessão expirar via API (401 sem refresh)
    onSessionExpired(() => {
      registrarAuditoria(sessao, ACOES.SESSAO_EXPIRADA, {});
      encerrarSessao();
      clearTokens();
      setUser(null);
      setSessao(null);
    });

    carregarDados();

    const interval = setInterval(() => {
      const s = obterSessao();
      if (!s) {
        registrarAuditoria(sessao, ACOES.SESSAO_EXPIRADA, {});
        setUser(null);
        setSessao(null);
      } else {
        const restante = 15 * 60 * 1000 - (Date.now() - s.ultimaAtividade);
        setSessaoAviso(restante < 5 * 60 * 1000);
      }
    }, 60000);
    return () => clearInterval(interval);
  }, [user, sessao, carregarDados]);

  const PAGE_TITLES = {
    dashboard:        { title: "Dashboard",               subtitle: "Visão geral das solicitações" },
    solicitacoes:     { title: "Solicitações de Pagamento", subtitle: "Registre e envie variáveis de pagamento para aprovação" },
    aprovacoes:       { title: "Aprovações",              subtitle: "Fila de aprovação por bloco" },
    exportacao:       { title: "Exportação TXT",          subtitle: "Geração do arquivo TOTVS RM" },
    cad_colaboradores:{ title: "Colaboradores",           subtitle: "Cadastros › Colaboradores" },
    cad_eventos:      { title: "Eventos da Folha",        subtitle: "Cadastros › Eventos" },
    cad_hierarquia:   { title: "Hierarquia de Aprovação", subtitle: "Cadastros › Hierarquia" },
    cad_alcadas:      { title: "Regras de Alçadas",       subtitle: "Cadastros › Alçadas" },
    cad_usuarios:     { title: "Usuários do Sistema",     subtitle: "Cadastros › Usuários" },
    auditoria:        { title: "Auditoria",               subtitle: "Log completo de ações" },
    plano_saude:      { title: "Benefícios",               subtitle: "" },
    desligamentos:    { title: "Solicitações de Desligamento",              subtitle: "Gerencie solicitações de desligamento de colaboradores" },
    atualizacao_cadastral: { title: "Atualização de Dados Cadastrais", subtitle: "Solicitação de alteração cadastral" },
    ocorrencias:      { title: "Solicitações de Advertências/Suspensões",   subtitle: "Registro de ocorrências disciplinares" },
    autorizacoes:     { title: "Autorização de Desconto",                   subtitle: "Autorização para desconto na folha de pagamento" },
  };

  if (!user) return <Login onLogin={(u, s) => { setUser(u); setSessao(s); setPage("solicitacoes"); }} />;

  const { title, subtitle } = PAGE_TITLES[page] || {};

  const solsParaDashboard = blocos.flatMap(b =>
    b.linhas.map(l => ({ ...l, status: b.status, tipo: l.evento?.descricao || "" }))
  );

  const solsParaExportacao = blocos
    .filter(b => b.status === "aprovado_final")
    .flatMap(b => b.linhas.map(l => ({ ...l, status: b.status, competencia: b.competencia })));

  return (
    <div style={{ display: "flex", minHeight: "100vh", fontFamily: "'DM Sans', sans-serif", background: "#F8FAFC" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />
      <Sidebar active={page} onNav={setPage} user={user} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <Topbar title={title} subtitle={subtitle} user={user} onLogout={async () => { registrarAuditoria(sessao, ACOES.LOGOUT, {}); try { await api.logout(); } catch(_) {} encerrarSessao(); clearTokens(); setUser(null); setSessao(null); }} />
        {sessaoAviso && (
          <div style={{
            background: "#FFFBEB", borderBottom: "1px solid #FCD34D",
            padding: "8px 28px", fontSize: 12, color: "#92400E",
            display: "flex", alignItems: "center", gap: 8
          }}>
            ⚠️ <b>Sua sessão expira em menos de 5 minutos</b> por inatividade. Salve seu trabalho.
          </div>
        )}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {page === "dashboard"         && <Dashboard solicitacoes={solsParaDashboard} blocos={blocos} user={user} />}
          {page === "solicitacoes"      && <Solicitacoes solicitacoes={solicitacoes} setSolicitacoes={setSolicitacoes} blocos={blocos} setBlocos={setBlocos} user={user} colaboradores={colaboradores} eventos={eventos} recarregarDados={carregarDados} />}
          {page === "aprovacoes"        && <Aprovacoes blocos={blocos} setBlocos={setBlocos} user={user} recarregarDados={carregarDados} />}
          {page === "exportacao"        && <Exportacao solicitacoes={solsParaExportacao} blocos={blocos.filter(b => b.status === "aprovado_final")} />}
          {page === "cad_colaboradores" && <CadColaboradores colaboradores={colaboradores} setColaboradores={setColaboradores} />}
          {page === "cad_eventos"       && <CadEventos eventos={eventos} setEventos={setEventos} />}
          {page === "cad_hierarquia"    && <CadHierarquia hierarquia={hierarquia} setHierarquia={setHierarquia} usuarios={usuarios} />}
          {page === "cad_alcadas"       && <CadAlcadas alcadas={alcadas} setAlcadas={setAlcadas} eventos={eventos} />}
          {page === "cad_usuarios"      && <CadUsuarios usuarios={usuarios} setUsuarios={setUsuarios} />}
          {page === "desligamentos"     && <Desligamentos user={user} colaboradores={colaboradores} api={api} recarregarDados={carregarDados} />}
          {page === "auditoria"         && <Auditoria solicitacoes={solicitacoes} blocos={blocos} sessao={sessao} />}
          {page === "ocorrencias"       && <Ocorrencias user={user} colaboradores={colaboradores} />}
          {page === "autorizacoes"      && <Autorizacoes user={user} colaboradores={colaboradores} />}
          {page === "atualizacao_cadastral" && <AtualizacaoCadastral user={user} colaboradores={colaboradores} />}
          {page === "plano_saude" && <PlanoSaude user={user} colaboradores={colaboradores} />}
        </div>
      </div>
    </div>
  );
}
