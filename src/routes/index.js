// src/api.js — Camada de comunicação com o backend DP Flow  

const BASE = import.meta.env.VITE_API_URL || "https://benel-dpflow-backend.vercel.app";

let _accessToken = null;
let _refreshToken = null;
let _onSessionExpired = null;

export function setTokens(access, refresh) {
  _accessToken = access;
  _refreshToken = refresh;
  if (refresh) sessionStorage.setItem("dpflow_refresh", refresh);
  if (access)  sessionStorage.setItem("dpflow_access",  access);
}

export function getAccessToken() { return _accessToken; }

export function loadTokensFromStorage() {
  _accessToken  = sessionStorage.getItem("dpflow_access");
  _refreshToken = sessionStorage.getItem("dpflow_refresh");
  return { accessToken: _accessToken, refreshToken: _refreshToken };
}

export function clearTokens() {
  _accessToken  = null;
  _refreshToken = null;
  sessionStorage.removeItem("dpflow_refresh");
  sessionStorage.removeItem("dpflow_access");
}

export function onSessionExpired(callback) {
  _onSessionExpired = callback;
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (_accessToken) headers["Authorization"] = `Bearer ${_accessToken}`;

  let res = await fetch(`${BASE}/api${path}`, { ...options, headers });

  // Token expirado — tentar refresh automático
  if (res.status === 401 && _refreshToken) {
    try {
      const rr = await fetch(`${BASE}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: _refreshToken }),
      });
      if (rr.ok) {
        const rd = await rr.json();
        setTokens(rd.data.accessToken, rd.data.refreshToken);
        headers["Authorization"] = `Bearer ${_accessToken}`;
        res = await fetch(`${BASE}/api${path}`, { ...options, headers });
      } else {
        clearTokens();
        if (_onSessionExpired) _onSessionExpired();
        throw Object.assign(new Error("Sessão expirada. Faça login novamente."), { code: "SESSION_EXPIRED" });
      }
    } catch (e) {
      if (e.code === "SESSION_EXPIRED") throw e;
      clearTokens();
      if (_onSessionExpired) _onSessionExpired();
      throw Object.assign(new Error("Sessão expirada. Faça login novamente."), { code: "SESSION_EXPIRED" });
    }
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.message || `Erro ${res.status}`);
  return data.data ?? data;
}

export const api = {
  // ── Auth ──────────────────────────────────────────────────────────────────
  login: (email, senha) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email, senha }) }),

  logout: () =>
    request("/auth/logout", { method: "POST" }),

  me: () => request("/auth/me"),

  // ── Colaboradores ─────────────────────────────────────────────────────────
  listarColaboradores: (incluirDemitidos = false) =>
    request(`/colaboradores${incluirDemitidos ? "?incluirDemitidos=true" : ""}`),

  buscarColaboradores: (q) =>
    request(`/colaboradores/buscar?q=${encodeURIComponent(q)}`),

  criarColaborador: (data) =>
    request("/colaboradores", { method: "POST", body: JSON.stringify(data) }),

  atualizarColaborador: (id, data) =>
    request(`/colaboradores/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  importarColaboradores: (lista) =>
    request("/colaboradores/importar", {
      method: "POST",
      body: JSON.stringify({ colaboradores: lista }),
    }),

  // ── Eventos ───────────────────────────────────────────────────────────────
  listarEventos: () => request("/eventos"),

  criarEvento: (data) =>
    request("/eventos", { method: "POST", body: JSON.stringify(data) }),

  atualizarEvento: (id, data) =>
    request(`/eventos/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  // ── Blocos ────────────────────────────────────────────────────────────────
  listarBlocos: (filtros = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(filtros).filter(([, v]) => v))
    ).toString();
    return request(`/blocos${qs ? "?" + qs : ""}`);
  },

  buscarBloco: (id) => request(`/blocos/${id}`),

  criarBloco: (data) =>
    request("/blocos", { method: "POST", body: JSON.stringify(data) }),

  aprovarBloco: (id, acao, justificativa) =>
    request(`/blocos/${id}/aprovar`, {
      method: "PUT",
      body: JSON.stringify({ acao, justificativa: justificativa || "" }),
    }),

  exportarTxtUrl: () => `${BASE}/api/blocos/exportar/txt`,

  // ── Usuários ──────────────────────────────────────────────────────────────
  listarUsuarios: () => request("/usuarios"),

  criarUsuario: (data) =>
    request("/usuarios", { method: "POST", body: JSON.stringify(data) }),

  atualizarUsuario: (id, data) =>
    request(`/usuarios/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  // ── Auditoria ─────────────────────────────────────────────────────────────
  listarAuditoria: () => request("/auditoria"),

  // ── Health ────────────────────────────────────────────────────────────────
  health: () => request("/health"),

  // ── Centro de Custo ───────────────────────────────────────────────────────
  listarCentrosCusto: () => request("/centros-custo"),

  // ── Autorização de Desconto ───────────────────────────────────────────────
  listarAutorizacoes: () => request("/autorizacoes"),
  criarAutorizacao: (data) => request("/autorizacoes", { method: "POST", body: JSON.stringify(data) }),
  addAnexoAutorizacao: (id, data) => request(`/autorizacoes/${id}/anexo`, { method: "POST", body: JSON.stringify(data) }),
  cancelarAutorizacao: (id) => request(`/autorizacoes/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),

  // ── Hierarquia ────────────────────────────────────────────────────────────
  listarHierarquia: () => request("/hierarquia"),
  criarHierarquia:  (data)    => request("/hierarquia",     { method: "POST", body: JSON.stringify(data) }),
  atualizarHierarquia: (id, data) => request(`/hierarquia/${id}`, { method: "PUT",  body: JSON.stringify(data) }),

  // ── Alçadas ───────────────────────────────────────────────────────────────
  listarAlcadas:    ()        => request("/alcadas"),
  criarAlcada:      (data)    => request("/alcadas",        { method: "POST", body: JSON.stringify(data) }),
  atualizarAlcada:  (id, data)=> request(`/alcadas/${id}`,  { method: "PUT",  body: JSON.stringify(data) }),

  // ── Ocorrências Disciplinares ─────────────────────────────────────────────
  listarOcorrencias: (qs = "") => request(`/ocorrencias${qs ? "?" + qs : ""}`),

  criarOcorrencia: (data) =>
    request("/ocorrencias", { method: "POST", body: JSON.stringify(data) }),

  cancelarOcorrencia: (id) =>
    request(`/ocorrencias/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),

  exportarOcorrenciasUrl: () => `${BASE}/api/ocorrencias/exportar`,

  resetarSenhaAdmin: (id, novaSenha) =>
    request(`/usuarios/${id}/reset-senha`, {
      method: "PUT",
      body: JSON.stringify({ novaSenha }),
    }),

  // ── Desligamentos ─────────────────────────────────────────────────────────
  validarColaboradorDesligamento: (id) =>
    request(`/desligamentos/validar-colaborador/${id}`),

  listarDesligamentos: (status = "") =>
    request(`/desligamentos${status ? "?status=" + status : ""}`),

  buscarDesligamento: (id) => request(`/desligamentos/${id}`),

  criarDesligamento: (data) =>
    request("/desligamentos", { method: "POST", body: JSON.stringify(data) }),

  cancelarDesligamento: (id) =>
    request(`/desligamentos/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),

  enviarDesligamento: (id) =>
    request(`/desligamentos/${id}/enviar`, { method: "PUT", body: JSON.stringify({}) }),

  aprovarDesligamento: (id, acao, observacao) =>
    request(`/desligamentos/${id}/aprovar`, {
      method: "PUT",
      body: JSON.stringify({ acao, observacao: observacao || "" }),
    }),

  addAnexoDesligamento: (id, dados) =>
    request(`/desligamentos/${id}/anexos`, {
      method: "POST",
      body: JSON.stringify(dados),
    }),
  
  addAnexoOcorrencia: (id, dados) =>
    request(`/ocorrencias/${id}/anexos`, {
      method: "POST",
      body: JSON.stringify(dados),
    }),

  // ── Plano de Saúde ─────────────────────────────────────────────────────────
  listarPlanoSaude: () => request("/plano-saude"),

  buscarPlanoSaude: (id) => request(`/plano-saude/${id}`),

  criarPlanoSaude: (data) =>
    request("/plano-saude", { method: "POST", body: JSON.stringify(data) }),

  addAnexoPlanoSaude: (id, dados) =>
    request(`/plano-saude/${id}/anexos`, {
      method: "POST",
      body: JSON.stringify(dados),
    }),

  cancelarPlanoSaude: (id) =>
    request(`/plano-saude/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),
  
  // ── Atualização Cadastral ─────────────────────────────────────────────────
  listarAtualizacaoCadastral: (params = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([,v])=>v))).toString();
    return request(`/atualizacao-cadastral${qs ? "?" + qs : ""}`);
  },
  criarAtualizacaoCadastral: (data) =>
    request("/atualizacao-cadastral", { method: "POST", body: JSON.stringify(data) }),
  aprovarAtualizacaoCadastral: (id, acao, observacao) =>
    request(`/atualizacao-cadastral/${id}/aprovar`, { method: "PUT", body: JSON.stringify({ acao, observacao }) }),
  cancelarAtualizacaoCadastral: (id) =>
    request(`/atualizacao-cadastral/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),

  getToken: () => _accessToken,

  // ── Sistema Disciplinar ────────────────────────────────────────────────────
  listarCartilha: (categoria) =>
    request(`/disciplinar/cartilha${categoria ? "?categoria="+encodeURIComponent(categoria) : ""}`),
  criarCartilha: (data) =>
    request("/disciplinar/cartilha", { method: "POST", body: JSON.stringify(data) }),
  atualizarCartilha: (id, data) =>
    request(`/disciplinar/cartilha/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  sugerirPenalidade: (colaborador_id, cartilha_id) =>
    request(`/disciplinar/sugerir?colaborador_id=${colaborador_id}&cartilha_id=${cartilha_id}`),
  listarDisciplinar: (params = {}) => {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([,v])=>v))).toString();
    return request(`/disciplinar${qs ? "?"+qs : ""}`);
  },
  buscarDisciplinar: (id) => request(`/disciplinar/${id}`),
  criarDisciplinar: (data) =>
    request("/disciplinar", { method: "POST", body: JSON.stringify(data) }),
  analisarDisciplinar: (id, data) =>
    request(`/disciplinar/${id}/analisar`, { method: "PUT", body: JSON.stringify(data) }),
  cancelarDisciplinar: (id) =>
    request(`/disciplinar/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),

  // ── Rescisão Valores ───────────────────────────────────────────────────────
  listarRescisaoValores: (mes, ano) =>
    request(`/rescisao-valores?mes=${mes}&ano=${ano}`),
  lancarRescisaoValor: (data) =>
    request("/rescisao-valores", { method: "POST", body: JSON.stringify(data) }),
  excluirRescisaoValor: (id) =>
    request(`/rescisao-valores/${id}`, { method: "DELETE" }),
  buscarRescisaoPorDesligamento: (id) =>
    request(`/rescisao-valores/desligamento/${id}`),
  importarRescisaoRM: () =>
    request("/rescisao-valores/importar", { method: "POST", body: JSON.stringify({}) }),
  importarRescisaoLote: (registros) =>
    request("/rescisao-valores/importar-lote", { method: "POST", body: JSON.stringify({ registros }) }),
  testarConexaoRM: () =>
    request("/rescisao-valores/testar-conexao"),
};
