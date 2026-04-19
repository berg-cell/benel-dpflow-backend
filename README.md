# DP Flow Backend — Benel Soluções em Transporte e Logística

API RESTful para o Sistema de Gestão de Variáveis para Folha de Pagamento com integração TOTVS RM Labore.

---

## Estrutura do projeto

```
benel-backend/
├── src/
│   ├── config/
│   │   └── database.js          # Configuração PostgreSQL com pool
│   ├── controllers/
│   │   ├── authController.js    # Login, logout, refresh, alterar senha
│   │   ├── usuarioController.js # CRUD de usuários (admin)
│   │   ├── colaboradorController.js
│   │   ├── eventoController.js
│   │   ├── blocoController.js   # Solicitações + aprovação + exportação TXT
│   │   └── auditoriaController.js
│   ├── docs/
│   │   └── swagger.js           # Configuração Swagger/OpenAPI
│   ├── middlewares/
│   │   └── index.js             # JWT, RBAC, Rate limit, Sanitização, Audit log
│   ├── models/
│   │   └── index.js             # Queries parametrizadas (anti SQL Injection)
│   ├── routes/
│   │   └── index.js             # Todas as rotas da API
│   ├── services/
│   │   └── authService.js       # Lógica de autenticação + bcrypt + JWT
│   ├── utils/
│   │   ├── logger.js            # Winston — logs em arquivo e console
│   │   ├── response.js          # Respostas padronizadas
│   │   ├── sanitize.js          # XSS, SQL Injection, Prompt Injection
│   │   └── totvs.js             # Geração e validação do arquivo TXT RM Labore
│   ├── validators/
│   │   └── schemas.js           # Schemas Joi para todos os endpoints
│   ├── app.js                   # Express + Helmet + CORS + middlewares
│   └── server.js                # Entry point + graceful shutdown
├── scripts/
│   ├── migrate.js               # Cria todas as tabelas no PostgreSQL
│   └── seed.js                  # Dados iniciais (usuários, eventos, colaboradores)
├── tests/
│   ├── unit/
│   │   ├── sanitize.test.js
│   │   └── totvs.test.js
│   └── integration/
│       └── auth.test.js
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
└── package.json
```

---

## Pré-requisitos

- Node.js >= 18
- PostgreSQL >= 13
- npm >= 9

---

## Instalação local

```bash
# 1. Clonar / descompactar o projeto
cd benel-backend

# 2. Instalar dependências
npm install

# 3. Copiar e configurar variáveis de ambiente
cp .env.example .env
# Edite o .env com suas credenciais de banco e chaves JWT

# 4. Criar o banco de dados no PostgreSQL
psql -U postgres -c "CREATE DATABASE benel_dpflow;"

# 5. Rodar migrações (criar tabelas)
npm run migrate

# 6. Popular dados iniciais
npm run seed

# 7. Iniciar em desenvolvimento
npm run dev
```

---

## Rodando com Docker (recomendado)

```bash
# Sobe banco PostgreSQL + API juntos
docker-compose up -d

# Rodar migrações dentro do container
docker exec benel_api node scripts/migrate.js

# Rodar seed dentro do container
docker exec benel_api node scripts/seed.js

# Ver logs
docker-compose logs -f api
```

---

## Endpoints principais

| Método | Rota                        | Auth | Perfis         | Descrição                    |
|--------|-----------------------------|------|----------------|------------------------------|
| POST   | /api/auth/login             | ❌   | —              | Login (rate limit 5x/15min)  |
| POST   | /api/auth/refresh           | ❌   | —              | Renovar access token         |
| POST   | /api/auth/logout            | ✅   | todos          | Logout                       |
| GET    | /api/auth/me                | ✅   | todos          | Dados do usuário logado      |
| PUT    | /api/auth/alterar-senha     | ✅   | todos          | Alterar senha                |
| GET    | /api/usuarios               | ✅   | admin          | Listar usuários              |
| POST   | /api/usuarios               | ✅   | admin          | Criar usuário                |
| GET    | /api/colaboradores          | ✅   | todos          | Listar colaboradores         |
| POST   | /api/colaboradores          | ✅   | dp, admin      | Criar colaborador            |
| POST   | /api/colaboradores/importar | ✅   | dp, admin      | Importar em massa (CSV/JSON) |
| GET    | /api/eventos                | ✅   | todos          | Listar eventos               |
| POST   | /api/eventos                | ✅   | dp, admin      | Criar evento                 |
| GET    | /api/blocos                 | ✅   | todos*         | Listar blocos                |
| POST   | /api/blocos                 | ✅   | todos          | Criar bloco                  |
| GET    | /api/blocos/:id             | ✅   | todos*         | Detalhe do bloco             |
| PUT    | /api/blocos/:id/aprovar     | ✅   | por alçada     | Aprovar/rejeitar/devolver    |
| GET    | /api/blocos/exportar/txt    | ✅   | dp, admin      | Gerar arquivo TXT TOTVS RM   |
| GET    | /api/auditoria              | ✅   | dp, admin      | Log de auditoria             |
| GET    | /api/health                 | ❌   | —              | Status do servidor           |

> *Gestor vê apenas seus próprios blocos (prevenção IDOR)

---

## Autenticação

```bash
# Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"email":"admin@benel.com.br","senha":"Admin@2025!"}'

# Usar o accessToken nas requisições
curl http://localhost:3001/api/colaboradores \
  -H "Authorization: Bearer SEU_TOKEN_AQUI"
```

---

## Documentação Swagger

Disponível em: `http://localhost:3001/docs` (apenas em desenvolvimento)

---

## Testes

```bash
# Todos os testes
npm test

# Com cobertura
npm run test:coverage

# Modo watch
npm run test:watch
```

---

## Segurança implementada

| Camada                   | Tecnologia            | Descrição                                    |
|--------------------------|-----------------------|----------------------------------------------|
| Hash de senha            | bcryptjs (12 rounds)  | Senhas nunca armazenadas em texto claro       |
| JWT                      | jsonwebtoken          | Access token (8h) + Refresh token (7d)       |
| Rate limit login         | express-rate-limit    | Máx 5 tentativas / 15 min por IP             |
| Rate limit geral         | express-rate-limit    | Máx 100 req / 15 min por IP                  |
| Cabeçalhos de segurança  | helmet                | CSP, HSTS, X-Frame-Options, noSniff          |
| CORS                     | cors                  | Apenas origens autorizadas no .env           |
| SQL Injection            | pg (parametrizado)    | Queries sempre com $1, $2... sem concatenação|
| XSS                      | xss                   | Sanitização automática de todos os inputs    |
| Prompt Injection         | custom regex          | Detecta e bloqueia comandos maliciosos       |
| RBAC                     | middleware autorizar  | Controle por perfil em cada rota             |
| IDOR                     | middleware + models   | Gestor só acessa seus próprios recursos      |
| Audit log                | PostgreSQL + Winston  | Registra todas as ações críticas             |
| Validação                | Joi                   | Schema validation em todos os endpoints      |
| Erros seguros            | errorHandler          | Não vaza stack trace em produção             |
| Graceful shutdown        | SIGTERM/SIGINT        | Encerramento seguro do servidor              |

---

## Credenciais de demo (após seed)

| Perfil   | E-mail                   | Senha           |
|----------|--------------------------|-----------------|
| Admin    | admin@benel.com.br       | Admin@2025!     |
| Gestor   | gestor@benel.com.br      | Gestor@2025!    |
| Superior | superior@benel.com.br    | Superior@2025!  |
| DP       | dp@benel.com.br          | DP@2025!        |
