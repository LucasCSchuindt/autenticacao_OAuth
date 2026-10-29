-- Migração inicial: tabelas usadas pelo fluxo OAuth

-- Transações em andamento (state, nonce e PKCE). Uso único, expiram em 10 minutos.
CREATE TABLE IF NOT EXISTS oauth_transactions (
  id_hash       TEXT PRIMARY KEY,
  provider      TEXT NOT NULL,
  state_hash    TEXT NOT NULL,
  nonce         TEXT,
  code_verifier TEXT NOT NULL,
  expires_at    INTEGER NOT NULL
);

-- Sessões ativas. O cookie guarda o ID; o banco guarda só o hash dele.
CREATE TABLE IF NOT EXISTS sessions (
  id_hash      TEXT PRIMARY KEY,
  issuer       TEXT NOT NULL,
  subject      TEXT NOT NULL,
  email        TEXT,
  display_name TEXT,
  expires_at   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_transactions_expires_at ON oauth_transactions (expires_at);
