-- Migração inicial
CREATE TABLE IF NOT EXISTS notas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  aluno TEXT NOT NULL,
  nota REAL NOT NULL,
  criado_em TEXT DEFAULT (datetime('now'))
);
