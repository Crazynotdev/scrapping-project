const Database = require('better-sqlite3');
const path = require('path');
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'ngl.sqlite');

const db = new Database(dbPath);

// Enable WAL for concurrent reads/writes
db.pragma('journal_mode = WAL');

// Create tables if missing
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password_hash TEXT,
  link_id TEXT UNIQUE,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_link TEXT,
  content TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  read INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_target ON messages(target_link);
`);

module.exports = db;
