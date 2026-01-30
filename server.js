require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const Filter = require('bad-words');
const { stringify } = require('csv-stringify/sync');
const db = require('./db');
const winston = require('winston');
const fs = require('fs');
const path = require('path');

const app = express();
const logger = winston.createLogger({
  level: 'info',
  transports: [new winston.transports.Console()]
});

const JWT_SECRET = process.env.JWT_SECRET || 'dvd_234';
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'http://localhost:3000';

app.use(helmet());
app.use(cors({ origin: FRONT_ORIGIN }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Basic rate limiter for send endpoint
const globalSendLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, try later' }
});

// Helper: per-target limiter generator
const perTargetLimiter = (req, res, next) => {
  // naive per-target check: limit stored in-memory (for prod use redis)
  if (!global.__perTarget) global.__perTarget = {};
  const target = (req.body && req.body.target) || req.query.target;
  const ip = req.ip;
  const key = `${target}::${ip}`;
  const now = Date.now();
  const windowMs = 60_000;
  const max = 6; // 6 messages per minute per ip per target
  const entry = global.__perTarget[key] || { ts: now, count: 0 };
  if (now - entry.ts > windowMs) entry.ts = now, entry.count = 0;
  entry.count += 1;
  global.__perTarget[key] = entry;
  if (entry.count > max) return res.status(429).json({ error: 'Too many messages to this user' });
  next();
};

// Profanity filter
const filter = new Filter(); // can add custom bad words: filter.addWords('foo');

// Validation schemas
const sendSchema = Joi.object({
  message: Joi.string().min(1).max(2000).required(),
  target: Joi.string().alphanum().min(3).max(50).required()
});

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  linkId: Joi.string().alphanum().min(3).max(50).required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// Middleware: authenticate JWT
function auth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// POST /api/send
app.post('/api/send', globalSendLimiter, perTargetLimiter, async (req, res) => {
  const { error, value } = sendSchema.validate({ message: req.body.message, target: req.body.target });
  if (error) return res.status(400).json({ error: error.message });
  let content = value.message.trim();
  // Basic sanitize: escape angle brackets to avoid stored XSS
  content = content.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  // Profanity check
  const hasProfanity = filter.isProfane(content);
  if (hasProfanity) {
    // option: reject, or store with flag. Here we reject.
    return res.status(400).json({ error: 'Message contains disallowed language' });
  }
  try {
    const stmt = db.prepare('INSERT INTO messages (target_link, content) VALUES (?, ?)');
    const info = stmt.run(value.target, content);
    logger.info('New message', { id: info.lastInsertRowid, target: value.target });
    return res.json({ ok: true });
  } catch (e) {
    logger.error('DB error on send', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Registration (only for initial setup; in prod add email verification)
app.post('/api/auth/register', async (req, res) => {
  const { error, value } = registerSchema.validate({ email: req.body.email, password: req.body.password, linkId: req.body.linkId });
  if (error) return res.status(400).json({ error: error.message });
  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ? OR link_id = ?').get(value.email, value.linkId);
    if (existing) return res.status(400).json({ error: 'Email or linkId already exists' });
    const hash = await bcrypt.hash(value.password, 12);
    const stmt = db.prepare('INSERT INTO users (email, password_hash, link_id) VALUES (?, ?, ?)');
    const info = stmt.run(value.email, hash, value.linkId);
    const token = jwt.sign({ id: info.lastInsertRowid, email: value.email, linkId: value.linkId }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ ok: true, token });
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.message });
  try {
    const row = db.prepare('SELECT id, email, password_hash, link_id FROM users WHERE email = ?').get(value.email);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(value.password, row.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: row.id, email: row.email, linkId: row.link_id }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ ok: true, token });
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET messages (auth, paginated)
app.get('/api/messages', auth, (req, res) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const perPage = Math.min(50, parseInt(req.query.per_page || '20', 10));
  const offset = (page - 1) * perPage;
  try {
    const total = db.prepare('SELECT COUNT(*) as c FROM messages WHERE target_link = ?').get(req.user.linkId).c;
    const rows = db.prepare('SELECT id, content, created_at, read FROM messages WHERE target_link = ? ORDER BY id DESC LIMIT ? OFFSET ?').all(req.user.linkId, perPage, offset);
    return res.json({ total, page, perPage, messages: rows });
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE message (auth)
app.delete('/api/messages/:id', auth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    const info = db.prepare('DELETE FROM messages WHERE id = ? AND target_link = ?').run(id, req.user.linkId);
    return res.json({ ok: true, deleted: info.changes });
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Export messages CSV (auth)
app.get('/api/messages/export', auth, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, content, created_at, read FROM messages WHERE target_link = ? ORDER BY id DESC').all(req.user.linkId);
    const csv = stringify(rows, { header: true, columns: ['id', 'content', 'created_at', 'read'] });
    res.setHeader('Content-Disposition', `attachment; filename="messages-${req.user.linkId}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server listening on ${PORT}`));
