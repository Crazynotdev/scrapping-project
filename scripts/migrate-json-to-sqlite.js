const fs = require('fs');
const path = require('path');
const db = require('../db');

const jsonPath = path.join(__dirname, '..', 'data', 'messages.json');
if (!fs.existsSync(jsonPath)) {
  console.error('No messages.json found at', jsonPath);
  process.exit(1);
}
const raw = fs.readFileSync(jsonPath, 'utf8');
const arr = JSON.parse(raw);

const insert = db.prepare('INSERT INTO messages (target_link, content, created_at) VALUES (?, ?, ?)');
const insertMany = db.transaction((items) => {
  for (const m of items) {
    insert.run(m.target || m.target_link || m.linkId, m.message || m.content, m.created_at || new Date().toISOString());
  }
});

insertMany(arr);
console.log('Migrated', arr.length, 'messages to SQLite');
