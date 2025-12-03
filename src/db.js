// src/db.js — INSECURE DB
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'insecure-blog.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // Users table (plain-text passwords)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    )
  `);

  // Posts table (no sanitization)
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL, -- Stored XSS here!
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Comments table (also Stored XSS)
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL, -- Stored XSS here!
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

// Create seed admin
db.serialize(() => {
  db.get(`SELECT * FROM users WHERE email = 'admin@example.com'`, (err, row) => {
    if (!row) {
      db.run(`
        INSERT INTO users (name, email, password, role)
        VALUES ('Admin User', 'admin@example.com', 'password123', 'admin')
      `);
    }
  });
});

module.exports = db;
