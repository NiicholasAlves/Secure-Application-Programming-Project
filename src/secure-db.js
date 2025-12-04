// src/secure-db.js
// SECURE database initialisation using hashed passwords

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const dbPath = path.join(__dirname, '..', 'secure-blog.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // Users table with hashed passwords
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,  -- SECURE: stores bcrypt hash
      role TEXT NOT NULL DEFAULT 'user'
    )
  `);

  // Posts table
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Comments table (we keep it even if we don't fully use it yet)
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (post_id) REFERENCES posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

// Seed an admin user with hashed password if not exists
db.serialize(() => {
  db.get(`SELECT * FROM users WHERE email = ?`, ['admin@example.com'], async (err, row) => {
    if (err) {
      console.error('Error checking admin user (secure):', err);
      return;
    }
    if (!row) {
      try {
        const hashed = await bcrypt.hash('password123', 10);
        db.run(
          `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
          ['Admin User', 'admin@example.com', hashed, 'admin'],
          (err2) => {
            if (err2) {
              console.error('Error creating secure admin user:', err2);
            } else {
              console.log('Secure admin user created: admin@example.com / password123');
            }
          }
        );
      } catch (hashErr) {
        console.error('Error hashing admin password:', hashErr);
      }
    }
  });
});

module.exports = db;
