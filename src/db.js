// src/db.js
// INSECURE database initialisation for demo purposes

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Database file in project root
const dbPath = path.join(__dirname, '..', 'insecure-blog.db');
const db = new sqlite3.Database(dbPath);

// Create tables (simple, not hardened)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,  -- INSECURE: storing plain text passwords
      role TEXT NOT NULL DEFAULT 'user'
    )
  `);

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
});

// Seed a demo user if not exists (plain text password)
db.serialize(() => {
  db.get(`SELECT * FROM users WHERE email = 'admin@example.com'`, (err, row) => {
    if (err) {
      console.error('Error checking admin user:', err);
      return;
    }
    if (!row) {
      db.run(
        `INSERT INTO users (name, email, password, role)
         VALUES ('Admin User', 'admin@example.com', 'password123', 'admin')`,
        (err2) => {
          if (err2) {
            console.error('Error creating admin user:', err2);
          } else {
            console.log('Insecure admin user created: admin@example.com / password123');
          }
        }
      );
    }
  });
});

module.exports = db;
