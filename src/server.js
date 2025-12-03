// src/server.js
// INSECURE Express server – contains SQL Injection vulnerability in /login

const express = require('express');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;

// Middleware to parse form data
app.use(express.urlencoded({ extended: true }));

// Very basic "session" using a global variable (INSECURE)
let currentUser = null;

// Home page
app.get('/', (req, res) => {
  let html = `
    <h1>Insecure Blog - Insecure Branch</h1>
    ${currentUser ? `<p>Logged in as: ${currentUser.name} (${currentUser.email})</p>` : '<p>Not logged in</p>'}
    <p><a href="/login">Login</a></p>
    <p><a href="/init-db">Initialize DB (for demo)</a></p>
  `;
  res.send(html);
});

// Initialise DB route (for demo only - INSECURE to expose this)
app.get('/init-db', (req, res) => {
  res.send(`
    <h2>Database initialised</h2>
    <p>Admin user: admin@example.com / password123</p>
    <p><a href="/login">Go to login</a></p>
  `);
});

// Login form
app.get('/login', (req, res) => {
  const html = `
    <h1>Login (Insecure)</h1>
    <form method="POST" action="/login">
      <label>Email:</label><br>
      <input type="text" name="email"><br><br>
      <label>Password:</label><br>
      <input type="password" name="password"><br><br>
      <button type="submit">Login</button>
    </form>
    <p>Try normal login or SQL injection such as:</p>
    <pre>' OR '1'='1</pre>
    <p><a href="/">Back to home</a></p>
  `;
  res.send(html);
});

// INSECURE LOGIN: vulnerable to SQL injection
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // 🚨 INTENTIONALLY INSECURE: builds SQL string by concatenating user input
  const insecureQuery = `
    SELECT * FROM users
    WHERE email = '${email}'
      AND password = '${password}'
  `;

  console.log('Executing insecure query:', insecureQuery);

  db.get(insecureQuery, (err, row) => {
    if (err) {
      // INSECURE: exposing error details to the user
      return res.send(`<p>Database error (insecure): ${err.message}</p>`);
    }

    if (!row) {
      return res.send(`
        <h1>Login failed</h1>
        <p>Invalid email or password.</p>
        <p><a href="/login">Try again</a></p>
      `);
    }

    // INSECURE "session" management: global variable
    currentUser = row;

    res.send(`
      <h1>Login successful</h1>
      <p>Welcome, ${row.name}!</p>
      <p>Your role: ${row.role}</p>
      <p><a href="/">Go to home</a></p>
    `);
  });
});

// Simple logout (resets global variable)
app.get('/logout', (req, res) => {
  currentUser = null;
  res.redirect('/');
});

app.listen(PORT, () => {
  console.log(`Insecure app listening on http://localhost:${PORT}`);
});
