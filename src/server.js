// src/server.js
// INSECURE Express server – contains SQL Injection and XSS vulnerabilities

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
    <p><a href="/posts">View Posts</a></p>
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

// View all posts (Stored + Reflected + DOM-based XSS will appear here)
app.get('/posts', (req, res) => {
  const search = req.query.search || "";

  let query = `SELECT * FROM posts`;
  if (search) {
    // INSECURE: search is concatenated directly → SQL injection + reflected XSS
    query += ` WHERE title LIKE '%${search}%' OR content LIKE '%${search}%'`;
  }
  query += ` ORDER BY created_at DESC`;

  db.all(query, (err, posts) => {
    if (err) return res.send("Database error: " + err.message);

    let html = `<h1>Insecure Posts</h1>`;

    if (currentUser) {
      html += `
        <p><a href="/create-post">Create New Post</a></p>
        <p>Logged in as: ${currentUser.name} <a href="/logout">Logout</a></p>
      `;
    } else {
      html += `<p><a href="/login">Login first</a></p>`;
    }

    // Search form (Reflected XSS point)
    html += `
      <form method="GET" action="/posts">
        <input type="text" name="search" value="${search}">
        <button type="submit">Search</button>
      </form>
      <p>Search term: ${search}</p> <!-- Reflected XSS here -->
    `;

    posts.forEach(post => {
      html += `
        <div style="border:1px solid black; padding:10px; margin:10px;">
          <h3>${post.title}</h3>
          <p>${post.content}</p> <!-- Stored XSS shows here -->
        </div>
      `;
    });

    // DOM-based XSS demo – uses location.hash unsafely
    html += `
      <div id="dom-xss-output" style="margin-top:20px; padding:10px; border:1px dashed red;">
        <strong>DOM XSS Output Area</strong>
      </div>
      <script>
        (function() {
          var hash = window.location.hash.substring(1); // everything after #
          if (hash) {
            var el = document.getElementById('dom-xss-output');
            // INSECURE: direct use of innerHTML with untrusted data
            el.innerHTML = hash;
          }
        })();
      </script>
      <p>DOM XSS demo: try visiting this page with a URL fragment, for example:</p>
      <pre>/posts#&lt;img src=x onerror=alert(3)&gt;</pre>
    `;

    res.send(html);
  });
});

// Create post form
app.get('/create-post', (req, res) => {
  if (!currentUser) return res.redirect('/login');

  res.send(`
    <h1>Create Post</h1>
    <form method="POST" action="/create-post">
      <input type="text" name="title" placeholder="Title"><br><br>
      <textarea name="content" placeholder="Content"></textarea><br><br>
      <button type="submit">Submit</button>
    </form>
    <p>⚠️ Try a Stored XSS attack!</p>
    <p><a href="/posts">Back to posts</a></p>
  `);
});

// INSECURE: Stored XSS vulnerability here!
app.post('/create-post', (req, res) => {
  if (!currentUser) return res.redirect('/login');

  const { title, content } = req.body;

  const query = `
    INSERT INTO posts (user_id, title, content)
    VALUES (${currentUser.id}, '${title}', '${content}')
  `;

  db.run(query, (err) => {
    if (err) {
      console.error("Insert error:", err.message);
    }
    res.redirect('/posts');
  });
});

app.listen(PORT, () => {
  console.log(`Insecure app listening on http://localhost:${PORT}`);
});
