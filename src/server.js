// src/server.js
// SECURE Express server – mitigates SQL Injection, XSS and Sensitive Data Exposure

const express = require('express');
const path = require('path');
const session = require('express-session');
const helmet = require('helmet');
const csrf = require('csurf');
const bcrypt = require('bcrypt');
const db = require('./secure-db');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(helmet()); // basic security headers

// Proper session management
app.use(session({
  secret: 'change-this-secret-in-real-app', // in real apps, keep this in env variable
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // helps prevent XSS stealing cookie
    // secure: true, // would be used in HTTPS
    maxAge: 60 * 60 * 1000 // 1 hour
  }
}));

// CSRF protection
const csrfProtection = csrf();
app.use(csrfProtection);

// Helper: escape HTML to prevent XSS
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Middleware to make user available in templates
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// Home page
app.get('/', (req, res) => {
  const user = res.locals.currentUser;
  let html = `
    <h1>Secure Blog - Secure Branch</h1>
    ${user ? `<p>Logged in as: ${escapeHtml(user.name)} (${escapeHtml(user.email)})</p>` : '<p>Not logged in</p>'}
    <p><a href="/login">Login</a> | <a href="/register">Register</a></p>
    <p><a href="/posts">View Posts</a></p>
  `;
  res.send(html);
});

// ========= REGISTER =========

// Register form
app.get('/register', (req, res) => {
  const token = req.csrfToken();
  res.send(`
    <h1>Register</h1>
    <form method="POST" action="/register">
      <input type="hidden" name="_csrf" value="${token}">
      <label>Name:</label><br>
      <input type="text" name="name"><br><br>
      <label>Email:</label><br>
      <input type="text" name="email"><br><br>
      <label>Password:</label><br>
      <input type="password" name="password"><br><br>
      <button type="submit">Register</button>
    </form>
    <p><a href="/login">Already registered? Login</a></p>
    <p><a href="/">Back to home</a></p>
  `);
});

// Register handler – uses bcrypt + parameterised INSERT
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.send('<p>All fields are required. <a href="/register">Back</a></p>');
  }

  try {
    // Check if email already exists
    db.get(`SELECT id FROM users WHERE email = ?`, [email], async (err, existing) => {
      if (err) {
        console.error('Secure register DB error:', err);
        return res.send('<p>Something went wrong. Please try again later.</p>');
      }

      if (existing) {
        return res.send('<p>Email already registered. <a href="/login">Login</a></p>');
      }

      const hashed = await bcrypt.hash(password, 10);
      db.run(
        `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
        [name, email, hashed, 'user'],
        (insertErr) => {
          if (insertErr) {
            console.error('Error inserting new user:', insertErr);
            return res.send('<p>Could not create account. Please try again later.</p>');
          }
          res.send('<p>Registration successful. <a href="/login">Click here to login</a></p>');
        }
      );
    });
  } catch (err) {
    console.error('Register error:', err);
    res.send('<p>Something went wrong. Please try again later.</p>');
  }
});

// ========= LOGIN =========

// Login form (includes CSRF token)
app.get('/login', (req, res) => {
  const token = req.csrfToken();
  const html = `
    <h1>Login (Secure)</h1>
    <form method="POST" action="/login">
      <input type="hidden" name="_csrf" value="${token}">
      <label>Email:</label><br>
      <input type="text" name="email"><br><br>
      <label>Password:</label><br>
      <input type="password" name="password"><br><br>
      <button type="submit">Login</button>
    </form>
    <p><a href="/register">Need an account? Register</a></p>
    <p><a href="/">Back to home</a></p>
  `;
  res.send(html);
});

// SECURE LOGIN: parameterised query + bcrypt
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Parameterised query prevents SQL Injection
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err) {
      console.error('Secure login DB error:', err);
      return res.send('<p>Something went wrong. Please try again later.</p>');
    }

    if (!user) {
      return res.send('<p>Invalid email or password. <a href="/login">Try again</a></p>');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send('<p>Invalid email or password. <a href="/login">Try again</a></p>');
    }

    // Store only minimal info in session
    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    };

    res.send(`
      <h1>Login successful (Secure)</h1>
      <p>Welcome, ${escapeHtml(user.name)}!</p>
      <p>Your role: ${escapeHtml(user.role)}</p>
      <p><a href="/">Go to home</a></p>
    `);
  });
});

// Logout: destroy session
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// ========= POSTS (LIST + SEARCH + DELETE) =========

// View all posts (XSS mitigated with escaping and safe queries)
app.get('/posts', (req, res) => {
  const search = req.query.search || '';
  const params = [];

  let query = `SELECT * FROM posts`;
  if (search) {
    query += ` WHERE title LIKE ? OR content LIKE ?`;
    const like = `%${search}%`;
    params.push(like, like);
  }
  query += ` ORDER BY created_at DESC`;

  db.all(query, params, (err, posts) => {
    if (err) {
      console.error('Secure posts DB error:', err);
      return res.send('<p>Something went wrong loading posts.</p>');
    }

    const user = res.locals.currentUser;
    let html = `<h1>Secure Posts</h1>`;

    if (user) {
      html += `
        <p><a href="/create-post">Create New Post</a></p>
        <p>Logged in as: ${escapeHtml(user.name)} <a href="/logout">Logout</a></p>
      `;
    } else {
      html += `<p><a href="/login">Login first</a></p>`;
    }

    // Search form with escaped value
    html += `
      <form method="GET" action="/posts">
        <input type="text" name="search" value="${escapeHtml(search)}">
        <button type="submit">Search</button>
      </form>
    `;

    posts.forEach(post => {
      html += `
        <div style="border:1px solid black; padding:10px; margin:10px;">
          <h3>${escapeHtml(post.title)}</h3>
          <p>${escapeHtml(post.content)}</p>
      `;

      // Show Delete link only to owner or admin
      if (user && (user.role === 'admin' || user.id === post.user_id)) {
        html += `
          <p><a href="/delete-post/${post.id}">Delete</a></p>
        `;
      }

      html += `</div>`;
    });

    res.send(html);
  });
});

// ========= CREATE POST =========

// Create post form (includes CSRF token)
app.get('/create-post', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');

  const token = req.csrfToken();

  res.send(`
    <h1>Create Post (Secure)</h1>
    <form method="POST" action="/create-post">
      <input type="hidden" name="_csrf" value="${token}">
      <input type="text" name="title" placeholder="Title"><br><br>
      <textarea name="content" placeholder="Content"></textarea><br><br>
      <button type="submit">Submit</button>
    </form>
    <p><a href="/posts">Back to posts</a></p>
  `);
});

// SECURE: use parameterised INSERT
app.post('/create-post', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');

  const { title, content } = req.body;

  db.run(
    `INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)`,
    [user.id, title, content],
    (err) => {
      if (err) {
        console.error('Secure insert post error:', err);
      }
      res.redirect('/posts');
    }
  );
});

// ========= DELETE POST =========

// Simple secure delete: only owner or admin
app.get('/delete-post/:id', (req, res) => {
  const user = res.locals.currentUser;
  const postId = req.params.id;

  if (!user) {
    return res.send('<p>You must be logged in to delete posts. <a href="/login">Login</a></p>');
  }

  db.get(`SELECT * FROM posts WHERE id = ?`, [postId], (err, post) => {
    if (err) {
      console.error('Secure select post for delete error:', err);
      return res.send('<p>Something went wrong. Please try again later.</p>');
    }
    if (!post) {
      return res.send('<p>Post not found. <a href="/posts">Back to posts</a></p>');
    }

    // Only post owner or admin can delete
    if (user.role !== 'admin' && user.id !== post.user_id) {
      return res.send('<p>You are not authorised to delete this post.</p>');
    }

    db.run(`DELETE FROM posts WHERE id = ?`, [postId], (delErr) => {
      if (delErr) {
        console.error('Secure delete post error:', delErr);
        return res.send('<p>Could not delete post. Please try again.</p>');
      }
      res.redirect('/posts');
    });
  });
});

app.listen(PORT, () => {
  console.log(`Secure app listening on http://localhost:${PORT}`);
});
