const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { Pool } = require('pg');

const app = express();
const PORT = 5000;
const SECRET = "my-super-secret-key-12345-change-this-later"; // ← change this in production!

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ────────────── PostgreSQL connection ──────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }   // required for Neon
});

// Initialize tables (runs once on startup)
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS todos (
        id SERIAL PRIMARY KEY,
        userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        completed INTEGER DEFAULT 0
      )
    `);

    console.log('✅ Database tables are ready (PostgreSQL / Neon)');
  } catch (err) {
    console.error('❌ Database initialization failed:', err.message);
  }
}

initDatabase();

// ────────────── Helper: verify JWT token ──────────────
function getUserFromToken(req) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return null;
  try {
    return jwt.verify(token, SECRET);
  } catch (e) {
    return null;
  }
}

// ────────────── Register ──────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: "Password too short (min 4 chars)" });
  }

  try {
    const hashed = bcrypt.hashSync(password, 8);

    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
      [username, hashed]
    );

    const userId = result.rows[0].id;
    const token = jwt.sign({ id: userId, username }, SECRET, { expiresIn: '7d' });

    res.status(201).json({ token, username });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(400).json({ error: "Username already taken or database error" });
  }
});

// ────────────── Login ──────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: "Wrong username or password" });
    }

    const token = jwt.sign({ id: user.id, username }, SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

// ────────────── Protected Todo routes ──────────────

app.get('/api/todos', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  try {
    const result = await pool.query(
      "SELECT * FROM todos WHERE userId = $1 ORDER BY id DESC",
      [user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET todos error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

app.post('/api/todos', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: "Task is empty" });

  try {
    const result = await pool.query(
      "INSERT INTO todos (userId, text, completed) VALUES ($1, $2, 0) RETURNING id, text, completed",
      [user.id, text.trim()]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("POST todo error:", err.message);
    res.status(500).json({ error: "Cannot save task" });
  }
});

app.patch('/api/todos/:id', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  const { completed } = req.body;
  const todoId = req.params.id;

  try {
    const result = await pool.query(
      "UPDATE todos SET completed = $1 WHERE id = $2 AND userId = $3 RETURNING id, completed",
      [completed ? 1 : 0, todoId, user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Task not found or not yours" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("PATCH todo error:", err.message);
    res.status(500).json({ error: "Cannot update task" });
  }
});

app.delete('/api/todos/:id', async (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  const todoId = req.params.id;

  try {
    const result = await pool.query(
      "DELETE FROM todos WHERE id = $1 AND userId = $2",
      [todoId, user.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Task not found or not yours" });
    }

    res.status(204).end();
  } catch (err) {
    console.error("DELETE todo error:", err.message);
    res.status(500).json({ error: "Cannot delete task" });
  }
});

// Serve frontend
app.get('/*path', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running → http://localhost:${PORT}`);
});
