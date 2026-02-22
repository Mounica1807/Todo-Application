const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;
const SECRET = "my-super-secret-key-12345-change-this-later"; // ← change this!

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./todos.db');

// ────────────── Create tables ──────────────
db.serialize(() => {
  console.log("Creating/checking tables...");

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `, function(err) {
    if (err) console.error("Users table creation failed:", err.message);
    else console.log("Users table OK");
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS todos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      text TEXT NOT NULL,
      completed INTEGER DEFAULT 0
    )
  `, function(err) {
    if (err) console.error("Todos table creation failed:", err.message);
    else console.log("Todos table OK");
  });
});

// In GET /api/todos
app.get('/api/todos', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  console.log("Fetching todos for user ID:", user.id);   // ← add this

  db.all("SELECT * FROM todos WHERE userId = ? ORDER BY id DESC", [user.id], (err, rows) => {
    if (err) {
      console.error("GET /todos error:", err.message);     // ← add this
      return res.status(500).json({ error: "Database error: " + err.message });
    }
    res.json(rows);
  });
});

// ────────────── Helper: check who is logged in ──────────────
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
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: "Password too short (min 4 chars)" });
  }

  const hashed = bcrypt.hashSync(password, 8);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "Username already taken" });
      }

      const token = jwt.sign({ id: this.lastID, username }, SECRET, { expiresIn: '7d' });
      res.json({ token, username });
    }
  );
});

// ────────────── Login ──────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: "Wrong username or password" });
    }

    const correct = bcrypt.compareSync(password, user.password);
    if (!correct) {
      return res.status(400).json({ error: "Wrong username or password" });
    }

    const token = jwt.sign({ id: user.id, username }, SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  });
});

// ────────────── Protected todo routes ──────────────

app.get('/api/todos', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  db.all("SELECT * FROM todos WHERE userId = ? ORDER BY id DESC", [user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(rows);
  });
});

app.post('/api/todos', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: "Task is empty" });

  db.run(
    "INSERT INTO todos (userId, text, completed) VALUES (?, ?, 0)",
    [user.id, text.trim()],
    function (err) {
      if (err) return res.status(500).json({ error: "Cannot save task" });
      res.json({ id: this.lastID, text, completed: 0 });
    }
  );
});

app.patch('/api/todos/:id', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  const { completed } = req.body;

  db.run(
    "UPDATE todos SET completed = ? WHERE id = ? AND userId = ?",
    [completed ? 1 : 0, req.params.id, user.id],
    function (err) {
      if (err || this.changes === 0) {
        return res.status(400).json({ error: "Cannot update task" });
      }
      res.json({ success: true });
    }
  );
});

app.delete('/api/todos/:id', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: "Please login" });

  db.run(
    "DELETE FROM todos WHERE id = ? AND userId = ?",
    [req.params.id, user.id],
    function (err) {
      if (err || this.changes === 0) {
        return res.status(400).json({ error: "Cannot delete task" });
      }
      res.json({ success: true });
    }
  );
});

// Serve frontend
app.get('/*path', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running → http://localhost:${PORT}`);
});