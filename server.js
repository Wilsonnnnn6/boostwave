const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const dbPath = path.join(__dirname, "data", "app.db");
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT 'Followers',
    plan TEXT NOT NULL,
    profile_url TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

const orderCols = db.prepare("PRAGMA table_info(orders)").all();
const hasServiceCol = orderCols.some((col) => col.name === "service");
if (!hasServiceCol) {
  db.exec("ALTER TABLE orders ADD COLUMN service TEXT NOT NULL DEFAULT 'Followers';");
}

const insertUser = db.prepare(
  "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)"
);
const getUserByEmail = db.prepare("SELECT * FROM users WHERE email = ?");
const insertOrder = db.prepare(
  "INSERT INTO orders (user_id, platform, service, plan, profile_url, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
);
const getOrdersByUser = db.prepare(
  "SELECT id, platform, service, plan, profile_url, notes, created_at FROM orders WHERE user_id = ? ORDER BY id DESC"
);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"]
      }
    }
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(
  session({
    name: "boostwave.sid",
    secret: process.env.SESSION_SECRET || "dev_only_replace_with_env_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validPassword(password) {
  if (typeof password !== "string" || password.length < 8 || password.length > 72) {
    return false;
  }

  const hasLetter = /[A-Za-z]/.test(password);
  const hasNumber = /\d/.test(password);
  return hasLetter && hasNumber;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return next();
}

function issueCsrfToken(req) {
  const token = crypto.randomBytes(32).toString("hex");
  req.session.csrfToken = token;
  return token;
}

function requireCsrf(req, res, next) {
  const token = req.get("x-csrf-token");
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  return next();
}

app.get("/api/auth/csrf", (req, res) => {
  res.json({ csrfToken: issueCsrfToken(req) });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({ loggedIn: false });
  }

  return res.json({
    loggedIn: true,
    user: {
      id: req.session.userId,
      name: req.session.userName,
      email: req.session.userEmail
    }
  });
});

app.post("/api/auth/signup", requireCsrf, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!name || name.length < 2 || name.length > 80) {
    return res.status(400).json({ error: "Name must be 2-80 characters" });
  }
  if (!email || email.length > 120 || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email address" });
  }
  if (!validPassword(password)) {
    return res.status(400).json({ error: "Password must be 8-72 chars and include letters and numbers" });
  }

  if (getUserByEmail.get(email)) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const hash = await bcrypt.hash(password, 12);
  const createdAt = new Date().toISOString();

  try {
    const result = insertUser.run(name, email, hash, createdAt);
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        return res.status(500).json({ error: "Session error" });
      }

      req.session.userId = Number(result.lastInsertRowid);
      req.session.userName = name;
      req.session.userEmail = email;
      issueCsrfToken(req);
      return res.status(201).json({ success: true });
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to create account" });
  }
});

app.post("/api/auth/login", requireCsrf, async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = getUserByEmail.get(email);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  req.session.regenerate((regenErr) => {
    if (regenErr) {
      return res.status(500).json({ error: "Session error" });
    }

    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userEmail = user.email;
    issueCsrfToken(req);
    return res.json({ success: true });
  });
});

app.post("/api/auth/logout", requireCsrf, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("boostwave.sid");
    res.json({ success: true });
  });
});

app.post("/api/orders", requireAuth, requireCsrf, (req, res) => {
  const platform = String(req.body.platform || "").trim();
  const service = String(req.body.service || "").trim();
  const plan = String(req.body.plan || "").trim();
  const profileUrl = String(req.body.profileUrl || "").trim();
  const notes = String(req.body.notes || "").trim();

  const allowedPlatforms = ["Instagram", "TikTok", "YouTube", "X", "Facebook"];
  const allowedServices = {
    Instagram: ["Followers", "Likes", "Views", "Services"],
    TikTok: ["Followers", "Likes", "Views", "Services"],
    YouTube: ["Subscribers", "Likes", "Views", "Services", "Watch Hours"],
    X: ["Followers", "Likes", "Views", "Services"],
    Facebook: ["Followers", "Likes", "Views", "Services"]
  };

  if (!allowedPlatforms.includes(platform)) {
    return res.status(400).json({ error: "Invalid platform" });
  }
  if (!allowedServices[platform].includes(service)) {
    return res.status(400).json({ error: "Invalid service for selected platform" });
  }
  if (!plan || plan.length > 80) {
    return res.status(400).json({ error: "Invalid package" });
  }

  try {
    const url = new URL(profileUrl);
    if (!["http:", "https:"].includes(url.protocol)) {
      return res.status(400).json({ error: "Invalid profile URL" });
    }
  } catch {
    return res.status(400).json({ error: "Invalid profile URL" });
  }

  const createdAt = new Date().toISOString();
  insertOrder.run(req.session.userId, platform, service, plan, profileUrl, notes.slice(0, 300), createdAt);
  return res.status(201).json({ success: true });
});

app.get("/api/orders", requireAuth, (req, res) => {
  const orders = getOrdersByUser.all(req.session.userId);
  return res.json({ orders });
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`BoostWave running on http://localhost:${PORT}`);
});
