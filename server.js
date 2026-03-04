require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();

/* =========================
   🔐 Security Middlewares
========================= */

app.use(helmet());

app.use(cors({
  origin: [
    "https://7930navid.github.io",
    "http://localhost:8080"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
}));


app.use(express.json());

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(globalLimiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

/* =========================
   🗄 Database Connection
========================= */

const usersDB = new Pool({
  connectionString: process.env.USERS_DB_URL,
  ssl: { rejectUnauthorized: false } // change if provider requires true
});

/* =========================
   🧱 Initialize Table
========================= */

async function initDB() {
  await usersDB.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      bio TEXT NOT NULL,
      avatar TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("✅ Users table ready");
}

/* =========================
   🔑 JWT Middleware
========================= */

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: "Invalid token" });
  }
}

/* =========================
   📝 SIGNUP
========================= */

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, bio, avatar } = req.body;

    if (!username || !email || !password || !bio || !avatar)
      return res.status(400).json({ message: "All fields required" });

    const exists = await usersDB.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (exists.rows.length > 0)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 12);

    await usersDB.query(
      "INSERT INTO users (username, email, password, bio, avatar) VALUES ($1,$2,$3,$4,$5)",
      [username, email, hashedPassword, bio, avatar]
    );

    res.status(201).json({ message: "Registered successfully" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   🔐 SIGNIN
========================= */

app.post("/signin", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const result = await usersDB.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = result.rows[0];

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        bio: user.bio,
        avatar: user.avatar
      }
    });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   👤 GET OWN PROFILE
========================= */

app.get("/me", verifyToken, async (req, res) => {
  try {
    const result = await usersDB.query(
      "SELECT id, username, email, bio, avatar FROM users WHERE id=$1",
      [req.user.id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json(result.rows[0]);

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   ✏️ EDIT PROFILE
========================= */

app.put("/editprofile", verifyToken, async (req, res) => {
  try {
    const { username, password, bio, avatar } = req.body;

    if (!username || !bio || !avatar)
      return res.status(400).json({ message: "Missing fields" });

    let query;
    let values;

    if (password && password.trim() !== "") {
      const hashed = await bcrypt.hash(password, 12);
      query = `
        UPDATE users
        SET username=$1, password=$2, bio=$3, avatar=$4
        WHERE id=$5
        RETURNING id, username, email, bio, avatar
      `;
      values = [username, hashed, bio, avatar, req.user.id];
    } else {
      query = `
        UPDATE users
        SET username=$1, bio=$2, avatar=$3
        WHERE id=$4
        RETURNING id, username, email, bio, avatar
      `;
      values = [username, bio, avatar, req.user.id];
    }

    const result = await usersDB.query(query, values);

    res.json({
      message: "Profile updated",
      user: result.rows[0]
    });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   ❌ DELETE ACCOUNT
========================= */

app.delete("/deleteuser", verifyToken, async (req, res) => {
  try {
    await usersDB.query(
      "DELETE FROM users WHERE id=$1",
      [req.user.id]
    );

    res.json({ message: "Account deleted" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   🌍 PUBLIC PROFILE
========================= */

app.get("/public-profile", async (req, res) => {
  try {
    const { email } = req.query;

    if (!email)
      return res.status(400).json({ message: "Email required" });

    const result = await usersDB.query(
      "SELECT username, bio, avatar FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json(result.rows[0]);

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   🟢 Health Check
========================= */

app.get("/", (req, res) =>
  res.json({ status: "Backend is running ✅" })
);

/* =========================
   🚀 Start Server
========================= */

const PORT = process.env.PORT || 5000;

initDB().then(() => {
  app.listen(PORT, () =>
    console.log(`🚀 Server running on port ${PORT}`)
  );
});