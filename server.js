require("dotenv").config();

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const hpp = require("hpp");
const morgan = require("morgan");
const validator = require("validator");
const { Pool } = require("pg");

const app = express();

/* =========================
   BASIC SECURITY
========================= */

app.disable("x-powered-by");

app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: [
    "https://7930navid.github.io",
    "http://localhost:8080"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

app.use(express.json({ limit: "10kb" }));
app.use(hpp());
app.use(morgan("combined"));

/* =========================
   RATE LIMIT
========================= */

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "Too many login attempts" }
});

/* =========================
   DB
========================= */

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

/* =========================
   EMAIL TRANSPORT (OPTIMIZED)
========================= */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* =========================
   INIT DB
========================= */

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar TEXT,
      cover_photo TEXT,
      reset_token TEXT,
      reset_expiry TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  `);

  console.log("✅ Database Ready");
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = header.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "AsirNet",
      audience: "AsirNetUsers"
    });

    req.user = decoded;
    next();

  } catch {
    return res.status(403).json({ message: "Invalid token" });
  }
}

/* =========================
   SIGNUP
========================= */

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, bio, avatar, cover_photo } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ message: "Missing fields" });

    if (!validator.isEmail(email))
      return res.status(400).json({ message: "Invalid email" });

    if (password.length < 8)
      return res.status(400).json({ message: "Weak password" });

    const exists = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (exists.rows.length > 0)
      return res.status(400).json({ message: "User exists" });

    const hash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO users (username,email,password,bio,avatar,cover_photo)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        username,
        email,
        hash,
        bio || "",
        avatar || null,
        cover_photo || null
      ]
    );

    res.status(201).json({ message: "User created" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   SIGNIN (FIXED)
========================= */

app.post("/signin", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Missing fields" });

    const result = await db.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (!result.rows.length)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = result.rows[0];

    const match = await Promise.race([
      bcrypt.compare(password, user.password),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("bcrypt timeout")), 5000)
      )
    ]);

    if (!match)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
        issuer: "AsirNet",
        audience: "AsirNetUsers"
      }
    );

    const { password, reset_token, reset_expiry, ...safeUser } = user;

    return res.json({ token, user: safeUser });

  } catch (err) {
    console.error("SIGNIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   PROFILE
========================= */

app.get("/me", auth, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id,username,email,bio,avatar,cover_photo FROM users WHERE id=$1",
      [req.user.id]
    );

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   UPDATE PROFILE
========================= */

app.put("/profile", auth, async (req, res) => {
  try {
    const { username, bio, avatar, cover_photo } = req.body;

    const result = await db.query(
      `UPDATE users
       SET username=$1,bio=$2,avatar=$3,cover_photo=$4
       WHERE id=$5
       RETURNING id,username,email,bio,avatar,cover_photo`,
      [username, bio, avatar, cover_photo, req.user.id]
    );

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   USERS
========================= */

app.get("/users", auth, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id,username,email,bio,avatar,cover_photo FROM users"
    );

    res.json(result.rows);
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   DELETE ACCOUNT
========================= */

app.delete("/delete-account", auth, async (req, res) => {
  try {
    await db.query("DELETE FROM users WHERE id=$1", [req.user.id]);
    res.json({ message: "Account deleted" });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   FORGOT PASSWORD (FIXED)
========================= */

app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (!user.rows.length)
      return res.status(404).json({ message: "User not found" });

    const token = crypto.randomBytes(32).toString("hex");
    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await db.query(
      "UPDATE users SET reset_token=$1, reset_expiry=$2 WHERE email=$3",
      [token, expiry, email]
    );

    const resetLink = `https://7930navid.github.io/My-platform/reset-password.html?token=${token}`;

    await transporter.sendMail({
      from: `"AsirNet Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Reset Password",
      html: `
        <div style="font-family:Poppins">
          <h2>Reset Password</h2>
          <a href="${resetLink}"
            style="padding:12px 20px;background:#00e5ff;color:white;text-decoration:none;border-radius:10px;display:inline-block;">
            Reset Password
          </a>
          <p>This link expires in 15 minutes.</p>
        </div>
      `
    });

    res.json({ message: "Reset email sent" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   RESET PASSWORD (FIXED)
========================= */

app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await db.query(
      `SELECT * FROM users 
       WHERE reset_token=$1 
       AND reset_expiry > NOW()`,
      [token]
    );

    if (!user.rows.length)
      return res.status(400).json({ message: "Invalid or expired token" });

    const hash = await bcrypt.hash(newPassword, 12);

    await db.query(
      `UPDATE users 
       SET password=$1, reset_token=NULL, reset_expiry=NULL
       WHERE id=$2`,
      [hash, user.rows[0].id]
    );

    res.json({ message: "Password updated" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 5000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log("🚀 AsirNet running on", PORT);
  });
});