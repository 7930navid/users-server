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
   SECURITY
========================= */

app.disable("x-powered-by");

app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: [
    "https://7930navid.github.io",
    "http://localhost:8080"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
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
  max: 5
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
   EMAIL
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
  `);

  console.log("✅ DB Ready");
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = header.split(" ")[1];

    req.user = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "AsirNet",
      audience: "AsirNetUsers"
    });

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

    if (exists.rows.length)
      return res.status(400).json({ message: "User exists" });

    const hash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO users (username,email,password,bio,avatar,cover_photo)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [username, email, hash, bio || "", avatar || "", cover_photo || ""]
    );

    res.status(201).json({ message: "User created" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   SIGNIN (FIXED SAFE DESTRUCTURE)
========================= */

app.post("/signin", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await db.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (!result.rows.length)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);

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

    // ✅ FIX: no redeclare bug
    const { password: _, reset_token, reset_expiry, ...safeUser } = user;

    res.json({ token, user: safeUser });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   ME
========================= */

app.get("/me", auth, async (req, res) => {
  const result = await db.query(
    "SELECT id,username,email,bio,avatar,cover_photo FROM users WHERE id=$1",
    [req.user.id]
  );

  res.json(result.rows[0]);
});

/* =========================
   DELETE ACCOUNT
========================= */

app.delete("/delete-account", auth, async (req, res) => {
  await db.query("DELETE FROM users WHERE id=$1", [req.user.id]);
  res.json({ message: "Account deleted" });
});

/* =========================
   FORGOT PASSWORD
========================= */

app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email required" });
    }

    const user = await db.query(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (!user.rows.length) {
      return res.status(404).json({ message: "User not found" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await db.query(
      "UPDATE users SET reset_token=$1, reset_expiry=$2 WHERE email=$3",
      [token, expiry, email]
    );

    const resetLink = `https://7930navid.github.io/My-platform/reset-password.html?token=${token}`;

    const mailOptions = {
      from: `"AsirNet" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Reset Password",
      html: `
        <div>
          <h3>Reset your password</h3>
          <a href="${resetLink}" 
             style="padding:10px 20px;background:#00e5ff;color:#000;text-decoration:none;border-radius:8px;">
             Click to Reset Password
          </a>
          <p>This link will expire in 15 minutes.</p>
        </div>
      `
    };

    // 🔥 IMPORTANT FIX: EMAIL TIMEOUT PROTECTION
    try {
      await Promise.race([
        transporter.sendMail(mailOptions),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Email timeout")), 8000)
        )
      ]);
    } catch (mailErr) {
      console.error("Email send failed:", mailErr.message);
      // still respond to user even if email fails
      return res.json({
        message: "Reset token created but email failed. Try again later."
      });
    }

    return res.json({ message: "Reset email sent" });

  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});
/* =========================
   RESET PASSWORD
========================= */

app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const user = await db.query(
      `SELECT * FROM users WHERE reset_token=$1`,
      [token]
    );

    if (!user.rows.length)
      return res.status(400).json({ message: "Invalid token" });

    const hash = await bcrypt.hash(newPassword, 12);

    await db.query(
      `UPDATE users 
       SET password=$1, reset_token=NULL, reset_expiry=NULL
       WHERE id=$2`,
      [hash, user.rows[0].id]
    );

    res.json({ message: "Password updated" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   START
========================= */

const PORT = process.env.PORT || 5000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log("🚀 Server running on", PORT);
  });
});