const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");


const { Pool } = require("pg");

const app = express();
app.use(helmet());
app.use(bodyParser.json());

app.use(
  cors({
    origin: ["https://7930navid.github.io", "http://localhost:8080"],
  })
);

// 🔹 User-DB connections
const usersDB = new Pool({
  connectionString: process.env.USERS_DB_URL,
  ssl: { rejectUnauthorized: false },
});


// 🔹 Initialize tables
async function initDB() {
  try {
    await usersDB.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        bio TEXT NOT NULL,
        avatar TEXT NOT NULL
      );
    `);


    console.log("✅ User table initialized successfully!");
  } catch (err) {
    console.error("❌ Error initializing table:", err.message);
  }
}

// 🔹 Signup
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password, bio, avatar } = req.body;

    if (!username || !email || !password || !bio || !avatar)
      return res.status(400).json({ message: "Please fill all fields" });

    const exists = await usersDB.query("SELECT * FROM users WHERE email=$1", [email]);
    if (exists.rows.length > 0)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await usersDB.query(
      "INSERT INTO users (username, email, password, bio, avatar) VALUES ($1, $2, $3, $4, $5)",
      [username, email, hashedPassword, bio, avatar]
    );

    res.json({ message: "Registered successfully" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Error registering user", error: err.message });
  }
});

// 🔹 Signin
app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Please fill all fields" });

    const result = await usersDB.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ message: "Invalid email or password" });

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid)
      return res.status(401).json({ message: "Invalid email or password" });

    res.json({ message: "Login successful", user: { ...user, password: undefined } });
  } catch (err) {
    res.status(500).json({ message: "Error logging in", error: err.message });
  }
});


// 🔹 Edit Profile (password optional)
app.put("/editprofile", async (req, res) => {
  try {
    const { email, username, password, bio, avatar } = req.body;

    if (!email || !username || !bio || !avatar) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const client = await usersDB.connect();

    try {
      await client.query("BEGIN");

      let updateQuery;
      let values;

      // 🔹 password থাকলে
      if (password && password.trim() !== "") {
        const hashedPassword = await bcrypt.hash(password, 10);

        updateQuery = `
          UPDATE users
          SET username=$1, password=$2, bio=$3, avatar=$4
          WHERE email=$5
          RETURNING id, email, username, bio, avatar
        `;

        values = [username, hashedPassword, bio, avatar, email];

      } else {
        // 🔹 password ছাড়া update
        updateQuery = `
          UPDATE users
          SET username=$1, bio=$2, avatar=$3
          WHERE email=$4
          RETURNING id, email, username, bio, avatar
        `;

        values = [username, bio, avatar, email];
      }

      const userResult = await client.query(updateQuery, values);

      if (userResult.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ message: "User not found" });
      }

      await client.query("COMMIT");

      res.json({
        message: "Profile updated successfully",
        user: userResult.rows[0] // password null
      });

    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error updating profile" });
  }
});
// 🔹 Delete User + Posts
app.delete("/deleteuser/:email", async (req, res) => {
  try {
    const { email } = req.params;
    const result = await usersDB.query("DELETE FROM users WHERE email=$1", [email]);

    if (result.rowCount > 0)
      res.json({ message: `${email} has been deleted` });
    else
      res.status(404).json({ message: "User not found" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting user", error: err.message });
  }
});

// 🔹 Fetch all users
app.get("/users", async (req, res) => {
  try {
    const users = await usersDB.query("SELECT * FROM users");
    res.json(users.rows.map(u => ({ ...u, password: undefined })));
  } catch (err) {
    res.status(500).json({ message: "Error fetching users", error: err.message });
  }
});


// 🔐 Verify password (for sensitive actions)
app.post("/verify-password", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Missing data" });
    }

    const result = await usersDB.query(
      "SELECT password FROM users WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashedPassword = result.rows[0].password;
    const isValid = await bcrypt.compare(password, hashedPassword);

    if (!isValid) {
      return res.status(401).json({ message: "Wrong password" });
    }

    res.json({ message: "Password verified" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// 🔹 Server check
app.get("/", (req, res) => res.json({ message: "Backend is working ✅" }));

// 🔹 Start Server
const PORT = process.env.PORT || 5000;
async function startServer() {
  await initDB();
  app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
}
startServer();

