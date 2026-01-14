const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const db = require("./config/db");

const app = express();

app.use(express.json());

/* =======================
   JWT MIDDLEWARE
======================= */
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Missing token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

/* =======================
   TEST
======================= */
app.get("/", (req, res) => {
  res.json({ message: "JustBus backend is running 🚍" });
});

/* =======================
   REGISTER (MYSQL)
======================= */
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, role, phone, gender, birth_date } = req.body;

    if (!name || !email || !password || !role || !phone) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (!/^\d{9,15}$/.test(phone)) {
      return res.status(400).json({ message: "Invalid phone number" });
    }

    const [existing] = await db.execute(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      `INSERT INTO users 
       (name, email, password, role, phone, gender, birth_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        email,
        hashedPassword,
        role,
        phone || null,
        gender || null,
        birth_date || null,
      ]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =======================
   LOGIN (MYSQL)
======================= */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const [rows] = await db.execute(
      "SELECT id, email, password, role FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      token,
      role: user.role,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
        name,
        email,
        phone,
        gender,
        birth_date
       FROM users
       WHERE id = ?`,
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(rows[0]); 
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

//info edit
app.put("/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, birth_date, phone } = req.body;

    if (!name && !birth_date && !phone) {
      return res.status(400).json({ message: "Nothing to update" });
    }

    if (birth_date && isNaN(Date.parse(birth_date))) {
      return res.status(400).json({ message: "Invalid birth date" });
    }

    const fields = [];
    const values = [];

    if (name) {
      fields.push("name = ?");
      values.push(name);
    }

    if (birth_date) {
      fields.push("birth_date = ?");
      values.push(birth_date);
    }

    if (phone) {
      fields.push("phone = ?");
      values.push(phone);
    }

    values.push(userId);

    const sql = `
      UPDATE users
      SET ${fields.join(", ")}
      WHERE id = ?
    `;

    await db.query(sql, values);

    return res.json({ message: "Profile updated successfully" });
  } catch (err) {
    // handle unique phone constraint
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        message: "Phone number already in use",
      });
    }

    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =======================
   CHANGE PASSWORD
======================= */
app.put("/auth/change-password", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Missing fields" });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    // 1️⃣ Get current password hash
    const [rows] = await db.query("SELECT password FROM users WHERE id = ?", [
      userId,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const isValid = await bcrypt.compare(currentPassword, rows[0].password);

    if (!isValid) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    // 2️⃣ Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 3️⃣ Update password
    await db.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      userId,
    ]);

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   SPECIAL TRIPS (MYSQL)
========================= */
app.get("/special-trips", async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM SpecialTrip");
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch trips" });
  }
});

app.get('/api/cities', async (req, res) => {
  const [rows] = await db.query(
    `SELECT DISTINCT from_city FROM trips`
  );

  res.json(rows);
});

/* =========================
    TRIPS (MYSQL)
========================= */

app.get('/api/trips', async (req, res) => {
  const { from, to, date } = req.query;

  try {
    const [rows] = await db.query(
      `
      SELECT 
        id,
        from_city,
        to_city,
        pickup_location,
        dropoff_location,
        departure_time,
        duration_minutes,
        price,
        available_seats
      FROM trips
      WHERE from_city = ?
        AND to_city = ?
        AND trip_date = ?
      ORDER BY departure_time
      `,
      [from, to, date]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch trips' });
  }
});


/* =======================
   START SERVER
======================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});