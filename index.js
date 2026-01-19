/* =========================================
   IMPORTS & CONFIGURATION
========================================= */
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const nodemailer = require("nodemailer");

const db = require("./config/db");

/* =========================================
   APP INITIALIZATION
========================================= */
const app = express();
app.use(express.json());

console.log("EMAIL_USER =", process.env.EMAIL_USER);
console.log("EMAIL_PASS exists =", !!process.env.EMAIL_PASS);

/* =========================================
   EMAIL TRANSPORTER (NODEMAILER)
========================================= */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

/* =========================================
   TEST EMAIL TRANSPORTER
========================================= */
transporter.verify((error, success) => {
  if (error) {
    console.error("❌ Email transporter error:", error);
  } else {
    console.log("✅ Email transporter is ready");
  }
});

/* =========================================
   JWT AUTH MIDDLEWARE
========================================= */
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

/* =========================================
   SERVER TEST ENDPOINT
========================================= */
app.get("/", (req, res) => {
  res.json({ message: "JustBus backend is running 🚍" });
});

/* =========================================
   AUTH — REGISTER
========================================= */
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

/* =========================================
   AUTH — LOGIN
========================================= */
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

/* =========================================
   USER PROFILE — GET
========================================= */
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

/* =========================================
   USER PROFILE — UPDATE
========================================= */
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
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        message: "Phone number already in use",
      });
    }

    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================================
   AUTH — CHANGE PASSWORD
========================================= */
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

    const hashedPassword = await bcrypt.hash(newPassword, 10);

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

/* =========================================
   AUTH — FORGOT PASSWORD
========================================= */
app.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const [rows] = await db.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);

    if (rows.length === 0) {
      return res.json({
        message: "If this email exists, a reset code has been sent",
      });
    }

    const userId = rows[0].id;

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    await db.query(
      "UPDATE users SET reset_code = ?, reset_code_expires = ? WHERE id = ?",
      [resetCode, expires, userId]
    );

    await transporter.sendMail({
      from: `"JustBus Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "JustBus Password Reset Code",
      html: `
        <p>You requested a password reset.</p>
        <h2>${resetCode}</h2>
        <p>This code expires in 15 minutes.</p>
      `,
    });

    res.json({ message: "A reset code has been sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================================
   AUTH — RESET PASSWORD
========================================= */
app.post("/auth/reset-password", async (req, res) => {
  try {
    const { code, newPassword } = req.body;

    if (!code || !newPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const [rows] = await db.query(
      `SELECT id, reset_code_expires
       FROM users WHERE reset_code = ?`,
      [code]
    );

    if (rows.length === 0) {
      return res.status(400).json({ message: "Invalid reset code" });
    }

    const user = rows[0];

    if (!user.reset_code_expires || new Date(user.reset_code_expires) < new Date()) {
      return res.status(400).json({ message: "Reset code expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.query(
      `UPDATE users
       SET password = ?, reset_code = NULL, reset_code_expires = NULL
       WHERE id = ?`,
      [hashedPassword, user.id]
    );

    res.json({ message: "Password reset successfully" });
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

/* =========================
   CITIES (MYSQL)
========================= */
app.get("/api/cities", async (req, res) => {
  const [rows] = await db.query(`
    SELECT DISTINCT from_city
    FROM trips
    WHERE from_city != 'JUST university'
  `);

  res.json(rows);
});

/* =========================
   TRIPS SEARCH (MYSQL)
========================= */
app.get("/api/trips", async (req, res) => {
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
        arrival_time,
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
    res.status(500).json({
      message: err.message,
      code: err.code,
    });
  }
});

/* =========================
   BOOKINGS — HOLD SEATS (RACE CONDITION SAFE)
========================= */
app.post('/api/bookings/hold', authenticateToken, async (req, res) => {
  const { tripId, pickup, dropoff, seats } = req.body;
  const userId = req.user.id;

  if (!tripId || !pickup || !dropoff) {
    return res.status(400).json({ message: 'Missing trip data' });
  }

  if (!Array.isArray(seats) || seats.length === 0) {
    return res.status(400).json({ message: 'Seats are required' });
  }

  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    await conn.query(`
      DELETE FROM bookings
      WHERE status = 'held'
      AND hold_expires_at < NOW()
    `);

    const [taken] = await conn.execute(
      `
      SELECT seat_number
      FROM booking_seats
      WHERE trip_id = ?
      AND seat_number IN (${seats.map(() => '?').join(',')})
      `,
      [tripId, ...seats]
    );

    if (taken.length > 0) {
      await conn.rollback();
      return res.status(409).json({
        message: 'Seats already booked',
        seats: taken.map(s => s.seat_number),
      });
    }

    const holdExpiresAt = new Date(Date.now() + 3 * 60 * 1000);
    const qrToken = require('crypto').randomUUID();

    const [bookingResult] = await conn.execute(
      `
      INSERT INTO bookings
      (user_id, trip_id, pickup_location, dropoff_location, total_price, qr_token, status, hold_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, 'held', ?)
      `,
      [
        userId,
        tripId,
        pickup,
        dropoff,
        seats.length * 2.5,
        qrToken,
        holdExpiresAt,
      ]
    );

    const bookingId = bookingResult.insertId;

    for (const seat of seats) {
      await conn.execute(
        `
        INSERT INTO booking_seats (booking_id, trip_id, seat_number)
        VALUES (?, ?, ?)
        `,
        [bookingId, tripId, seat]
      );
    }

    await conn.commit();

    return res.json({
      bookingId,
      holdExpiresAt,
    });
  } catch (err) {
    await conn.rollback();
    console.error('HOLD ERROR:', err);

    return res.status(500).json({
      message: 'Hold failed',
      error: err.message,
    });
  } finally {
    conn.release();
  }
});

/* =========================
   BOOKINGS — CONFIRM
========================= */
app.post('/api/bookings/confirm', authenticateToken, async (req, res) => {
  const { bookingId } = req.body;
  const userId = req.user.id;

  if (!bookingId) {
    return res.status(400).json({ message: 'bookingId required' });
  }

  const conn = await db.getConnection();

  try {
    const [rows] = await conn.execute(
      `SELECT * FROM bookings
       WHERE id = ?
         AND user_id = ?
         AND status = 'held'
         AND hold_expires_at > UTC_TIMESTAMP()`,
      [bookingId, userId]
    );

    if (rows.length === 0) {
      return res.status(409).json({
        message: 'Hold expired or booking not found',
      });
    }

    await conn.execute(
      `UPDATE bookings
       SET status = 'confirmed'
       WHERE id = ?`,
      [bookingId]
    );

    res.json({ success: true });
  } catch (e) {
    console.error('CONFIRM ERROR:', e);
    res.status(500).json({ message: 'Confirm failed' });
  } finally {
    conn.release();
  }
});

/* =========================
   CLEANUP EXPIRED HOLDS (CRON)
========================= */
setInterval(async () => {
  await db.query(`
    DELETE FROM bookings
    WHERE status = 'held'
    AND hold_expires_at < NOW()
  `);
}, 60 * 1000);

/* =========================
   SEAT STATUS — PER TRIP
========================= */
app.get('/api/trips/:tripId/seats', async (req, res) => {
  const { tripId } = req.params;

  const [rows] = await db.query(
    `
    SELECT
      bs.seat_number,
      COALESCE(u.gender, 'none') AS gender
    FROM booking_seats bs
    JOIN bookings b ON b.id = bs.booking_id
    JOIN users u ON u.id = b.user_id
    WHERE bs.trip_id = ?
    `,
    [tripId]
  );

  res.json({
    reservedSeats: rows.map(r => ({
      seat_number: r.seat_number,
      gender: r.gender
    }))
  });
});

/* =========================
   DRIVER — QR SCAN
========================= */
app.post('/driver/scan', authenticateToken, async (req, res) => {
  const { qrToken } = req.body;

  if (!qrToken) {
    return res.status(400).json({ message: 'Missing qrToken' });
  }

  const [rows] = await db.query(
    `
    SELECT b.id, b.status, t.trip_date
    FROM bookings b
    JOIN trips t ON t.id = b.trip_id
    WHERE b.qr_token = ?
    `,
    [qrToken]
  );

  if (rows.length === 0) {
    return res.status(404).json({ valid: false, message: 'Invalid ticket' });
  }

  const booking = rows[0];

  if (booking.status !== 'confirmed') {
    return res.json({ valid: false, message: 'Ticket already used or cancelled' });
  }

  await db.query(
    `UPDATE bookings SET status = 'used' WHERE id = ?`,
    [booking.id]
  );

  await db.query(
    `INSERT INTO scan_logs (booking_id, scanned_at)
     VALUES (?, NOW())`,
    [booking.id]
  );

  res.json({
    valid: true,
    bookingId: booking.id,
    message: 'Ticket valid'
  });
});

/* =========================================
   START SERVER
========================================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
