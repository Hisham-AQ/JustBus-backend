const express = require("express");
require("dotenv").config();
const app = express();
app.use(express.json());
const authenticateToken = require("./middleware/authMiddleware");
const axios = require("axios");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

app.use("/auth", require("./routes/auth.routes"));
app.use("/api", require("./routes/user.routes"));
app.use("/api", require("./routes/trips.routes"));
app.use("/api", require("./routes/bookings.routes"));
app.use("/api", require("./routes/parcels.routes"));
app.use("/api", require("./routes/specialTrips.routes"));

const db = require("./config/db");



/* =========================================
   SERVER TEST ENDPOINT
========================================= */
app.get("/", (req, res) => {
  res.json({ message: "JustBus backend is running 🚍" });
});


///////// test db
db.query("SELECT 1")
  .then(() => console.log("DB connected ✅"))
  .catch(err => console.error("DB connection failed ❌", err.message));


/* =========================
   wallet
========================= */

app.get("/api/wallet", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  const [rows] = await db.query(
    "SELECT wallet_balance FROM users WHERE id = ?",
    [userId]
  );

  res.json({
    balance: rows[0].wallet_balance
  });
});



/* =========================
   CARDS
========================= */

app.post("/api/cards", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { cardNumber, holder, expiry, brand } = req.body;

  try {
    const last4 = cardNumber.slice(-4);

    await db.query(
      "INSERT INTO user_cards (user_id, card_number, card_holder, expiry, brand) VALUES (?, ?, ?, ?, ?)",
      [userId, last4, holder, expiry, brand]
    );

    res.json({ message: "Card added" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


app.get("/api/cards", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  const [rows] = await db.query(
    "SELECT * FROM user_cards WHERE user_id = ?",
    [userId]
  );

  res.json(rows);
});



/* =========================
   CLEANUP EXPIRED HOLDS (CRON)
========================= */
setInterval(async () => {
  try {
    await db.query(`
      DELETE FROM bookings
      WHERE status = 'held'
      AND hold_expires_at < NOW()
    `);
  } catch (err) {
    console.error("Cleanup job error:", err.message);
  }
}, 60 * 1000);


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
