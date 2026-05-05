const express = require("express");
require("dotenv").config();
const app = express();

const cors = require("cors");

app.use(cors({
  origin: ["http://127.0.0.1:5174", "http://localhost:5174"],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));


app.use(express.json());
const authenticateToken = require("./middleware/authMiddleware");
const axios = require("axios");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const adminRoutes = require("./routes/admin.routes");
const busesRoutes = require("./routes/buses.routes");
const routesRoutes = require("./routes/routes.routes");
const driversRoutes = require("./routes/drivers.routes");
const adminTripsRoutes = require("./routes/adminTrips.routes");
const studentsRoutes = require("./routes/students.routes");
const dashboardRoutes = require("./routes/dashboard.routes");
const ratingsRoutes = require("./routes/ratings.routes");
const tripsRoutes = require("./routes/trips.routes");
const activityRoutes = require("./routes/activity.routes");
const walletRoutes = require("./routes/wallet.routes");
const cardRoutes = require("./routes/card.routes");
const rewardsRoutes = require("./routes/userRewards.routes");



app.use("/api/auth", require("./routes/auth.routes"));
app.use("/api/admin/trips", adminTripsRoutes);
app.use("/api/routes", routesRoutes);
app.use("/api/buses", require("./routes/buses.routes"));
app.use("/api/admin", adminRoutes);
app.use("/api", require("./routes/trips.routes"));
app.use("/api", require("./routes/bookings.routes"));
app.use("/api", require("./routes/parcels.routes"));
app.use("/api", require("./routes/specialTrips.routes"));
app.use("/api", require("./routes/users.routes"));
app.use("/api/students", studentsRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/ratings", ratingsRoutes);
app.use("/api/alerts", require("./routes/alerts.routes"));
app.use("/api/rewards", require("./routes/rewards.routes"));
app.use("/api", require("./routes/ai.routes"));
app.use("/api/trips", tripsRoutes);
app.use("/api", activityRoutes);
app.use("/api/wallet", walletRoutes);
app.use("/api/cards", cardRoutes);
app.use("/api/rewards", rewardsRoutes);


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


////////////////// holds TIME
setInterval(async () => {
  try {
    await db.query(`
      DELETE FROM bookings
      WHERE status = 'held'
      AND hold_expires_at < NOW()
    `);
   //console.log("Expired holds cleaned");
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

const http = require("http");
const { Server } = require("socket.io");

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
  }
});

module.exports.io = io;

io.on("connection", (socket) => {
  console.log("🟢 Client connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("🔴 Client disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});