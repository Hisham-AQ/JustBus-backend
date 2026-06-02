const http = require("http");
const { Server } = require("socket.io");
const express = require("express");
require("dotenv").config();
const app = express();
const server = http.createServer(app);
const helmet = require("helmet");
app.use(helmet());

const cors = require("cors");


app.use(cors({
  origin: [
    "https://justbus-web-production.up.railway.app",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));



app.use(express.json());
const authenticateToken = require("./middleware/authMiddleware");
const axios = require("axios");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// WEB ROUTES
const adminRoutes = require("./routes/web/admin.routes");
const busesRoutes = require("./routes/web/buses.routes");
const driversRoutes = require("./routes/web/adminDrivers.routes");
const adminTripsRoutes = require("./routes/web/adminTrips.routes");
const studentsRoutes = require("./routes/web/students.routes");
const dashboardRoutes = require("./routes/web/dashboard.routes");
const stationsRoutes = require("./routes/web/stations.routes");
const adminSpecialTripsRoutes = require("./routes/web/adminSpecialTrips.routes");
const adminParcelsRoutes = require("./routes/web/adminParcels.routes");
const adminTripBookingsRoutes = require("./routes/web/adminTripBookings.routes");
const adminRewardsRoutes = require("./routes/web/adminRewards.routes");
const adminPointsRoutes = require("./routes/web/adminPoints.routes");
const adminRatingsRoutes = require("./routes/web/adminRatings.routes");
const lostItemRoutes = require("./routes/web/adminLostItem.routes");
const adminNotificationsRoutes = require("./routes/web/adminNotifications.routes");
const adminPanicRoutes = require("./routes/web/adminPanic.routes");


// MOBILE ROUTES
const authRoutes = require("./routes/mobile/auth.routes");
const tripsRoutes = require("./routes/mobile/userTrips.routes");
const activityRoutes = require("./routes/mobile/activity.routes");
const walletRoutes = require("./routes/mobile/wallet.routes");
const cardRoutes = require("./routes/mobile/userCard.routes");
const rewardsRoutes = require("./routes/mobile/userRewards.routes");
const notificationsRoutes = require("./routes/mobile/notifications.routes");
const lostItemsRoutes = require("./routes/mobile/lostItems.routes");
const driverRoutes = require("./routes/mobile/driver.routes");
const ratingsRoutes = require("./routes/mobile/ratings.routes");
const aiRoutes = require("./routes/mobile/ai.routes");
const usersRoutes = require("./routes/mobile/users.routes");
const specialTripsRoutes = require("./routes/mobile/specialTrips.routes");
const parcelsRoutes = require("./routes/mobile/parcels.routes");
const bookingsRoutes = require("./routes/mobile/bookings.routes");
const panicRoutes = require("./routes/mobile/panic.routes");

// ================= ROUTES =================

// AUTH
app.use("/api/auth", authRoutes);

// WEB
app.use("/api/admin", adminRoutes);
app.use("/api/admin/trips", adminTripsRoutes);
app.use("/api/buses", busesRoutes);
app.use("/api/drivers", driversRoutes);
app.use("/api/students", studentsRoutes);
app.use('/api/dashboard', require('./routes/web/dashboard.routes'));
app.use("/api/bookings", bookingsRoutes);
app.use("/api/stations", stationsRoutes);
app.use("/api/admin/special-trips", adminSpecialTripsRoutes);
app.use("/api/admin/trip-bookings", adminTripBookingsRoutes);
app.use("/api/admin/rewards", adminRewardsRoutes);
app.use("/api/admin/points", adminPointsRoutes);
app.use("/api/admin/ratings", adminRatingsRoutes);
app.use('/api/admin/parcels', require('./routes/web/adminParcels.routes'));
app.use("/api/admin/wallet", require("./routes/web/adminWallet.routes"));
app.use("/api/admin/map", require("./routes/web/adminLiveMap.routes"));
app.use("/api", lostItemRoutes);
app.use("/api/admin/notifications", adminNotificationsRoutes);
app.use("/api/admin/panic", adminPanicRoutes);
app.use("/api/admin/cancellation-requests", require("./routes/web/adminCancellationRequests.routes"));
app.use("/api/admin/misconduct", require("./routes/web/adminMisconduct.routes"));


// MOBILE
app.use("/api/trips", tripsRoutes);
app.use("/api/activity", activityRoutes);
app.use("/api/wallet", walletRoutes);
app.use("/api/cards", cardRoutes);
app.use("/api/rewards", rewardsRoutes);
app.use("/api/notifications", notificationsRoutes);
app.use("/api/lost-items", lostItemsRoutes);
app.use("/api/driver", driverRoutes);
app.use("/api/ratings", ratingsRoutes);
app.use("/api/ai", aiRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/special-trips", specialTripsRoutes);
app.use("/api/parcels", parcelsRoutes);
app.use("/api/panic", panicRoutes);

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


/* =========================================
   START SERVER
========================================= */


const io = new Server(server, {
  cors: {
    origin: [
      "https://justbus-web-production.up.railway.app",
      "http://localhost:5173",
      "http://localhost:5174",
      "http://localhost:3000"
    ],
    methods: ["GET", "POST"]
  }
});

module.exports.io = io;

app.set("io", io);

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



///////temp code
/*(async () => {
  const hash = await bcrypt.hash("password123", 10);
  console.log("HASH:", hash);
})();*/