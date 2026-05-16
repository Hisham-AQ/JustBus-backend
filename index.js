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
const busesRoutes = require("./routes/web/buses.routes");
const routesRoutes = require("./routes/web/routes.routes");
const driversRoutes = require("./routes/web/adminDrivers.routes");
const adminTripsRoutes = require("./routes/web/adminTrips.routes");
const studentsRoutes = require("./routes/web/students.routes");
const dashboardRoutes = require("./routes/web/dashboard.routes");
const adminRatingsRoutes = require("./routes/web/adminRatings.routes");
const tripsRoutes = require("./routes/mobile/userTrips.routes");
const activityRoutes = require("./routes/mobile/activity.routes");
const walletRoutes = require("./routes/mobile/wallet.routes");
const cardRoutes = require("./routes/mobile/userCard.routes");
const rewardsRoutes = require("./routes/mobile/userRewards.routes");
const notificationsRoutes = require("./routes/notifications.routes");
const lostItemsRoutes = require("./routes/lostItems.routes");
const driverRoutes = require("./routes/mobile/driver.routes");
const ratingsRoutes = require("./routes/ratings.routes");
const stationsRoutes = require("./routes/web/stations.routes");


app.use("/api/auth", require("./routes/mobile/auth.routes"));
app.use("/api/admin/trips", adminTripsRoutes);
app.use("/api/routes", routesRoutes);
app.use("/api/buses", require("./routes/web/buses.routes"));
app.use("/api/admin", adminRoutes);
app.use("/api/drivers", driversRoutes);
app.use("/api", require("./routes/mobile/userTrips.routes"));
app.use("/api", require("./routes/web/bookings.routes"));
app.use("/api", require("./routes/parcels.routes"));
app.use("/api", require("./routes/mobile/specialTrips.routes"));
app.use("/api", require("./routes/mobile/users.routes"));
app.use("/api/students", studentsRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/ratings", adminRatingsRoutes);
app.use("/api/alerts", require("./routes/web/alerts.routes"));
app.use("/api/rewards", require("./routes/rewards.routes"));
app.use("/api", require("./routes/mobile/ai.routes"));
app.use("/api/trips", tripsRoutes);
app.use("/api", activityRoutes);
app.use("/api/wallet", walletRoutes);
app.use("/api/cards", cardRoutes);
app.use("/api/rewards", rewardsRoutes);
app.use("/api", notificationsRoutes);
app.use("/api", lostItemsRoutes);
app.use("/api/driver", driverRoutes);
app.use("/api/ratings", ratingsRoutes);
app.use("/api/stations", stationsRoutes);


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



///////temp code
/*(async () => {
  const hash = await bcrypt.hash("password123", 10);
  console.log("HASH:", hash);
})();*/