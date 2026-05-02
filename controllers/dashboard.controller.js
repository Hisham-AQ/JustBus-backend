const db = require("../config/db");

// ================= DASHBOARD STATS =================
exports.getStats = async (req, res) => {
  try {
    const [students] = await db.query(
      "SELECT COUNT(*) AS count FROM users WHERE role = 'student'"
    );

    const [drivers] = await db.query(
      "SELECT COUNT(*) AS count FROM drivers"
    );

    const [trips] = await db.query(
      "SELECT COUNT(*) AS count FROM trips"
    );

    const [buses] = await db.query(
      "SELECT COUNT(*) AS count FROM buses"
    );

    const [activeTrips] = await db.query(
      "SELECT COUNT(*) AS count FROM trips WHERE status = 'scheduled' OR status = 'ongoing'"
    );

    res.json({
      totalStudents: students[0].count,
      totalDrivers: drivers[0].count,
      totalTrips: trips[0].count,
      totalBuses: buses[0].count,
      activeTrips: activeTrips[0].count
    });

  } catch (err) {
    console.error("DASHBOARD STATS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};