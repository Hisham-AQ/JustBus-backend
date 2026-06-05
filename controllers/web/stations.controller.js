const db = require("../../config/db");


// ================= getStations =================
exports.getStations = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT id, name, lat, lng
      FROM stations
      ORDER BY name
    `);

    res.json(rows);

  } catch (err) {
    console.error("GET STATIONS ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};