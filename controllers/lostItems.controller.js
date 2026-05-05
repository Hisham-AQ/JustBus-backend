const db = require("../config/db");


// ✅ CREATE REPORT
exports.createReport = async (req, res) => {
  const userId = req.user.id;
  const {
    category,
    item_name,
    ride_id,
    lost_date,
    description,
    image_url
  } = req.body;

  try {
    await db.query(
      `INSERT INTO lost_items 
       (user_id, category, item_name, ride_id, lost_date, description, image_url)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, category, item_name, ride_id, lost_date, description, image_url]
    );

    res.json({ message: "Report submitted" });

  } catch (err) {
    console.error("CREATE REPORT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ✅ GET MY REPORTS
exports.getMyReports = async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await db.query(
      `SELECT id, item_name, status, lost_date 
       FROM lost_items
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json(rows);

  } catch (err) {
    console.error("GET REPORTS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};