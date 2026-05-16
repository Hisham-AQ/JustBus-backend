const db = require("../../config/db");

// ================= ANALYTICS =================
exports.getAnalytics = async (req, res) => {
  try {
    // average rating
    const [avg] = await db.query(
      "SELECT AVG(rating) AS averageRating FROM ratings"
    );

    // total ratings
    const [total] = await db.query(
      "SELECT COUNT(*) AS totalRatings FROM ratings"
    );

    // distribution (1–5 stars)
    const [distribution] = await db.query(`
      SELECT rating, COUNT(*) AS count
      FROM ratings
      GROUP BY rating
      ORDER BY rating
    `);

    res.json({
      averageRating: avg[0].averageRating || 0,
      totalRatings: total[0].totalRatings,
      distribution
    });

  } catch (err) {
    console.error("RATINGS ANALYTICS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= COMMENTS =================
exports.getComments = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        r.id,
        r.rating,
        r.comment,
        r.created_at,
        u.name AS userName
      FROM ratings r
      JOIN users u ON u.id = r.user_id
      WHERE r.comment IS NOT NULL AND r.comment != ''
      ORDER BY r.created_at DESC
    `);

    res.json(rows);

  } catch (err) {
    console.error("GET COMMENTS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};