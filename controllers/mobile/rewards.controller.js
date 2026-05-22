const db = require("../../config/db");


exports.getRules = async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM reward_rules WHERE id = 1");
    res.json(rows[0]);
  } catch (err) {
    console.error("GET RULES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


exports.updateRules = async (req, res) => {
  const { pointsPerTrip, bonusThreshold, reward } = req.body;

  try {
    await db.query(
      `UPDATE reward_rules 
       SET 
         points_per_trip = COALESCE(?, points_per_trip),
         bonus_threshold = COALESCE(?, bonus_threshold),
         reward = COALESCE(?, reward)
       WHERE id = 1`,
      [pointsPerTrip, bonusThreshold, reward]
    );

    res.json({ message: "Rules updated" });

  } catch (err) {
    console.error("UPDATE RULES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};