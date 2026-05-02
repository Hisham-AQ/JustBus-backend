// TEMP in-memory storage (later move to DB)
let rules = {
  pointsPerTrip: 10,
  bonusThreshold: 100,
  reward: "Free Ride"
};

// ================= GET RULES =================
exports.getRules = async (req, res) => {
  try {
    res.json(rules);
  } catch (err) {
    console.error("GET RULES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= UPDATE RULES =================
exports.updateRules = async (req, res) => {
  try {
    const { pointsPerTrip, bonusThreshold, reward } = req.body;

    // update only provided fields
    if (pointsPerTrip !== undefined) rules.pointsPerTrip = pointsPerTrip;
    if (bonusThreshold !== undefined) rules.bonusThreshold = bonusThreshold;
    if (reward !== undefined) rules.reward = reward;

    res.json({
      message: "Rules updated",
      rules
    });

  } catch (err) {
    console.error("UPDATE RULES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};