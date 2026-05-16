// TEMP mock alerts (later move to DB)
const alerts = [
  {
    id: 1,
    title: "Route Delay",
    message: "Route 5B delayed due to traffic",
    created_at: new Date(),
    resolved: false
  },
  {
    id: 2,
    title: "System Alert",
    message: "Bus GPS offline",
    created_at: new Date(),
    resolved: false
  }
];

// ================= GET ALERTS =================
exports.getAlerts = async (req, res) => {
  try {
    res.json(alerts);
  } catch (err) {
    console.error("GET ALERTS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};