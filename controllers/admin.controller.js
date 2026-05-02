const db = require("../config/db");

// ================= GET ALL USERS =================
exports.getUsers = async (req, res) => {
  try {
    const [users] = await db.execute(
      "SELECT id, email, role FROM users"
    );

    res.json(users);

  } catch (err) {
    console.error("GET USERS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};