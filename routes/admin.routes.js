const db = require("../config/db");
const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");

router.get(
  "/users",
  authenticateToken,
  allowRoles("admin"),
  async (req, res) => {
    try {
      const [users] = await db.execute(
        "SELECT id, email, role FROM users"
      );

      res.json(users);

    } catch (err) {
      console.error("GET USERS ERROR:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

module.exports = router;