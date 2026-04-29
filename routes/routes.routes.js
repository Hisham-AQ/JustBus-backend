const express = require("express");
const router = express.Router();

const db = require("../config/db");
const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");


// GET all routes
router.get("/", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM routes");
    res.json(rows);
  } catch (err) {
    console.error("GET ROUTES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// CREATE route
router.post("/", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { name, start_point, end_point } = req.body;

    if (!name || !start_point || !end_point) {
      return res.status(400).json({ message: "Missing fields" });
    }

    await db.execute(
      "INSERT INTO routes (name, start_point, end_point) VALUES (?, ?, ?)",
      [name, start_point, end_point]
    );

    res.status(201).json({ message: "Route created successfully" });

  } catch (err) {
    console.error("CREATE ROUTE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// UPDATE route
router.put("/:id", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, start_point, end_point } = req.body;

    await db.execute(
      "UPDATE routes SET name = ?, start_point = ?, end_point = ? WHERE id = ?",
      [name, start_point, end_point, id]
    );

    res.json({ message: "Route updated successfully" });

  } catch (err) {
    console.error("UPDATE ROUTE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// DELETE route
router.delete("/:id", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute("DELETE FROM routes WHERE id = ?", [id]);

    res.json({ message: "Route deleted successfully" });

  } catch (err) {
    console.error("DELETE ROUTE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;