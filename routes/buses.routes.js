const express = require("express");
const router = express.Router();

const db = require("../config/db");
const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");


// GET all buses
router.get("/", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM buses");
    res.json(rows);
  } catch (err) {
    console.error("GET BUSES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// CREATE bus
router.post("/", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { plate_number, capacity, status } = req.body;

    if (!plate_number || !capacity) {
      return res.status(400).json({ message: "Missing fields" });
    }

    await db.execute(
      "INSERT INTO buses (plate_number, capacity, status) VALUES (?, ?, ?)",
      [plate_number, capacity, status || "active"]
    );

    res.status(201).json({ message: "Bus created successfully" });

  } catch (err) {
    console.error("CREATE BUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// UPDATE bus
router.put("/:id", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;
    const { plate_number, capacity, status } = req.body;

    await db.execute(
      "UPDATE buses SET plate_number = ?, capacity = ?, status = ? WHERE id = ?",
      [plate_number, capacity, status, id]
    );

    res.json({ message: "Bus updated successfully" });

  } catch (err) {
    console.error("UPDATE BUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// DELETE bus
router.delete("/:id", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute("DELETE FROM buses WHERE id = ?", [id]);

    res.json({ message: "Bus deleted successfully" });

  } catch (err) {
    console.error("DELETE BUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// OPTIONAL (for later)
router.get("/locations", authenticateToken, allowRoles("admin"), async (req, res) => {
  res.json([]); // placeholder
});


module.exports = router;