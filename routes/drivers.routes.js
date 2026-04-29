const express = require("express");
const router = express.Router();

const db = require("../config/db");
const authenticateToken = require("../middleware/authMiddleware");
const allowRoles = require("../middleware/roleMiddleware");


// GET drivers
router.get("/", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM drivers");
    res.json(rows);
  } catch (err) {
    console.error("GET DRIVERS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// CREATE driver
router.post("/", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { name, phone, email, license_number, status } = req.body;

    if (!name || !phone) {
      return res.status(400).json({ message: "Missing fields" });
    }

    await db.execute(
      "INSERT INTO drivers (name, phone, email, license_number, status) VALUES (?, ?, ?, ?, ?)",
      [name, phone, email || null, license_number || null, status || "active"]
    );

    res.status(201).json({ message: "Driver created successfully" });

  } catch (err) {
    console.error("CREATE DRIVER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// UPDATE driver
router.put("/:id", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, email, license_number, status } = req.body;

    await db.execute(
      "UPDATE drivers SET name = ?, phone = ?, email = ?, license_number = ?, status = ? WHERE id = ?",
      [name, phone, email, license_number, status, id]
    );

    res.json({ message: "Driver updated successfully" });

  } catch (err) {
    console.error("UPDATE DRIVER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// DELETE driver
router.delete("/:id", authenticateToken, allowRoles("admin"), async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute("DELETE FROM drivers WHERE id = ?", [id]);

    res.json({ message: "Driver deleted successfully" });

  } catch (err) {
    console.error("DELETE DRIVER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;