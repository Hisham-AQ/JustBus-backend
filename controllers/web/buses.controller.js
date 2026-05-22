const db = require("../../config/db");

// ================= GET BUSES =================
exports.getBuses = async (req, res) => {
  try {
    const [rows] = await db.query(`
SELECT 
  b.id,
  b.plate_number AS plateNumber,
  b.capacity,
  b.status,
  b.model,
  b.bus_condition AS \`condition\`,

  d.id AS driverId,
  u.name AS driverName

FROM buses b

LEFT JOIN drivers d
ON d.bus_id = b.id

LEFT JOIN users u
ON d.user_id = u.id
`);

    res.json(rows);

  } catch (err) {
    console.error("GET BUSES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= CREATE BUS =================
exports.createBus = async (req, res) => {
  try {
const { plateNumber, capacity, status, model, condition } = req.body;

    if (!plateNumber || !capacity) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const [result] = await db.execute(
      `INSERT INTO buses (plate_number, capacity, status, model, bus_condition)
VALUES (?, ?, ?, ?, ?)`,
      [
  plateNumber,
  capacity,
  status || "active",
  model || null,
  condition || null
      ]
    );

    res.status(201).json({
      message: "Bus created successfully",
      id: result.insertId
    });

  } catch (err) {
    console.error("CREATE BUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= UPDATE BUS =================
exports.updateBus = async (req, res) => {
  try {
    const { id } = req.params;
    const { plateNumber, capacity, status, model, condition } = req.body;

    await db.execute(
      `UPDATE buses 
       SET plate_number = ?, capacity = ?, status = ?, model = ?, bus_condition = ?
       WHERE id = ?`,
      [
  plateNumber,
  capacity,
  status,
  model,
  condition,
  id
]
    );

    res.json({ message: "Bus updated successfully" });

  } catch (err) {
    console.error("UPDATE BUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= DELETE BUS =================
exports.deleteBus = async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute("DELETE FROM buses WHERE id = ?", [id]);

    res.json({ message: "Bus deleted successfully" });

  } catch (err) {
    console.error("DELETE BUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= OPTIONAL =================
exports.getBusLocations = async (req, res) => {
  res.json([]);
};