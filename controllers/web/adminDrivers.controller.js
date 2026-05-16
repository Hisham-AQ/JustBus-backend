const db = require("../../config/db");

// ================= GET DRIVERS =================
exports.getDrivers = async (req, res) => {
  try {

    const [rows] = await db.query(`
      SELECT 
        d.id,
        d.name,
        d.phone,
        d.email,
        d.license_number AS licenseNumber,
        d.status,
        d.bus_id AS busId,

        b.id AS bus_id,
        b.plate_number,
        b.model,
        b.capacity

      FROM drivers d

      LEFT JOIN buses b
      ON d.bus_id = b.id
    `);

    const formatted = rows.map(driver => ({
      id: driver.id,
      name: driver.name,
      phone: driver.phone,
      email: driver.email,
      licenseNumber: driver.licenseNumber,
      status: driver.status,
      busId: driver.busId,

      bus: driver.bus_id
        ? {
            id: driver.bus_id,
            plateNumber: driver.plate_number,
            model: driver.model,
            capacity: driver.capacity,
          }
        : null
    }));

    res.json(formatted);

  } catch (err) {

    console.error("GET DRIVERS ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= CREATE DRIVER =================
exports.createDriver = async (req, res) => {
  try {
    const { name, phone, email, licenseNumber, status, busId } = req.body;

    // clear bus from previous driver
    if (busId) {
      await db.execute(
        "UPDATE drivers SET bus_id = NULL WHERE bus_id = ?",
        [busId]
      );
    }

    await db.execute(
      `INSERT INTO drivers (name, phone, email, license_number, status, bus_id)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name, phone, email || null, licenseNumber || null, status || "active", busId || null]
    );

    res.status(201).json({ message: "Driver created successfully" });

  } catch (err) {
    console.error("CREATE DRIVER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= UPDATE DRIVER =================
exports.updateDriver = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, email, licenseNumber, status, busId } = req.body;

    // clear bus from other drivers
    if (busId) {
      await db.execute(
        "UPDATE drivers SET bus_id = NULL WHERE bus_id = ? AND id != ?",
        [busId, id]
      );
    }

    await db.execute(
      `UPDATE drivers 
       SET name = ?, phone = ?, email = ?, license_number = ?, status = ?, bus_id = ?
       WHERE id = ?`,
      [name, phone, email, licenseNumber, status, busId || null, id]
    );

    res.json({ message: "Driver updated successfully" });

  } catch (err) {
    console.error("UPDATE DRIVER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= DELETE DRIVER =================
exports.deleteDriver = async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute("DELETE FROM drivers WHERE id = ?", [id]);

    res.json({ message: "Driver deleted successfully" });

  } catch (err) {
    console.error("DELETE DRIVER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};