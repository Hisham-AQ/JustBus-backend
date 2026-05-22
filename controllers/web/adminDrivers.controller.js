const db = require("../../config/db");

// ================= GET DRIVERS =================
exports.getDrivers = async (req, res) => {
  try {

    const [rows] = await db.query(`
      SELECT 
        d.id,
u.name,
u.phone,
u.email,
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


      LEFT JOIN users u
ON d.user_id = u.id


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
const bcrypt = require("bcrypt");

exports.createDriver = async (req, res) => {

  try {

    const {
      name,
      email,
      phone,
      password,
      licenseNumber,
      status,
      busId
    } = req.body;

    // Check existing email
    const [existing] = await db.query(
      `
      SELECT id
      FROM users
      WHERE email = ?
      `,
      [email]
    );

    if (existing.length > 0) {

      return res.status(400).json({
        message: "Email already exists"
      });
    }

    // Hash password
    const hashedPassword =
      await bcrypt.hash(password, 10);

    // Create user
    const [userResult] =
      await db.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password,
          phone,
          role
        )
        VALUES (?, ?, ?, ?, 'driver')
        `,
        [
          name,
          email,
          hashedPassword,
          phone
        ]
      );

    const userId =
      userResult.insertId;

    // Remove old bus assignment
    if (busId) {

      await db.execute(
        `
        UPDATE drivers
        SET bus_id = NULL
        WHERE bus_id = ?
        `,
        [busId]
      );
    }

    // Create driver
    await db.query(
      `
      INSERT INTO drivers
      (
        user_id,
        license_number,
        status,
        bus_id
      )
      VALUES (?, ?, ?, ?)
      `,
      [
        userId,
        licenseNumber || null,
        status || "active",
        busId || null
      ]
    );

    res.status(201).json({
      message:
        "Driver created successfully"
    });

  } catch (err) {

    console.error(
      "CREATE DRIVER ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= UPDATE DRIVER =================
exports.updateDriver = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      licenseNumber,
      status,
      busId
    } = req.body;

    // Check if bus already assigned

    if (busId) {

      const [existing] =
        await db.query(

          `
      SELECT id
      FROM drivers
      WHERE bus_id = ?
      AND id != ?
      `,
          [busId, id]
        );

      if (existing.length > 0) {

        return res.status(400).json({

          message:
            "This bus is already assigned to another driver"

        });
      }
    }

    if (busId) {
      await db.execute(
        "UPDATE drivers SET bus_id = NULL WHERE bus_id = ? AND id != ?",
        [busId, id]
      );
    }

    await db.execute(
      `
  UPDATE drivers
  SET
    license_number = ?,
    status = ?,
    bus_id = ?
  WHERE id = ?
  `,
      [
        licenseNumber || null,
        status || 'active',
        busId || null,
        id
      ]
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

// ================= DRIVER ACTIVITY =================
exports.getDriverActivity =
  async (req, res) => {

    try {

      const [rows] =
        await db.query(`

          SELECT

            d.id,
            u.name,
            d.status,

            b.plate_number,

            ROUND(
              AVG(r.driver_rating),
              1
            ) AS rating,

            COUNT(t.id) AS tripsToday

          FROM drivers d

          LEFT JOIN buses b
          ON d.bus_id = b.id

          LEFT JOIN users u
          ON d.user_id = u.id

          LEFT JOIN trips t
          ON t.driver_id = d.id

          LEFT JOIN ratings r
          ON r.trip_id = t.id

          GROUP BY d.id

          ORDER BY tripsToday DESC

          LIMIT 5

        `);

      res.json(rows);

    } catch (err) {

      console.error(
        "DRIVER ACTIVITY ERROR:",
        err
      );

      res.status(500).json({
        message: "Server error"
      });
    }
  };