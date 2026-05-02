const db = require("../config/db");

// ================= GET ROUTES =================
exports.getRoutes = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        r.id,
        r.name,
        r.start_point AS startPoint,
        r.end_point AS endPoint,
        r.status,
        COUNT(b.id) AS busCount
      FROM routes r
      LEFT JOIN buses b ON b.route_id = r.id
      GROUP BY r.id
    `);

    // attach stops
    for (const route of rows) {
      const [stops] = await db.query(
        `SELECT name, stop_order AS \`order\`, lat, lng
         FROM route_stops
         WHERE route_id = ?
         ORDER BY stop_order ASC`,
        [route.id]
      );

      route.stops = stops;
    }

    res.json(rows);

  } catch (err) {
    console.error("GET ROUTES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= CREATE ROUTE =================
exports.createRoute = async (req, res) => {
  try {
    const { name, startStop, endStop, status, stops } = req.body;

    if (!name || !startStop || !endStop) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const [result] = await db.execute(
      `INSERT INTO routes (name, start_point, end_point, status)
       VALUES (?, ?, ?, ?)`,
      [name, startStop, endStop, status || "active"]
    );

    const routeId = result.insertId;

    if (stops && stops.length > 0) {
      for (const stop of stops) {
        await db.execute(
          `INSERT INTO route_stops (route_id, name, stop_order, lat, lng)
           VALUES (?, ?, ?, ?, ?)`,
          [routeId, stop.name, stop.order, stop.lat || null, stop.lng || null]
        );
      }
    }

    res.status(201).json({ message: "Route created successfully" });

  } catch (err) {
    console.error("CREATE ROUTE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= UPDATE ROUTE =================
exports.updateRoute = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, start_point, end_point, status, stops } = req.body;

    await db.execute(
      `UPDATE routes 
       SET name = ?, start_point = ?, end_point = ?, status = ?
       WHERE id = ?`,
      [name, start_point, end_point, status, id]
    );

    // delete old stops
    await db.execute(
      "DELETE FROM route_stops WHERE route_id = ?",
      [id]
    );

    // insert new stops
    if (stops && stops.length > 0) {
      for (const stop of stops) {
        await db.execute(
          `INSERT INTO route_stops (route_id, name, stop_order, lat, lng)
           VALUES (?, ?, ?, ?, ?)`,
          [id, stop.name, stop.order, stop.lat, stop.lng]
        );
      }
    }

    res.json({ message: "Route updated successfully" });

  } catch (err) {
    console.error("UPDATE ROUTE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= DELETE ROUTE =================
exports.deleteRoute = async (req, res) => {
  try {
    const { id } = req.params;

    await db.execute("DELETE FROM routes WHERE id = ?", [id]);

    res.json({ message: "Route deleted successfully" });

  } catch (err) {
    console.error("DELETE ROUTE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};