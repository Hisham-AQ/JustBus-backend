const db = require("../../config/db");

// ================= GET ALL ALERTS =================

exports.getAlerts = async (req, res) => {

  try {

    const [rows] = await db.query(`

      SELECT

        p.id,
        p.issue_type,
        p.note,
        p.lat,
        p.lng,
        p.created_at,

        u.name AS userName,
        u.phone AS userPhone,

        t.id AS tripId,
        t.from_city,
        t.to_city,

        b.plate_number

      FROM panic_alerts p

      LEFT JOIN users u
      ON p.user_id = u.id

      LEFT JOIN trips t
      ON p.trip_id = t.id

      LEFT JOIN buses b
      ON t.bus_id = b.id

      WHERE p.status = 'pending'

      ORDER BY p.created_at DESC

    `);

    res.json(rows);

  } catch (err) {

    console.error(
      "GET ALERTS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= RESOLVE ALERT =================

exports.resolveAlert = async (req, res) => {

  try {

    const { id } = req.params;

    await db.query(
      `
      UPDATE panic_alerts
      SET status = 'resolved'
      WHERE id = ?
      `,
      [id]
    );

    res.json({
      message: "Alert resolved"
    });

  } catch (err) {

    console.error(
      "RESOLVE ALERT ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};