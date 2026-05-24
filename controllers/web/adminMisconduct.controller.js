const db = require("../../config/db");

// ================= GET REPORTS =================

exports.getReports = async (req, res) => {

  try {

    const [rows] = await db.query(`

      SELECT

        mr.id,
        mr.seat_number,
        mr.name,
        mr.category,
        mr.severity,
        mr.description,
        mr.status,
        mr.created_at,

        t.from_city,
        t.to_city,
        t.id AS tripNumber,

        du.name AS driverName,

        su.id AS studentId,
        su.name AS studentName,
        su.email AS studentEmail

      FROM misconduct_reports mr

      LEFT JOIN trips t
      ON mr.trip_id = t.id

      LEFT JOIN drivers d
      ON mr.driver_id = d.id

      LEFT JOIN users du
      ON d.user_id = du.id

      LEFT JOIN bookings b
      ON mr.booking_id = b.id

      LEFT JOIN users su
      ON b.user_id = su.id

      ORDER BY mr.created_at DESC

    `);

    res.json(rows);

  } catch (err) {

    console.error(
      "GET REPORTS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= RESOLVE =================

exports.resolveReport = async (req, res) => {

  try {

    const { id } = req.params;

    await db.query(
      `
      UPDATE misconduct_reports
      SET
        status = 'resolved',
        resolved_at = NOW()
      WHERE id = ?
      `,
      [
        id
      ]
    );

    res.json({
      message: "Report resolved"
    });

  } catch (err) {

    console.error(
      "RESOLVE REPORT ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= BLACKLIST STUDENT =================

exports.blacklistStudent =
  async (req, res) => {

    try {

      const { userId } = req.params;

      const {
        reason,
        until
      } = req.body;

      await db.query(
        `
        UPDATE users
        SET
          is_blacklisted = 1,
          blacklist_reason = ?,
          blacklist_until = ?
        WHERE id = ?
        `,
        [
          reason || "Misconduct",
          until || null,
          userId
        ]
      );

      res.json({
        message:
          "Student blacklisted"
      });

    } catch (err) {

      console.error(
        "BLACKLIST ERROR:",
        err
      );

      res.status(500).json({
        message: "Server error"
      });
    }
};