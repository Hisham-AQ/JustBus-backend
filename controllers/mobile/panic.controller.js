const db = require("../../config/db");

exports.sendPanicAlert = async (req, res) => {
  try {
    const userId = req.user.id;

    const {
      trip_id,
      issue_type,
      note,
      lat,
      lng,
    } = req.body;

    if (!trip_id || !issue_type) {
      return res.status(400).json({
        message: "Missing required fields",
      });
    }

    await db.query(
      `
      INSERT INTO panic_alerts (
        user_id,
        trip_id,
        issue_type,
        note,
        lat,
        lng
      )
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        userId,
        trip_id,
        issue_type,
        note || null,
        lat || null,
        lng || null,
      ]
    );

    res.status(201).json({
      message: "Panic alert sent successfully",
    });

  } catch (err) {
    console.error("SEND PANIC ALERT ERROR:", err);

    res.status(500).json({
      message: "Server error",
    });
  }
};