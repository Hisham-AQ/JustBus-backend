const db = require("../../config/db");

// ================= ADD POINTS =================
exports.addPoints = async (req, res) => {

  try {

    const {
      userId,
      points,
      reason
    } = req.body;

    if (
      !userId ||
      !points ||
      points <= 0
    ) {
      return res.status(400).json({
        message: "Invalid data"
      });
    }

    // Update user points
    await db.query(`
      UPDATE users
      SET points = points + ?
      WHERE id = ?
    `, [
      points,
      userId
    ]);

    // Insert transaction
    await db.query(`
      INSERT INTO points_transactions (
        user_id,
        type,
        points
      )
      VALUES (?, ?, ?)
    `, [
      userId,
      reason || "admin_bonus",
      points
    ]);

    res.json({
      message:
        "Points added successfully"
    });

  } catch (err) {

    console.error(
      "ADD POINTS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= REMOVE POINTS =================
exports.removePoints = async (req, res) => {

  try {

    const {
      userId,
      points,
      reason
    } = req.body;

    if (
      !userId ||
      !points ||
      points <= 0
    ) {
      return res.status(400).json({
        message: "Invalid data"
      });
    }

    const [users] = await db.query(`
      SELECT points
      FROM users
      WHERE id = ?
    `, [userId]);

    if (users.length === 0) {

      return res.status(404).json({
        message: "User not found"
      });
    }

    const currentPoints =
      users[0].points || 0;

    if (currentPoints < points) {

      return res.status(400).json({
        message:
          "User does not have enough points"
      });
    }

    await db.query(`
      UPDATE users
      SET points = points - ?
      WHERE id = ?
    `, [
      points,
      userId
    ]);

    // Insert transaction
    await db.query(`
      INSERT INTO points_transactions (
        user_id,
        type,
        points
      )
      VALUES (?, ?, ?)
    `, [
      userId,
      reason || "admin_penalty",
      -points
    ]);

    res.json({
      message:
        "Points removed successfully"
    });

  } catch (err) {

    console.error(
      "REMOVE POINTS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};


// ================= GET HISTORY =================
exports.getPointsHistory = async (req, res) => {

  try {

    const { id } = req.params;

    const [rows] = await db.query(`
      SELECT *
      FROM points_transactions
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [id]);

    res.json(rows);

  } catch (err) {

    console.error(
      "POINTS HISTORY ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};