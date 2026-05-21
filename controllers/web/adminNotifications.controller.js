const db = require("../../config/db");


// ================= GLOBAL =================
exports.sendGlobalNotification =
async (req, res) => {

  const {
    title,
    message,
    type
  } = req.body;

  try {

    await db.query(`
      INSERT INTO notifications
      (
        title,
        message,
        type,
        is_global
      )
      VALUES (?, ?, ?, 1)
    `, [
      title,
      message,
      type
    ]);

    res.json({
      success: true,
      message: "Global notification sent"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};


// ================= USER =================
exports.sendUserNotification =
async (req, res) => {

  const {
    user_id,
    title,
    message,
    type
  } = req.body;

  try {

    await db.query(`
      INSERT INTO notifications
      (
        title,
        message,
        type,
        is_global,
        user_id
      )
      VALUES (?, ?, ?, 0, ?)
    `, [
      title,
      message,
      type,
      user_id
    ]);

    res.json({
      success: true,
      message: "User notification sent"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= GET ALL =================
exports.getAllNotifications =
async (req, res) => {

  try {

    const [rows] = await db.query(`
      SELECT
        id,
        title,
        message,
        type,
        is_global,
        user_id,
        created_at
      FROM notifications
      ORDER BY created_at DESC
      LIMIT 100
    `);

    res.json(rows);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};


//delete notification
exports.deleteNotification =
async (req, res) => {

  const { id } = req.params;

  try {

    await db.query(`
      DELETE FROM notifications
      WHERE id = ?
    `, [id]);

    res.json({
      success: true
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};