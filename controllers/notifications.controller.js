const db = require("../config/db");


exports.getNotifications = async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query(
            `SELECT id, title, message, type, created_at 
       FROM notifications
       WHERE is_global = 1 OR user_id = ?
       ORDER BY created_at DESC`,
            [userId]
        );

        res.json(rows);

    } catch (err) {
        console.error("NOTIFICATIONS ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};