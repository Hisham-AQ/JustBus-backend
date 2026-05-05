const db = require("../config/db");


exports.getNotifications = async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query(
            `SELECT id, title, message, type, is_read, created_at
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

exports.markAsRead = async (req, res) => {
    const { id } = req.params;

    try {
        await db.query(
            "UPDATE notifications SET is_read = 1 WHERE id = ?",
            [id]
        );

        res.json({ success: true });

    } catch (err) {
        console.error("READ ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};

exports.deleteNotification = async (req, res) => {
    const { id } = req.params;

    try {
        await db.query(
            "DELETE FROM notifications WHERE id = ?",
            [id]
        );

        res.json({ success: true });

    } catch (err) {
        console.error("DELETE ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};