const db = require("../../config/db");


exports.getNotifications = async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query(
            `
    SELECT
        n.id,
        n.title,
        n.message,
        n.type,
        COALESCE(nu.is_read, 0) AS is_read,
        n.created_at

    FROM notifications n

    LEFT JOIN notification_users nu
        ON n.id = nu.notification_id
        AND nu.user_id = ?

    WHERE
        (n.is_global = 1 OR n.user_id = ?)
        AND COALESCE(nu.is_hidden, 0) = 0

    ORDER BY n.created_at DESC
    `,
            [userId, userId]
        );

        res.json(rows);

    } catch (err) {
        console.error("NOTIFICATIONS ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};



exports.markAsRead = async (req, res) => {
    const userId = req.user.id;
    const { id } = req.params;

    try {
        await db.query(
            `
            INSERT INTO notification_users
            (notification_id, user_id, is_read)

            VALUES (?, ?, 1)

            ON DUPLICATE KEY UPDATE
            is_read = 1
            `,
            [id, userId]
        );

        res.json({ success: true });

    } catch (err) {
        console.error("READ ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};


exports.deleteNotification = async (req, res) => {
    const userId = req.user.id;
    const { id } = req.params;

    try {
        await db.query(
            `
            INSERT INTO notification_users
            (notification_id, user_id, is_hidden)

            VALUES (?, ?, 1)

            ON DUPLICATE KEY UPDATE
            is_hidden = 1
            `,
            [id, userId]
        );

        res.json({ success: true });

    } catch (err) {
        console.error("DELETE ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};
