const db = require("../config/db");


exports.createReport = async (req, res) => {
    const userId = req.user?.id;

    console.log("USER:", req.user);
    console.log("BODY:", req.body);

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const {
        category,
        item_name,
        ride_id,
        lost_date,
        description
    } = req.body;

    try {
        await db.query(
            `INSERT INTO lost_items 
       (user_id, category, item_name, ride_id, lost_date, description)
       VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, category, item_name, ride_id || null, lost_date, description]
        );

        res.json({ message: "Report submitted" });

    } catch (err) {
        console.error("CREATE REPORT ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};

// GET MY REPORTS
exports.getMyReports = async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query(
            `SELECT id, item_name, status, lost_date 
       FROM lost_items
       WHERE user_id = ?
       ORDER BY created_at DESC`,
            [userId]
        );

        res.json(rows);

    } catch (err) {
        console.error("GET REPORTS ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};