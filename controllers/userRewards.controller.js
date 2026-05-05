const db = require("../config/db");


exports.redeemReward = async (req, res) => {
    const userId = req.user.id;
    const { type } = req.body;

    const conn = await db.getConnection();

    try {
        await conn.beginTransaction();

        const [rewardRows] = await conn.execute(
            "SELECT * FROM rewards WHERE type = ?",
            [type]
        );

        if (rewardRows.length === 0) {
            await conn.rollback();
            return res.status(400).json({ message: "Invalid reward type" });
        }

        const reward = rewardRows[0];
        const requiredPoints = reward.points_required;

        const [rows] = await conn.execute(
            "SELECT points FROM users WHERE id = ? FOR UPDATE",
            [userId]
        );

        if (rows.length === 0) {
            await conn.rollback();
            return res.status(404).json({ message: "User not found" });
        }

        const points = rows[0].points;

        if (points < requiredPoints) {
            await conn.rollback();
            return res.status(400).json({ message: "Not enough points" });
        }

        await conn.execute(
            "UPDATE users SET points = points - ? WHERE id = ?",
            [requiredPoints, userId]
        );

        const code =
            "RW-" +
            Date.now().toString(36) +
            Math.random().toString(36).substring(2, 5).toUpperCase();

        await conn.execute(
            "INSERT INTO user_rewards (user_id, type, code) VALUES (?, ?, ?)",
            [userId, reward.type, code]
        );

        await conn.commit();

        res.json({
            message: "Reward redeemed",
            code: code
        });

    } catch (err) {
        await conn.rollback();
        console.error("REDEEM ERROR:", err);
        res.status(500).json({ message: "Server error" });
    } finally {
        conn.release();
    }
};

exports.getPoints = async (req, res) => {
    const userId = req.user.id;

    const [rows] = await db.query(
        "SELECT points FROM users WHERE id = ?",
        [userId]
    );

    res.json({ points: rows[0]?.points || 0 });
};

exports.validateReward = async (req, res) => {
    const userId = req.user.id;
    const { code } = req.body;

    try {
        const [rows] = await db.query(
            "SELECT * FROM user_rewards WHERE code = ? AND user_id = ? AND is_used = 0",
            [code, userId]
        );

        if (rows.length === 0) {
            return res.status(400).json({
                valid: false,
                message: "Invalid or already used code",
            });
        }

        const reward = rows[0];

        let finalPrice = null;

        switch (reward.type) {
            case "free_package":
                finalPrice = 0;
                break;

            case "discount":
                finalPrice = 2; 
                break;

            case "free_trip":
                finalPrice = 0; 
                break;

            default:
                finalPrice = null;
        }

        res.json({
            valid: true,
            type: reward.type,
            finalPrice: finalPrice,
        });



    } catch (err) {
        console.error("VALIDATE ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};