const db = require("../config/db");


// ================= GET BALANCE =================
exports.getBalance = async (req, res) => {
    const userId = req.user.id;

    try {
        const [rows] = await db.query(
            "SELECT wallet_balance FROM users WHERE id = ?",
            [userId]
        );

        res.json({
            balance: rows[0]?.wallet_balance || 0,
        });

    } catch (err) {
        console.error("GET BALANCE ERROR:", err);
        res.status(500).json({ message: "Server error" });
    }
};


// ================= TOP UP =================
exports.topUp = async (req, res) => {
    const userId = req.user.id;
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ message: "Invalid amount" });
    }

    const conn = await db.getConnection();

    try {
        await conn.beginTransaction();

        await conn.query(
            "UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?",
            [amount, userId]
        );

        await conn.query(
            "INSERT INTO wallet_transactions (user_id, type, amount) VALUES (?, ?, ?)",
            [userId, "topup", amount]
        );

        await conn.commit();

        const [rows] = await conn.query(
            "SELECT wallet_balance FROM users WHERE id = ?",
            [userId]
        );

        res.json({
            message: "Top up successful",
            balance: rows[0].wallet_balance
        });

    } catch (err) {
        await conn.rollback();
        console.error("TOP UP ERROR:", err);
        res.status(500).json({ message: "Server error" });
    } finally {
        conn.release();
    }
};

// ================= PAY WITH WALLET =================
exports.payWithWallet = async (req, res) => {
    const userId = req.user.id;
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ message: "Invalid amount" });
    }

    const conn = await db.getConnection();

    try {
        await conn.beginTransaction();

        const parsedAmount = parseFloat(amount);

        if (isNaN(parsedAmount) || parsedAmount <= 0) {
            return res.status(400).json({ message: "Invalid amount" });
        }

        const [rows] = await conn.query(
            "SELECT wallet_balance FROM users WHERE id = ?",
            [userId]
        );

        const balance = rows[0]?.wallet_balance || 0;

        if (balance < amount) {
            await conn.rollback();
            return res.status(400).json({ message: "Insufficient balance" });
        }

        await conn.query(
            "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?",
            [amount, userId]
        );

        await conn.query(
            "INSERT INTO wallet_transactions (user_id, type, amount) VALUES (?, ?, ?)",
            [userId, "payment", amount]
        );

        await conn.commit();

        const [updated] = await conn.query(
            "SELECT wallet_balance FROM users WHERE id = ?",
            [userId]
        );

        res.json({
            message: "Payment successful",
            balance: updated[0].wallet_balance
        });

    } catch (err) {
        await conn.rollback();
        console.error(err);
        res.status(500).json({ message: "Server error" });
    } finally {
        conn.release();
    }
};