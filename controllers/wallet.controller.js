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

  try {
    await db.query(
      "UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?",
      [amount, userId]
    );

    res.json({ message: "Wallet updated" });

  } catch (err) {
    console.error("TOP UP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};