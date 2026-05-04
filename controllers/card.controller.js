const db = require("../config/db");

exports.getCards = async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await db.query(
      "SELECT * FROM user_cards WHERE user_id = ?",
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.addCard = async (req, res) => {
  const userId = req.user.id;
  const { cardNumber, holder, expiry, brand } = req.body;

  try {
    const last4 = cardNumber.slice(-4);

    await db.query(
      "INSERT INTO user_cards (user_id, card_number, card_holder, expiry, brand) VALUES (?, ?, ?, ?, ?)",
      [userId, last4, holder, expiry, brand]
    );

    res.json({ message: "Card added" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.deleteCard = async (req, res) => {
  const userId = req.user.id;
  const { id } = req.params;

  try {
    await db.query(
      "DELETE FROM user_cards WHERE id = ? AND user_id = ?",
      [id, userId]
    );

    res.json({ message: "Card deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};