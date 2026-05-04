exports.addCard = async (req, res) => {
    const userId = req.user.id;
    const { cardNumber, holder, expiry } = req.body;

    try {
        const clean = String(cardNumber).replace(/\s+/g, "");

        if (!/^\d{13,19}$/.test(clean)) {
            return res.status(400).json({ message: "Invalid card number" });
        }

        if (!/^\d{2}\/\d{2}$/.test(expiry)) {
            return res.status(400).json({ message: "Invalid expiry format" });
        }

        if (!holder || holder.length < 3) {
            return res.status(400).json({ message: "Invalid card holder name" });
        }

        const finalBrand = detectBrand(clean);

        const [existing] = await db.query(
            "SELECT id FROM user_cards WHERE user_id = ? AND card_number = ?",
            [userId, clean]
        );

        if (existing.length > 0) {
            return res.status(400).json({ message: "Card already exists" });
        }

        //const last4 = cardNumber.slice(-4); 

        await db.query(
            "INSERT INTO user_cards (user_id, card_number, card_holder, expiry, brand) VALUES (?, ?, ?, ?, ?)",
            [userId, clean, holder, expiry, finalBrand]
        );

        res.json({ message: "Card added" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
};

function detectBrand(number) {
    if (number.startsWith("4")) return "Visa";
    if (/^5[1-5]/.test(number)) return "MasterCard";
    return "Unknown";
}