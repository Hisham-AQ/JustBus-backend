const db = require("../config/db");

/* GET ALL */
exports.getAllSpecialTrips = async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM SpecialTrip");
    res.json(rows);
  } catch (err) {
    console.error("GET SPECIAL TRIPS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/* GET ONE */
exports.getSpecialTrip = async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await db.query(
      "SELECT * FROM SpecialTrip WHERE id = ?",
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Trip not found" });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error("GET ONE SPECIAL TRIP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/* BOOK */
exports.bookSpecialTrip = async (req, res) => {
  const userId = req.user.id;
  const { tripId } = req.body;

  try {
    const [tripRows] = await db.query(
      "SELECT price, seats_available FROM SpecialTrip WHERE id = ?",
      [tripId]
    );

    if (tripRows.length === 0) {
      return res.status(404).json({ message: "Trip not found" });
    }

    const trip = tripRows[0];

    if (trip.seats_available <= 0) {
      return res.status(400).json({ message: "Trip is full" });
    }

    const [userRows] = await db.query(
      "SELECT wallet_balance FROM users WHERE id = ?",
      [userId]
    );

    if (userRows[0].wallet_balance < trip.price) {
      return res.status(400).json({ message: "Not enough balance" });
    }

    // ⚠️ Not transactional (we’ll improve later)
    await db.query(
      "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?",
      [trip.price, userId]
    );

    await db.query(
      "INSERT INTO special_trip_bookings (user_id, trip_id) VALUES (?, ?)",
      [userId, tripId]
    );

    await db.query(
      "UPDATE SpecialTrip SET seats_available = seats_available - 1 WHERE id = ?",
      [tripId]
    );

    res.json({ message: "Booking confirmed" });

  } catch (err) {
    console.error("BOOK SPECIAL TRIP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};