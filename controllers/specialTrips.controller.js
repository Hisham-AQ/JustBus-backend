const db = require("../config/db");

/* GET ALL */
exports.bookSpecialTrip = async (req, res) => {
  const userId = req.user.id;
  if (!tripId || isNaN(tripId)) {
    return res.status(400).json({ message: "Invalid tripId" });
  }

  const connection = await db.getConnection();

  try {
    await connection.beginTransaction();

    const [existing] = await connection.query(
      "SELECT id FROM special_trip_bookings WHERE user_id = ? AND trip_id = ?",
      [userId, tripId]
    );

    if (existing.length > 0) {
      await connection.rollback();
      return res.status(400).json({ message: "You already booked this trip" });
    }

    const [tripRows] = await connection.query(
      "SELECT price, seats_available FROM SpecialTrip WHERE id = ? FOR UPDATE",
      [tripId]
    );

    if (tripRows.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "Trip not found" });
    }

    const trip = tripRows[0];

    if (trip.seats_available <= 0) {
      await connection.rollback();
      return res.status(400).json({ message: "Trip is full" });
    }

    const [userRows] = await connection.query(
      "SELECT wallet_balance FROM users WHERE id = ? FOR UPDATE",
      [userId]
    );

    const balance = parseFloat(userRows[0].wallet_balance);

    if (balance < trip.price) {
      await connection.rollback();
      return res.status(400).json({ message: "Not enough balance" });
    }

    const [updateResult] = await connection.query(
      "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ? AND wallet_balance >= ?",
      [trip.price, userId, trip.price]
    );

    if (updateResult.affectedRows === 0) {
      await connection.rollback();
      return res.status(400).json({ message: "Not enough balance" });
    }

    const [seatResult] = await connection.query(
      "UPDATE SpecialTrip SET seats_available = seats_available - 1 WHERE id = ? AND seats_available > 0",
      [tripId]
    );

    if (seatResult.affectedRows === 0) {
      await connection.rollback();
      return res.status(400).json({ message: "Trip is full" });
    }


    const crypto = require("crypto");
    const qrToken = "TRIP-" + crypto.randomUUID();


    const [result] = await connection.query(
      "INSERT INTO special_trip_bookings (user_id, trip_id, qr_token) VALUES (?, ?, ?)",
      [userId, tripId, qrToken]
    );

    await connection.commit();

    res.json({
      message: "Booking confirmed",
      bookingId: result.insertId,
      qrToken: qrToken
    });

  } catch (err) {
    await connection.rollback();

    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({
        message: "You already booked this trip"
      });
    }

    console.error("BOOK SPECIAL TRIP ERROR:", {
      userId,
      tripId,
      error: err
    });

    return res.status(500).json({
      message: process.env.NODE_ENV === "production"
        ? "Server error"
        : err.message
    });

  } finally {
    connection.release();
  }
};