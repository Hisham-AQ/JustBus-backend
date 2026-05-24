const db = require("../../config/db");



// ================= holdSeats =================
exports.holdSeats = async (req, res) => {
  const { tripId, pickup, dropoff, seats } = req.body;
  const userId = req.user.id;

  if (!tripId || !pickup || !dropoff) {
    return res.status(400).json({ message: 'Missing trip data' });
  }

  if (!Array.isArray(seats) || seats.length === 0) {
    return res.status(400).json({ message: 'Seats are required' });
  }

  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    const [taken] = await conn.execute(
      `
      SELECT seat_number
      FROM booking_seats bs
      JOIN bookings b ON b.id = bs.booking_id
      WHERE bs.trip_id = ?
      AND bs.seat_number IN (${seats.map(() => '?').join(',')})
      AND (
         b.status = 'confirmed'
         OR (b.status = 'held' AND b.hold_expires_at > NOW())
          )
      `,
      [tripId, ...seats]
    );

    if (taken.length > 0) {
      await conn.rollback();
      return res.status(409).json({
        message: 'Seats already booked',
        seats: taken.map(s => s.seat_number),
      });
    }

    const holdExpiresAt = new Date(Date.now() + 3 * 60 * 1000);

    const qrToken = require('crypto').randomUUID();
    const [tripRows] = await conn.query(
      "SELECT price FROM trips WHERE id = ?",
      [tripId]
    );

    if (tripRows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ message: "Trip not found" });
    }

    const pricePerSeat = parseFloat(tripRows[0].price);

    const totalPrice = parseFloat((seats.length * pricePerSeat).toFixed(2));

    const [bookingResult] = await conn.execute(
      `
      INSERT INTO bookings
      (user_id, trip_id, pickup_location, dropoff_location, total_price, qr_token, status, hold_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, 'held', ?)
      `,
      [
        userId,
        tripId,
        pickup,
        dropoff,
        totalPrice,
        qrToken,
        holdExpiresAt,
      ]
    );

    const bookingId = bookingResult.insertId;

    for (const seat of seats) {
      await conn.execute(
        `
        INSERT INTO booking_seats (booking_id, trip_id, seat_number)
        VALUES (?, ?, ?)
        `,
        [bookingId, tripId, seat]
      );
    }

    await conn.commit();

    res.json({ bookingId, holdExpiresAt, totalPrice });

  } catch (err) {
    await conn.rollback();

    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        message: "Seat already taken ",
      });
    }

    console.error("HOLD ERROR:", err);
    res.status(500).json({ message: "Hold failed" });
  } finally {
    conn.release();
  }
};


// ================= confirmBooking =================
exports.confirmBooking = async (req, res) => {
  const { bookingId, rewardCode } = req.body;
  const userId = req.user.id;

  if (!bookingId) {
    return res.status(400).json({ message: 'bookingId required' });
  }

  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute(
      `SELECT * FROM bookings
       WHERE id = ?
       AND user_id = ?
       AND status = 'held'
       AND hold_expires_at > UTC_TIMESTAMP()
       FOR UPDATE`,
      [bookingId, userId]
    );

    if (rows.length === 0) {
      await conn.rollback();
      return res.status(409).json({
        message: 'Hold expired or booking not found',
      });
    }

    const booking = rows[0];
    let amount = booking.total_price;

    let isFree = false;
    let rewardId = null;

    if (rewardCode) {
      const [rewardRows] = await conn.execute(
        `SELECT * FROM user_rewards
         WHERE code = ?
         AND user_id = ?
         AND is_used = 0
         FOR UPDATE`,
        [rewardCode, userId]
      );

      if (rewardRows.length === 0) {
        await conn.rollback();
        return res.status(400).json({ message: "Invalid or used reward code" });
      }

      const reward = rewardRows[0];
      rewardId = reward.id;

      if (reward.type !== "free_trip") {
        await conn.rollback();
        return res.status(400).json({
          message: "Only free trip rewards allowed",
        });
      }

      isFree = true;
      amount = 0;
    }

    let balance;

    if (!isFree) {
      const [balanceRows] = await conn.execute(
        "SELECT wallet_balance FROM users WHERE id = ? FOR UPDATE",
        [userId]
      );

      balance = balanceRows[0]?.wallet_balance || 0;
    }

    if (!isFree) {
      if (balance < amount) {
        await conn.rollback();
        return res.status(400).json({ message: "Insufficient balance" });
      }

      const [updateResult] = await conn.execute(
        "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ? AND wallet_balance >= ?",
        [amount, userId, amount]
      );

      if (updateResult.affectedRows === 0) {
        await conn.rollback();
        return res.status(400).json({ message: "Insufficient balance" });
      }

      await conn.execute(
        "INSERT INTO wallet_transactions (user_id, type, amount) VALUES (?, ?, ?)",
        [userId, "payment", amount]
      );
    } else {

      await conn.execute(
        "INSERT INTO wallet_transactions (user_id, type, amount) VALUES (?, ?, ?)",
        [userId, "reward", 0]
      );

    }

    if (rewardId) {
      await conn.execute(
        "UPDATE user_rewards SET is_used = 1 WHERE id = ?",
        [rewardId]
      );
    }

    await conn.execute(
      "UPDATE users SET points = points + ? WHERE id = ?",
      [10, userId]
    );

    await conn.execute(
      "INSERT INTO points_transactions (user_id, type, points) VALUES (?, ?, ?)",
      [userId, "trip", 10]
    );

    await conn.execute(
      `UPDATE bookings
        SET status = 'confirmed',
        total_price = ?
        WHERE id = ?`,
      [amount, bookingId]
    );

    const [seatRows] = await conn.execute(
      `
  SELECT COUNT(*) AS seatCount
  FROM booking_seats
  WHERE booking_id = ?
  `,
      [bookingId]
    );

    const reservedSeats =
      seatRows[0].seatCount;

await conn.execute(
  `
  UPDATE trips
  SET available_seats =
      available_seats - ?
  WHERE id = ?
  AND available_seats >= ?
  `,
  [
    reservedSeats,
    booking.trip_id,
    reservedSeats
  ]
);

    await conn.commit();

    res.json({
      success: true,
      isFree,
      message: isFree
        ? "Booking confirmed (FREE 🎉)"
        : "Booking confirmed & paid"
    });

  } catch (err) {
    await conn.rollback();
    console.error("CONFIRM ERROR:", err);
    res.status(500).json({ message: "Confirm failed" });
  } finally {
    conn.release();
  }
};