const db = require("../config/db");

/* HOLD SEATS */
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

    await conn.query(`
      DELETE FROM bookings
      WHERE status = 'held'
      AND hold_expires_at < NOW()
    `);

    const [taken] = await conn.execute(
      `
      SELECT seat_number
      FROM booking_seats
      WHERE trip_id = ?
      AND seat_number IN (${seats.map(() => '?').join(',')})
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
        seats.length * 2.5,
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

    res.json({ bookingId, holdExpiresAt });

  } catch (err) {
    await conn.rollback();
    console.error("HOLD ERROR:", err);
    res.status(500).json({ message: "Hold failed" });
  } finally {
    conn.release();
  }
};

/* CONFIRM BOOKING */
exports.confirmBooking = async (req, res) => {
  const { bookingId } = req.body;
  const userId = req.user.id;

  if (!bookingId) {
    return res.status(400).json({ message: 'bookingId required' });
  }

  const conn = await db.getConnection();

  try {
    const [rows] = await conn.execute(
      `SELECT * FROM bookings
       WHERE id = ?
         AND user_id = ?
         AND status = 'held'
         AND hold_expires_at > UTC_TIMESTAMP()`,
      [bookingId, userId]
    );

    if (rows.length === 0) {
      return res.status(409).json({
        message: 'Hold expired or booking not found',
      });
    }

    await conn.execute(
      `UPDATE bookings
       SET status = 'confirmed'
       WHERE id = ?`,
      [bookingId]
    );

    res.json({ success: true });

  } catch (err) {
    console.error("CONFIRM ERROR:", err);
    res.status(500).json({ message: "Confirm failed" });
  } finally {
    conn.release();
  }
};