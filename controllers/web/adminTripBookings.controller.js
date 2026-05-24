const db = require("../../config/db");

// ================= GET ALL TRIP BOOKINGS =================
exports.getTripBookings = async (req, res) => {

  try {

    const [rows] = await db.query(`
      SELECT

        t.id AS tripId,
        t.from_city,
        t.to_city,
        t.departure_time,
        t.arrival_time,
        t.trip_date,

        u.name AS driverName,

        b.plate_number AS busPlate,
        b.capacity AS busCapacity,

        COUNT(
  CASE
    WHEN book.status IN (
      'confirmed',
      'held',
      'completed'
    )
    THEN 1
  END
) AS totalBookings

      FROM trips t

      LEFT JOIN drivers d
      ON t.driver_id = d.id

      LEFT JOIN users u
ON d.user_id = u.id

      LEFT JOIN buses b
      ON t.bus_id = b.id

      LEFT JOIN bookings book
      ON t.id = book.trip_id
      AND book.status != 'cancelled'

      GROUP BY t.id

      ORDER BY t.trip_date DESC
    `);

    const parsed = rows.map(trip => ({

  ...trip,

remainingSeats:
  trip.busCapacity
    ? Math.max(
        trip.busCapacity
        - trip.totalBookings,
        0
      )
    : null,

  occupancyPercentage:
    trip.busCapacity
      ? Math.round(
          (
            trip.totalBookings
            / trip.busCapacity
          ) * 100
        )
      : 0
}));

res.json(parsed);

  } catch (err) {

    console.error(
      "GET TRIP BOOKINGS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= GET PASSENGERS =================
exports.getTripPassengers = async (req, res) => {

  try {

    const { id } = req.params;

    const [rows] = await db.query(`
  SELECT

    b.id AS booking_id,

    u.id AS user_id,
    u.name,
    u.email,

    b.pickup_location,
    b.dropoff_location,
    b.status,
    b.created_at,

    bs.seat_number,
    bs.is_boarded,
    bs.is_dropped_off

  FROM bookings b

  JOIN users u
  ON b.user_id = u.id

  LEFT JOIN booking_seats bs
  ON bs.booking_id = b.id

  WHERE b.trip_id = ?

  ORDER BY bs.seat_number ASC
`, [id]);

    res.json(rows);

  } catch (err) {

    console.error(
      "GET TRIP PASSENGERS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};


// ================= CANCEL + REFUND =================

exports.cancelBooking =
  async (req, res) => {

    const conn =
      await db.getConnection();

    try {

      await conn.beginTransaction();

      const { bookingId } =
        req.params;

      // ================= GET BOOKING =================

      const [bookings] =
        await conn.query(
          `
          SELECT

          b.id AS booking_id,
            b.id,
            b.user_id,
            b.trip_id,
            b.total_price,
            b.status,

            t.available_seats

          FROM bookings b

          JOIN trips t
          ON b.trip_id = t.id

          WHERE b.id = ?
          `,
          [bookingId]
        );

      if (
        bookings.length === 0
      ) {

        await conn.rollback();

        return res.status(404).json({
          message:
            "Booking not found"
        });
      }

      const booking =
        bookings[0];

        // ================= CHECK IF BOARDED =================

const [seats] =
  await conn.query(
    `
    SELECT is_boarded
    FROM booking_seats
    WHERE booking_id = ?
    `,
    [bookingId]
  );

const boarded =
  seats.some(
    s => s.is_boarded
  );

if (boarded) {

  await conn.rollback();

  return res.status(400).json({
    message:
      "Cannot refund boarded passenger"
  });
}

      // already cancelled

      if (
        booking.status ===
        "cancelled"
      ) {

        await conn.rollback();

        return res.status(400).json({
          message:
            "Booking already cancelled"
        });
      }

      // ================= CANCEL BOOKING =================

      await conn.query(
        `
        UPDATE bookings
        SET status = 'cancelled'
        WHERE id = ?
        `,
        [bookingId]
      );

      // ================= FREE SEATS =================

await conn.query(
  `
  DELETE FROM booking_seats
  WHERE booking_id = ?
  `,
  [bookingId]
);

      // ================= REFUND WALLET =================

      await conn.query(
        `
        UPDATE users
        SET wallet_balance =
          wallet_balance + ?
        WHERE id = ?
        `,
        [
          booking.total_price,
          booking.user_id
        ]
      );

      // ================= WALLET TRANSACTION =================

      await conn.query(
        `
        INSERT INTO wallet_transactions
        (
          user_id,
          type,
          amount,
          description
        )
        VALUES (?, ?, ?, ?)
        `,
        [
          booking.user_id,
          "refund",
          booking.total_price,
          "Admin cancelled booking refund"
        ]
      );

// ================= CREATE NOTIFICATION =================

const [notificationResult] =
  await conn.query(
    `
    INSERT INTO notifications
(
  title,
  message,
  type,
  is_global,
  user_id
)
VALUES (?, ?, ?, ?, ?)
    `,
    [
  "Trip Reservation Cancelled",

  `Your reservation for trip #${booking.trip_id} was cancelled by admin. Refund of ${booking.total_price} JD has been added to your wallet.`,

  "refund",

  0,

  booking.user_id
]
  );

  // ================= LINK USER =================

await conn.query(
  `
  INSERT INTO notification_users
  (
    notification_id,
    user_id,
    is_read,
    is_hidden
  )
  VALUES (?, ?, ?, ?)
  `,
  [
    notificationResult.insertId,
    booking.user_id,
    0,
    0
  ]
);

      // ================= RESTORE SEATS =================

      await conn.query(
        `
        UPDATE trips
        SET available_seats =
          available_seats + 1
        WHERE id = ?
        `,
        [booking.trip_id]
      );

      await conn.commit();

      res.json({
        message:
          "Booking cancelled and refunded"
      });

    } catch (err) {

      await conn.rollback();

      console.error(
        "CANCEL BOOKING ERROR:",
        err
      );

      res.status(500).json({
        message:
          "Server error"
      });

    } finally {

      conn.release();
    }
};