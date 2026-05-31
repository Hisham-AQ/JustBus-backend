const db = require("../../config/db");


// get requests
exports.getCancellationRequests = async (req, res) => {
  try {

    const [rows] = await db.query(`
      SELECT

        r.id,
        r.reason,
        r.status,
        r.created_at,

        b.id AS booking_id,
        b.total_price,

        u.id AS user_id,
        u.name,
        u.email,

        t.id AS trip_id,
        t.from_city,
        t.to_city,
        t.trip_date,
        t.departure_time

      FROM booking_cancellation_requests r

      JOIN bookings b
      ON r.booking_id = b.id

      JOIN users u
      ON r.user_id = u.id

      JOIN trips t
      ON b.trip_id = t.id

      ORDER BY r.created_at DESC
    `);

    res.json(rows);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};


//approve request
exports.approveRequest = async (req, res) => {

  const conn = await db.getConnection();

  try {

    await conn.beginTransaction();

    const { id } = req.params;

    // ================= GET REQUEST =================

    const [requests] = await conn.query(
      `
      SELECT booking_id
      FROM booking_cancellation_requests
      WHERE id = ?
      `,
      [id]
    );

    if (!requests.length) {

      await conn.rollback();

      return res.status(404).json({
        message: "Request not found"
      });
    }

    const bookingId =
      requests[0].booking_id;

    // ================= MARK REQUEST APPROVED =================

    await conn.query(
      `
      UPDATE booking_cancellation_requests
      SET status = 'approved'
      WHERE id = ?
      `,
      [id]
    );

    // ================= GET BOOKING =================

    const [bookings] =
      await conn.query(
        `
        SELECT

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

    if (!bookings.length) {

      await conn.rollback();

      return res.status(404).json({
        message: "Booking not found"
      });
    }

    const booking =
      bookings[0];

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

    // ================= CHECK PAYMENT TYPE =================

    const [paymentRows] =
      await conn.query(
        `
        SELECT type
        FROM wallet_transactions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 1
        `,
        [booking.user_id]
      );

    const paymentType =
      paymentRows[0]?.type ||
      "payment";

    // ================= CHECK BOARDED =================

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

    // ================= REFUND =================

    if (paymentType === "reward") {

      const [rewardRows] =
        await conn.query(
          `
          SELECT points_required
          FROM rewards
          WHERE type = 'free_trip'
          LIMIT 1
          `
        );

      const refundPoints =
        rewardRows[0]
          ?.points_required || 100;

      await conn.query(
        `
        UPDATE users
        SET points = points + ?
        WHERE id = ?
        `,
        [
          refundPoints,
          booking.user_id
        ]
      );

      await conn.query(
        `
        INSERT INTO points_transactions
        (
          user_id,
          type,
          points
        )
        VALUES (?, ?, ?)
        `,
        [
          booking.user_id,
          "refund",
          refundPoints
        ]
      );

    } else {

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
          "Cancellation request approved"
        ]
      );
    }

    // ================= NOTIFICATION =================

    const {
      sendNotificationToUser
    } = require("../../utils/sendNotification");

    await sendNotificationToUser({
      userId: booking.user_id,
      title: "Cancellation Approved",
      message:
        "Your cancellation request has been approved and your refund has been processed.",
      type: "refund"
    });

    // ================= RESTORE SEAT =================

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
        "Request approved and booking refunded"
    });

  } catch (err) {

    await conn.rollback();

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });

  } finally {

    conn.release();
  }
};

//reject request
exports.rejectRequest = async (req, res) => {

  try {

    const { id } = req.params;

    await db.query(
      `
      UPDATE booking_cancellation_requests
      SET status = 'rejected'
      WHERE id = ?
      `,
      [id]
    );

    res.json({
      message: "Request rejected"
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};
