const db = require("../../config/db");


// ================= getMyActivity =================
exports.getMyActivity = async (req, res) => {
  const userId = req.user.id;

  try {
    const [trips] = await db.query(
      `
  SELECT 
    b.id AS booking_id,
    b.status,
    b.total_price,
    bus.bus_number,
    
    EXISTS (
  SELECT 1
  FROM ratings r
  WHERE r.trip_id = t.id
  AND r.user_id = b.user_id
) AS has_rating,

      EXISTS (
    SELECT 1
    FROM booking_cancellation_requests r
    WHERE r.booking_id = b.id
    AND r.status = 'pending'
  ) AS has_pending_cancellation,
   
    b.qr_token,
    b.pickup_location,
    b.dropoff_location,
    b.created_at AS booking_date,
    t.id AS trip_id,
    t.from_city,
    t.to_city,
    t.trip_date,
    t.departure_time,
    t.arrival_time,
    t.bus_id,

    GROUP_CONCAT(
  bs.seat_number
  ORDER BY bs.seat_number ASC
) AS seats
  FROM bookings b

  JOIN trips t
  ON t.id = b.trip_id

  JOIN buses bus
ON bus.id = t.bus_id

  LEFT JOIN booking_seats bs
  ON bs.booking_id = b.id

  WHERE b.user_id = ?

  GROUP BY b.id

  ORDER BY b.created_at DESC
  `,
      [userId]
    );

    const [parcels] = await db.query(`
  SELECT 
    pickup_location,
    dropoff_location,
    weight,
    delivery_type,
    parcel_type,
    pin_code,
    status
  FROM parcel_requests
  WHERE user_id = ?
  ORDER BY created_at DESC
`, [userId]);

    const [specialTrips] = await db.query(`
  SELECT 
    s.title,
    s.pickup_points,
    stb.created_at,
    stb.status
  FROM special_trip_bookings stb
  JOIN SpecialTrip s ON s.id = stb.trip_id
  WHERE stb.user_id = ?
  ORDER BY stb.created_at DESC
`, [userId]);

    res.json({
      trips,
      parcels,
      specialTrips,
    });

  } catch (err) {
    console.error("ACTIVITY ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= requestCancellation =================
exports.requestCancellation = async (req, res) => {
  try {
    const { booking_id, reason } = req.body;

    if (!reason) {
      return res.status(400).json({
        message: "Reason is required",
      });
    }

    const [existing] = await db.query(
      `
      SELECT id
      FROM booking_cancellation_requests
      WHERE booking_id = ?
      AND status = 'pending'
      LIMIT 1
      `,
      [booking_id]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        message:
          "Cancellation request already submitted",
      });
    }

    await db.query(
      `
      INSERT INTO booking_cancellation_requests
      (
        booking_id,
        user_id,
        reason
      )
      VALUES (?, ?, ?)
      `,
      [
        booking_id,
        req.user.id,
        reason,
      ]
    );

    res.json({
      success: true,
      message:
        "Cancellation request submitted",
    });
  } catch (e) {
    console.log(e);

    res.status(500).json({
      message: "Server error",
    });
  }
};