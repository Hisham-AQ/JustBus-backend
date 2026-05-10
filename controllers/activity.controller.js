const db = require("../config/db");

exports.getMyActivity = async (req, res) => {
  const userId = req.user.id;

  try {
    // Trips
    const [trips] = await db.query(
      `
  SELECT 
    b.id AS booking_id,
    b.status,
    b.total_price,
    b.qr_code,

    t.from_city,
    t.to_city,
    t.trip_date,
    t.departure_time,
    t.arrival_time,
    t.bus_id,

    GROUP_CONCAT(bs.seat_number) AS seats

  FROM bookings b

  JOIN trips t
  ON t.id = b.trip_id

  LEFT JOIN booking_seats bs
  ON bs.booking_id = b.id

  WHERE b.user_id = ?

  GROUP BY b.id

  ORDER BY b.created_at DESC
  `,
      [userId]
    );

    //  Parcels
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

    //  Special Trips
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