const db = require("../config/db");

exports.getMyActivity = async (req, res) => {
  const userId = req.user.id;

  try {
    // 🚍 Trips (العادية)
    const [trips] = await db.query(
      `
      SELECT 
        t.from_city,
        t.to_city,
        t.trip_date,
        b.pickup_location,
        b.dropoff_location,
        b.status,
        b.total_price
      FROM bookings b
      JOIN trips t ON t.id = b.trip_id
      WHERE b.user_id = ?
      ORDER BY b.created_at DESC
      `,
      [userId]
    );

    // 📦 Parcels
    const [parcels] = await db.query(
      `
      SELECT 
        pickup_location,
        dropoff_location,
        parcel_type,
        weight,
        delivery_type,
        price,
        status,
        created_at
      FROM parcel_requests
      WHERE user_id = ?
      ORDER BY created_at DESC
      `,
      [userId]
    );

    // 🚐 Special Trips
    const [specialTrips] = await db.query(
      `
      SELECT 
        t.from_city,
        t.to_city,
        stb.status,
        stb.qr_token,
        stb.created_at
      FROM special_trip_bookings stb
      JOIN trips t ON t.id = stb.trip_id
      WHERE stb.user_id = ?
      ORDER BY stb.created_at DESC
      `,
      [userId]
    );

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