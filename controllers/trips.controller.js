const db = require("../config/db");

exports.getCities = async (req, res) => {
  const [rows] = await db.query(`
    SELECT DISTINCT from_city
    FROM trips
    WHERE from_city != 'JUST university'
  `);

  res.json(rows);
};

exports.searchTrips = async (req, res) => {
  const { from, to, date } = req.query;

  console.log("FROM:", from);
  console.log("TO:", to);
  console.log("DATE:", date);

  try {
    const [rows] = await db.query(
      `
  SELECT 
    id,
    from_city,
    to_city,
    pickup_location,
    dropoff_location,
    departure_time,
    arrival_time,
    duration_minutes,
    price,
    available_seats
  FROM trips
  WHERE TRIM(LOWER(from_city)) = TRIM(LOWER(?))
    AND TRIM(LOWER(to_city)) = TRIM(LOWER(?))
    AND DATE(trip_date) = DATE(?)
  ORDER BY departure_time
  `,
      [from, to, date]
    );
    res.json(rows);

  } catch (err) {
    console.error("SEARCH TRIPS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.getSeats = async (req, res) => {
  const { tripId } = req.params;

  const [rows] = await db.query(
    `
    SELECT
      bs.seat_number,
      COALESCE(u.gender, 'none') AS gender
    FROM booking_seats bs
    JOIN bookings b ON b.id = bs.booking_id
    JOIN users u ON u.id = b.user_id
    WHERE bs.trip_id = ?
    `,
    [tripId]
  );

  res.json({
    reservedSeats: rows.map(r => ({
      seat_number: r.seat_number,
      gender: r.gender
    }))
  });
};