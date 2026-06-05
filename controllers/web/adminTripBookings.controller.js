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