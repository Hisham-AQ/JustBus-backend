const db = require("../config/db");
const geolib = require("geolib");


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
    available_seats,
    status
    FROM trips
    WHERE TRIM(LOWER(from_city)) = TRIM(LOWER(?))
    AND TRIM(LOWER(to_city)) = TRIM(LOWER(?))
    AND DATE(trip_date) = DATE(?)
    ORDER BY departure_time
  `,
      [from, to, date]
    );
    const parsed = rows.map(trip => ({
      ...trip,

      pickup_location:
        typeof trip.pickup_location === "string"
          ? JSON.parse(trip.pickup_location)
          : trip.pickup_location,

      dropoff_location:
        typeof trip.dropoff_location === "string"
          ? JSON.parse(trip.dropoff_location)
          : trip.dropoff_location
    }));

    res.json(parsed);

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

exports.getMyTrips = async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await db.query(
      `
      SELECT 
        t.from_city,
        t.to_city,
        t.trip_date,
        b.persons,
        b.status
      FROM bookings b
      JOIN trips t ON t.id = b.trip_id
      WHERE b.user_id = ?
      ORDER BY t.trip_date DESC
      `,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.getLiveLocation = async (req, res) => {

  const { tripId } = req.params;
  const userId = req.user.id;
  try {

    const [rows] = await db.query(
      `
SELECT
    t.current_lat,
    t.current_lng,
    t.status,

    b.is_boarded,

    b.pickup_location,
    b.dropoff_location

FROM bookings b

JOIN trips t
ON b.trip_id = t.id

WHERE t.id = ?
AND b.user_id = ?
ORDER BY b.id DESC


LIMIT 1
`,
      [tripId, userId]
    );

    if (rows.length === 0) {

      return res.status(404).json({
        message: "Trip not found"
      });
    }

    const trip = rows[0];
    console.log("USER ID => ", userId);
    console.log("TRIP DATA => ", trip);

    const pickupLocation =
      typeof trip.pickup_location === "string"
        ? JSON.parse(trip.pickup_location)
        : trip.pickup_location;

    const pickupLocation =
      typeof trip.pickup_location === "string"
        ? JSON.parse(trip.pickup_location)
        : trip.pickup_location;

    const dropoffLocation =
      typeof trip.dropoff_location === "string"
        ? JSON.parse(trip.dropoff_location)
        : trip.dropoff_location;

    trip.pickup_location = pickupLocation;
    trip.dropoff_location = dropoffLocation;

    const targetLocation =
      trip.is_boarded
        ? dropoffLocation
        : pickupLocation;

    const targetCoords = {
      lat: targetLocation.lat,
      lng: targetLocation.lng
    };

    if (
      !targetLocation ||
      targetLocation.lat == null ||
      targetLocation.lng == null
    ) {
      return res.status(400).json({
        message: "Location coordinates not found"
      });
    }

    if (!trip.current_lat || !trip.current_lng) {
      trip.pickup_location = pickupLocation;
      trip.dropoff_location = dropoffLocation;
      return res.json({

        ...trip,

        eta_minutes: null,

        eta_type:
          trip.is_boarded
            ? "dropoff"
            : "pickup",
      });
    }

    const meters = geolib.getDistance(

      {
        latitude: trip.current_lat,
        longitude: trip.current_lng,
      },

      {
        latitude: targetCoords.lat,
        longitude: targetCoords.lng,
      }
    );

    const distanceKm = meters / 1000;

    const averageSpeed = 40;

    const etaMinutes =
      (distanceKm / averageSpeed) * 60;

    res.json({
      ...trip,
      eta_minutes: etaMinutes
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      message: "Server error"
    });
  }
};