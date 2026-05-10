const db = require("../config/db");
const geolib = require("geolib");

const stationCoordinates = {

  "North Terminal": {
    lat: 32.5525,
    lng: 35.8510,
  },

  "Queen Alia Hospital": {
    lat: 32.5480,
    lng: 35.8570,
  },

  "Yajooz": {
    lat: 32.5400,
    lng: 35.8700,
  },

  "Main Gate": {
    lat: 32.4970,
    lng: 35.9910,
  },

  "Gate 2": {
    lat: 32.4940,
    lng: 35.9890,
  },

};

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
      bs.is_boarded,
      t.dropoff_location
  FROM trips t

  JOIN bookings b
  ON b.trip_id = t.id

  JOIN booking_seats bs
  ON bs.booking_id = b.id

  WHERE t.id = ?
AND b.user_id = ?
  `,
      [tripId, userId]
    );

    if (rows.length === 0) {

      return res.status(404).json({
        message: "Trip not found"
      });
    }

    const trip = rows[0];

    const {
      pickupLocation
    } = req.query;

    const targetLocation =
      trip.is_boarded
        ? trip.dropoff_location
        : pickupLocation;

    const targetCoords =
      stationCoordinates[targetLocation];
    if (!targetCoords) {

      return res.status(400).json({
        message: "Invalid pickup location"
      });
    }
    if (!trip.current_lat || !trip.current_lng) {

      return res.json({
        ...trip,
        eta_minutes: null
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