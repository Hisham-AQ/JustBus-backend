const db = require("../config/db");
const geolib = require("geolib");

const stationCoordinates = {

  "North Terminal": {
    lat: 31.995629808817434,
    lng: 35.91964650163556,
  },

  "Qween Alia Hospital": {
    lat: 32.001525772847884,
    lng: 35.91889548308669,
  },

  "Yagouz Bridge": {
    lat: 32.028837894083615,
    lng: 35.89279145624723,
  },

  "Alsarh Schools": {
    lat: 32.05685634250778,
    lng: 35.87063769457635,
  },

  "Old Zarqa Complex": {
    lat: 32.0635622996553,
    lng: 36.09562624022441,
  },

  "Al-Hashemi": {
    lat: 32.13272820449825,
    lng: 36.112979071325114,
  },

  "Main Gate": {
    lat: 32.497808157554395,
    lng: 35.98654176592043,
  },

  "Gate 2": {
    lat: 32.495002976775716,
    lng: 35.98582293390612,
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

    const targetLocation =
      trip.is_boarded
        ? trip.dropoff_location
        : trip.pickup_location;

    console.log(
      "TARGET LOCATION:",
      targetLocation
    );

    const finalLocation =
      Array.isArray(targetLocation)
        ? targetLocation[0]
        : targetLocation;

    const normalizedLocation =
      String(finalLocation || "")
        .trim();

    const targetCoords =
      stationCoordinates[
      normalizedLocation
      ];
    if (!targetCoords) {

      return res.status(400).json({
        message:
          `Location not found: ${normalizedLocation}`
      });
    }

    if (!trip.current_lat || !trip.current_lng) {

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