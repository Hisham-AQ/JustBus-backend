const db = require("../../config/db");

// ================= GET ALL TRIPS =================
exports.getTrips = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT
  t.id,
  t.from_city AS fromCity,
  t.to_city AS toCity,

  t.pickup_location AS pickupLocation,
  t.dropoff_location AS dropoffLocation,

  t.departure_time AS departureTime,
  t.arrival_time AS arrivalTime,
  t.duration_minutes AS durationMinutes,

  t.price,
  t.available_seats AS availableSeats,
  t.trip_date AS tripDate,

  t.status,

  t.driver_id AS driverId,
  d.name AS driverName,

  t.bus_id AS busId,
  b.plate_number AS busPlate,

  t.current_lat AS currentLat,
  t.current_lng AS currentLng

FROM trips t

LEFT JOIN drivers d
ON t.driver_id = d.id

LEFT JOIN buses b
ON t.bus_id = b.id

ORDER BY t.trip_date, t.departure_time
    `);

    // ✅ Parse JSON fields
    const parsed = rows.map(trip => {
  let pickup = [];
  let dropoff = [];

  // SAFE pickup parsing
  try {
    pickup =
      typeof trip.pickupLocation === "string"
        ? JSON.parse(trip.pickupLocation)
        : trip.pickupLocation || [];
  } catch {
    pickup = [];
  }

  // SAFE dropoff parsing
  try {
    dropoff =
      typeof trip.dropoffLocation === "string"
        ? JSON.parse(trip.dropoffLocation)
        : trip.dropoffLocation || [];
  } catch {
    dropoff = [];
  }

  return {
    ...trip,
    pickupLocation: pickup,
    dropoffLocation: dropoff
  };
});

    res.json(parsed);

  } catch (err) {
    console.error("GET ADMIN TRIPS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= CREATE TRIP =================
exports.createTrip = async (req, res) => {
  try {
    const {
      fromCity,
      toCity,
      pickupLocation,
      dropoffLocation,
      departureTime,
      arrivalTime,
      durationMinutes,
      price,
      availableSeats,
      tripDate,
      status,
      driverId,
      currentLat,
      currentLng
    } = req.body;

  // ✅ Proper validation
if (!departureTime || !tripDate || !price) {
  return res.status(400).json({
    message: "Missing required fields"
  });
}

// Convert station IDs into full station objects

const [pickupStations] = await db.query(
  `
  SELECT id, name, lat, lng
  FROM stations
  WHERE id IN (?)
  `,
  [pickupLocation]
);

const [dropoffStations] = await db.query(
  `
  SELECT id, name, lat, lng
  FROM stations
  WHERE id IN (?)
  `,
  [dropoffLocation]
);

if (driverId) {

  const [conflict] = await db.query(
    `
    SELECT id
    FROM trips
    WHERE driver_id = ?
    AND trip_date = ?
    AND status != 'completed'
    AND (
      departure_time = ?
      OR arrival_time = ?
    )
    `,
    [
      driverId,
      tripDate,
      departureTime,
      arrivalTime
    ]
  );

  if (conflict.length > 0) {
    return res.status(400).json({
      message: "Driver already assigned to another trip at this time"
    });
  }
}

if (busId) {

  const [conflict] = await db.query(
    `
    SELECT id
    FROM trips
    WHERE bus_id = ?
    AND trip_date = ?
    AND status != 'completed'
    AND (
      departure_time = ?
      OR arrival_time = ?
    )
    `,
    [
      busId,
      tripDate,
      departureTime,
      arrivalTime
    ]
  );

  if (conflict.length > 0) {
    return res.status(400).json({
      message: "Bus already assigned to another trip at this time"
    });
  }
}

let busId = null;

if (driverId) {

  const [drivers] = await db.query(
    `
    SELECT bus_id
    FROM drivers
    WHERE id = ?
    `,
    [driverId]
  );

  if (drivers.length > 0) {
    busId = drivers[0].bus_id;
  }
}

    await db.query(
      `INSERT INTO trips
      (from_city, to_city, pickup_location, dropoff_location,
       departure_time, arrival_time, duration_minutes,
       price, available_seats, trip_date, status,
       driver_id, bus_id, current_lat, current_lng)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fromCity,
        toCity,
        JSON.stringify(pickupStations),
        JSON.stringify(dropoffStations),
        departureTime,
        arrivalTime,
        durationMinutes,
        price,
        availableSeats,
        tripDate,
        status || "scheduled",
        driverId || null,
        busId || null,
        currentLat || null,
        currentLng || null
      ]
    );

    res.status(201).json({ message: "Trip created successfully" });

  } catch (err) {
    console.error("CREATE ADMIN TRIP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= UPDATE TRIP =================
exports.updateTrip = async (req, res) => {
  try {
    const { id } = req.params;

    const {
      fromCity,
      toCity,
      pickupLocation,
      dropoffLocation,
      departureTime,
      arrivalTime,
      durationMinutes,
      price,
      availableSeats,
      tripDate,
      status,
      driverId,
      currentLat,
      currentLng
    } = req.body;

    const [pickupStations] = await db.query(
  `
  SELECT id, name, lat, lng
  FROM stations
  WHERE id IN (?)
  `,
  [pickupLocation]
);

const [dropoffStations] = await db.query(
  `
  SELECT id, name, lat, lng
  FROM stations
  WHERE id IN (?)
  `,
  [dropoffLocation]
);

let busId = null;

if (driverId) {

  const [drivers] = await db.query(
    `
    SELECT bus_id
    FROM drivers
    WHERE id = ?
    `,
    [driverId]
  );

  if (drivers.length > 0) {
    busId = drivers[0].bus_id;
  }
}

if (driverId) {

  const [conflict] = await db.query(
    `
    SELECT id
    FROM trips
    WHERE driver_id = ?
    AND trip_date = ?
    AND id != ?
    AND status != 'completed'
    AND (
      departure_time = ?
      OR arrival_time = ?
    )
    `,
    [
      driverId,
      tripDate,
      id,
      departureTime,
      arrivalTime
    ]
  );

  if (conflict.length > 0) {
    return res.status(400).json({
      message: "Driver already assigned to another trip at this time"
    });
  }
}

if (busId) {

  const [conflict] = await db.query(
    `
    SELECT id
    FROM trips
    WHERE bus_id = ?
    AND trip_date = ?
    AND id != ?
    AND status != 'completed'
    AND (
      departure_time = ?
      OR arrival_time = ?
    )
    `,
    [
      busId,
      tripDate,
      id,
      departureTime,
      arrivalTime
    ]
  );

  if (conflict.length > 0) {
    return res.status(400).json({
      message: "Bus already assigned to another trip at this time"
    });
  }
}

    await db.query(
      `UPDATE trips SET
        from_city = ?,
        to_city = ?,
        pickup_location = ?,
        dropoff_location = ?,
        departure_time = ?,
        arrival_time = ?,
        duration_minutes = ?,
        price = ?,
        available_seats = ?,
        trip_date = ?,
        status = ?,
        driver_id = ?,
        bus_id = ?,
        current_lat = ?,
        current_lng = ?
      WHERE id = ?`,
      [
        fromCity,
        toCity,
        JSON.stringify(pickupStations),
        JSON.stringify(dropoffStations),
        departureTime,
        arrivalTime,
        durationMinutes,
        price,
        availableSeats,
        tripDate,
        status,
        driverId,
        busId,
        currentLat,
        currentLng,
        id
      ]
    );

    res.json({ message: "Trip updated successfully" });

  } catch (err) {
    console.error("UPDATE ADMIN TRIP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= DELETE TRIP =================
exports.deleteTrip = async (req, res) => {
  try {
    const { id } = req.params;

    await db.query("DELETE FROM trips WHERE id = ?", [id]);

    res.json({ message: "Trip deleted successfully" });

  } catch (err) {
    console.error("DELETE ADMIN TRIP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};