const db = require("../config/db");

// ================= GET ALL TRIPS =================
exports.getTrips = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        id,
        from_city AS fromCity,
        to_city AS toCity,
        pickup_location AS pickupLocation,
        dropoff_location AS dropoffLocation,
        departure_time AS departureTime,
        arrival_time AS arrivalTime,
        duration_minutes AS durationMinutes,
        price,
        available_seats AS availableSeats,
        trip_date AS tripDate,
        status,
        driver_id AS driverId,
        bus_id AS busId,
        current_lat AS currentLat,
        current_lng AS currentLng
      FROM trips
      ORDER BY trip_date, departure_time
    `);

    // ✅ Parse JSON fields
    const parsed = rows.map(trip => ({
      ...trip,
      pickupLocation: trip.pickupLocation ? JSON.parse(trip.pickupLocation) : null,
      dropoffLocation: trip.dropoffLocation ? JSON.parse(trip.dropoffLocation) : null
    }));

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
      busId,
      currentLat,
      currentLng
    } = req.body;

    // ✅ Proper validation
    if (!form.departureTime) e.departureTime = 'Departure time required';
    if (!form.tripDate) e.tripDate = 'Trip date required';
    if (!form.price) e.price = 'Price required';

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
        JSON.stringify(pickupLocation),   // ✅ JSON
        JSON.stringify(dropoffLocation), // ✅ JSON
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
      busId,
      currentLat,
      currentLng
    } = req.body;

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
        JSON.stringify(pickupLocation),
        JSON.stringify(dropoffLocation),
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