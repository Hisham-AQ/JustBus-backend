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
        trip_date AS tripDate
      FROM trips
      ORDER BY trip_date, departure_time
    `);

    res.json(rows);
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
      tripDate
    } = req.body;

    if (!fromCity || !toCity || !departureTime || !tripDate) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    await db.query(
      `INSERT INTO trips
      (from_city, to_city, pickup_location, dropoff_location,
       departure_time, arrival_time, duration_minutes,
       price, available_seats, trip_date)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fromCity,
        toCity,
        pickupLocation,
        dropoffLocation,
        departureTime,
        arrivalTime,
        durationMinutes,
        price,
        availableSeats,
        tripDate
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
      tripDate
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
        trip_date = ?
      WHERE id = ?`,
      [
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