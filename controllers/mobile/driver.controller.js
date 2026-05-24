const db = require("../../config/db");



// ================= getDriverTrips =================
exports.getDriverTrips = async (req, res) => {
    const userId = req.user.id;

    try {

        const [rows] = await db.query(
            `SELECT
                t.id,
                t.from_city,
                t.to_city,
                t.trip_date,
                t.departure_time,
                t.arrival_time,
                t.status

            FROM trips t

            JOIN drivers d
            ON t.driver_id = d.id

            WHERE d.user_id = ?

            ORDER BY
                t.trip_date DESC,
                t.departure_time ASC`,
            [userId]
        );

        res.json(rows);

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};

exports.getDriverTripById = async (req, res) => {

    const userId = req.user.id;
    const { tripId } = req.params;

    try {

        const [rows] = await db.query(
            `SELECT
    t.id,
    t.from_city,
    t.to_city,
    t.pickup_location,
    t.dropoff_location,
    t.trip_date,
    t.departure_time,
    t.arrival_time,
    t.status,
    t.available_seats,
    t.price,

    b.bus_number,

    u.name AS driver_name,
    u.avatar AS driver_avatar

FROM trips t

LEFT JOIN buses b
ON t.bus_id = b.id

LEFT JOIN drivers d
ON t.driver_id = d.id

LEFT JOIN users u
ON d.user_id = u.id

WHERE d.user_id = ?
AND t.id = ?`,

            [userId, tripId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                message: "Trip not found"
            });
        }

        const trip = rows[0];

        res.json(trip);

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};

exports.getPassengers = async (req, res) => {

    const userId = req.user.id;
    const { tripId } = req.query;

    try {

        const [rows] = await db.query(
            `SELECT
        bs.id,
        u.name,
        bs.seat_number,
        bs.is_boarded,
        bs.is_dropped_off,
        t.status,

       b.pickup_location,
       b.dropoff_location

    FROM booking_seats bs

    JOIN bookings b
    ON bs.booking_id = b.id

    JOIN users u
    ON b.user_id = u.id

    JOIN trips t
    ON b.trip_id = t.id

    JOIN drivers d
    ON t.driver_id = d.id

    WHERE d.user_id = ?
    AND t.id = ?

    ORDER BY bs.seat_number ASC`,
            [userId, tripId]
        );

        const parsed = [];

        for (const row of rows) {

            let pickupLocation = row.pickup_location;

            if (typeof pickupLocation === "string") {
                try {
                    pickupLocation = JSON.parse(pickupLocation);
                } catch (_) {

                    const [stationRows] = await db.query(
                        "SELECT lat, lng FROM stations WHERE name = ? LIMIT 1",
                        [pickupLocation]
                    );

                    pickupLocation = {
                        name: pickupLocation,
                        lat: stationRows[0]?.lat ?? null,
                        lng: stationRows[0]?.lng ?? null,
                    };
                }
            }

            let dropoffLocation = row.dropoff_location;

            if (typeof dropoffLocation === "string") {
                try {
                    dropoffLocation = JSON.parse(dropoffLocation);
                } catch (_) {

                    const [stationRows] = await db.query(
                        "SELECT lat, lng FROM stations WHERE name = ? LIMIT 1",
                        [dropoffLocation]
                    );

                    dropoffLocation = {
                        name: dropoffLocation,
                        lat: stationRows[0]?.lat ?? null,
                        lng: stationRows[0]?.lng ?? null,
                    };
                }
            }

            parsed.push({
                ...row,
                pickup_location: pickupLocation,
                dropoff_location: dropoffLocation
            });
        }

        res.json(parsed);

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};


exports.startTrip = async (req, res) => {
    const userId = req.user.id;

    const [drivers] = await db.query(
        `SELECT id FROM drivers WHERE user_id = ?`,
        [userId]
    );

    if (drivers.length === 0) {
        return res.status(404).json({
            message: "Driver not found"
        });
    }

    const driverId = drivers[0].id;
    const { tripId } = req.body;

    try {
        await db.query(
            `UPDATE trips
             SET status = 'ongoing'
              WHERE id = ? AND driver_id = ?`,
            [tripId, driverId]
        );

        res.json({
            message: "Trip started"
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            message: "Server error"
        });
    }
};


exports.endTrip = async (req, res) => {
    const userId = req.user.id;

    const [drivers] = await db.query(
        `SELECT id FROM drivers WHERE user_id = ?`,
        [userId]
    );

    if (drivers.length === 0) {
        return res.status(404).json({
            message: "Driver not found"
        });
    }

    const driverId = drivers[0].id;
    const { tripId } = req.body;

    try {

        await db.query(
            `
UPDATE trips
SET
  status = 'completed',
  current_lat = NULL,
  current_lng = NULL
WHERE id = ?
AND driver_id = ?
`,
            [tripId, driverId]
        );

        await db.query(
            `
UPDATE bookings
SET status = 'completed'
WHERE trip_id = ?
AND status = 'confirmed'
`,
            [tripId]
        );

        res.json({
            message: "Trip completed"
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            message: "Server error"
        });
    }
};

exports.scanTicket = async (req, res) => {
    const { qrToken, tripId } = req.body;

    try {

        const bookingId = parseInt(qrToken);

        const [rows] = await db.query(
            `SELECT 
             b.id AS booking_id,
             b.status,
             b.is_boarded

             FROM bookings b

             JOIN trips t
             ON b.trip_id = t.id

             WHERE b.id = ?
             AND t.id = ?`,


            [bookingId, tripId]

        );

        if (rows.length === 0) {
            return res.status(400).json({
                valid: false,
                message: "Invalid ticket"
            });
        }

        const booking = rows[0];

        if (booking.status !== 'confirmed') {
            return res.status(400).json({
                valid: false,
                message: "Booking not confirmed"
            });
        }

        if (booking.is_boarded) {
            return res.status(400).json({
                valid: false,
                message: "Already scanned"
            });
        }
        await db.query(
            `UPDATE booking_seats
       SET is_boarded = 1
       WHERE booking_id = ?`,
            [booking.booking_id]
        );

        await db.query(
            `UPDATE bookings
             SET is_boarded = 1
             WHERE id = ?`,
            [booking.booking_id]
        );

        const [drivers] = await db.query(
            `
    SELECT id
    FROM drivers
    WHERE user_id = ?
    `,
            [req.user.id]
        );

        const driverId = drivers[0].id;

        if (drivers.length === 0) {
            return res.status(404).json({
                message: "Driver not found"
            });
        }

        await db.query(
            `INSERT INTO scan_logs
              (booking_id, driver_id, result)
              VALUES (?, ?, ?)`,
            [
                booking.booking_id,
                driverId,
                'valid'
            ]
        );
        res.json({
            valid: true,
            message: "Passenger boarded"
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};



exports.dropOffPassenger = async (req, res) => {
    const { seatId, tripId } = req.body;
    try {

        await db.query(
            `UPDATE booking_seats bs

             JOIN bookings b
             ON bs.booking_id = b.id

             JOIN trips t
             ON b.trip_id = t.id
 
            JOIN drivers d
            ON t.driver_id = d.id

             SET bs.is_dropped_off = 1

          WHERE bs.id = ?
            AND d.user_id = ?
            AND t.id = ?`,

            [seatId, req.user.id, tripId]
        );

        res.json({
            success: true
        });

    } catch (err) {
        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};

//misconduct
exports.reportMisconduct = async (req, res) => {

    const userId = req.user.id;

    const {
        seat_number,
        booking_id,
        passenger_name,
        category,
        severity,
        description,
        tripId

    } = req.body;

    try {

        const [drivers] = await db.query(
            `SELECT id
             FROM drivers
             WHERE user_id = ?`,
            [userId]
        );

        if (drivers.length === 0) {
            return res.status(404).json({
                message: "Driver not found"
            });
        }

        const driverId = drivers[0].id;

        const [bookings] = await db.query(
            `
    SELECT b.id AS booking_id

    FROM booking_seats bs

    JOIN bookings b
    ON bs.booking_id = b.id

    JOIN trips t
    ON b.trip_id = t.id

    WHERE
        t.driver_id = ?
        AND bs.seat_number = ?
            AND t.id = ?

    LIMIT 1
    `,
            [driverId, seat_number, tripId]
        );

        const bookingId =
            bookings.length > 0
                ? bookings[0].booking_id
                : null;


        if (!seat_number || !category || !severity || !description) {
            return res.status(400).json({
                message: "Missing required fields"
            });

        }
        await db.query(
            `INSERT INTO misconduct_reports
        (
     driver_id,
     trip_id,
     booking_id,
     seat_number,
     passenger_name,
     category,
     severity,
     description
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                driverId,
                tripId,
                bookingId,
                seat_number,
                passenger_name || null,
                category,
                severity,
                description
            ]
        );

        res.json({
            success: true,
            message: "Report submitted"
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};

exports.updateLocation = async (req, res) => {

    const { tripId, lat, lng } = req.body;

    try {

        await db.query(
            `UPDATE trips
             SET current_lat = ?,
                 current_lng = ?
             WHERE id = ?
             AND driver_id = (
    SELECT id
    FROM drivers
    WHERE user_id = ?
)`,
            [lat, lng, tripId, req.user.id]
        );

        res.json({
            success: true
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};


