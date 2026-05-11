const db = require("../config/db");

exports.getCurrentTrip = async (req, res) => {

    const userId = req.user.id;
    console.log(req.user);
    console.log(userId);

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

                d.name AS driver_name

            FROM trips t

            LEFT JOIN buses b
            ON t.bus_id = b.id

            LEFT JOIN drivers d
            ON t.driver_id = d.id

            WHERE d.user_id = ?

            ORDER BY t.trip_date DESC

            LIMIT 1`,
            [userId]
        );

        if (rows.length === 0) {

            return res.status(404).json({
                message: "No assigned trip"
            });
        }

        res.json(rows[0]);

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};

exports.getPassengers = async (req, res) => {

    const userId = req.user.id;

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

    ORDER BY bs.seat_number ASC`,
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
`,
            [tripId]
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
    const { qrToken } = req.body;

    console.log("QR RECEIVED:", qrToken);

    try {

        const bookingId = parseInt(qrToken);

        const [rows] = await db.query(
            `SELECT 
        b.id AS booking_id,
        b.status,
        bs.is_boarded

     FROM bookings b

     JOIN booking_seats bs
     ON b.id = bs.booking_id

     WHERE b.id = ?`,
            [bookingId]
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
            [booking.id]
        );

        const [drivers] = await db.query(
            `SELECT id
            FROM drivers
           WHERE user_id = ?`,
            [req.user.id]
        );

        if (drivers.length === 0) {
            return res.status(404).json({
                message: "Driver not found"
            });
        }

        const driverId = drivers[0].id;
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
    const { seatId } = req.body;

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
            AND d.user_id = ?`,
            [seatId, req.user.id]
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

exports.reportMisconduct = async (req, res) => {

    const userId = req.user.id;

    const {
        seat_number,
        passenger_name,
        category,
        severity,
        description
    } = req.body;

    try {

        // get actual driver id
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

    LIMIT 1
    `,
            [driverId, seat_number]
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
         booking_id,
          seat_number,
           passenger_name,
          category,
          severity,
            description
           )
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                driverId,
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
             WHERE id = ?`,
            [lat, lng, tripId]
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