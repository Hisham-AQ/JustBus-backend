const db = require("../config/db");

exports.getCurrentTrip = async (req, res) => {
    const driverId = req.user.id;

    try {
        const [rows] = await db.query(`
      SELECT 
        st.id,
        st.trip_date,
        st.departure_time,
        st.arrival_time,
        st.status,
        st.available_seats,
        st.price,
        r.pickup_location,
        r.dropoff_location,
        b.bus_number,
        d.name AS driver_name
      FROM trips st
      JOIN routes r ON st.route_id = r.id
      LEFT JOIN buses b ON st.bus_id = b.id
      LEFT JOIN drivers d ON st.driver_id = d.id
      WHERE d.user_id = ?
      ORDER BY st.trip_date DESC
      LIMIT 1
    `, [driverId]);

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


exports.startTrip = async (req, res) => {
    const driverId = req.user.id;
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
    const driverId = req.user.id;
    const { tripId } = req.body;

    try {
        await db.query(
            `UPDATE trips
             SET status = 'completed'
             WHERE id = ? AND driver_id = ?`,
            [tripId, driverId]
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

    try {

        const [rows] = await db.query(
            `SELECT 
            b.id AS booking_id,
            b.status,
            bs.is_boarded
            FROM bookings b
            JOIN booking_seats bs
            ON b.id = bs.booking_id
            WHERE b.qr_token = ?`,
            [qrToken]
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
            `INSERT INTO scan_logs
              (booking_id, driver_id, result)
              VALUES (?, ?, ?)`,
            [
                booking.booking_id,
                req.user.id,
                'success'
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

exports.getPassengers = async (req, res) => {
    const driverId = req.user.id;

    try {

        const [rows] = await db.query(
            `SELECT
        bs.id,
        u.full_name,
        bs.seat_number,
        bs.is_boarded,
        bs.is_dropped_off
       FROM booking_seats bs

       JOIN bookings b
       ON bs.booking_id = b.id

       JOIN users u
       ON b.user_id = u.id

       JOIN trips t
       ON bs.trip_id = t.id

       WHERE t.driver_id = ?
       ORDER BY bs.seat_number ASC`,
            [driverId]
        );

        res.json(rows);

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
            `UPDATE booking_seats
       SET is_dropped_off = 1
       WHERE id = ?`,
            [seatId]
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

    const driverId = req.user.id;

    const {
        booking_id,
        category,
        severity,
        description
    } = req.body;

    try {

        await db.query(
            `INSERT INTO misconduct_reports
            (
              driver_id,
              booking_id,
              category,
              severity,
              description
            )
            VALUES (?, ?, ?, ?, ?)`,
            [
                driverId,
                booking_id || null,
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