const db = require("../../config/db");

exports.submitRating = async (req, res) => {

    const userId = req.user.id;

    const {
        tripId,
        driverRating,
        tripRating,
        serviceRating,
        comment
    } = req.body;

    try {

        await db.query(
            `
            INSERT INTO ratings
            (
                user_id,
                trip_id,
                driver_rating,
                trip_rating,
                service_rating,
                comment
            )
            VALUES (?, ?, ?, ?, ?, ?)
            `,
            [
                userId,
                tripId,
                driverRating,
                tripRating,
                serviceRating,
                comment
            ]
        );

        res.json({
            success: true,
            message: "Rating submitted"
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};