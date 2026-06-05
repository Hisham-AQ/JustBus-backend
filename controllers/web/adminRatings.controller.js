const db = require("../../config/db");

// ================= ANALYTICS =================
exports.getAnalytics = async (req, res) => {

  try {

    const [avg] = await db.query(`
      SELECT
        AVG(driver_rating) AS avgDriver,
        AVG(trip_rating) AS avgTrip,
        AVG(service_rating) AS avgService,
        COUNT(*) AS totalRatings
      FROM ratings
    `);

    const [distribution] = await db.query(`
      SELECT
        driver_rating AS rating,
        COUNT(*) AS count
      FROM ratings
      GROUP BY driver_rating
      ORDER BY driver_rating
    `);

    const [recentComments] = await db.query(`
      SELECT
        r.id,
        r.comment,
        r.created_at,

        r.driver_rating,
        r.trip_rating,
        r.service_rating,

        u.name AS userName

      FROM ratings r

      JOIN users u
      ON u.id = r.user_id

      WHERE r.comment IS NOT NULL
      AND r.comment != ''

      ORDER BY r.created_at DESC

      LIMIT 10
    `);

    res.json({

      averages: {

        avgDriver:
          Number(
            avg[0].avgDriver || 0
          ).toFixed(1),

        avgTrip:
          Number(
            avg[0].avgTrip || 0
          ).toFixed(1),

        avgService:
          Number(
            avg[0].avgService || 0
          ).toFixed(1),

        totalRatings:
          avg[0].totalRatings || 0
      },

      distribution,

      recentComments
    });

  } catch (err) {

    console.error(
      "ADMIN RATINGS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= ALL COMMENTS =================
exports.getComments = async (req, res) => {

  try {

    const [rows] = await db.query(`
      SELECT
        r.id,
        r.comment,
        r.created_at,

        r.driver_rating,
        r.trip_rating,
        r.service_rating,

        u.name AS userName

      FROM ratings r

      JOIN users u
      ON u.id = r.user_id

      WHERE r.comment IS NOT NULL
      AND r.comment != ''

      ORDER BY r.created_at DESC
    `);

    res.json(rows);

  } catch (err) {

    console.error(
      "GET COMMENTS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= DRIVER RATINGS =================
exports.getDriverRatings = async (req, res) => {

  try {

    const [rows] = await db.query(`

      SELECT

  d.id,
  u.name,

        COUNT(r.id) AS totalReviews,

        ROUND(
          AVG(r.driver_rating),
          1
        ) AS avgDriverRating,

        ROUND(
          AVG(r.trip_rating),
          1
        ) AS avgTripRating,

        ROUND(
          AVG(r.service_rating),
          1
        ) AS avgServiceRating

      FROM ratings r

      JOIN trips t
      ON r.trip_id = t.id

      JOIN drivers d
      ON t.driver_id = d.id

      JOIN users u
ON d.user_id = u.id

      GROUP BY d.id

      ORDER BY avgDriverRating DESC

    `);

    res.json(rows);

  } catch (err) {

    console.error(
      "DRIVER RATINGS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= DRIVER REVIEWS =================
exports.getDriverReviews = async (req, res) => {

  try {

    const { id } = req.params;

    const [rows] = await db.query(`

      SELECT

        r.id,
        r.comment,
        r.created_at,

        r.driver_rating,
        r.trip_rating,
        r.service_rating,

        u.name AS userName

      FROM ratings r

      JOIN users u
      ON u.id = r.user_id

      JOIN trips t
      ON r.trip_id = t.id

      WHERE t.driver_id = ?

      ORDER BY r.created_at DESC

    `, [id]);

    res.json(rows);

  } catch (err) {

    console.error(
      "GET DRIVER REVIEWS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};