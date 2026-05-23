const db = require("../../config/db");

// ================= DASHBOARD STATS =================
exports.getDashboardStats =
  async (req, res) => {

    try {

      // Active buses
      const [buses] =
        await db.query(`
          SELECT COUNT(*) AS total
          FROM buses
        `);

      // Students onboard
      const [students] =
        await db.query(`
          SELECT COUNT(*) AS total
          FROM users
          WHERE role = 'student'
        `);

      // Pending parcels
      const [parcels] =
        await db.query(`
          SELECT COUNT(*) AS total
          FROM parcel_requests
          WHERE status = 'pending'
        `);

      res.json({

        activeBuses:
          buses[0].total,

        studentsOnBoard:
          students[0].total,

        pendingParcels:
          parcels[0].total
      });

    } catch (err) {

      console.error(
        "DASHBOARD STATS ERROR:",
        err
      );

      res.status(500).json({
        message: "Server error"
      });
    }
};

// ================= WEEKLY TRIPS =================
exports.getWeeklyTrips =
  async (req, res) => {

    try {

      const [rows] =
        await db.query(`

          SELECT

            DAYNAME(created_at) AS day,

            COUNT(*) AS trips

          FROM trips

          WHERE created_at >=
            DATE_SUB(NOW(), INTERVAL 7 DAY)

GROUP BY
  DAYOFWEEK(created_at),
  DAYNAME(created_at)

ORDER BY
  DAYOFWEEK(created_at)

        `);

      const daysOrder = [
        'Sunday',
        'Monday',
        'Tuesday',
        'Wednesday',
        'Thursday',
        'Friday',
        'Saturday'
      ];

      const formatted =
        daysOrder.map(day => {

          const found =
            rows.find(
              r => r.day === day
            );

          return {

            name:
              day.slice(0, 3),

            trips:
              found
                ? found.trips
                : 0
          };
        });

      res.json(formatted);

    } catch (err) {

      console.error(
        "WEEKLY TRIPS ERROR:",
        err
      );

      res.status(500).json({
        message: "Server error"
      });
    }
};