const db =
  require("../../config/db");

exports.getLiveBuses =
  async (req, res) => {

    try {

      const [rows] =
        await db.query(`

          SELECT

            t.id,
            t.from_city,
            t.to_city,


  t.pickup_location,
  t.dropoff_location,

            t.current_lat,
            t.current_lng,

            t.status,

            b.plate_number,

            d.name AS driver_name

          FROM trips t

          LEFT JOIN buses b
          ON t.bus_id = b.id

          LEFT JOIN drivers d
          ON t.driver_id = d.id

          WHERE
            t.status = 'ongoing'

          AND
            t.current_lat IS NOT NULL

          AND
            t.current_lng IS NOT NULL

        `);

     const parsed = rows.map(bus => ({

  ...bus,

  pickup_location:
    typeof bus.pickup_location === "string"
      ? JSON.parse(bus.pickup_location)
      : bus.pickup_location,

  dropoff_location:
    typeof bus.dropoff_location === "string"
      ? JSON.parse(bus.dropoff_location)
      : bus.dropoff_location

}));

res.json(parsed);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        message:
          "Server error"
      });
    }
};