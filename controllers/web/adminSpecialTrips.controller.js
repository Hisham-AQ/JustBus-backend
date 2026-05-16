const db = require("../../config/db");

// ================= GET ALL =================
exports.getSpecialTrips = async (req, res) => {
  try {

    const [rows] = await db.query(`
  SELECT
    st.*,

    d.name AS driverName,

    b.plate_number AS busPlate

  FROM SpecialTrip st

  LEFT JOIN drivers d
  ON st.driver_id = d.id

  LEFT JOIN buses b
  ON st.bus_id = b.id

  ORDER BY st.created_at DESC
`);

const parsedRows = rows.map(trip => ({
  ...trip,

pickup_points: (() => {

  try {

    return JSON.parse(trip.pickup_points);

  } catch {

    return trip.pickup_points
      ? [trip.pickup_points]
      : [];
  }

})()
}));

    res.json(parsedRows);

  } catch (err) {
    console.error("GET SPECIAL TRIPS ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= CREATE =================
exports.createSpecialTrip = async (req, res) => {

  try {

    const {
      title,
      description,
      price,
      duration,
      image_url,
      category,
      seats_total,
      seats_available,
      departure_time,
      return_time,
      pickup_points,
      bus_type,
      includes,
      notes,
      status,
      driver_id
    } = req.body;

    let bus_id = null;
let bus_capacity = 0;

if (driver_id) {

  const [drivers] = await db.query(
    `
    SELECT
      d.bus_id,
      b.capacity
    FROM drivers d

    LEFT JOIN buses b
    ON d.bus_id = b.id

    WHERE d.id = ?
    `,
    [driver_id]
  );

  if (drivers.length > 0) {

    bus_id = drivers[0].bus_id;

    bus_capacity = drivers[0].capacity || 0;
  }
}

    await db.query(
      `
      INSERT INTO SpecialTrip (
        title,
        description,
        price,
        duration,
        image_url,
        category,
        seats_total,
seats_available,
        departure_time,
        return_time,
        pickup_points,
        bus_type,
        includes,
        notes,
        status,
        driver_id,
        bus_id
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        title,
        description,
        price,
        duration,
        image_url,
        category,
bus_capacity,
bus_capacity,
        departure_time,
        return_time,
        JSON.stringify(pickup_points || []),
        bus_type,
        includes,
        notes,
        status || "active",
        driver_id || null,
        bus_id
      ]
    );

    res.status(201).json({
      message: "Special trip created successfully"
    });

  } catch (err) {

    console.error("CREATE SPECIAL TRIP ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= UPDATE =================
exports.updateSpecialTrip = async (req, res) => {

  try {

    const { id } = req.params;

    const {
      title,
      description,
      price,
      duration,
      image_url,
      category,
      seats_total,
      seats_available,
      departure_time,
      return_time,
      pickup_points,
      bus_type,
      includes,
      notes,
      status,
      driver_id
    } = req.body;

    let bus_id = null;
let bus_capacity = 0;

    if (driver_id) {

      const [drivers] = await db.query(
        `
       SELECT
  d.bus_id,
  b.capacity
FROM drivers d

LEFT JOIN buses b
ON d.bus_id = b.id

WHERE d.id = ?
        `,
        [driver_id]
      );
if (drivers.length > 0) {

  bus_id = drivers[0].bus_id;

  bus_capacity = drivers[0].capacity || 0;
}
    }

    const finalSeatsAvailable =
  Math.min(
    seats_available || bus_capacity,
    bus_capacity
  );

    await db.query(
      `
      UPDATE SpecialTrip
      SET
        title = ?,
        description = ?,
        price = ?,
        duration = ?,
        image_url = ?,
        category = ?,
        seats_total = ?,
        seats_available = ?,
        departure_time = ?,
        return_time = ?,
        pickup_points = ?,
        bus_type = ?,
        includes = ?,
        notes = ?,
        status = ?,
        driver_id = ?,
        bus_id = ?
      WHERE id = ?
      `,
      [
        title,
        description,
        price,
        duration,
        image_url,
        category,
bus_capacity,
finalSeatsAvailable,
        departure_time,
        return_time,
        JSON.stringify(pickup_points || []),
        bus_type,
        includes,
        notes,
        status,
        driver_id || null,
        bus_id,
        id
      ]
    );


    res.json({
      message: "Special trip updated successfully"
    });

  } catch (err) {

    console.error("UPDATE SPECIAL TRIP ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= DELETE =================
exports.deleteSpecialTrip = async (req, res) => {

  try {

    const { id } = req.params;

    await db.query(
      `
      DELETE FROM SpecialTrip
      WHERE id = ?
      `,
      [id]
    );

    res.json({
      message: "Special trip deleted successfully"
    });

  } catch (err) {

    console.error("DELETE SPECIAL TRIP ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};