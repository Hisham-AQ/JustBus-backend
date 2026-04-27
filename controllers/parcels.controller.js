const db = require("../config/db");

exports.createParcel = async (req, res) => {
  const userId = req.user.id;

  const {
    pickup_location,
    dropoff_location,
    parcel_type,
    weight,
    delivery_type,
    notes,
    price
  } = req.body;

  try {
    const pinCode = Math.floor(100000 + Math.random() * 900000).toString();

    const [result] = await db.execute(`
      INSERT INTO parcel_requests
      (user_id, pickup_location, dropoff_location, parcel_type, weight, delivery_type, notes, price, pin_code)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      userId,
      pickup_location,
      dropoff_location,
      parcel_type,
      weight,
      delivery_type,
      notes,
      price,
      pinCode
    ]);

    const orderNumber = "ORD-" + String(result.insertId).padStart(4, '0');

    await db.execute(
      "UPDATE parcel_requests SET order_number = ? WHERE id = ?",
      [orderNumber, result.insertId]
    );

    res.json({
      message: "Parcel request submitted",
      orderNumber,
      pinCode
    });

  } catch (err) {
    console.error("PARCEL ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};