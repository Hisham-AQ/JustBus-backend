const db = require("../config/db");
const { io } = require("../index");

// ================= CREATE PARCEL =================
exports.createParcel = async (req, res) => {
  const userId = req.user.id;

  const {
    pickup_location,
    dropoff_location,
    parcel_type,
    weight,
    delivery_type,
    notes,
    receiver_name
  } = req.body;

  const connection = await db.getConnection();


  if (!receiver_name || receiver_name.trim() === "") {
    await connection.rollback();
    return res.status(400).json({ message: "Receiver name required" });
  }

  if (users.length === 0) {
    await connection.rollback();
    return res.status(404).json({ message: "User not found" });
  }

  if (pickup_location === dropoff_location) {
    await connection.rollback();
    return res.status(400).json({ message: "Invalid route" });
  }

  if (weight <= 0) {
    await connection.rollback();
    return res.status(400).json({ message: "Invalid weight" });
  }

  try {
    await connection.beginTransaction();

    const [users] = await connection.execute(
      "SELECT balance FROM users WHERE id = ? FOR UPDATE",
      [userId]
    );


    const balance = parseFloat(users[0].balance);

    const calculatedPrice = calculatePrice({
      pickup_location,
      dropoff_location,
      weight,
      parcel_type,
      delivery_type
    });

    if (balance < calculatedPrice) {
      await connection.rollback();
      return res.status(400).json({
        message: "Insufficient balance"
      });
    }

    await connection.execute(
      "UPDATE users SET balance = balance - ? WHERE id = ?",
      [calculatedPrice, userId]
    );

    const crypto = require("crypto");
    const pinCode = crypto.randomInt(100000, 999999).toString();

    const [result] = await connection.execute(`
      INSERT INTO parcel_requests
      (user_id, pickup_location, dropoff_location, parcel_type, weight, delivery_type, notes, price, pin_code, receiver_name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      userId,
      pickup_location,
      dropoff_location,
      parcel_type,
      weight,
      delivery_type,
      notes,
      calculatedPrice,
      pinCode,
      receiver_name
    ]);

    const orderNumber = "ORD-" + String(result.insertId).padStart(4, '0');

    await connection.execute(
      "UPDATE parcel_requests SET order_number = ? WHERE id = ?",
      [orderNumber, result.insertId]
    );

    await connection.commit();

    res.json({
      message: "Parcel request submitted",
      orderNumber,
      pinCode
    });

  } catch (err) {
    await connection.rollback();
    console.error("CREATE PARCEL ERROR:", err);
    res.status(500).json({ message: "Server error" });
  } finally {
    connection.release();
  }
};

function calculatePrice({ pickup_location, dropoff_location, weight, parcel_type, delivery_type }) {
  let base = 1.25;

  let dist = pickup_location === dropoff_location ? 0 : 1.25;

  let weightFee = 0.35 * weight;

  let typeFee = {
    'Documents': 0,
    'Small Box': 0.35,
    'Medium Box': 0.75,
    'Large Box': 1.10
  }[parcel_type] || 0.4;

  let express = delivery_type === "express" ? 1.25 : 0;

  return parseFloat((base + dist + weightFee + typeFee + express).toFixed(2));
}
