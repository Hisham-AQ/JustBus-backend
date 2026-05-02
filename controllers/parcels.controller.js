const db = require("../config/db");
const { io } = require("../index");
const crypto = require("crypto");

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

  try {
    if (!receiver_name || receiver_name.trim() === "") {
      return res.status(400).json({ message: "Receiver name required" });
    }

    if (pickup_location === dropoff_location) {
      return res.status(400).json({ message: "Invalid route" });
    }

    if (weight <= 0) {
      return res.status(400).json({ message: "Invalid weight" });
    }

    await connection.beginTransaction();

    const [users] = await connection.execute(
      "SELECT wallet_balance FROM users WHERE id = ? FOR UPDATE",
      [userId]
    );

    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "User not found" });
    }

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
      "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?",
      [calculatedPrice, userId]
    );

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

// ================= GET PARCELS =================
exports.getParcels = async (req, res) => {
  try {
    const [rows] = await db.execute(
      "SELECT * FROM parcel_requests WHERE user_id = ?",
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

// ================= UPDATE STATUS =================
exports.updateParcelStatus = async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    await db.execute(
      "UPDATE parcel_requests SET status = ? WHERE id = ?",
      [status, id]
    );

    res.json({ message: "Status updated" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

// ================= PRICE =================
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