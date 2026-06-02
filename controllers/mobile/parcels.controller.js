const db = require("../../config/db");
const crypto = require("crypto");

exports.createParcel = async (req, res) => {
  const userId = req.user.id;

  const {
    pickup_location,
    dropoff_location,
    parcel_type,
    weight,
    delivery_type,
    notes,
    receiver_name,
    rewardCode
  } = req.body;

  const connection = await db.getConnection();

  try {
    if (!receiver_name || receiver_name.trim() === "") {
      return res.status(400).json({ message: "Receiver name required" });
    }

    if (pickup_location === dropoff_location) {
      return res.status(400).json({ message: "Invalid route" });
    }

    if (!weight || weight <= 0) {
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

    const balance = parseFloat(users[0].wallet_balance);

    const calculatedPrice = calculatePrice({
      pickup_location,
      dropoff_location,
      weight,
      parcel_type,
      delivery_type
    });

    let finalPrice = calculatedPrice;
    let rewardId = null;
    if (rewardCode) {
      const [rewardRows] = await connection.execute(
        `SELECT * FROM user_rewards
     WHERE code = ?
     AND user_id = ?
     AND is_used = 0
     FOR UPDATE`,
        [rewardCode, userId]
      );

      if (rewardRows.length === 0) {
        await connection.rollback();
        return res.status(400).json({ message: "Invalid or used reward code" });
      }

      const reward = rewardRows[0];
      rewardId = reward.id;

      if (reward.type === "free_parcel") {
        finalPrice = 0;
      } else if (reward.type === "discount") {
        finalPrice = parseFloat((calculatedPrice * 0.9).toFixed(2));
      } else {
        await connection.rollback();
        return res.status(400).json({ message: "Unsupported reward type" });
      }
    }
    if (balance < finalPrice) {
      await connection.rollback();
      return res.status(400).json({
        message: "Insufficient balance"
      });
    }

    if (finalPrice > 0) {
      const [updateResult] = await connection.execute(
        "UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ? AND wallet_balance >= ?",
        [finalPrice, userId, finalPrice]
      );

      if (updateResult.affectedRows === 0) {
        await connection.rollback();
        return res.status(400).json({ message: "Insufficient balance" });
      }
    }


    await connection.execute(
      "INSERT INTO wallet_transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)",
      [userId, "payment", finalPrice, "Parcel delivery"]
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
      finalPrice,
      pinCode,
      receiver_name
    ]);


    const orderNumber = "ORD-" + String(result.insertId).padStart(4, '0');

    await connection.execute(
      "UPDATE parcel_requests SET order_number = ? WHERE id = ?",
      [orderNumber, result.insertId]
    );

    await connection.execute(
      "UPDATE users SET points = points + ? WHERE id = ?",
      [15, userId]
    );

    await connection.execute(
      "INSERT INTO points_transactions (user_id, type, points) VALUES (?, ?, ?)",
      [userId, "parcel", 15]
    );


    if (rewardId) {
      await connection.execute(
        "UPDATE user_rewards SET is_used = 1 WHERE id = ?",
        [rewardId]
      );
    }
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