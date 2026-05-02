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
    console.error("CREATE PARCEL ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= GET PARCELS =================
exports.getParcels = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        id,
        order_number,
        pickup_location,
        dropoff_location,
        parcel_type,
        weight,
        delivery_type,
        price,
        status,
        created_at
      FROM parcel_requests
      ORDER BY created_at DESC
    `);

    res.json(rows);

  } catch (err) {
    console.error("GET PARCELS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};


// ================= UPDATE PARCEL STATUS =================
exports.updateParcelStatus = async (req, res) => {
  
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ message: "Status is required" });
    }

    // optional: restrict allowed statuses
    const allowed = ["pending", "in_transit", "delivered", "cancelled"];
    if (!allowed.includes(status)) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const [result] = await db.execute(
      "UPDATE parcel_requests SET status = ? WHERE id = ?",
      [status, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Parcel not found" });
    }

    io.emit("parcel:updated", {
      id,
      status
    });

    res.json({ message: "Status updated" });

  } catch (err) {
    console.error("UPDATE PARCEL STATUS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};