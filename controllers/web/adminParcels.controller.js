const db = require("../../config/db");

const {
  sendNotificationToUser,
} = require("../../utils/sendNotification");

// ================= GET ALL PARCELS =================
exports.getParcels = async (req, res) => {

  try {

    const [rows] = await db.query(`
      SELECT
        p.*,

        u.name AS userName,
        u.email AS userEmail

      FROM parcel_requests p

      LEFT JOIN users u
      ON p.user_id = u.id

      ORDER BY p.created_at DESC
    `);

    res.json(rows);

  } catch (err) {

    console.error("GET PARCELS ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= UPDATE STATUS =================
exports.updateParcelStatus = async (req, res) => {

  try {

    const { id } = req.params;

    const { status } = req.body;

    await db.query(
      `
      UPDATE parcel_requests
      SET status = ?
      WHERE id = ?
      `,
      [status, id]
    );

    res.json({
      message: "Parcel status updated"
    });

  } catch (err) {

    console.error("UPDATE PARCEL STATUS ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= DELETE =================
exports.deleteParcel = async (req, res) => {

  try {

    const { id } = req.params;

    await db.query(
      `
      DELETE FROM parcel_requests
      WHERE id = ?
      `,
      [id]
    );

    res.json({
      message: "Parcel deleted successfully"
    });

  } catch (err) {

    console.error("DELETE PARCEL ERROR:", err);

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= VERIFY DELIVERY =================
exports.verifyDelivery = async (req, res) => {

  try {

    const { id } = req.params;

    const { pin_code } = req.body;

    const [rows] = await db.query(
      `
 SELECT
  pin_code,
  user_id,
  receiver_name
FROM parcel_requests
WHERE id = ?
      `,
      [id]
    );

    if (rows.length === 0) {

      return res.status(404).json({
        message: "Parcel not found"
      });
    }

    const parcel = rows[0];

    if (String(parcel.pin_code) !== String(pin_code)) {

      return res.status(400).json({
        message: "Invalid PIN code"
      });
    }



    await db.query(
      `
      UPDATE parcel_requests
      SET status = 'delivered'
      WHERE id = ?
      `,
      [id]
    );

    await sendNotificationToUser({
      userId: parcel.user_id,

      title: "Parcel Delivered",

      message:
        `Parcel for "${parcel.receiver_name}" has been marked as delivered.`,

      type: "parcel",
    });


    res.json({
      message: "Parcel delivered successfully"
    });

  } catch (err) {

    console.error(
      "VERIFY DELIVERY ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= PARCEL COUNT =================
exports.getParcelNotifications =
  async (req, res) => {

    try {

      const [rows] =
        await db.query(`

          SELECT COUNT(*) AS total

          FROM parcel_requests

          WHERE status != 'delivered'

        `);

      res.json({
        total: rows[0].total
      });

    } catch (err) {

      console.error(
        "PARCEL COUNT ERROR:",
        err
      );

      res.status(500).json({
        message: "Server error"
      });
    }
  };