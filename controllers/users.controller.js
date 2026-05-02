const db = require("../config/db");

exports.getProfile = async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
        name,
        email,
        phone,
        gender,
        birth_date
       FROM users
       WHERE id = ?`,
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(rows[0]);

  } catch (err) {
    console.error("GET PROFILE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.getUsers = async (req, res) => {
  try {
    const [users] = await db.query(
      "SELECT id, email, role FROM users"
    );

    res.json(users);

  } catch (err) {
    console.error("GET USERS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, birth_date, phone } = req.body;

    if (!name && !birth_date && !phone) {
      return res.status(400).json({ message: "Nothing to update" });
    }

    if (birth_date && isNaN(Date.parse(birth_date))) {
      return res.status(400).json({ message: "Invalid birth date" });
    }

    const fields = [];
    const values = [];

    if (name) {
      fields.push("name = ?");
      values.push(name);
    }

    if (birth_date) {
      fields.push("birth_date = ?");
      values.push(birth_date);
    }

    if (phone) {
      fields.push("phone = ?");
      values.push(phone);
    }

    values.push(userId);

    const sql = `
      UPDATE users
      SET ${fields.join(", ")}
      WHERE id = ?
    `;

    await db.query(sql, values);

    res.json({ message: "Profile updated successfully" });

  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        message: "Phone number already in use",
      });
    }

    console.error("UPDATE PROFILE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};