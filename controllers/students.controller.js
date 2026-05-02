const db = require("../config/db");

// ================= GET STUDENTS =================
exports.getStudents = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT id, name, email, phone, is_blacklisted
      FROM users
      WHERE role = 'student'
    `);

    res.json(rows);

  } catch (err) {
    console.error("GET STUDENTS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= LEADERBOARD =================
exports.getLeaderboard = async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT id, name, email
      FROM users
      WHERE role = 'student'
      ORDER BY id DESC
      LIMIT 10
    `);

    res.json(rows);

  } catch (err) {
    console.error("LEADERBOARD ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= BLACKLIST =================
exports.blacklistStudent = async (req, res) => {
  try {
    const { id } = req.params;
    const { reason, until } = req.body;

    await db.query(
      `UPDATE users 
       SET is_blacklisted = TRUE, blacklist_reason = ?, blacklist_until = ?
       WHERE id = ?`,
      [reason || null, until || null, id]
    );

    res.json({ message: "Student blacklisted" });

  } catch (err) {
    console.error("BLACKLIST ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= MANUAL BLACKLIST =================
exports.manualBlacklist = async (req, res) => {
  try {
    const { email, reason } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    await db.query(
      `INSERT INTO users (email, role, is_blacklisted, blacklist_reason)
       VALUES (?, 'student', TRUE, ?)`,
      [email, reason || null]
    );

    res.json({ message: "Student manually blacklisted" });

  } catch (err) {
    console.error("MANUAL BLACKLIST ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= REMOVE BLACKLIST =================
exports.removeBlacklist = async (req, res) => {
  try {
    const { id } = req.params;

    await db.query(
      `UPDATE users 
       SET is_blacklisted = FALSE, blacklist_reason = NULL, blacklist_until = NULL
       WHERE id = ?`,
      [id]
    );

    res.json({ message: "Blacklist removed" });

  } catch (err) {
    console.error("REMOVE BLACKLIST ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ================= DELETE =================
exports.deleteStudent = async (req, res) => {
  try {
    const { id } = req.params;

    await db.query("DELETE FROM users WHERE id = ?", [id]);

    res.json({ message: "Student deleted" });

  } catch (err) {
    console.error("DELETE STUDENT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
};