const db = require("../../config/db");

// ================= GET REWARDS =================
exports.getRewards = async (req, res) => {

  try {

    const [rows] = await db.query(`
      SELECT *
      FROM rewards
      ORDER BY points_required ASC
    `);

    res.json(rows);

  } catch (err) {

    console.error(
      "GET REWARDS ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= CREATE REWARD =================
exports.createReward = async (req, res) => {

  try {

    const {
      title,
      description,
      points_required,
      type
    } = req.body;

    await db.query(`
      INSERT INTO rewards (
        title,
        description,
        points_required,
        type
      )
      VALUES (?, ?, ?, ?)
    `, [
      title,
      description,
      points_required,
      type
    ]);

    res.status(201).json({
      message:
        "Reward created successfully"
    });

  } catch (err) {

    console.error(
      "CREATE REWARD ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= UPDATE REWARD =================
exports.updateReward = async (req, res) => {

  try {

    const { id } = req.params;

    const {
      title,
      description,
      points_required,
      type
    } = req.body;

    await db.query(`
      UPDATE rewards
      SET
        title = ?,
        description = ?,
        points_required = ?,
        type = ?
      WHERE id = ?
    `, [
      title,
      description,
      points_required,
      type,
      id
    ]);

    res.json({
      message:
        "Reward updated successfully"
    });

  } catch (err) {

    console.error(
      "UPDATE REWARD ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= DELETE REWARD =================
exports.deleteReward = async (req, res) => {

  try {

    const { id } = req.params;

    await db.query(`
      DELETE FROM rewards
      WHERE id = ?
    `, [id]);

    res.json({
      message:
        "Reward deleted successfully"
    });

  } catch (err) {

    console.error(
      "DELETE REWARD ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= GET RULES =================
exports.getRewardRules = async (req, res) => {

  try {

    const [rows] = await db.query(`
      SELECT *
      FROM reward_rules
      LIMIT 1
    `);

    res.json(
      rows[0] || null
    );

  } catch (err) {

    console.error(
      "GET RULES ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};

// ================= UPDATE RULES =================
exports.updateRewardRules =
async (req, res) => {

  try {

    const {
      points_per_trip,
      bonus_threshold,
      reward
    } = req.body;

    await db.query(`
      UPDATE reward_rules
      SET
        points_per_trip = ?,
        bonus_threshold = ?,
        reward = ?
      WHERE id = 1
    `, [
      points_per_trip,
      bonus_threshold,
      reward
    ]);

    res.json({
      message:
        "Reward rules updated"
    });

  } catch (err) {

    console.error(
      "UPDATE RULES ERROR:",
      err
    );

    res.status(500).json({
      message: "Server error"
    });
  }
};