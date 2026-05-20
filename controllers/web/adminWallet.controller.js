const db =
  require("../../config/db");

exports.getStudentWallets =
  async (req, res) => {

    try {

      const [rows] =
        await db.query(`

          SELECT
            id,
            name,
            email,
            wallet_balance

          FROM users

          WHERE role = 'student'

          ORDER BY name ASC

        `);

      res.json(rows);

    } catch (err) {

      console.error(err);

      res.status(500).json({
        message:
          "Server error"
      });
    }
};

// Update student balance
exports.updateStudentBalance =
  async (req, res) => {

    const { id } =
      req.params;

    const { amount } =
      req.body;

    try {

      const parsed =
        parseFloat(amount);

      if (
        isNaN(parsed)
      ) {

        return res
          .status(400)
          .json({

            message:
              "Invalid amount"

          });
      }

      await db.query(
        `
        UPDATE users

        SET wallet_balance = ?

        WHERE id = ?
        `,
        [parsed, id]
      );

      await db.query(
        `
        INSERT INTO
        wallet_transactions

        (
          user_id,
          type,
          amount,
          description
        )

        VALUES (?, ?, ?, ?)
        `,
        [
          id,
          "topup",
          parsed,
          "Admin balance edit"
        ]
      );

      res.json({

        message:
          "Balance updated"

      });

    } catch (err) {

      console.error(err);

      res.status(500).json({
        message:
          "Server error"
      });
    }
};