const db = require("../../config/db");
const { sendNotificationToUser,} = require("../../utils/sendNotification");


// ================= getAllReports =================
exports.getAllReports = async (req, res) => {
    try {

        const [rows] = await db.query(`
            SELECT
                li.id,
                li.category,
                li.item_name,
                li.description,
                li.status,
                li.lost_date,
                li.image_url,
                u.name AS user_name
            FROM lost_items li
            LEFT JOIN users u
            ON li.user_id = u.id
            ORDER BY li.created_at DESC
        `);

        res.json(rows);

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};


// ================= updateReportStatus =================
exports.updateReportStatus = async (req, res) => {

    const { id } = req.params;
    const { status } = req.body;
    try {
        const [items] = await db.query(`
  SELECT
    item_name,
    user_id
  FROM lost_items
  WHERE id = ?
`, [id]);

if (items.length === 0) {

  return res.status(404).json({
    message: "Item not found"
  });
}

const item =
  items[0];

        await db.query(`
            UPDATE lost_items
            SET status = ?
            WHERE id = ?
        `, [status, id]);

        if (
  status === "found" ||
  status === "claimed"
) {

await sendNotificationToUser({
  userId: item.user_id,

  title: "Lost Item Update",

  message:
    `Your lost item "${item.item_name}" status was updated to "${status}".`,

  type: "lost_item",
});
}

        res.json({
            message: "Status updated"
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            message: "Server error"
        });
    }
};