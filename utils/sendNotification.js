const db = require("../config/db");
const admin = require("./firebase");

exports.sendNotificationToUser = async ({
  userId,
  title,
  message,
  type = "general",
}) => {
  try {
    console.log("SAVING NOTIFICATION");
    await db.query(
      `
  INSERT INTO notifications
  (
    user_id,
    title,
    message,
    type,
    is_global
  )
  VALUES (?, ?, ?, ?, ?)
  `,
      [
        userId,
        title,
        message,
        type,
        0,
      ]
    );
    console.log("NOTIFICATION SAVED");
    // get fcm token
    const [users] = await db.query(
      `
      SELECT fcm_token
      FROM users
      WHERE id = ?
      LIMIT 1
      `,
      [userId]
    );

    if (!users.length) return;

    const token = users[0].fcm_token;

    if (!token) return;

    // send push
    await admin.messaging().send({
      token,

      notification: {
        title,
        body: message,
      },

      android: {
        priority: "high",
      },
    });

    console.log(
      "Push notification sent"
    );
  } catch (e) {

    console.log("==========");

    console.log(e);

    console.log("==========");
  }

};