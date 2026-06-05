const db = require("../config/db");
const admin = require("./firebase");


exports.sendNotificationToUser = async ({
  userId,
  title,
  message,
  type = "general",
}) => {

  try {

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

    try {

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

    } catch (e) {

      console.log(
        "FCM SEND ERROR:",
        e.message
      );
    }

  } catch (e) {

    console.log(
      "NOTIFICATION ERROR:",
      e.message
    );
  }
};