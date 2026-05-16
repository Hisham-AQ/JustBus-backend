const express = require("express");
const router = express.Router();

const authMiddleware = require("../../middleware/authMiddleware");

const controller = require("../../controllers/mobile/notifications.controller");

// GET notifications
router.get("/", authMiddleware, controller.getNotifications);

router.patch(
  "/:id/read",
  authMiddleware,
  controller.markAsRead
);

router.delete(
  "/:id",
  authMiddleware,
  controller.deleteNotification
);

module.exports = router;