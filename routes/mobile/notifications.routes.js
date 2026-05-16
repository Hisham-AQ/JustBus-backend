const express = require("express");
const router = express.Router();

const authMiddleware = require("../../middleware/authMiddleware");

const controller = require("../../controllers/mobile/notifications.controller");

// GET notifications
router.get("/notifications", authMiddleware, controller.getNotifications);

router.patch(
    "/notifications/:id/read",
    authMiddleware,
    controller.markAsRead
);

router.delete(
    "/notifications/:id",
    authMiddleware,
    controller.deleteNotification
);

module.exports = router;