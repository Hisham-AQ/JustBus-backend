const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminNotifications.controller");

router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getAllNotifications
);

router.post(
  "/global",
  authenticateToken,
  adminOnly,
  controller.sendGlobalNotification
);


router.post(
  "/user",
  authenticateToken,
  adminOnly,
  controller.sendUserNotification
);

router.delete(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.deleteNotification
);

module.exports = router;