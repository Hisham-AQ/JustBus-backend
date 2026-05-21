const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminNotifications.controller");

  // ================= GET ALL =================
router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getAllNotifications
);

// ================= GLOBAL =================
router.post(
  "/global",
  authenticateToken,
  adminOnly,
  controller.sendGlobalNotification
);


// ================= USER =================
router.post(
  "/user",
  authenticateToken,
  adminOnly,
  controller.sendUserNotification
);

//delete 
router.delete(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.deleteNotification
);

module.exports = router;