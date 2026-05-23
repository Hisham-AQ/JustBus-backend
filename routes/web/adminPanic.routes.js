const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminPanic.controller");

// GET ALERTS
router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getAlerts
);

// RESOLVE ALERT
router.put(
  "/:id/resolve",
  authenticateToken,
  adminOnly,
  controller.resolveAlert
);

// RESOLVED ALERTS
router.get(
  "/history",
  authenticateToken,
  adminOnly,
  controller.getResolvedAlerts
);

module.exports = router;