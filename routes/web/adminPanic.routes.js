const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/adminPanic.controller");

router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getAlerts
);

router.put(
  "/:id/resolve",
  authenticateToken,
  adminOnly,
  controller.resolveAlert
);

router.get(
  "/history",
  authenticateToken,
  adminOnly,
  controller.getResolvedAlerts
);

module.exports = router;