const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller =
  require("../../controllers/web/dashboard.controller");

router.get(
  "/stats",
  authenticateToken,
  adminOnly,
  controller.getDashboardStats
);

router.get(
  "/weekly-trips",
  authenticateToken,
  adminOnly,
  controller.getWeeklyTrips
);

module.exports = router;