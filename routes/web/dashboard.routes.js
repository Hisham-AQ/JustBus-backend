const express = require("express");

const router = express.Router();

const controller =
  require("../../controllers/web/dashboard.controller");

router.get(
  "/stats",
  controller.getDashboardStats
);

router.get(
  "/weekly-trips",
  controller.getWeeklyTrips
);

module.exports = router;