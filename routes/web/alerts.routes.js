const express = require("express");
const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const alertsController =
  require("../../controllers/web/alerts.controller");

// GET alerts
router.get(
  "/",
  authenticateToken,
  alertsController.getAlerts
);

module.exports = router;