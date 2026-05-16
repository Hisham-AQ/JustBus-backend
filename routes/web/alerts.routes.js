const express = require("express");
const router = express.Router();

const alertsController = require("../../controllers/web/alerts.controller");

// GET alerts
router.get("/", alertsController.getAlerts);

module.exports = router;