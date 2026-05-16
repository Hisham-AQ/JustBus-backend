const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");
const dashboardController = require("../../controllers/web/dashboard.controller");

router.get("/stats", authenticateToken, allowRoles("admin"), dashboardController.getStats);

module.exports = router;