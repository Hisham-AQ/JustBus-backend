const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const controller = require("../controllers/notifications.controller");

// GET notifications
router.get("/notifications", authMiddleware, controller.getNotifications);

module.exports = router;