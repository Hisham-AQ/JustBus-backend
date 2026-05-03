const express = require("express");
const router = express.Router();

const activityController = require("../controllers/activity.controller");
const authenticateToken = require("../middleware/authMiddleware");

router.get("/activity", authenticateToken, controller.getMyActivity);

module.exports = router;