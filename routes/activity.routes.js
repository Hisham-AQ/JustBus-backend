const express = require("express");
const router = express.Router();

const activityController = require("../controllers/activity.controller");
const authenticateToken = require("../middleware/authMiddleware");

router.get("/", authenticateToken, activityController.getMyActivity);

module.exports = router;