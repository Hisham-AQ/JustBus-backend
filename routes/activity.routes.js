const express = require("express");
const router = express.Router();

const authenticateToken = require("../middleware/authMiddleware");
const controller = require("../controllers/activity.controller");

router.get("/activity", authenticateToken, controller.getMyActivity);

module.exports = router;