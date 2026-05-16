const express = require("express");
const router = express.Router();

const authMiddleware = require("../../middleware/authMiddleware");
const controller = require("../../controllers/mobile/userRewards.controller");

// GET points
router.get("/", authMiddleware, controller.getPoints);

// Redeem reward (generate code)
router.post("/redeem", authMiddleware, controller.redeemReward);

// Validate reward
router.post("/validate-reward", authMiddleware, controller.validateReward);

module.exports = router;