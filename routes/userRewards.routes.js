const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const controller = require("../controllers/userRewards.controller");

// GET points
router.get("/", authMiddleware, controller.getPoints);

// Redeem reward
router.post("/redeem", authMiddleware, controller.redeemReward);
router.post("/validate-reward", authMiddleware, validateReward);

module.exports = router;