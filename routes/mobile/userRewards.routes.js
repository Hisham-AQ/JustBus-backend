const express = require("express");
const router = express.Router();

const authMiddleware = require("../../middleware/authMiddleware");
const controller = require("../../controllers/mobile/userRewards.controller");

router.get("/", authMiddleware, controller.getPoints);

router.post("/redeem", authMiddleware, controller.redeemReward);

router.post("/validate-reward", authMiddleware, controller.validateReward);

module.exports = router;