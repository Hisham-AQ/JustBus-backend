const express = require("express");
const router = express.Router();

const authenticateToken = require("../../middleware/authMiddleware");
const allowRoles = require("../../middleware/roleMiddleware");

const rewardsController = require("../../controllers/mobile/rewards.controller");

router.get(
  "/rules",
  authenticateToken,
  allowRoles("admin"),
  rewardsController.getRules
);

router.put(
  "/rules",
  authenticateToken,
  allowRoles("admin"),
  rewardsController.updateRules
);

module.exports = router;