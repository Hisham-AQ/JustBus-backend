const express = require("express");

const router = express.Router();

const authenticateToken =
  require("../../middleware/authMiddleware");

const adminOnly =
  require("../../middleware/adminOnly");

const controller = require(
  "../../controllers/web/adminRewards.controller"
);

// ================= REWARDS =================
router.get(
  "/",
  authenticateToken,
  adminOnly,
  controller.getRewards
);

router.post(
  "/",
  authenticateToken,
  adminOnly,
  controller.createReward
);

router.put(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.updateReward
);

router.delete(
  "/:id",
  authenticateToken,
  adminOnly,
  controller.deleteReward
);

// ================= RULES =================
router.get(
  "/rules",
  authenticateToken,
  adminOnly,
  controller.getRewardRules
);

router.put(
  "/rules",
  authenticateToken,
  adminOnly,
  controller.updateRewardRules
);

module.exports = router;